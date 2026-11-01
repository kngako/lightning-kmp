package fr.acinq.lightning.iceberg

import fr.acinq.bitcoin.ByteVector
import fr.acinq.bitcoin.OutPoint
import fr.acinq.bitcoin.PublicKey
import fr.acinq.bitcoin.ScriptFlags
import fr.acinq.bitcoin.Transaction
import fr.acinq.bitcoin.TxId
import fr.acinq.bitcoin.TxOut
import fr.acinq.bitcoin.crypto.musig2.IndividualNonce
import fr.acinq.bitcoin.utils.Either
import fr.acinq.lightning.Lightning.randomBytes32
import fr.acinq.lightning.blockchain.WatchConfirmed
import fr.acinq.lightning.blockchain.WatchConfirmedTriggered
import fr.acinq.lightning.blockchain.fee.FeeratePerKw
import fr.acinq.lightning.channel.ChannelCommand
import fr.acinq.lightning.channel.ChannelSpendSignature
import fr.acinq.lightning.channel.LNChannel
import fr.acinq.lightning.channel.SpliceStatus
import fr.acinq.lightning.channel.TestsHelper.addHtlc
import fr.acinq.lightning.channel.TestsHelper.crossSign
import fr.acinq.lightning.channel.findOutgoingMessage
import fr.acinq.lightning.channel.TestsHelper.fulfillHtlc
import fr.acinq.lightning.channel.hasOutgoingMessage
import fr.acinq.lightning.channel.TestsHelper.localClose
import fr.acinq.lightning.channel.TestsHelper.mutualCloseAlice
import fr.acinq.lightning.channel.TestsHelper.mutualCloseBob
import fr.acinq.lightning.channel.TestsHelper.reachNormal
import fr.acinq.lightning.channel.states.Normal
import fr.acinq.lightning.channel.states.SpliceTestsCommon.Companion.exchangeSpliceSigs
import fr.acinq.lightning.channel.states.SpliceTestsCommon.Companion.spliceIn
import fr.acinq.lightning.channel.states.SpliceTestsCommon.Companion.spliceInAndOutWithoutSigs
import fr.acinq.lightning.channel.states.SyncingTestsCommon.Companion.disconnect
import fr.acinq.lightning.crypto.FundingSigner
import fr.acinq.lightning.crypto.IcebergFundingSigner
import fr.acinq.lightning.crypto.IcebergGroup
import fr.acinq.lightning.crypto.IcebergSigner
import fr.acinq.lightning.tests.TestConstants
import fr.acinq.lightning.tests.utils.LightningTestSuite
import fr.acinq.lightning.tests.utils.runSuspendTest
import fr.acinq.lightning.transactions.Transactions
import fr.acinq.lightning.utils.msat
import fr.acinq.lightning.utils.sat
import fr.acinq.lightning.wire.LiquidityAds
import fr.acinq.lightning.wire.SpliceAck
import fr.acinq.lightning.wire.SpliceInit
import fr.acinq.lightning.wire.SpliceLocked
import fr.acinq.lightning.wire.Stfu
import fr.acinq.lightning.wire.TxAddInput
import fr.acinq.lightning.wire.CommitSig
import kotlinx.coroutines.CompletableDeferred
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.test.assertNotEquals
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

/**
 * Splicing a channel whose funding key is an Iceberg group's (FEATURE-PARITY.md, Phase 6, design B):
 * the group serves its one key at every funding index, the counterparty rotates its own, and the
 * script interpreter judges every transaction the group signs on the way.
 *
 * lightning-kmp does not implement the seller side of liquidity ads, so a liquidity purchase is
 * carried here only as far as the counterparty accepting the group's request; the purchase itself
 * is proved against eclair on regtest (`docs/group-lightning-liquidity.md`, Phase 0).
 */
class IcebergSpliceTestsCommon : LightningTestSuite() {

    /**
     * The group's signer, recording which transaction each nonce identity signed. Iceberg derives
     * round one from a label, so one identity answered under two different transactions leaks the
     * share with no error: this is the check that it never happens across a splice.
     */
    private class OneMessagePerNonce(private val underlying: FundingSigner) : FundingSigner by underlying {
        val verification = mutableMapOf<FundingSigner.VerificationNonceId, TxId>()
        val published = mutableListOf<Pair<FundingSigner.PublishedNonceSession, TxId>>()
        /** What each signature was said to be for, in order. */
        val contexts = mutableListOf<FundingSigner.SigningContext>()

        override suspend fun signWithFreshNonce(tx: Transactions.ChannelSpendTransaction, remoteFundingPubKey: PublicKey, extraUtxos: Map<OutPoint, TxOut>, fundingTxId: TxId, remoteNonce: IndividualNonce, context: FundingSigner.SigningContext): Either<Throwable, ChannelSpendSignature.PartialSignatureWithNonce> {
            contexts += context
            return underlying.signWithFreshNonce(tx, remoteFundingPubKey, extraUtxos, fundingTxId, remoteNonce, context)
        }

        override suspend fun signWithVerificationNonce(tx: Transactions.ChannelSpendTransaction, remoteFundingPubKey: PublicKey, extraUtxos: Map<OutPoint, TxOut>, id: FundingSigner.VerificationNonceId, remoteNonce: IndividualNonce, context: FundingSigner.SigningContext): Either<Throwable, ChannelSpendSignature.PartialSignatureWithNonce> {
            val earlier = verification.put(id, tx.tx.txid)
            check(earlier == null || earlier == tx.tx.txid) { "verification nonce $id signed $earlier and then ${tx.tx.txid}" }
            contexts += context
            return underlying.signWithVerificationNonce(tx, remoteFundingPubKey, extraUtxos, id, remoteNonce, context)
        }

        override suspend fun signWithPublishedNonce(tx: Transactions.ChannelSpendTransaction, remoteFundingPubKey: PublicKey, extraUtxos: Map<OutPoint, TxOut>, session: FundingSigner.PublishedNonceSession, remoteNonce: IndividualNonce, context: FundingSigner.SigningContext): Either<Throwable, ChannelSpendSignature.PartialSignatureWithNonce> {
            published.filter { it.first === session }.forEach { (_, earlier) -> check(earlier == tx.tx.txid) { "a published nonce session signed $earlier and then ${tx.tx.txid}" } }
            published += session to tx.tx.txid
            contexts += context
            return underlying.signWithPublishedNonce(tx, remoteFundingPubKey, extraUtxos, session, remoteNonce, context)
        }
    }

    private val group: IcebergGroup = IcebergSigner.keygen(4, 2, randomBytes32())

    private fun signer() = OneMessagePerNonce(IcebergFundingSigner(group))

    /**
     * One complete payment from Alice to Bob: add, cross-sign, fulfill, cross-sign. While a splice is
     * unconfirmed each side signs one commitment per live funding output, in one `commit_sig` batch.
     */
    private fun payOnce(alice: LNChannel<Normal>, bob: LNChannel<Normal>): Pair<LNChannel<Normal>, LNChannel<Normal>> {
        val live = alice.commitments.active.size
        val (nodes, preimage, htlc) = addHtlc(1_000_000.msat, alice, bob)
        val (alice1, bob1) = crossSign(nodes.first, nodes.second, commitmentsCount = live)
        val (alice2, bob2) = fulfillHtlc(htlc.id, preimage, alice1, bob1)
        return crossSign(bob2, alice2, commitmentsCount = live).let { (bob3, alice3) -> Pair(alice3, bob3) }
    }

    /**
     * After a splice: the newest funding output is the group key with the counterparty's key at the
     * new index, that key differs from the one at the parent index, and both sides hold a commitment
     * that spends the new output.
     */
    private fun assertSplicedUnderGroupKey(alice: LNChannel<Normal>, bob: LNChannel<Normal>, groupOnBobSide: Boolean) {
        val (stock, grouped) = if (groupOnBobSide) alice to bob else bob to alice
        val latest = stock.commitments.latest
        assertEquals(1, latest.fundingTxIndex)
        assertEquals(group.groupPublicKey, latest.remoteFundingPubkey, "the stock side does not see the group key at index 1")
        val parent = stock.commitments.active.first { it.fundingTxIndex == 0L }
        assertEquals(group.groupPublicKey, parent.remoteFundingPubkey)
        val stockKey = grouped.commitments.latest.remoteFundingPubkey
        assertNotEquals(grouped.commitments.active.first { it.fundingTxIndex == 0L }.remoteFundingPubkey, stockKey, "the counterparty did not rotate its key")
        val expected = Transactions.makeFundingScript(stockKey, group.groupPublicKey, Transactions.CommitmentFormat.SimpleTaprootChannels).pubkeyScript
        val fundingTxOut = alice.commitments.latest.localFundingStatus.txOut
        assertEquals(expected, fundingTxOut.publicKeyScript, "the new funding output is not the 2-of-2 of the group key and the counterparty's new key")
        assertBothSidesSpend(alice, bob)
    }

    private fun assertBothSidesSpend(alice: LNChannel<Normal>, bob: LNChannel<Normal>) {
        val fundingInput = alice.commitments.latest.fundingInput
        val fundingTxOut = alice.commitments.latest.localFundingStatus.txOut
        listOf(alice, bob).forEach { node ->
            val signed = node.signCommitTx()
            Transaction.correctlySpends(signed, mapOf(fundingInput to fundingTxOut), ScriptFlags.STANDARD_SCRIPT_VERIFY_FLAGS)
        }
    }

    /** The splice transaction, which spends the parent funding output under the group's signature. */
    private fun assertSpliceTxSpendsParent(node: LNChannel<Normal>) {
        val spliceTx = node.commitments.latest.localFundingStatus.signedTx
        assertNotNull(spliceTx)
        val parent = node.commitments.active.first { it.fundingTxIndex == 0L }
        assertTrue(spliceTx.txIn.any { it.outPoint == parent.fundingInput }, "the splice does not spend the parent funding output")
        val status = node.commitments.latest.localFundingStatus
        assertIs<fr.acinq.lightning.channel.LocalFundingStatus.UnconfirmedFundingTx>(status)
        // The script interpreter is the judge: the shared input carries the group's aggregate signature.
        Transaction.correctlySpends(spliceTx, status.sharedTx.tx.spentOutputs, ScriptFlags.STANDARD_SCRIPT_VERIFY_FLAGS)
    }

    private fun lock(alice: LNChannel<Normal>, bob: LNChannel<Normal>): Pair<LNChannel<Normal>, LNChannel<Normal>> {
        val spliceTx = alice.commitments.latest.localFundingStatus.signedTx!!
        val (alice1, actionsAlice1) = alice.process(ChannelCommand.WatchReceived(WatchConfirmedTriggered(alice.channelId, WatchConfirmed.ChannelFundingDepthOk, 42, 0, spliceTx)))
        val (bob1, _) = bob.process(ChannelCommand.MessageReceived(actionsAlice1.findOutgoingMessage<SpliceLocked>()))
        val (bob2, actionsBob2) = bob1.process(ChannelCommand.WatchReceived(WatchConfirmedTriggered(bob.channelId, WatchConfirmed.ChannelFundingDepthOk, 42, 0, spliceTx)))
        val (alice2, _) = alice1.process(ChannelCommand.MessageReceived(actionsBob2.findOutgoingMessage<SpliceLocked>()))
        assertIs<LNChannel<Normal>>(alice2)
        assertIs<LNChannel<Normal>>(bob2)
        assertEquals(1, alice2.commitments.active.size)
        assertEquals(1, bob2.commitments.active.size)
        return alice2 to bob2
    }

    /**
     * The shared input was signed once, told it was this splice: the parent output it spends, the new
     * output by index and script, the counterparty's new key, and every output the transaction spends.
     */
    private fun assertToldItWasTheSplice(signer: OneMessagePerNonce, grouped: LNChannel<Normal>): FundingSigner.SigningContext.Splice {
        val splice = signer.contexts.filterIsInstance<FundingSigner.SigningContext.Splice>().single()
        val latest = grouped.commitments.latest
        val parent = grouped.commitments.active.first { it.fundingTxIndex == 0L }
        assertEquals(0, splice.parentFundingTxIndex)
        assertEquals(1, splice.fundingTxIndex)
        assertEquals(parent.fundingInput, splice.parentFunding.outPoint)
        assertEquals(latest.remoteFundingPubkey, splice.remoteFundingPubKey)
        val spliceTx = latest.localFundingStatus.signedTx!!
        assertEquals(latest.localFundingStatus.txOut, spliceTx.txOut[splice.fundingOutputIndex])
        assertEquals(spliceTx.txIn.map { it.outPoint }.toSet(), splice.spentOutputs.keys)
        assertEquals(splice.parentFunding.txOut.amount + splice.localContribution + splice.remoteContribution, latest.fundingAmount)
        // The first commitment on the new output was signed before the shared input, and said which output it was on.
        val firstOnNew = signer.contexts.indexOfFirst { it is FundingSigner.SigningContext.RemoteCommitment && it.fundingTxIndex == 1L }
        assertTrue(firstOnNew in 0 until signer.contexts.indexOf(splice), "the shared input was signed before the first commitment on the new output")
        return splice
    }

    @Test
    fun `the group splices in from its wallet, and serves its one key at the new index`() {
        val signer = signer()
        val (alice, bob, _) = reachNormal(aliceFundingSigner = signer)
        val (alice1, bob1) = spliceIn(alice, bob, listOf(50_000.sat))
        assertSplicedUnderGroupKey(alice1, bob1, groupOnBobSide = false)
        assertSpliceTxSpendsParent(alice1)
        val splice = assertToldItWasTheSplice(signer, alice1)
        assertTrue(splice.localContribution > 0.sat && splice.remoteContribution == 0.sat)
        assertEquals(null, splice.purchase)
    }

    @Test
    fun `the counterparty splices in, and the group accepts it -- the path an on-the-fly splice takes`() {
        val signer = signer()
        val (alice, bob, _) = reachNormal(bobFundingSigner = signer)
        val (alice1, bob1) = spliceIn(alice, bob, listOf(50_000.sat))
        assertSplicedUnderGroupKey(alice1, bob1, groupOnBobSide = true)
        assertSpliceTxSpendsParent(bob1)
        val splice = assertToldItWasTheSplice(signer, bob1)
        assertTrue(splice.localContribution == 0.sat && splice.remoteContribution > 0.sat)
    }

    @Test
    fun `the group splices out`() {
        val signer = signer()
        val (alice, bob, _) = reachNormal(aliceFundingSigner = signer)
        val (alice1, commitSigAlice, bob1, commitSigBob) = spliceInAndOutWithoutSigs(alice, bob, inAmounts = listOf(50_000.sat), outAmount = 100_000.sat)
        val (alice2, bob2) = exchangeSpliceSigs(alice1, commitSigAlice, bob1, commitSigBob)
        assertSplicedUnderGroupKey(alice2, bob2, groupOnBobSide = false)
        assertSpliceTxSpendsParent(alice2)
        // Ours falls by the amount spliced out and our share of the mining fee; the extra output is the splice-out.
        val splice = assertToldItWasTheSplice(signer, alice2)
        assertTrue(splice.localContribution < 0.sat)
        assertEquals(1, alice2.commitments.latest.localFundingStatus.signedTx!!.txOut.count { it.amount == 100_000.sat })
    }

    @Test
    fun `payments over both live commitments, then over the locked one`() {
        val signer = signer()
        val (alice, bob, _) = reachNormal(bobFundingSigner = signer)
        val (alice1, bob1) = spliceIn(alice, bob, listOf(50_000.sat))
        assertEquals(2, alice1.commitments.active.size)
        // While the splice is unconfirmed, every update signs one commitment per funding output, both
        // at the same commit index; the group signs each, told which output each is on.
        signer.contexts.clear()
        val (alice2, bob2) = payOnce(alice1, bob1)
        assertBothSidesSpend(alice2, bob2)
        val whileLive = signer.contexts.filterIsInstance<FundingSigner.SigningContext.RemoteCommitment>()
        assertEquals(setOf(0L, 1L), whileLive.map { it.fundingTxIndex }.toSet())
        whileLive.groupBy { it.commitIndex }.values.forEach { atIndex -> assertEquals(listOf(0L, 1L), atIndex.map { it.fundingTxIndex }.sorted(), "one commitment per funding output at each index") }
        val (alice3, bob3) = lock(alice2, bob2)
        signer.contexts.clear()
        val (alice4, bob4) = payOnce(alice3, bob3)
        assertBothSidesSpend(alice4, bob4)
        assertEquals(setOf(1L), signer.contexts.filterIsInstance<FundingSigner.SigningContext.RemoteCommitment>().map { it.fundingTxIndex }.toSet())
    }

    @Test
    fun `a mutual close after a splice spends the new funding output -- the group as closee and as closer`() = runSuspendTest {
        val (alice, bob, _) = reachNormal(bobFundingSigner = signer())
        val (spliced1, spliced2) = spliceIn(alice, bob, listOf(50_000.sat))
        val (alice1, bob1) = lock(spliced1, spliced2)
        mutualCloseAlice(alice1, bob1, TestConstants.feeratePerKw)
        mutualCloseBob(alice1, bob1, TestConstants.feeratePerKw)
    }

    @Test
    fun `a force close after a splice -- the group signs its own commitment on the new output`() {
        val signer = signer()
        val (alice, bob, _) = reachNormal(bobFundingSigner = signer)
        val (alice1, bob1) = spliceIn(alice, bob, listOf(50_000.sat))
        val (alice2, bob2) = lock(alice1, bob1)
        val (alice3, bob3) = payOnce(alice2, bob2)
        signer.contexts.clear()
        localClose(bob3)
        assertEquals(1L, signer.contexts.filterIsInstance<FundingSigner.SigningContext.LocalCommitment>().single().fundingTxIndex)
        localClose(alice3)
    }

    @Test
    fun `a disconnect before the splice is signed, and a resume`() {
        val signer = signer()
        val (alice, bob, _) = reachNormal(aliceFundingSigner = signer, bobUsePeerStorage = false)
        val (alice1, _, bob1, _) = spliceInAndOutWithoutSigs(alice, bob, inAmounts = listOf(50_000.sat), outAmount = 100_000.sat)
        assertIs<SpliceStatus.WaitingForSigs>(alice1.state.spliceStatus)
        val (alice2, bob2, reestablish) = disconnect(alice1, bob1)
        val (reestablishAlice, reestablishBob) = reestablish
        val (bob3, actionsBob3) = bob2.process(ChannelCommand.MessageReceived(reestablishAlice))
        val (alice3, actionsAlice3) = alice2.process(ChannelCommand.MessageReceived(reestablishBob))
        assertIs<LNChannel<Normal>>(alice3)
        assertIs<LNChannel<Normal>>(bob3)
        val (alice4, bob4) = exchangeSpliceSigs(alice3, actionsAlice3.findOutgoingMessage<CommitSig>(), bob3, actionsBob3.findOutgoingMessage<CommitSig>())
        assertSplicedUnderGroupKey(alice4, bob4, groupOnBobSide = false)
        assertSpliceTxSpendsParent(alice4)
        val (alice5, bob5) = payOnce(alice4, bob4)
        assertBothSidesSpend(alice5, bob5)
    }

    @Test
    fun `a liquidity purchase names the group key at index 1, and the counterparty's offer to fund it validates against that key`() {
        val (alice, bob, _) = reachNormal(aliceFundingSigner = signer())
        val fundingRates = LiquidityAds.WillFundRates(
            fundingRates = listOf(LiquidityAds.FundingRate(100_000.sat, 500_000.sat, 0, 250, 0.sat, 1000.sat)),
            paymentTypes = setOf(LiquidityAds.PaymentType.FromChannelBalance),
        )
        val request = LiquidityAds.RequestFunding(200_000.sat, fundingRates.findRate(200_000.sat)!!, LiquidityAds.PaymentDetails.FromChannelBalance)
        val cmd = ChannelCommand.Commitment.Splice.Request(CompletableDeferred(), null, null, request, 0.msat, FeeratePerKw(1000.sat), listOf())
        val (alice1, actionsAlice1) = alice.process(cmd)
        val (bob1, actionsBob1) = bob.process(ChannelCommand.MessageReceived(actionsAlice1.findOutgoingMessage<Stfu>()))
        val (alice2, actionsAlice2) = alice1.process(ChannelCommand.MessageReceived(actionsBob1.findOutgoingMessage<Stfu>()))
        val spliceInit = actionsAlice2.findOutgoingMessage<SpliceInit>()
        assertEquals(group.groupPublicKey, spliceInit.fundingPubkey, "the purchase did not name the group key at the new index")
        assertEquals(request, spliceInit.requestFunding)
        // We haven't implemented the seller side, so we mock it, over the funding script the group's key makes.
        val (_, actionsBob2) = bob1.process(ChannelCommand.MessageReceived(spliceInit))
        val defaultSpliceAck = actionsBob2.findOutgoingMessage<SpliceAck>()
        val fundingScript = Transactions.makeFundingScript(spliceInit.fundingPubkey, defaultSpliceAck.fundingPubkey, Transactions.CommitmentFormat.SimpleTaprootChannels).pubkeyScript
        val willFund = fundingRates.validateRequest(bob.staticParams.nodeParams.nodePrivateKey, fundingScript, cmd.feerate, request, isChannelCreation = false, 0.msat)?.willFund
        assertNotNull(willFund)
        val (alice3, actionsAlice3) = alice2.process(ChannelCommand.MessageReceived(SpliceAck(alice.channelId, request.requestedAmount, defaultSpliceAck.fundingPubkey, willFund, channelType = null)))
        assertIs<Normal>(alice3.state)
        assertIs<SpliceStatus.InProgress>(alice3.state.spliceStatus)
        actionsAlice3.hasOutgoingMessage<TxAddInput>()
        // And a seller who funded some other script is refused, as for any channel.
        val wrong = fundingRates.validateRequest(bob.staticParams.nodeParams.nodePrivateKey, ByteVector("deadbeef"), cmd.feerate, request, isChannelCreation = false, 0.msat)?.willFund
        val (alice4, _) = alice2.process(ChannelCommand.MessageReceived(SpliceAck(alice.channelId, request.requestedAmount, defaultSpliceAck.fundingPubkey, wrong, channelType = null)))
        assertIs<Normal>(alice4.state)
        assertIs<SpliceStatus.Aborted>(alice4.state.spliceStatus)
    }
}
