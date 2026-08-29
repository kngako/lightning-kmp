package fr.acinq.lightning.iceberg

import fr.acinq.bitcoin.OutPoint
import fr.acinq.bitcoin.PrivateKey
import fr.acinq.bitcoin.PublicKey
import fr.acinq.bitcoin.ScriptFlags
import fr.acinq.bitcoin.Transaction
import fr.acinq.bitcoin.TxId
import fr.acinq.bitcoin.TxOut
import fr.acinq.bitcoin.crypto.musig2.IndividualNonce
import fr.acinq.bitcoin.utils.Either
import fr.acinq.lightning.Lightning.randomBytes32
import fr.acinq.lightning.channel.ChannelCommand
import fr.acinq.lightning.channel.ChannelSpendSignature
import fr.acinq.lightning.channel.TestsHelper.addHtlc
import fr.acinq.lightning.channel.TestsHelper.crossSign
import fr.acinq.lightning.channel.TestsHelper.fulfillHtlc
import fr.acinq.lightning.channel.TestsHelper.localClose
import fr.acinq.lightning.channel.TestsHelper.mutualCloseAlice
import fr.acinq.lightning.channel.TestsHelper.mutualCloseBob
import fr.acinq.lightning.channel.TestsHelper.reachNormal
import fr.acinq.lightning.channel.LNChannel
import fr.acinq.lightning.channel.states.Normal
import fr.acinq.lightning.channel.states.SyncingTestsCommon.Companion.disconnect
import fr.acinq.lightning.crypto.FundingSigner
import fr.acinq.lightning.crypto.IcebergFundingSigner
import fr.acinq.lightning.crypto.IcebergGroup
import fr.acinq.lightning.crypto.IcebergSigner
import fr.acinq.lightning.tests.TestConstants
import fr.acinq.lightning.tests.utils.LightningTestSuite
import fr.acinq.lightning.tests.utils.runSuspendTest
import fr.acinq.lightning.transactions.Scripts
import fr.acinq.lightning.transactions.Transactions
import fr.acinq.lightning.utils.msat
import java.util.concurrent.atomic.AtomicLong
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertIs
import kotlin.test.assertTrue

/**
 * The end-to-end claim, ported from the eclair fork's IcebergChannelSpec: Lightning payments added
 * and resolved over a channel where one of the two MuSig2 signers is not a private key at all, but
 * an Iceberg t-of-n threshold group. The counterparty is entirely stock and cannot tell the
 * difference.
 *
 * WHAT MAKES THIS UNFAKEABLE. The script interpreter is the judge: both sides' fully-signed
 * commitment transactions are checked with `Transaction.correctlySpends` against the real funding
 * output, and the mutual-close and force-close helpers do the same. A group-backed channel cannot
 * produce those transactions unless a real aggregate Schnorr signature satisfies the real taproot
 * funding output.
 */
class IcebergChannelTestsJvm : LightningTestSuite() {

    private fun signerFor(group: IcebergGroup): IcebergFundingSigner = IcebergFundingSigner(group)

    /** Assert that both parties hold a commitment that really spends the real funding output. */
    private fun assertBothSidesSpendTheFundingOutput(alice: LNChannel<Normal>, bob: LNChannel<Normal>) {
        val fundingInput = alice.commitments.latest.fundingInput
        val fundingTxOut = alice.commitments.latest.localFundingStatus.txOut
        listOf("alice" to alice, "bob" to bob).forEach { (who, node) ->
            val signedCommitTx = node.signCommitTx()
            // The script interpreter is the judge, not a library-internal verify.
            Transaction.correctlySpends(signedCommitTx, mapOf(fundingInput to fundingTxOut), ScriptFlags.STANDARD_SCRIPT_VERIFY_FLAGS)
            assertEquals(fundingInput.txid, signedCommitTx.txIn.first().outPoint.txid, "$who's commit tx does not spend the funding tx")
        }
    }

    /**
     * Open a channel with one side's funding key held by an Iceberg group, and check the group key
     * genuinely reached the funding output rather than merely being used to sign.
     */
    private fun openGroupBackedChannel(group: IcebergGroup, groupOnBobSide: Boolean): Pair<LNChannel<Normal>, LNChannel<Normal>> {
        val signer = signerFor(group)
        val (alice, bob, _) = if (groupOnBobSide) reachNormal(bobFundingSigner = signer) else reachNormal(aliceFundingSigner = signer)

        // The peer of the group-backed side must have recorded the GROUP's key as its counterparty's
        // funding key. If this is the locally-derived key instead, the group merely co-signed something
        // it does not control, which is the failure mode this whole refactor exists to remove.
        val peer = if (groupOnBobSide) alice else bob
        assertEquals(group.groupPubkey, peer.commitments.latest.remoteFundingPubkey, "the peer's remoteFundingPubkey is not the group key")

        // ...and the on-chain output really is the 2-of-2 of that group key with the stock party's.
        val stockKey = if (groupOnBobSide) bob.commitments.latest.remoteFundingPubkey else alice.commitments.latest.remoteFundingPubkey
        val fundingTxOut = alice.commitments.latest.localFundingStatus.txOut
        val expectedScript = Transactions.makeFundingScript(stockKey, group.groupPubkey, Transactions.CommitmentFormat.SimpleTaprootChannels).pubkeyScript
        assertEquals(expectedScript, fundingTxOut.publicKeyScript, "the funding output is not the 2-of-2 taproot script for (stock key, group key)")

        assertBothSidesSpendTheFundingOutput(alice, bob)
        return Pair(alice, bob)
    }

    /** One complete payment: add, cross-sign, fulfill, cross-sign. */
    private fun payOnce(alice: LNChannel<Normal>, bob: LNChannel<Normal>): Pair<LNChannel<Normal>, LNChannel<Normal>> {
        val (nodes, preimage, htlc) = addHtlc(1_000_000.msat, alice, bob)
        val (alice1, bob1) = nodes
        val (alice2, bob2) = crossSign(alice1, bob1)
        val (alice3, bob3) = fulfillHtlc(htlc.id, preimage, alice2, bob2)
        return crossSign(bob3, alice3).let { (bob4, alice4) -> Pair(alice4, bob4) }
    }

    @Test
    fun `how many group operations ONE payment actually costs`() {
        // The direct paired measurement puts the cost of a group at roughly twice a composed estimate,
        // and a composition is only as good as its assumed operation count. So that count is worth
        // establishing by observation rather than by reading the call graph.
        val group = IcebergSigner.keygen(8, 3, randomBytes32().toByteArray())
        val counting = CountingFundingSigner(signerFor(group))
        val (alice, bob, _) = reachNormal(bobFundingSigner = counting)
        println("channel establishment: ${counting.roundOneCalls} round-one, ${counting.roundTwoCalls} round-two")

        counting.resetCounts()
        val (alice1, bob1) = payOnce(alice, bob)
        val (r1First, r2First) = counting.roundOneCalls to counting.roundTwoCalls
        val breakdown = "verificationNonce=${counting.nonceCalls.get()} signWithVerificationNonce=${counting.signVerificationCalls.get()} signWithFreshNonce=${counting.signFreshCalls.get()} closeeNonce=${counting.closeeNonceCalls.get()} signWithCloseeNonce=${counting.signCloseeCalls.get()}"

        counting.resetCounts()
        payOnce(alice1, bob1)
        val (r1Second, r2Second) = counting.roundOneCalls to counting.roundTwoCalls

        println("ONE payment cycle: $r1First round-one, $r2First round-two ($breakdown)")
        // Per-payment cost must not grow with the commit index, or the channel would get steadily more
        // expensive the longer it stays open.
        assertEquals(r1First, r1Second, "round-one count changed between payments")
        assertEquals(r2First, r2Second, "round-two count changed between payments")
        assertTrue(r1First > 0 && r2First > 0)
    }

    @Test
    fun `a 2-of-4 group holds one side's funding key -- the channel opens and the group key is in the funding output`() {
        val group = IcebergSigner.keygen(4, 2, randomBytes32().toByteArray())
        openGroupBackedChannel(group, groupOnBobSide = true)
    }

    @Test
    fun `a payment is added and resolved over a group-backed channel, and the resulting commitment still spends the funding output`() {
        val group = IcebergSigner.keygen(4, 2, randomBytes32().toByteArray())
        val (alice, bob) = openGroupBackedChannel(group, groupOnBobSide = true)
        val (alice1, bob1) = payOnce(alice, bob)
        // The post-payment commitment is a DIFFERENT transaction, signed after establishment, at a
        // commit index whose nonce is derived from the real funding txid.
        assertBothSidesSpendTheFundingOutput(alice1, bob1)
    }

    @Test
    fun `ten sequential payments -- every commitment derives its own nonce and none of them collide`() {
        val group = IcebergSigner.keygen(4, 2, randomBytes32().toByteArray())
        var nodes = openGroupBackedChannel(group, groupOnBobSide = true)
        // A threshold signer derives round one from a session label. If that label did not advance with
        // the commit index -- or advanced but collided -- this is where it shows up, as a rejected
        // commit_sig rather than as anything subtle.
        repeat(10) { nodes = payOnce(nodes.first, nodes.second) }
        assertTrue(nodes.first.commitments.localCommitIndex >= 10)
        assertBothSidesSpendTheFundingOutput(nodes.first, nodes.second)
    }

    @Test
    fun `the group key works in both lexicographic positions relative to the counterparty`() {
        // Scripts.sort decides the key aggregation order, and the two cases are genuinely different
        // sessions. The channel's counterparty key is drawn from a random path per channel, so we
        // cannot pre-order the group key: we open channels until both orderings have been exercised.
        val covered = mutableSetOf<Boolean>()
        var attempts = 0
        while (covered.size < 2 && attempts < 20) {
            attempts += 1
            val group = IcebergSigner.keygen(4, 2, randomBytes32().toByteArray())
            val (alice, bob) = openGroupBackedChannel(group, groupOnBobSide = true)
            val aliceKey = bob.commitments.latest.remoteFundingPubkey
            covered += Scripts.sort(listOf(aliceKey, group.groupPubkey)).first() == group.groupPubkey
            payOnce(alice, bob)
        }
        assertEquals(setOf(true, false), covered, "could not exercise both key orderings in $attempts attempts")
    }

    @Test
    fun `the configurations the paper reports -- 2-of-4 and 3-of-7`() {
        for ((t, n) in listOf(2 to 4, 3 to 7)) {
            val group = IcebergSigner.keygen(n, t, randomBytes32().toByteArray())
            val (alice, bob) = openGroupBackedChannel(group, groupOnBobSide = true)
            val (alice1, bob1) = payOnce(alice, bob)
            assertBothSidesSpendTheFundingOutput(alice1, bob1)
        }
    }

    @Test
    fun `the channel INITIATOR can also be group-backed, not just the non-initiator`() {
        // Bob-only is the stronger headline ("a stock node accepted the group's signatures"), but it
        // only exercises the fundee half of the establishment handshake. Running the group on Alice
        // shows it works on the initiator side too.
        val group = IcebergSigner.keygen(4, 2, randomBytes32().toByteArray())
        val (alice, bob) = openGroupBackedChannel(group, groupOnBobSide = false)
        val (alice1, bob1) = payOnce(alice, bob)
        assertBothSidesSpendTheFundingOutput(alice1, bob1)
    }

    @Test
    fun `force-close -- the group signs its own commitment transaction`() {
        val group = IcebergSigner.keygen(4, 2, randomBytes32().toByteArray())
        val (alice, bob) = openGroupBackedChannel(group, groupOnBobSide = true)
        val (alice1, bob1) = payOnce(alice, bob)
        // The group-backed side publishes its commitment: fullySignedCommitTx signs under the
        // deterministic verification nonce published earlier in revoke_and_ack. localClose checks
        // the published commit tx with the script interpreter.
        localClose(bob1)
        // The stock side force-closing is the same code path as any channel.
        localClose(alice1)
    }

    @Test
    fun `mutual close -- group-backed side is the closee`() = runSuspendTest {
        val group = IcebergSigner.keygen(4, 2, randomBytes32().toByteArray())
        val (alice, bob) = openGroupBackedChannel(group, groupOnBobSide = true)
        val (alice1, bob1) = payOnce(alice, bob)
        // Alice closes: the group (bob) signs the closing transaction under the nonce it published
        // in its shutdown message. The helper's correctlySpends is the judge.
        mutualCloseAlice(alice1, bob1, TestConstants.feeratePerKw)
    }

    @Test
    fun `mutual close -- group-backed side is the closer`() = runSuspendTest {
        val group = IcebergSigner.keygen(4, 2, randomBytes32().toByteArray())
        val (alice, bob) = openGroupBackedChannel(group, groupOnBobSide = true)
        // Bob closes: the group signs its closing transactions with fresh nonces (closing_complete).
        mutualCloseBob(alice, bob, TestConstants.feeratePerKw)
    }

    @Test
    fun `reconnect -- verification nonces re-derive identically and the channel keeps working`() {
        val group = IcebergSigner.keygen(4, 2, randomBytes32().toByteArray())
        val signer = signerFor(group)
        val (alice, bob, fundingTxId) = reachNormal(bobFundingSigner = signer, bobUsePeerStorage = false)
        val (alice1, bob1) = payOnce(alice, bob)

        val (alice2, bob2, reestablish) = disconnect(alice1, bob1)
        val (reestablishAlice, reestablishBob) = reestablish

        // The load-bearing property: the nonce bob re-derives for its channel_reestablish must be
        // exactly the nonce a FRESH signer over the same group derives -- nothing may be carried over.
        val aliceFundingPubkey = bob2.commitments.latest.remoteFundingPubkey
        val expectedNonce = signerFor(group).verificationNonce(FundingSigner.VerificationNonceId(fundingTxId, aliceFundingPubkey, bob2.commitments.localCommitIndex + 1))
        assertEquals(expectedNonce, reestablishBob.nextCommitNonces[fundingTxId], "reconnect nonce is not a pure function of the nonce identity")

        val (alice3, _) = alice2.process(ChannelCommand.MessageReceived(reestablishBob))
        val (bob3, _) = bob2.process(ChannelCommand.MessageReceived(reestablishAlice))
        assertIs<LNChannel<Normal>>(alice3)
        assertIs<LNChannel<Normal>>(bob3)

        // And the channel keeps making payments after the reconnection.
        val (alice4, bob4) = payOnce(alice3, bob3)
        assertBothSidesSpendTheFundingOutput(alice4, bob4)
    }

    @Test
    fun `splice on a group-backed channel fails loudly`() {
        val group = IcebergSigner.keygen(4, 2, randomBytes32().toByteArray())
        val (_, bob) = openGroupBackedChannel(group, groupOnBobSide = true)
        // A splice derives the funding key at index 1, which a threshold signer does not have: the
        // channel must fail loudly instead of silently reusing index 0's key. This index guard is
        // what the splice paths (SpliceInit/SpliceAck in Normal.kt) hit first.
        assertFailsWith<IllegalArgumentException> { bob.channelKeys.fundingPublicKey(1) }
        assertFailsWith<IllegalArgumentException> { bob.channelKeys.fundingSigner(1) }
    }
}

/**
 * Wraps a [FundingSigner] and counts the group operations a channel asks for, one counter per
 * method (port of the eclair fork's CountingFundingSigner). The methods cost different amounts of
 * threshold work, so the round split is observed here, not assumed:
 *
 *   verificationNonce         -> one round one (a nonce derivation over the 2t-1 quorum), no round two
 *   signWithVerificationNonce -> one round one and one round two; its round one re-derives a nonce an
 *                                earlier verificationNonce already published, the redundancy a cache removes
 *   signWithFreshNonce        -> one round one and one round two, on a nonce never published
 *   closeeNonce               -> one round one, no round two
 *   signWithCloseeNonce       -> one round one (re-derived) and one round two
 */
class CountingFundingSigner(private val underlying: FundingSigner) : FundingSigner {
    val nonceCalls = AtomicLong(0)
    val signVerificationCalls = AtomicLong(0)
    val signFreshCalls = AtomicLong(0)
    val closeeNonceCalls = AtomicLong(0)
    val signCloseeCalls = AtomicLong(0)

    override val publicKey: PublicKey = underlying.publicKey
    override val privateKeyOrNull: PrivateKey? = underlying.privateKeyOrNull

    override fun verificationNonce(id: FundingSigner.VerificationNonceId): IndividualNonce {
        nonceCalls.incrementAndGet()
        return underlying.verificationNonce(id)
    }

    override fun signWithVerificationNonce(tx: Transactions.ChannelSpendTransaction, remoteFundingPubKey: PublicKey, extraUtxos: Map<OutPoint, TxOut>, id: FundingSigner.VerificationNonceId, remoteNonce: IndividualNonce): Either<Throwable, ChannelSpendSignature.PartialSignatureWithNonce> {
        signVerificationCalls.incrementAndGet()
        return underlying.signWithVerificationNonce(tx, remoteFundingPubKey, extraUtxos, id, remoteNonce)
    }

    override fun signWithFreshNonce(tx: Transactions.ChannelSpendTransaction, remoteFundingPubKey: PublicKey, extraUtxos: Map<OutPoint, TxOut>, fundingTxId: TxId, remoteNonce: IndividualNonce): Either<Throwable, ChannelSpendSignature.PartialSignatureWithNonce> {
        signFreshCalls.incrementAndGet()
        return underlying.signWithFreshNonce(tx, remoteFundingPubKey, extraUtxos, fundingTxId, remoteNonce)
    }

    override fun closeeNonce(fundingTxId: TxId, remoteFundingPubKey: PublicKey): FundingSigner.CloseeNonceSession {
        closeeNonceCalls.incrementAndGet()
        return underlying.closeeNonce(fundingTxId, remoteFundingPubKey)
    }

    override fun signWithCloseeNonce(tx: Transactions.ChannelSpendTransaction, remoteFundingPubKey: PublicKey, extraUtxos: Map<OutPoint, TxOut>, session: FundingSigner.CloseeNonceSession, remoteNonce: IndividualNonce): Either<Throwable, ChannelSpendSignature.PartialSignatureWithNonce> {
        signCloseeCalls.incrementAndGet()
        return underlying.signWithCloseeNonce(tx, remoteFundingPubKey, extraUtxos, session, remoteNonce)
    }

    /** Every method enters round one. */
    val roundOneCalls: Long get() = nonceCalls.get() + signVerificationCalls.get() + signFreshCalls.get() + closeeNonceCalls.get() + signCloseeCalls.get()
    /** Only the signing methods reach round two. */
    val roundTwoCalls: Long get() = signVerificationCalls.get() + signFreshCalls.get() + signCloseeCalls.get()
    fun resetCounts() {
        nonceCalls.set(0); signVerificationCalls.set(0); signFreshCalls.set(0); closeeNonceCalls.set(0); signCloseeCalls.set(0)
    }
}
