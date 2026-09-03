package fr.acinq.lightning.prefractal

import fr.acinq.bitcoin.ByteVector32
import fr.acinq.bitcoin.ScriptFlags
import fr.acinq.bitcoin.Transaction
import fr.acinq.lightning.Lightning.randomBytes32
import fr.acinq.lightning.channel.ChannelCommand
import fr.acinq.lightning.channel.LNChannel
import fr.acinq.lightning.channel.TestsHelper.addHtlc
import fr.acinq.lightning.channel.TestsHelper.crossSign
import fr.acinq.lightning.channel.TestsHelper.fulfillHtlc
import fr.acinq.lightning.channel.TestsHelper.localClose
import fr.acinq.lightning.channel.TestsHelper.mutualCloseAlice
import fr.acinq.lightning.channel.TestsHelper.mutualCloseBob
import fr.acinq.lightning.channel.TestsHelper.reachNormal
import fr.acinq.lightning.channel.states.Normal
import fr.acinq.lightning.channel.states.SyncingTestsCommon.Companion.disconnect
import fr.acinq.lightning.crypto.CountingFundingSigner
import fr.acinq.lightning.crypto.FundingSigner
import fr.acinq.lightning.crypto.PrefractalFundingSigner
import fr.acinq.lightning.crypto.PrefractalGroup
import fr.acinq.lightning.crypto.PrefractalSigner
import fr.acinq.lightning.tests.TestConstants
import fr.acinq.lightning.tests.utils.LightningTestSuite
import fr.acinq.lightning.tests.utils.runSuspendTest
import fr.acinq.lightning.transactions.Scripts
import fr.acinq.lightning.transactions.Transactions
import fr.acinq.lightning.utils.msat
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertIs
import kotlin.test.assertTrue

/**
 * The end-to-end claim for the prefractal signer: Lightning payments added and resolved over a
 * channel where one of the two MuSig2 signers is not a private key at all, but a nested
 * FROST+MuSig2 t-of-n threshold group. The counterparty is entirely stock and cannot tell the
 * difference.
 *
 * Mirror of [fr.acinq.lightning.iceberg.IcebergChannelTestsCommon], driving the same generic
 * harness: `reachNormal` already takes `aliceFundingSigner`/`bobFundingSigner`, so nothing in the
 * channel code knows which scheme is behind the seam.
 *
 * WHAT MAKES THIS UNFAKEABLE. The script interpreter is the judge: both sides' fully-signed
 * commitment transactions are checked with `Transaction.correctlySpends` against the real funding
 * output, and the mutual-close and force-close helpers do the same. A group-backed channel cannot
 * produce those transactions unless a real aggregate Schnorr signature satisfies the real taproot
 * funding output.
 *
 * GROUP-KEY PARITY IS PART OF THE COVERAGE. The nested equation carries no frost-level key parity
 * factor; anything that reintroduced one would produce a group whose channels work about half the
 * time, depending on the Y parity of a randomly dealt threshold key. The fixtures below are fixed
 * seeds of each parity rather than random ones, and [seedOddY] is the default everywhere so the
 * harder case is the one exercised by default.
 */
class PrefractalChannelTestsCommon : LightningTestSuite() {

    // Asserted in `the parity fixtures are what they say they are` below.
    private val seedEvenY = ByteVector32.fromValidHex("0000000000000000000000000000000000000000000000000000000000000001")
    private val seedOddY = ByteVector32.fromValidHex("0000000000000000000000000000000000000000000000000000000000000002")

    private fun signerFor(group: PrefractalGroup): PrefractalFundingSigner = PrefractalFundingSigner(group)

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
     * Open a channel with one side's funding key held by a prefractal group, and check the group key
     * genuinely reached the funding output rather than merely being used to sign.
     */
    private fun openGroupBackedChannel(group: PrefractalGroup, groupOnBobSide: Boolean): Pair<LNChannel<Normal>, LNChannel<Normal>> {
        val signer = signerFor(group)
        val (alice, bob, _) = if (groupOnBobSide) reachNormal(bobFundingSigner = signer) else reachNormal(aliceFundingSigner = signer)

        // The peer of the group-backed side must have recorded the GROUP's key as its counterparty's
        // funding key. If this is the locally-derived key instead, the group merely co-signed
        // something it does not control.
        val peer = if (groupOnBobSide) alice else bob
        assertEquals(group.groupPublicKey, peer.commitments.latest.remoteFundingPubkey, "the peer's remoteFundingPubkey is not the group key")

        // ...and the on-chain output really is the 2-of-2 of that group key with the stock party's.
        val stockKey = if (groupOnBobSide) bob.commitments.latest.remoteFundingPubkey else alice.commitments.latest.remoteFundingPubkey
        val fundingTxOut = alice.commitments.latest.localFundingStatus.txOut
        val expectedScript = Transactions.makeFundingScript(stockKey, group.groupPublicKey, Transactions.CommitmentFormat.SimpleTaprootChannels).pubkeyScript
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
    fun `the parity fixtures are what they say they are`() {
        assertEquals(0x02.toByte(), PrefractalSigner.keygen(3, 2, seedEvenY).groupPublicKey.value[0], "seedEvenY should yield an even-Y group key")
        assertEquals(0x03.toByte(), PrefractalSigner.keygen(3, 2, seedOddY).groupPublicKey.value[0], "seedOddY should yield an odd-Y group key")
    }

    @Test
    fun `how many group operations ONE payment actually costs`() {
        // Worth establishing by observation rather than by reading the call graph, and the numbers
        // differ from iceberg's: prefractal's round one is t nonce derivations plus one aggregation,
        // and its round two is t signature shares plus one sum -- there is no 2t-1 quorum here.
        val group = PrefractalSigner.keygen(8, 3, seedOddY)
        val counting = CountingFundingSigner(signerFor(group))
        val (alice, bob, _) = reachNormal(bobFundingSigner = counting)
        println("channel establishment: ${counting.roundOneCalls} round-one, ${counting.roundTwoCalls} round-two")

        counting.resetCounts()
        val (alice1, bob1) = payOnce(alice, bob)
        val (r1First, r2First) = counting.roundOneCalls to counting.roundTwoCalls
        val breakdown = "verificationNonce=${counting.nonceCalls.value} signWithVerificationNonce=${counting.signVerificationCalls.value} signWithFreshNonce=${counting.signFreshCalls.value} publishedNonceSession=${counting.publishedNonceCalls.value} signWithPublishedNonce=${counting.signPublishedCalls.value}"

        counting.resetCounts()
        payOnce(alice1, bob1)
        val (r1Second, r2Second) = counting.roundOneCalls to counting.roundTwoCalls

        println("ONE payment cycle: $r1First round-one, $r2First round-two ($breakdown)")
        // Per-payment cost must not grow with the commit index, or the channel would get steadily
        // more expensive the longer it stays open.
        assertEquals(r1First, r1Second, "round-one count changed between payments")
        assertEquals(r2First, r2Second, "round-two count changed between payments")
        assertTrue(r1First > 0 && r2First > 0)

        // These FundingSigner-level counts are the same as iceberg's, because the channel asks for
        // the same calls whatever is behind the seam. Where the two schemes differ is INSIDE each
        // call, and that is what this part pins: prefractal's round one is t member nonces plus one
        // aggregation, where iceberg's is 2t-1. For this 3-of-8 group that is 3 rather than 5.
        val r1 = PrefractalSigner.roundOne(group, (1..group.t).toList(), randomBytes32())
        assertEquals(group.t, r1.memberPublicNonces.size, "round one should cost exactly t member nonces")
        assertEquals(group.t, r1.signerIds.size)
        assertEquals(3, group.quorum, "quorum is t, not 2t-1")
        println("per round-one member operations: ${r1.memberPublicNonces.size} (t=${group.t}; iceberg would need ${2 * group.t - 1})")
    }

    @Test
    fun `a 2-of-3 group holds one side's funding key -- the channel opens and the group key is in the funding output`() {
        openGroupBackedChannel(PrefractalSigner.keygen(3, 2, seedOddY), groupOnBobSide = true)
    }

    @Test
    fun `a payment is added and resolved over a group-backed channel and the resulting commitment still spends the funding output`() {
        val (alice, bob) = openGroupBackedChannel(PrefractalSigner.keygen(3, 2, seedOddY), groupOnBobSide = true)
        val (alice1, bob1) = payOnce(alice, bob)
        // The post-payment commitment is a DIFFERENT transaction, signed after establishment, at a
        // commit index whose nonce is derived from the real funding txid.
        assertBothSidesSpendTheFundingOutput(alice1, bob1)
    }

    @Test
    fun `ten sequential payments -- every commitment derives its own nonce and none of them collide`() {
        var nodes = openGroupBackedChannel(PrefractalSigner.keygen(3, 2, seedOddY), groupOnBobSide = true)
        // Nonces are derived from a session label. If that label did not advance with the commit
        // index -- or advanced but collided -- this is where it shows up, as a rejected commit_sig
        // rather than as anything subtle.
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
            val group = PrefractalSigner.keygen(3, 2, randomBytes32())
            val (alice, bob) = openGroupBackedChannel(group, groupOnBobSide = true)
            val aliceKey = bob.commitments.latest.remoteFundingPubkey
            covered += Scripts.sort(listOf(aliceKey, group.groupPublicKey)).first() == group.groupPublicKey
            payOnce(alice, bob)
        }
        assertEquals(setOf(true, false), covered, "could not exercise both key orderings in $attempts attempts")
    }

    @Test
    fun `the t-of-n matrix including configurations iceberg cannot express`() {
        // 2-of-2 and 3-of-4 violate iceberg's t <= (n+1)/2 and are unavailable there.
        for ((t, n) in listOf(2 to 2, 2 to 3, 3 to 4, 3 to 5)) {
            for (seed in listOf(seedEvenY, seedOddY)) {
                val group = PrefractalSigner.keygen(n, t, seed)
                val (alice, bob) = openGroupBackedChannel(group, groupOnBobSide = true)
                val (alice1, bob1) = payOnce(alice, bob)
                assertBothSidesSpendTheFundingOutput(alice1, bob1)
            }
        }
    }

    @Test
    fun `the channel INITIATOR can also be group-backed and not just the non-initiator`() {
        // Bob-only is the stronger headline ("a stock node accepted the group's signatures"), but it
        // only exercises the fundee half of the establishment handshake. Running the group on Alice
        // shows it works on the initiator side too.
        val (alice, bob) = openGroupBackedChannel(PrefractalSigner.keygen(3, 2, seedOddY), groupOnBobSide = false)
        val (alice1, bob1) = payOnce(alice, bob)
        assertBothSidesSpendTheFundingOutput(alice1, bob1)
    }

    @Test
    fun `force-close -- the group signs its own commitment transaction`() {
        val (alice, bob) = openGroupBackedChannel(PrefractalSigner.keygen(3, 2, seedOddY), groupOnBobSide = true)
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
        val (alice, bob) = openGroupBackedChannel(PrefractalSigner.keygen(3, 2, seedOddY), groupOnBobSide = true)
        val (alice1, bob1) = payOnce(alice, bob)
        // Alice closes: the group (bob) signs the closing transaction under the nonce it published
        // in its shutdown message. The helper's correctlySpends is the judge.
        mutualCloseAlice(alice1, bob1, TestConstants.feeratePerKw)
    }

    @Test
    fun `mutual close -- group-backed side is the closer`() = runSuspendTest {
        val (alice, bob) = openGroupBackedChannel(PrefractalSigner.keygen(3, 2, seedOddY), groupOnBobSide = true)
        // Bob closes: the group signs its closing transactions with fresh nonces (closing_complete),
        // which exercises publishedNonceSession/signWithPublishedNonce.
        mutualCloseBob(alice, bob, TestConstants.feeratePerKw)
    }

    /**
     * THE TEST THAT PINS THE LABEL-DERIVED NONCE DESIGN. Nothing is stored between the rounds, so a
     * reconnecting node must re-derive exactly the nonce it published before. A FRESH signer over
     * the same group must produce the same value.
     */
    @Test
    fun `reconnect -- verification nonces re-derive identically and the channel keeps working`() {
        val group = PrefractalSigner.keygen(3, 2, seedOddY)
        val signer = signerFor(group)
        val (alice, bob, fundingTxId) = reachNormal(bobFundingSigner = signer, bobUsePeerStorage = false)
        val (alice1, bob1) = payOnce(alice, bob)

        val (alice2, bob2, reestablish) = disconnect(alice1, bob1)
        val (reestablishAlice, reestablishBob) = reestablish

        val aliceFundingPubkey = bob2.commitments.latest.remoteFundingPubkey
        // signerFor(group) is a brand new signer: nothing may be carried over from the one above.
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
        val (_, bob) = openGroupBackedChannel(PrefractalSigner.keygen(3, 2, seedOddY), groupOnBobSide = true)
        // A splice derives the funding key at index 1, which a threshold signer does not have: the
        // channel must fail loudly instead of silently reusing index 0's key.
        assertFailsWith<IllegalArgumentException> { bob.channelKeys.fundingPublicKey(1) }
        assertFailsWith<IllegalArgumentException> { bob.channelKeys.fundingSigner(1) }
    }
}
