package fr.acinq.lightning.iceberg

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
import fr.acinq.lightning.crypto.IcebergGroup
import fr.acinq.lightning.crypto.IcebergRoundTwoRequest
import fr.acinq.lightning.crypto.IcebergSigner
import fr.acinq.lightning.crypto.RemoteIcebergFundingSigner
import fr.acinq.lightning.crypto.SimulatedGroupTransport
import fr.acinq.lightning.tests.TestConstants
import fr.acinq.lightning.tests.utils.LightningTestSuite
import fr.acinq.lightning.tests.utils.runSuspendTest
import fr.acinq.lightning.utils.msat
import kotlin.test.AfterTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.test.assertTrue
import kotlin.time.Duration.Companion.seconds

/**
 * The channel suite again, with the group somewhere else: the funding key is held by a
 * [RemoteIcebergFundingSigner] whose members answer round two after a random delay, the way devices
 * on the far side of a relay do.
 *
 * Every test ends by asserting that no label was ever asked to sign two different messages. That is
 * the property `iceberg.md` says the deployment, not the library, has to provide, and a channel that
 * passed every other check here while breaking it would be leaking the group's shares.
 */
class RemoteIcebergChannelTestsCommon : LightningTestSuite() {

    private val transports = mutableListOf<SimulatedGroupTransport>()

    private fun remote(group: IcebergGroup, maxDelayMillis: Long = 3): RemoteIcebergFundingSigner {
        val transport = SimulatedGroupTransport(group, maxDelayMillis).also { transports += it }
        return RemoteIcebergFundingSigner(group.groupPublicKey, transport, deadline = 10.seconds)
    }

    @AfterTest
    fun `no label signed two messages`() {
        transports.forEach { assertEquals(emptyMap(), it.reusedLabels(), "a label was asked to sign two messages") }
    }

    private fun assertBothSidesSpendTheFundingOutput(alice: LNChannel<Normal>, bob: LNChannel<Normal>) {
        val fundingInput = alice.commitments.latest.fundingInput
        val fundingTxOut = alice.commitments.latest.localFundingStatus.txOut
        listOf(alice, bob).forEach { Transaction.correctlySpends(it.signCommitTx(), mapOf(fundingInput to fundingTxOut), ScriptFlags.STANDARD_SCRIPT_VERIFY_FLAGS) }
    }

    private fun payOnce(alice: LNChannel<Normal>, bob: LNChannel<Normal>): Pair<LNChannel<Normal>, LNChannel<Normal>> {
        val (nodes, preimage, htlc) = addHtlc(1_000_000.msat, alice, bob)
        val (alice2, bob2) = crossSign(nodes.first, nodes.second)
        val (alice3, bob3) = fulfillHtlc(htlc.id, preimage, alice2, bob2)
        return crossSign(bob3, alice3).let { (bob4, alice4) -> Pair(alice4, bob4) }
    }

    @Test
    fun `a channel opens and pays when the group answers from elsewhere`() {
        val group = IcebergSigner.keygen(4, 2, randomBytes32())
        val (alice, bob, _) = reachNormal(bobFundingSigner = remote(group))
        assertEquals(group.groupPublicKey, alice.commitments.latest.remoteFundingPubkey)
        val (alice1, bob1) = payOnce(alice, bob)
        assertBothSidesSpendTheFundingOutput(alice1, bob1)
    }

    @Test
    fun `ten payments, each signature under its own label`() {
        val group = IcebergSigner.keygen(4, 2, randomBytes32())
        val signer = remote(group)
        var nodes = reachNormal(bobFundingSigner = signer).let { (a, b, _) -> a to b }
        val transport = transports.single()
        val before = transport.requests.size
        val perPayment = (1..10).map {
            val k = transport.requests.size
            nodes = payOnce(nodes.first, nodes.second)
            transport.requests.size - k
        }
        val requests = transport.requests.drop(before)
        // Two round twos a payment, as the fork measured in process, and every one of them FRESH: the
        // group signs the counterparty's commitment, never its own, until a force close. Counted before
        // the check below, which signs our own commitment the way a force close would.
        assertEquals(List(10) { 2 }, perPayment)
        assertTrue(requests.all { it.kind == IcebergRoundTwoRequest.Kind.FRESH })
        assertEquals(requests.size, requests.map { it.label }.toSet().size)
        assertBothSidesSpendTheFundingOutput(nodes.first, nodes.second)
    }

    @Test
    fun `3-of-7, and the group as initiator`() {
        val group = IcebergSigner.keygen(7, 3, randomBytes32())
        val (alice, bob, _) = reachNormal(aliceFundingSigner = remote(group))
        val (alice1, bob1) = payOnce(alice, bob)
        assertBothSidesSpendTheFundingOutput(alice1, bob1)
    }

    @Test
    fun `force close -- the one time the group signs its own commitment`() {
        val group = IcebergSigner.keygen(4, 2, randomBytes32())
        val (alice, bob, _) = reachNormal(bobFundingSigner = remote(group))
        val (_, bob1) = payOnce(alice, bob)
        localClose(bob1)
        assertTrue(transports.single().requests.any { it.kind == IcebergRoundTwoRequest.Kind.LOCAL_COMMITMENT })
    }

    @Test
    fun `mutual close, the group as closee and as closer`() = runSuspendTest {
        val group = IcebergSigner.keygen(4, 2, randomBytes32())
        val (alice, bob, _) = reachNormal(bobFundingSigner = remote(group))
        mutualCloseAlice(alice, bob, TestConstants.feeratePerKw)
        assertTrue(transports.single().requests.any { it.kind == IcebergRoundTwoRequest.Kind.PUBLISHED })

        val other = IcebergSigner.keygen(4, 2, randomBytes32())
        val (alice2, bob2, _) = reachNormal(bobFundingSigner = remote(other))
        mutualCloseBob(alice2, bob2, TestConstants.feeratePerKw)
    }

    @Test
    fun `reconnect -- the published nonces are the ones round one gives, and payments continue`() {
        val group = IcebergSigner.keygen(4, 2, randomBytes32())
        val (alice, bob, _) = reachNormal(bobFundingSigner = remote(group), bobUsePeerStorage = false)
        val (alice1, bob1) = payOnce(alice, bob)
        val (alice2, bob2, reestablish) = disconnect(alice1, bob1)
        val (alice3, _) = alice2.process(ChannelCommand.MessageReceived(reestablish.second))
        val (bob3, _) = bob2.process(ChannelCommand.MessageReceived(reestablish.first))
        assertIs<LNChannel<Normal>>(alice3)
        assertIs<LNChannel<Normal>>(bob3)
        val (alice4, bob4) = payOnce(alice3, bob3)
        assertBothSidesSpendTheFundingOutput(alice4, bob4)
    }
}
