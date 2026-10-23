package fr.acinq.lightning.iceberg

import fr.acinq.bitcoin.ByteVector
import fr.acinq.bitcoin.ByteVector32
import fr.acinq.bitcoin.Crypto
import fr.acinq.bitcoin.PrivateKey
import fr.acinq.bitcoin.Script
import fr.acinq.bitcoin.ScriptFlags
import fr.acinq.bitcoin.Transaction
import fr.acinq.bitcoin.TxIn
import fr.acinq.bitcoin.TxOut
import fr.acinq.bitcoin.byteVector
import fr.acinq.lightning.Lightning.randomBytes32
import fr.acinq.lightning.Lightning.randomKey
import fr.acinq.lightning.blockchain.WatchSpent
import fr.acinq.lightning.blockchain.WatchSpentTriggered
import fr.acinq.lightning.channel.ChannelAction
import fr.acinq.lightning.channel.ChannelCommand
import fr.acinq.lightning.channel.GroupHeldOutputs
import fr.acinq.lightning.channel.LNChannel
import fr.acinq.lightning.channel.TestsHelper.addHtlc
import fr.acinq.lightning.channel.TestsHelper.crossSign
import fr.acinq.lightning.channel.TestsHelper.mutualCloseAlice
import fr.acinq.lightning.channel.TestsHelper.reachNormal
import fr.acinq.lightning.channel.findPublishTxs
import fr.acinq.lightning.channel.states.Closing
import fr.acinq.lightning.crypto.GroupBackedFundingSigner
import fr.acinq.lightning.crypto.GroupBasepoints
import fr.acinq.lightning.crypto.IcebergFundingSigner
import fr.acinq.lightning.crypto.IcebergSigner
import fr.acinq.lightning.tests.TestConstants
import fr.acinq.lightning.tests.utils.LightningTestSuite
import fr.acinq.lightning.tests.utils.runSuspendTest
import fr.acinq.lightning.utils.msat
import fr.acinq.lightning.utils.sat
import fr.acinq.lightning.wire.Error
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFails
import kotlin.test.assertFailsWith
import kotlin.test.assertIs
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

/**
 * A group node's channel, closing every way it can, with the money ending up where the group can
 * reach it and this node cannot.
 *
 * Bob is the group node: an Iceberg funding key, and payment and delayed-payment basepoints that a
 * private key stands in for here. In the app those are FROST keys from the group's on-chain wallet,
 * and a FROST quorum makes the signature; what this suite proves is where the outputs are, that the
 * holder of those keys spends them through the script path [GroupHeldOutputs] describes, and that the
 * node holds no key that does.
 */
class GroupBasepointsChannelTestsCommon : LightningTestSuite() {

    private val paymentSecret = randomKey()
    private val delayedSecret = randomKey()
    private val closeTo = Script.write(Script.pay2wpkh(randomKey().publicKey())).byteVector()

    private fun groupNode() = GroupBackedFundingSigner(
        IcebergFundingSigner(IcebergSigner.keygen(4, 2, randomBytes32())),
        GroupBasepoints(paymentSecret.publicKey(), delayedSecret.publicKey()),
        closeTo,
    )

    /** Spend [output] the way the group would, with [leafSecret] standing in for its FROST signature. */
    private fun sweep(output: GroupHeldOutputs.Output, leafSecret: PrivateKey): Transaction {
        val unsigned = Transaction(2, listOf(TxIn(output.outPoint, output.csvDelay)), listOf(TxOut(output.txOut.amount - 1_000.sat, closeTo)), 0)
        val sig = Crypto.signSchnorr(output.sighash(unsigned, 0, listOf(output.txOut)), leafSecret, null)
        return unsigned.updateWitness(0, output.witness(sig))
    }

    private fun tweaked(base: PrivateKey, tweak: ByteVector32?): PrivateKey = tweak?.let { base + PrivateKey(it) } ?: base

    @Test
    fun `the node holds no key for the group's basepoints`() {
        val (_, bob, _) = reachNormal(bobFundingSigner = groupNode())
        assertTrue(bob.channelKeys.hasGroupBasepoints)
        assertEquals(paymentSecret.publicKey(), bob.channelKeys.paymentBasePoint)
        assertEquals(delayedSecret.publicKey(), bob.channelKeys.delayedPaymentBasePoint)
        assertFailsWith<IllegalArgumentException> { bob.channelKeys.paymentBaseSecret }
        assertFailsWith<IllegalArgumentException> { bob.channelKeys.delayedPaymentBaseSecret }
        // The counterparty learned the group's basepoints at open, which is what puts them in its commitment.
        val (alice, _, _) = reachNormal(bobFundingSigner = groupNode())
        assertEquals(paymentSecret.publicKey(), alice.commitments.channelParams.remoteParams.paymentBasepoint)
    }

    @Test
    fun `our force close -- the node claims nothing, and the group sweeps to_local after the delay`() {
        val (_, bob, _) = reachNormal(bobFundingSigner = groupNode())
        val (bob1, actions) = bob.process(ChannelCommand.MessageReceived(Error(ByteVector32.Zeroes, "oops")))
        assertIs<LNChannel<Closing>>(bob1)
        val lcp = assertNotNull(bob1.state.localCommitPublished)
        assertEquals(listOf(lcp.commitTx), actions.findPublishTxs(), "the node published something besides its commitment")

        val output = assertNotNull(GroupHeldOutputs.inLocalCommit(bob.channelKeys, bob.commitments.latest, lcp.commitTx))
        assertEquals(GroupHeldOutputs.Kind.TO_LOCAL, output.kind)
        assertEquals(bob.commitments.latest.localCommitParams.toSelfDelay.toLong(), output.csvDelay)
        Transaction.correctlySpends(sweep(output, tweaked(delayedSecret, output.tweak)), mapOf(output.outPoint to output.txOut), ScriptFlags.STANDARD_SCRIPT_VERIFY_FLAGS)
        // Neither the untweaked basepoint nor any other key will do.
        assertFails { Transaction.correctlySpends(sweep(output, delayedSecret), mapOf(output.outPoint to output.txOut), ScriptFlags.STANDARD_SCRIPT_VERIFY_FLAGS) }
        assertFails { Transaction.correctlySpends(sweep(output, randomKey()), mapOf(output.outPoint to output.txOut), ScriptFlags.STANDARD_SCRIPT_VERIFY_FLAGS) }
    }

    @Test
    fun `their force close -- the node claims nothing, and the group sweeps to_remote a block later`() {
        val (alice, bob, _) = reachNormal(bobFundingSigner = groupNode())
        val commitTx = alice.signCommitTx()
        val (bob1, actions) = bob.process(ChannelCommand.WatchReceived(WatchSpentTriggered(bob.channelId, WatchSpent.ChannelSpent(TestConstants.fundingAmount), commitTx)))
        assertIs<LNChannel<Closing>>(bob1)
        assertNotNull(bob1.state.remoteCommitPublished)
        assertTrue(actions.findPublishTxs().isEmpty(), "the node tried to claim an output the group holds")

        val output = assertNotNull(GroupHeldOutputs.inRemoteCommit(bob.channelKeys, bob.commitments.latest, bob.commitments.latest.remoteCommit.remotePerCommitmentPoint, commitTx))
        assertEquals(GroupHeldOutputs.Kind.TO_REMOTE, output.kind)
        assertEquals(1, output.csvDelay)
        assertEquals(bob.commitments.latest.localCommit.spec.toLocal.truncateToSatoshi(), output.txOut.amount)
        Transaction.correctlySpends(sweep(output, paymentSecret), mapOf(output.outPoint to output.txOut), ScriptFlags.STANDARD_SCRIPT_VERIFY_FLAGS)
    }

    @Test
    fun `an HTLC on our force close -- the node signs the HTLC transaction, and the group sweeps what it pays`() {
        val (alice, bob, _) = reachNormal(bobFundingSigner = groupNode())
        val (nodes, _, _) = addHtlc(50_000_000.msat, payer = bob, payee = alice)
        val (bob1, _) = crossSign(nodes.first, nodes.second)
        val (bob2, actions) = bob1.process(ChannelCommand.MessageReceived(Error(ByteVector32.Zeroes, "oops")))
        assertIs<LNChannel<Closing>>(bob2)
        val lcp = assertNotNull(bob2.state.localCommitPublished)
        val htlcTimeoutTx = actions.findPublishTxs(ChannelAction.Blockchain.PublishTx.Type.HtlcTimeoutTx).single()
        Transaction.correctlySpends(htlcTimeoutTx, lcp.commitTx, ScriptFlags.STANDARD_SCRIPT_VERIFY_FLAGS)

        // The HTLC transaction confirms: the node would claim its output next, and must not.
        val (_, actions3) = bob2.process(ChannelCommand.WatchReceived(WatchSpentTriggered(bob2.channelId, WatchSpent.ClosingOutputSpent(htlcTimeoutTx.txOut.first().amount), htlcTimeoutTx)))
        assertTrue(actions3.findPublishTxs().isEmpty(), "the node tried to claim an HTLC output the group holds")

        val output = assertNotNull(GroupHeldOutputs.inHtlcTx(bob1.channelKeys, bob1.commitments.latest, htlcTimeoutTx))
        assertEquals(GroupHeldOutputs.Kind.HTLC_DELAYED, output.kind)
        Transaction.correctlySpends(sweep(output, tweaked(delayedSecret, output.tweak)), mapOf(output.outPoint to output.txOut), ScriptFlags.STANDARD_SCRIPT_VERIFY_FLAGS)
    }

    @Test
    fun `a mutual close pays the script the key manager gave the channel`() = runSuspendTest {
        val (alice, bob, _) = reachNormal(bobFundingSigner = groupNode())
        assertEquals(closeTo, bob.commitments.channelParams.localParams.defaultFinalScriptPubKey)
        val (_, _, closingTx) = mutualCloseAlice(alice, bob, TestConstants.feeratePerKw)
        assertTrue(closingTx.txOut.any { it.publicKeyScript == closeTo }, "the closing transaction does not pay the group's address")
    }

    @Test
    fun `a node without group basepoints is unchanged`() {
        val (_, bob, _) = reachNormal(bobFundingSigner = IcebergFundingSigner(IcebergSigner.keygen(4, 2, randomBytes32())))
        assertTrue(!bob.channelKeys.hasGroupBasepoints)
        val (bob1, actions) = bob.process(ChannelCommand.MessageReceived(Error(ByteVector32.Zeroes, "oops")))
        assertIs<LNChannel<Closing>>(bob1)
        assertEquals(2, actions.findPublishTxs().size, "commitment and main-output claim")
        assertEquals(null, GroupHeldOutputs.inLocalCommit(bob.channelKeys, bob.commitments.latest, bob1.state.localCommitPublished!!.commitTx))
    }
}
