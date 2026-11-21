package fr.acinq.lightning.channel

import fr.acinq.bitcoin.ByteVector32
import fr.acinq.bitcoin.ByteVector64
import fr.acinq.bitcoin.Crypto
import fr.acinq.bitcoin.OutPoint
import fr.acinq.bitcoin.PublicKey
import fr.acinq.bitcoin.Script
import fr.acinq.bitcoin.ScriptTree
import fr.acinq.bitcoin.ScriptWitness
import fr.acinq.bitcoin.SigHash
import fr.acinq.bitcoin.Transaction
import fr.acinq.bitcoin.TxOut
import fr.acinq.bitcoin.XonlyPublicKey
import fr.acinq.bitcoin.byteVector
import fr.acinq.bitcoin.byteVector32
import fr.acinq.lightning.crypto.ChannelKeys
import fr.acinq.lightning.crypto.GroupBasepoints
import fr.acinq.lightning.transactions.Scripts
import fr.acinq.lightning.transactions.Transactions

/**
 * Finds the outputs a closing channel pays to a group's basepoints ([GroupBasepoints]), and says how
 * the group spends them.
 *
 * When a channel's basepoints belong to a group, this node never claims our main output or the delayed
 * output of our HTLC transactions: it holds no key for them (`Helpers.Closing` skips those claims). The
 * group does, with a signature of its own under the leaf key, and this object is what tells it where
 * the output is, which leaf to sign, under which key, and after how many blocks. It needs nothing the
 * channel does not already have, so the node that watched the close can describe the output to a group
 * that did not.
 *
 * Every output here is a taproot SCRIPT-path spend with a NUMS (or revocation) internal key: there is
 * no key path to sign, and the leaf key is an x-only BIP340 key.
 */
object GroupHeldOutputs {

    enum class Kind {
        /** Our main output in the counterparty's commitment: the payment basepoint, untweaked, after 1 block. */
        TO_REMOTE,
        /** Our main output in our own commitment: the delayed payment basepoint, tweaked, after `to_self_delay`. */
        TO_LOCAL,
        /** The output of one of our HTLC transactions: as [TO_LOCAL]. */
        HTLC_DELAYED,
    }

    /**
     * One output the group can sweep.
     *
     * @param basepoint the group key it derives from.
     * @param tweak `SHA256(per_commitment_point || basepoint)`, the plain tweak from [basepoint] to
     *   [leafKey]; null for [Kind.TO_REMOTE], whose key is the basepoint itself.
     * @param csvDelay the relative lock the spending input's `nSequence` has to satisfy.
     */
    data class Output(
        val kind: Kind,
        val outPoint: OutPoint,
        val txOut: TxOut,
        val basepoint: PublicKey,
        val tweak: ByteVector32?,
        val leafKey: PublicKey,
        val internalKey: XonlyPublicKey,
        val leaf: ScriptTree.Leaf,
        val scriptTree: ScriptTree,
        val csvDelay: Long,
    ) {
        /** The BIP341 script-path sighash for spending this output as input [inputIndex] of [spendingTx]. */
        fun sighash(spendingTx: Transaction, inputIndex: Int, spentOutputs: List<TxOut>): ByteVector32 =
            spendingTx.hashForSigningTaprootScriptPath(inputIndex, spentOutputs, SigHash.SIGHASH_DEFAULT, leaf.hash())

        /** The witness, given the group's 64-byte signature under [leafKey]. */
        fun witness(signature: ByteVector64): ScriptWitness =
            Script.witnessScriptPathPay2tr(internalKey, leaf, ScriptWitness(listOf(signature)), scriptTree)
    }

    private fun tweakOf(perCommitmentPoint: PublicKey, basepoint: PublicKey): ByteVector32 =
        Crypto.sha256(perCommitmentPoint.value + basepoint.value).byteVector32()

    private fun find(tx: Transaction, script: List<fr.acinq.bitcoin.ScriptElt>): Pair<OutPoint, TxOut>? {
        val bytes = Script.write(script)
        val index = tx.txOut.indexOfFirst { it.publicKeyScript == bytes.byteVector() }
        return if (index < 0) null else OutPoint(tx, index.toLong()) to tx.txOut[index]
    }

    /** Our main output in our own published commitment, if it has one. */
    fun inLocalCommit(channelKeys: ChannelKeys, commitment: FullCommitment, commitTx: Transaction): Output? {
        if (!channelKeys.hasGroupBasepoints || commitment.commitmentFormat != Transactions.CommitmentFormat.SimpleTaprootChannels) return null
        val keys = channelKeys.localCommitmentKeys(commitment.channelParams, commitment.localCommit.index)
        val delay = commitment.localCommitParams.toSelfDelay
        val tree = Scripts.Taproot.toLocalScriptTree(keys.publicKeys, delay)
        val (outPoint, txOut) = find(commitTx, Scripts.Taproot.toLocal(keys.publicKeys, delay)) ?: return null
        val pcp = channelKeys.commitmentPoint(commitment.localCommit.index)
        return Output(Kind.TO_LOCAL, outPoint, txOut, channelKeys.delayedPaymentBasePoint, tweakOf(pcp, channelKeys.delayedPaymentBasePoint), keys.ourDelayedPaymentPublicKey, Scripts.Taproot.NUMS_POINT.xOnly(), tree.localDelayed, tree.scriptTree, delay.toLong())
    }

    /** Our main output in the counterparty's published commitment, built with [remotePerCommitmentPoint]. */
    fun inRemoteCommit(channelKeys: ChannelKeys, commitment: FullCommitment, remotePerCommitmentPoint: PublicKey, commitTx: Transaction): Output? {
        if (!channelKeys.hasGroupBasepoints || commitment.commitmentFormat != Transactions.CommitmentFormat.SimpleTaprootChannels) return null
        val keys = channelKeys.remoteCommitmentKeys(commitment.channelParams, remotePerCommitmentPoint)
        val leaf = Scripts.Taproot.toRemoteScriptTree(keys.publicKeys)
        val (outPoint, txOut) = find(commitTx, Scripts.Taproot.toRemote(keys.publicKeys)) ?: return null
        return Output(Kind.TO_REMOTE, outPoint, txOut, channelKeys.paymentBasePoint, null, channelKeys.paymentBasePoint, Scripts.Taproot.NUMS_POINT.xOnly(), leaf, leaf, 1)
    }

    /** The delayed output of one of our confirmed HTLC transactions, spending our own commitment. */
    fun inHtlcTx(channelKeys: ChannelKeys, commitment: FullCommitment, htlcTx: Transaction): Output? {
        if (!channelKeys.hasGroupBasepoints || commitment.commitmentFormat != Transactions.CommitmentFormat.SimpleTaprootChannels) return null
        val keys = channelKeys.localCommitmentKeys(commitment.channelParams, commitment.localCommit.index)
        val delay = commitment.localCommitParams.toSelfDelay
        val leaf = Scripts.Taproot.htlcDelayedScriptTree(keys.publicKeys, delay)
        val internalKey = keys.revocationPublicKey.xOnly()
        val (outPoint, txOut) = find(htlcTx, Script.pay2tr(internalKey, leaf)) ?: return null
        val pcp = channelKeys.commitmentPoint(commitment.localCommit.index)
        return Output(Kind.HTLC_DELAYED, outPoint, txOut, channelKeys.delayedPaymentBasePoint, tweakOf(pcp, channelKeys.delayedPaymentBasePoint), keys.ourDelayedPaymentPublicKey, internalKey, leaf, leaf, delay.toLong())
    }
}
