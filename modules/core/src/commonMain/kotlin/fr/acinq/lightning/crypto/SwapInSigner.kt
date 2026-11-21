package fr.acinq.lightning.crypto

import fr.acinq.bitcoin.ByteVector32
import fr.acinq.bitcoin.Crypto
import fr.acinq.bitcoin.OutPoint
import fr.acinq.bitcoin.PrivateKey
import fr.acinq.bitcoin.PublicKey
import fr.acinq.bitcoin.SigHash
import fr.acinq.bitcoin.Transaction
import fr.acinq.bitcoin.TxOut
import fr.acinq.bitcoin.crypto.iceberg.Iceberg
import fr.acinq.bitcoin.crypto.iceberg.NonceContribution
import fr.acinq.bitcoin.crypto.iceberg.SignatureShare
import fr.acinq.bitcoin.crypto.musig2.AggregatedNonce
import fr.acinq.bitcoin.crypto.musig2.IndividualNonce
import fr.acinq.bitcoin.crypto.musig2.KeyAggCache
import fr.acinq.bitcoin.crypto.musig2.Musig2
import fr.acinq.bitcoin.crypto.musig2.SecretNonce
import fr.acinq.bitcoin.utils.Either
import fr.acinq.bitcoin.utils.flatMap
import fr.acinq.bitcoin.utils.getOrElse
import fr.acinq.lightning.Lightning.randomBytes32
import fr.acinq.lightning.transactions.SwapInProtocol
import kotlinx.coroutines.withTimeoutOrNull
import kotlin.time.Duration

/**
 * The user's side of a swap-in input's MuSig2 key path, as a seam: a private key in a phone's wallet
 * ([LocalSwapInSigner]), or a threshold group that holds no such key anywhere ([IcebergSwapInSigner],
 * [RemoteIcebergSwapInSigner]).
 *
 * It follows the interactive-tx protocol's two moments. The nonce is made as `tx_add_input` is sent,
 * which is not a suspending point, so [nonceSession] is synchronous: a group serves it from round one,
 * which it computed ahead of time. The partial signature is made in `SharedTransaction.sign`, after both
 * `tx_complete`s and so after the server's nonce is known, and [sign] suspends while a group answers.
 *
 * A session is used once. The interactive-tx session keeps the one made for each of its inputs, and an
 * RBF attempt is a new interactive-tx session with new ones.
 */
interface SwapInSigner {
    /** The key the swap-in protocol puts first in the key path's aggregate. */
    val userPublicKey: PublicKey

    /** The user's side of one input's signing session: its public nonce goes out in `tx_complete`. */
    abstract class NonceSession {
        abstract val publicNonce: IndividualNonce
    }

    /** A fresh session for the swap-in coin at [outPoint], spent under [protocol]. */
    fun nonceSession(outPoint: OutPoint, protocol: SwapInProtocol): NonceSession

    /**
     * The user's partial signature for input [inputIndex] of [tx], spending a coin under [protocol], in
     * [session] and against the server's public nonce [serverNonce]. [spentOutputs] are every input's
     * previous output, in input order: a taproot sighash covers all of them.
     */
    suspend fun sign(tx: Transaction, inputIndex: Int, spentOutputs: List<TxOut>, protocol: SwapInProtocol, session: NonceSession, serverNonce: IndividualNonce): Either<Throwable, ByteVector32>

    companion object {
        /**
         * The key aggregation cache of a swap-in input's key path: `[user, server]` in that order -- the
         * protocol does not sort them, unlike a channel's funding keys -- tweaked by the refund leaf's
         * script tree. Spike 1 of `docs/group-lightning-swap-in.md` shows a share under the channel's order
         * or tweak is well-formed and spends nothing, so a group signer must build exactly this.
         */
        fun keyAggCache(protocol: SwapInProtocol): Either<Throwable, KeyAggCache> {
            val keys = listOf(protocol.userPublicKey, protocol.serverPublicKey)
            val (aggregate, cache) = KeyAggCache.create(keys)
            val tweak = aggregate.tweak(Crypto.TaprootTweak.ScriptPathTweak(protocol.scriptTreeHash))
            return cache.tweak(tweak, isXonly = true).map { it.first }
        }

        /** The sighash a swap-in input's key path signs: BIP341's, over every spent output. */
        fun message(tx: Transaction, inputIndex: Int, spentOutputs: List<TxOut>): ByteVector32 =
            Transaction.hashForSigningTaprootKeyPath(tx, inputIndex, spentOutputs, SigHash.SIGHASH_DEFAULT)
    }
}

/** A phone's swap-in key, signing in process: what `SwapInOnChainKeys` always did. */
class LocalSwapInSigner(private val userPrivateKey: PrivateKey) : SwapInSigner {
    override val userPublicKey: PublicKey = userPrivateKey.publicKey()

    private class LocalNonceSession(val secretNonce: SecretNonce, override val publicNonce: IndividualNonce) : SwapInSigner.NonceSession()

    override fun nonceSession(outPoint: OutPoint, protocol: SwapInProtocol): SwapInSigner.NonceSession {
        val (secret, public) = Musig2.generateNonce(randomBytes32(), Either.Left(userPrivateKey), listOf(protocol.userPublicKey, protocol.serverPublicKey), null, null)
        return LocalNonceSession(secret, public)
    }

    override suspend fun sign(tx: Transaction, inputIndex: Int, spentOutputs: List<TxOut>, protocol: SwapInProtocol, session: SwapInSigner.NonceSession, serverNonce: IndividualNonce): Either<Throwable, ByteVector32> {
        require(session is LocalNonceSession) { "the nonce session was not made by this signer" }
        return protocol.signSwapInputUser(tx, inputIndex, spentOutputs, userPrivateKey, session.secretNonce, session.publicNonce, serverNonce)
    }
}

/**
 * An Iceberg group as the swap-in's user, simulated in one process like [IcebergFundingSigner]: for
 * tests, where the whole group answers at once.
 */
class IcebergSwapInSigner(
    val group: IcebergGroup,
    val contributors: List<Int> = (1..group.quorum).toList(),
    val signers: List<Int> = (1..group.t).toList(),
) : SwapInSigner {
    override val userPublicKey: PublicKey = group.groupPublicKey

    private class Session(val label: ByteVector32, val roundOne: IcebergSigner.RoundOneResult) : SwapInSigner.NonceSession() {
        override val publicNonce: IndividualNonce = roundOne.publicNonce
    }

    override fun nonceSession(outPoint: OutPoint, protocol: SwapInProtocol): SwapInSigner.NonceSession {
        val label = randomBytes32()
        return Session(label, IcebergSigner.roundOne(group, contributors, label))
    }

    override suspend fun sign(tx: Transaction, inputIndex: Int, spentOutputs: List<TxOut>, protocol: SwapInProtocol, session: SwapInSigner.NonceSession, serverNonce: IndividualNonce): Either<Throwable, ByteVector32> {
        require(session is Session) { "the nonce session was not made by this signer" }
        require(protocol.userPublicKey == group.groupPublicKey) { "the input is not this group's swap-in" }
        return SwapInSigner.keyAggCache(protocol).flatMap { cache ->
            IcebergSigner.cosignerAggregatedNonce(listOf(serverNonce)).flatMap { cosigner ->
                IcebergSigner.roundTwo(group, signers, session.label, session.roundOne, cache, SwapInSigner.message(tx, inputIndex, spentOutputs), cosigner).map { it.partialSig }
            }
        }
    }
}

/**
 * Everything a member's device needs to decide whether to answer round two for a swap-in input, and to
 * answer it: the whole transaction and every spent output, so that a member checks what it signs rather
 * than signing a hash (`docs/group-lightning-swap-in.md`, Phase 4).
 */
data class IcebergSwapInRoundTwoRequest(
    val label: ByteVector32,
    val tx: Transaction,
    val inputIndex: Int,
    val spentOutputs: List<TxOut>,
    val protocol: SwapInProtocol,
    val message: ByteVector32,
    val contributions: List<NonceContribution>,
    val cosignerAggregatedNonce: AggregatedNonce,
)

/**
 * A swap-in's user key held by an Iceberg group that is not in this process: the counterpart of
 * [RemoteIcebergFundingSigner] for a swap-in input, over the same [IcebergGroupTransport].
 *
 * Its labels come from [IcebergGroupTransport.nextSwapInLabel], keyed by the coin and not by a funding
 * txid, which does not exist yet when `tx_add_input` goes out. Like every Iceberg label, each one signs
 * once: a round two that misses [deadline] burns it, and the next attempt asks for another.
 */
class RemoteIcebergSwapInSigner(
    override val userPublicKey: PublicKey,
    private val transport: IcebergGroupTransport,
    private val deadline: Duration,
) : SwapInSigner {
    private class Session(val label: ByteVector32, val contributions: List<NonceContribution>, override val publicNonce: IndividualNonce) : SwapInSigner.NonceSession()

    override fun nonceSession(outPoint: OutPoint, protocol: SwapInProtocol): SwapInSigner.NonceSession {
        val label = transport.nextSwapInLabel(outPoint)
        val contributions = transport.contributions(label) ?: throw IcebergNonceNotProvisioned(label)
        val nonce = Iceberg.aggregateNonces(contributions, transport.n, transport.t, userPublicKey).getOrElse { throw it }
        return Session(label, contributions, nonce)
    }

    override suspend fun sign(tx: Transaction, inputIndex: Int, spentOutputs: List<TxOut>, protocol: SwapInProtocol, session: SwapInSigner.NonceSession, serverNonce: IndividualNonce): Either<Throwable, ByteVector32> {
        require(session is Session) { "the nonce session was not made by this signer" }
        if (protocol.userPublicKey != userPublicKey) return Either.Left(IllegalArgumentException("the input is not this group's swap-in"))
        val message = SwapInSigner.message(tx, inputIndex, spentOutputs)
        return SwapInSigner.keyAggCache(protocol).flatMap { cache ->
            if (!Iceberg.keyAggregationCheck(cache, listOf(protocol.userPublicKey, protocol.serverPublicKey), userPublicKey)) {
                return@flatMap Either.Left(IllegalStateException("the swap-in's key aggregation does not hold the group's key first"))
            }
            IndividualNonce.aggregate(listOf(serverNonce)).flatMap { cosigner ->
                val request = IcebergSwapInRoundTwoRequest(session.label, tx, inputIndex, spentOutputs, protocol, message, session.contributions, cosigner)
                val shares: Either<Throwable, List<SignatureShare>> = withTimeoutOrNull(deadline) { transport.roundTwoSwapIn(request) }
                    ?: Either.Left(IcebergSigningTimeout(session.label, deadline))
                shares.flatMap { Iceberg.aggregatePartialSignatures(it, transport.n, transport.t) }
            }
        }
    }
}
