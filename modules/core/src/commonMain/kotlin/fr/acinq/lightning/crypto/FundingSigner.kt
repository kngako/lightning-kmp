package fr.acinq.lightning.crypto

import fr.acinq.bitcoin.OutPoint
import fr.acinq.bitcoin.PrivateKey
import fr.acinq.bitcoin.PublicKey
import fr.acinq.bitcoin.TxId
import fr.acinq.bitcoin.TxOut
import fr.acinq.bitcoin.crypto.musig2.IndividualNonce
import fr.acinq.bitcoin.utils.Either
import fr.acinq.lightning.channel.ChannelSpendSignature
import fr.acinq.lightning.transactions.Transactions

/**
 * Everything a channel needs from its funding key, expressed WITHOUT assuming a private key exists.
 *
 * This is a port of the eclair fork's `FundingSigner` (sources/eclair/.../crypto/FundingSigner.scala):
 * ONE SEAM, NOT TWO. A channel gets its funding *public* key and every funding-key *signature* from the
 * same object, so the two cannot disagree. An abstraction that covers only the signing calls does not
 * work: the on-chain funding pubkey would stay `channelKeys.fundingKey(...).publicKey()`, the
 * counterparty would aggregate against a key the injected signer does not control, and the failure
 * would surface much later as a signature that will not verify.
 *
 * TAPROOT ONLY. An [Transactions.CommitmentFormat.AnchorOutputs] channel signs with ECDSA, which no
 * threshold signer here implements; those paths go through [privateKey] and fail loudly rather than
 * silently producing something unverifiable. A stock channel is unaffected: [PrivateKeyFundingSigner]
 * has a real private key and behaves exactly as before, call for call.
 *
 * Unlike eclair's seam (typed to `CommitTx`, which is what made mutual close unreachable there), the
 * signing methods here are typed to the common supertype [Transactions.ChannelSpendTransaction], so
 * commit, splice and closing transactions all go through the same two methods.
 */
interface FundingSigner {

    /** The funding public key that goes into the channel's 2-of-2 funding output. */
    val publicKey: PublicKey

    /**
     * Deterministic public nonce for OUR local commit tx, published ahead of time (in `tx_complete`,
     * `channel_ready`, `channel_reestablish` or `revoke_and_ack`) and re-derived -- never cached --
     * when we later sign that same commitment. Determinism is what lets the two derivations agree
     * without storing anything.
     */
    fun verificationNonce(id: VerificationNonceId): IndividualNonce

    /**
     * Sign OUR OWN commit/closing tx under the already-published deterministic nonce for [id] --
     * i.e. the nonce whose public part we previously sent to our peer.
     *
     * NOTE the two separate identities. [id] selects WHICH deterministic nonce to derive, and
     * [remoteFundingPubKey] is the key actually being aggregated against. In lightning-kmp's
     * dual-funded flow they always agree (the funding txid and the peer's funding key are both known
     * before the first nonce is published), but callers coming from eclair's establishment-v1 should
     * beware: there the first nonce is derived from placeholders while the signature is made against
     * the peer's real key.
     *
     * SAFETY, HONESTLY STATED. Re-deriving a nonce is only safe while a given [id] is paired with
     * exactly one message. That invariant holds on lightning-kmp's taproot flows as written: one
     * `VerificationNonceId` signs exactly one local commitment transaction. Callers introducing new
     * signing sites must not break it.
     */
    fun signWithVerificationNonce(
        tx: Transactions.ChannelSpendTransaction,
        remoteFundingPubKey: PublicKey,
        extraUtxos: Map<OutPoint, TxOut>,
        id: VerificationNonceId,
        remoteNonce: IndividualNonce
    ): Either<Throwable, ChannelSpendSignature.PartialSignatureWithNonce>

    /**
     * Sign the COUNTERPARTY's commit/closing tx with a fresh single-use nonce, generated and consumed
     * within this call and never published ahead of time (they published their nonce; we did not).
     */
    fun signWithFreshNonce(
        tx: Transactions.ChannelSpendTransaction,
        remoteFundingPubKey: PublicKey,
        extraUtxos: Map<OutPoint, TxOut>,
        fundingTxId: TxId,
        remoteNonce: IndividualNonce
    ): Either<Throwable, ChannelSpendSignature.PartialSignatureWithNonce>

    /**
     * Begin a one-shot session whose nonce is PUBLISHED BEFORE THE TRANSACTION IT WILL SIGN EXISTS:
     * [PublishedNonceSession.publicNonce] goes out on the wire now, the session is kept in memory,
     * and the transaction is signed later with [signWithPublishedNonce].
     *
     * That ordering is the whole reason this is a session rather than a call. [signWithFreshNonce]
     * creates and consumes its nonce in one call because the transaction is already known;
     * [verificationNonce] publishes early but can re-derive deterministically because the message it
     * will sign is pinned by a [VerificationNonceId]. Here neither is true, so the nonce has to be
     * carried across the gap.
     *
     * Two flows have this shape, and both use this method:
     *  - mutual close as the CLOSEE -- the nonce is published in `shutdown`, and later signs the
     *    closer's closing transaction, which does not exist yet when `shutdown` goes out;
     *  - splicing -- the nonce is published in `tx_complete`'s funding-nonce TLV, and later signs the
     *    shared input spending the previous funding output, on a shared transaction that is not final
     *    when `tx_complete` goes out.
     *
     * What the session CARRIES is signer-specific and opaque to callers: a private-key signer holds
     * the secret nonce, a threshold signer only needs the session label it re-derives round one from.
     *
     * ONE SESSION SIGNS AT MOST ONCE. A signer may re-derive round one from the session, so pairing
     * one session with two different transactions is a nonce reuse that raises no error. Both flows
     * respect this: closing advances to a fresh session after every signature, and each interactive-tx
     * attempt (including each RBF attempt) builds its own session.
     *
     * @param fundingTxId the funding output being spent -- the current one when closing, the PREVIOUS
     *                    one when splicing, since that is the output the shared input spends.
     */
    fun publishedNonceSession(fundingTxId: TxId, remoteFundingPubKey: PublicKey): PublishedNonceSession

    /** Sign a transaction under the nonce of an earlier [publishedNonceSession]. */
    fun signWithPublishedNonce(
        tx: Transactions.ChannelSpendTransaction,
        remoteFundingPubKey: PublicKey,
        extraUtxos: Map<OutPoint, TxOut>,
        session: PublishedNonceSession,
        remoteNonce: IndividualNonce
    ): Either<Throwable, ChannelSpendSignature.PartialSignatureWithNonce>

    /** The raw funding private key, when this signer is backed by one. */
    val privateKeyOrNull: PrivateKey?

    /**
     * The raw private key, for the paths that genuinely cannot be expressed without one (ECDSA signing
     * on segwit-v0 channels, splicing). Names the operation so a channel backed by a threshold signer
     * fails with something a reader can act on, rather than a bare exception from deep inside
     * transaction construction.
     */
    fun privateKey(operation: String): PrivateKey = privateKeyOrNull
        ?: throw IllegalStateException("'$operation' requires a raw funding private key, which ${this::class.simpleName} does not have -- this channel's funding key is held by a threshold signer, and this operation has not been implemented for it")

    /**
     * Identifies WHICH deterministic verification nonce is meant. Its own type, rather than three
     * loose parameters, because eclair's establishment-v1 derives the first nonce from placeholder
     * values while the signature is made against the peer's real funding key -- so a signing call can
     * carry two different `(TxId, PublicKey)` pairs at once, and passing them positionally invites
     * swapping them.
     */
    data class VerificationNonceId(val fundingTxId: TxId, val remoteFundingPubKey: PublicKey, val commitIndex: Long)

    /**
     * A one-shot session created by [FundingSigner.publishedNonceSession]. Opaque to callers: they
     * publish [publicNonce] on the wire and hand the session back to
     * [FundingSigner.signWithPublishedNonce] when the transaction to sign finally exists.
     *
     * In-memory only -- never persisted, and dropped on disconnection, exactly like the
     * [Transactions.LocalNonce] it replaces. That is not a limitation to fix: the peer has to be told
     * the nonce, and after a reconnection both flows restart from a fresh session anyway (a new
     * `shutdown`, a new interactive-tx attempt).
     *
     * Deliberately NOT a data class: identity equality is correct here, since two sessions built
     * independently are two different nonces even when their public parts happen to be compared.
     */
    abstract class PublishedNonceSession {
        abstract val publicNonce: IndividualNonce
    }

    /** The default signer: identical, call for call, to the pre-existing raw-[PrivateKey] signing. */
    class PrivateKeyFundingSigner(val fundingKey: PrivateKey) : FundingSigner {
        override val publicKey: PublicKey = fundingKey.publicKey()
        override val privateKeyOrNull: PrivateKey = fundingKey

        override fun verificationNonce(id: VerificationNonceId): IndividualNonce =
            NonceGenerator.verificationNonce(id.fundingTxId, fundingKey, id.remoteFundingPubKey, id.commitIndex).publicNonce

        override fun signWithVerificationNonce(
            tx: Transactions.ChannelSpendTransaction,
            remoteFundingPubKey: PublicKey,
            extraUtxos: Map<OutPoint, TxOut>,
            id: VerificationNonceId,
            remoteNonce: IndividualNonce
        ): Either<Throwable, ChannelSpendSignature.PartialSignatureWithNonce> {
            val localNonce = NonceGenerator.verificationNonce(id.fundingTxId, fundingKey, id.remoteFundingPubKey, id.commitIndex)
            return tx.partialSign(fundingKey, remoteFundingPubKey, extraUtxos, localNonce, listOf(localNonce.publicNonce, remoteNonce))
        }

        override fun signWithFreshNonce(
            tx: Transactions.ChannelSpendTransaction,
            remoteFundingPubKey: PublicKey,
            extraUtxos: Map<OutPoint, TxOut>,
            fundingTxId: TxId,
            remoteNonce: IndividualNonce
        ): Either<Throwable, ChannelSpendSignature.PartialSignatureWithNonce> {
            val localNonce = NonceGenerator.signingNonce(publicKey, remoteFundingPubKey, fundingTxId)
            return tx.partialSign(fundingKey, remoteFundingPubKey, extraUtxos, localNonce, listOf(localNonce.publicNonce, remoteNonce))
        }

        override fun publishedNonceSession(fundingTxId: TxId, remoteFundingPubKey: PublicKey): PublishedNonceSession =
            PrivateKeyPublishedNonceSession(NonceGenerator.signingNonce(publicKey, remoteFundingPubKey, fundingTxId))

        override fun signWithPublishedNonce(
            tx: Transactions.ChannelSpendTransaction,
            remoteFundingPubKey: PublicKey,
            extraUtxos: Map<OutPoint, TxOut>,
            session: PublishedNonceSession,
            remoteNonce: IndividualNonce
        ): Either<Throwable, ChannelSpendSignature.PartialSignatureWithNonce> {
            require(session is PrivateKeyPublishedNonceSession) { "published nonce session was not created by this signer" }
            return tx.partialSign(fundingKey, remoteFundingPubKey, extraUtxos, session.localNonce, listOf(session.publicNonce, remoteNonce))
        }

        private class PrivateKeyPublishedNonceSession(val localNonce: Transactions.LocalNonce) : PublishedNonceSession() {
            override val publicNonce: IndividualNonce = localNonce.publicNonce
        }
    }
}
