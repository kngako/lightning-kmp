package fr.acinq.lightning.crypto

import fr.acinq.bitcoin.ByteVector32
import fr.acinq.bitcoin.Crypto
import fr.acinq.bitcoin.OutPoint
import fr.acinq.bitcoin.PrivateKey
import fr.acinq.bitcoin.PublicKey
import fr.acinq.bitcoin.TxId
import fr.acinq.bitcoin.TxOut
import fr.acinq.bitcoin.crypto.Pack
import fr.acinq.bitcoin.crypto.iceberg.Iceberg
import fr.acinq.bitcoin.crypto.iceberg.NonceContribution
import fr.acinq.bitcoin.crypto.iceberg.SignatureShare
import fr.acinq.bitcoin.crypto.musig2.AggregatedNonce
import fr.acinq.bitcoin.crypto.musig2.IndividualNonce
import fr.acinq.bitcoin.crypto.musig2.KeyAggCache
import fr.acinq.bitcoin.crypto.musig2.Session
import fr.acinq.bitcoin.utils.Either
import fr.acinq.lightning.channel.ChannelSpendSignature
import fr.acinq.lightning.transactions.Scripts
import fr.acinq.lightning.transactions.Transactions
import kotlinx.coroutines.withTimeoutOrNull
import kotlin.time.Duration

/**
 * What a [RemoteIcebergFundingSigner] needs from the group it stands for, and nothing about how the
 * group is reached. lightning-kmp knows no transport: the application supplies one.
 *
 * The split follows Iceberg's two rounds. Round one depends only on the share and the session label,
 * so the group can compute it ahead of time and the transport serves it from a pool ([contributions]):
 * it is synchronous because the channel needs a verification nonce in places that cannot wait, a
 * constructor among them. Round two needs the message, so it is a request that waits on people's
 * devices ([roundTwo]).
 */
interface IcebergGroupTransport {
    /** The group's size and threshold, as its shares were made. */
    val n: Int
    val t: Int

    /**
     * At least `2t-1` round-one contributions for [label], already received from the group, or null
     * when it has not provisioned that label. A null is a liveness failure, not a protocol one: the
     * caller fails by name rather than inventing a nonce.
     */
    fun contributions(label: ByteVector32): List<NonceContribution>?

    /**
     * The next fresh-nonce label for the channel funded by [fundingTxId]: [RemoteIcebergFundingSigner.freshLabel]
     * of a counter that only goes up. The transport persists the counter BEFORE returning, because a label
     * handed out twice signs two messages, which leaks a share and raises no error.
     */
    fun nextFreshLabel(fundingTxId: TxId): ByteVector32

    /**
     * Ask the group to sign [request] and suspend until at least `t` signature shares are in. The
     * caller enforces the deadline. Returning shares from members other than the round-one set is fine:
     * `iceberg.md` says a member that sat round one out can still sign.
     */
    suspend fun roundTwo(request: IcebergRoundTwoRequest): Either<Throwable, List<SignatureShare>>
}

/**
 * Everything a member's device needs to decide whether to answer round two, and to answer it. It carries
 * the transaction and not only its sighash, because a member that signs a hash it cannot see is a member
 * that can be made to sign anything.
 */
data class IcebergRoundTwoRequest(
    val kind: Kind,
    val label: ByteVector32,
    val tx: Transactions.ChannelSpendTransaction,
    val extraUtxos: Map<OutPoint, TxOut>,
    val fundingTxId: TxId,
    val remoteFundingPubKey: PublicKey,
    /** The commitment number, for the two kinds that sign a commitment. */
    val commitIndex: Long?,
    val message: ByteVector32,
    val contributions: List<NonceContribution>,
    val cosignerAggregatedNonce: AggregatedNonce,
) {
    enum class Kind {
        /** Our own commitment, under its deterministic verification nonce: only ever at a force close. */
        LOCAL_COMMITMENT,
        /** The counterparty's commitment, or a closing transaction, under a fresh label. */
        FRESH,
        /** A closing transaction as the closee, or a splice's shared input, under a published label. */
        PUBLISHED,
    }
}

class IcebergNonceNotProvisioned(val label: ByteVector32) :
    IllegalStateException("the group has not provisioned round one for label $label: top up the pool before reconnecting")

class IcebergSigningTimeout(val label: ByteVector32, val deadline: Duration) :
    IllegalStateException("the group did not answer round two for label $label within $deadline; the label is burned")

/**
 * A channel's funding key held by an Iceberg group that is NOT in this process: the members are other
 * people's devices, and [transport] reaches them.
 *
 * This is the out-of-scope half of `FEATURE-PARITY.md`. [IcebergFundingSigner] simulates the whole group
 * in one process and answers at once; this one waits, which is why the three signing methods of
 * [FundingSigner] suspend. Round one is never on the critical path: every label this signer uses is
 * computable ahead of time -- the verification labels already were, and fresh labels come from
 * [freshLabel] over a counter rather than from `randomBytes32()` -- so the group publishes its
 * contributions early and [IcebergGroupTransport.contributions] serves them.
 *
 * A round two that misses [deadline] fails with [IcebergSigningTimeout]. Its label is burned: the
 * transport has already handed it out, and a retry asks for a new one.
 *
 * The group's partial signature is checked against the outer session before it is returned, so a bad
 * share is caught here rather than by the counterparty.
 */
class RemoteIcebergFundingSigner(
    val groupPublicKey: PublicKey,
    val transport: IcebergGroupTransport,
    val deadline: Duration,
) : FundingSigner {

    override val publicKey: PublicKey = groupPublicKey
    override val privateKeyOrNull: PrivateKey? = null

    private fun groupNonce(label: ByteVector32): IndividualNonce {
        val contributions = transport.contributions(label) ?: throw IcebergNonceNotProvisioned(label)
        return when (val nonce = Iceberg.aggregateNonces(contributions, transport.n, transport.t, groupPublicKey)) {
            is Either.Right -> nonce.value
            is Either.Left -> throw nonce.value
        }
    }

    override fun verificationNonce(id: FundingSigner.VerificationNonceId): IndividualNonce =
        groupNonce(IcebergFundingSigner.verificationSessionId(id))

    override suspend fun signWithVerificationNonce(
        tx: Transactions.ChannelSpendTransaction,
        remoteFundingPubKey: PublicKey,
        extraUtxos: Map<OutPoint, TxOut>,
        id: FundingSigner.VerificationNonceId,
        remoteNonce: IndividualNonce
    ): Either<Throwable, ChannelSpendSignature.PartialSignatureWithNonce> =
        sign(IcebergRoundTwoRequest.Kind.LOCAL_COMMITMENT, IcebergFundingSigner.verificationSessionId(id), tx, remoteFundingPubKey, extraUtxos, id.fundingTxId, id.commitIndex, remoteNonce)

    override suspend fun signWithFreshNonce(
        tx: Transactions.ChannelSpendTransaction,
        remoteFundingPubKey: PublicKey,
        extraUtxos: Map<OutPoint, TxOut>,
        fundingTxId: TxId,
        remoteNonce: IndividualNonce
    ): Either<Throwable, ChannelSpendSignature.PartialSignatureWithNonce> =
        sign(IcebergRoundTwoRequest.Kind.FRESH, transport.nextFreshLabel(fundingTxId), tx, remoteFundingPubKey, extraUtxos, fundingTxId, null, remoteNonce)

    override fun publishedNonceSession(fundingTxId: TxId, remoteFundingPubKey: PublicKey): FundingSigner.PublishedNonceSession {
        val label = transport.nextFreshLabel(fundingTxId)
        return RemotePublishedNonceSession(label, fundingTxId, groupNonce(label))
    }

    override suspend fun signWithPublishedNonce(
        tx: Transactions.ChannelSpendTransaction,
        remoteFundingPubKey: PublicKey,
        extraUtxos: Map<OutPoint, TxOut>,
        session: FundingSigner.PublishedNonceSession,
        remoteNonce: IndividualNonce
    ): Either<Throwable, ChannelSpendSignature.PartialSignatureWithNonce> {
        require(session is RemotePublishedNonceSession) { "published nonce session was not created by this signer" }
        return sign(IcebergRoundTwoRequest.Kind.PUBLISHED, session.label, tx, remoteFundingPubKey, extraUtxos, session.fundingTxId, null, remoteNonce)
    }

    private suspend fun sign(
        kind: IcebergRoundTwoRequest.Kind,
        label: ByteVector32,
        tx: Transactions.ChannelSpendTransaction,
        remoteFundingPubKey: PublicKey,
        extraUtxos: Map<OutPoint, TxOut>,
        fundingTxId: TxId,
        commitIndex: Long?,
        remoteNonce: IndividualNonce
    ): Either<Throwable, ChannelSpendSignature.PartialSignatureWithNonce> {
        val prepared = try {
            prepare(label, tx, remoteFundingPubKey, extraUtxos, remoteNonce)
        } catch (e: Throwable) {
            return Either.Left(e)
        }
        val request = IcebergRoundTwoRequest(kind, label, tx, extraUtxos, fundingTxId, remoteFundingPubKey, commitIndex, prepared.message, prepared.contributions, prepared.cosignerAggregatedNonce)
        val shares = withTimeoutOrNull(deadline) { transport.roundTwo(request) } ?: return Either.Left(IcebergSigningTimeout(label, deadline))
        return when (shares) {
            is Either.Left -> shares
            is Either.Right -> when (val partial = Iceberg.aggregatePartialSignatures(shares.value, transport.n, transport.t)) {
                is Either.Left -> Either.Left(partial.value)
                is Either.Right -> when {
                    prepared.session.verify(partial.value, prepared.groupNonce, groupPublicKey) -> Either.Right(ChannelSpendSignature.PartialSignatureWithNonce(partial.value, prepared.groupNonce))
                    else -> Either.Left(IllegalStateException("the group's signature shares for label $label aggregate to a partial signature that does not verify"))
                }
            }
        }
    }

    private class Prepared(
        val message: ByteVector32,
        val contributions: List<NonceContribution>,
        val groupNonce: IndividualNonce,
        val cosignerAggregatedNonce: AggregatedNonce,
        val session: Session,
    )

    private fun prepare(label: ByteVector32, tx: Transactions.ChannelSpendTransaction, remoteFundingPubKey: PublicKey, extraUtxos: Map<OutPoint, TxOut>, remoteNonce: IndividualNonce): Prepared {
        val contributions = transport.contributions(label) ?: throw IcebergNonceNotProvisioned(label)
        val groupNonce = Iceberg.aggregateNonces(contributions, transport.n, transport.t, groupPublicKey).orThrow()
        val message = tx.taprootSighash(extraUtxos)
        // The outer session has to be the one ChannelSpendTransaction.partialSign builds: Scripts.sort
        // order and the BIP341 key-path tweak, or a well-formed share simply does not combine.
        val sortedKeys = Scripts.sort(listOf(publicKey, remoteFundingPubKey))
        val tweak = Scripts.Taproot.musig2Aggregate(publicKey, remoteFundingPubKey).tweak(Crypto.TaprootTweak.KeyPathTweak)
        val keyAggCache = KeyAggCache.create(sortedKeys).second.tweak(tweak, isXonly = true).orThrow().first
        check(Iceberg.keyAggregationCheck(keyAggCache, sortedKeys, publicKey)) { "the key aggregation cache does not aggregate this group's key with $remoteFundingPubKey in Scripts.sort order" }
        val cosignerAggregatedNonce = IndividualNonce.aggregate(listOf(remoteNonce)).orThrow()
        val session = Session.create(IndividualNonce.aggregate(listOf(groupNonce, remoteNonce)).orThrow(), message, keyAggCache)
        return Prepared(message, contributions, groupNonce, cosignerAggregatedNonce, session)
    }

    private fun <A> Either<Throwable, A>.orThrow(): A = when (this) {
        is Either.Right -> value
        is Either.Left -> throw value
    }

    private class RemotePublishedNonceSession(val label: ByteVector32, val fundingTxId: TxId, override val publicNonce: IndividualNonce) : FundingSigner.PublishedNonceSession()

    companion object {
        /**
         * The label for the [counter]th fresh nonce of the channel funded by [fundingTxId]. Tagged, so it
         * can never equal a [IcebergFundingSigner.verificationSessionId], which is an untagged SHA-256 of
         * different inputs. Every member computes the same labels, so the group can publish round one for
         * the next few counters before they are needed.
         */
        fun freshLabel(fundingTxId: TxId, counter: Long): ByteVector32 =
            Crypto.taggedHash(fundingTxId.value.toByteArray() + Pack.writeInt64BE(counter), "bennu/iceberg/fresh/v1")
    }
}
