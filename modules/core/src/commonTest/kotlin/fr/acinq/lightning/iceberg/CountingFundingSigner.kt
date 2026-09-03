package fr.acinq.lightning.iceberg

import fr.acinq.bitcoin.OutPoint
import fr.acinq.bitcoin.PrivateKey
import fr.acinq.bitcoin.PublicKey
import fr.acinq.bitcoin.TxId
import fr.acinq.bitcoin.TxOut
import fr.acinq.bitcoin.crypto.musig2.IndividualNonce
import fr.acinq.bitcoin.utils.Either
import fr.acinq.lightning.channel.ChannelSpendSignature
import fr.acinq.lightning.crypto.FundingSigner
import fr.acinq.lightning.transactions.Transactions

/** A single call counter. Plain and non-atomic: this is commonTest, and the channel state machine
 *  drives its signer from one thread. The reference used `java.util.concurrent.atomic.AtomicLong`,
 *  which would have pinned this file to jvmTest for no benefit -- the measurement it feeds is
 *  explicitly single-threaded, since a timing run shares the machine with nothing. */
class CallCounter {
    var value: Long = 0L
        internal set

    internal fun increment() {
        value += 1
    }
}

/**
 * Wraps a [FundingSigner] and counts the group operations a channel asks for, one counter per
 * method (port of the reference's CountingFundingSigner). The methods cost different amounts of
 * threshold work, so the round split is observed here, not assumed:
 *
 *   verificationNonce         -> one round one (a nonce derivation over the 2t-1 quorum), no round two
 *   signWithVerificationNonce -> one round one and one round two; its round one re-derives a nonce an
 *                                earlier verificationNonce already published, the redundancy a cache removes
 *   signWithFreshNonce        -> one round one and one round two, on a nonce never published
 *   publishedNonceSession     -> one round one, no round two
 *   signWithPublishedNonce    -> one round one (re-derived) and one round two
 *
 * Every override goes through [record], so a subclass can wrap each counted call without repeating
 * the mapping: the measurement harness's TimingFundingSigner overrides it to time the call too, and
 * therefore reports its round split from the same counting code the channel suite exercises.
 */
open class CountingFundingSigner(private val underlying: FundingSigner) : FundingSigner {
    val nonceCalls = CallCounter()
    val signVerificationCalls = CallCounter()
    val signFreshCalls = CallCounter()
    val publishedNonceCalls = CallCounter()
    val signPublishedCalls = CallCounter()

    override val publicKey: PublicKey = underlying.publicKey
    override val privateKeyOrNull: PrivateKey? = underlying.privateKeyOrNull

    /** Records one wrapped call against its counter. This class only counts; a subclass may also time it. */
    protected open fun <A> record(counter: CallCounter, call: () -> A): A {
        counter.increment()
        return call()
    }

    override fun verificationNonce(id: FundingSigner.VerificationNonceId): IndividualNonce =
        record(nonceCalls) { underlying.verificationNonce(id) }

    override fun signWithVerificationNonce(tx: Transactions.ChannelSpendTransaction, remoteFundingPubKey: PublicKey, extraUtxos: Map<OutPoint, TxOut>, id: FundingSigner.VerificationNonceId, remoteNonce: IndividualNonce): Either<Throwable, ChannelSpendSignature.PartialSignatureWithNonce> =
        record(signVerificationCalls) { underlying.signWithVerificationNonce(tx, remoteFundingPubKey, extraUtxos, id, remoteNonce) }

    override fun signWithFreshNonce(tx: Transactions.ChannelSpendTransaction, remoteFundingPubKey: PublicKey, extraUtxos: Map<OutPoint, TxOut>, fundingTxId: TxId, remoteNonce: IndividualNonce): Either<Throwable, ChannelSpendSignature.PartialSignatureWithNonce> =
        record(signFreshCalls) { underlying.signWithFreshNonce(tx, remoteFundingPubKey, extraUtxos, fundingTxId, remoteNonce) }

    override fun publishedNonceSession(fundingTxId: TxId, remoteFundingPubKey: PublicKey): FundingSigner.PublishedNonceSession =
        record(publishedNonceCalls) { underlying.publishedNonceSession(fundingTxId, remoteFundingPubKey) }

    override fun signWithPublishedNonce(tx: Transactions.ChannelSpendTransaction, remoteFundingPubKey: PublicKey, extraUtxos: Map<OutPoint, TxOut>, session: FundingSigner.PublishedNonceSession, remoteNonce: IndividualNonce): Either<Throwable, ChannelSpendSignature.PartialSignatureWithNonce> =
        record(signPublishedCalls) { underlying.signWithPublishedNonce(tx, remoteFundingPubKey, extraUtxos, session, remoteNonce) }

    /** Every method enters round one. */
    val roundOneCalls: Long get() = nonceCalls.value + signVerificationCalls.value + signFreshCalls.value + publishedNonceCalls.value + signPublishedCalls.value

    /** Only the signing methods reach round two. */
    val roundTwoCalls: Long get() = signVerificationCalls.value + signFreshCalls.value + signPublishedCalls.value

    /** Round ones that recompute a nonce an earlier call already published. */
    val redundantRoundOneCalls: Long get() = signVerificationCalls.value

    fun resetCounts() {
        listOf(nonceCalls, signVerificationCalls, signFreshCalls, publishedNonceCalls, signPublishedCalls).forEach { it.value = 0L }
    }
}
