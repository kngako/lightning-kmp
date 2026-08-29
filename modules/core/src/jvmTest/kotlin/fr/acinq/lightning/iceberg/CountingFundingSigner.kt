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
import java.util.concurrent.atomic.AtomicLong

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
 *
 * Every override goes through [record], so a subclass can wrap each counted call without repeating
 * the mapping: IcebergCycleMeasurementRun's TimingFundingSigner overrides it to time the call too,
 * so the measurement reports its round split from the same counting code the channel spec exercises.
 */
open class CountingFundingSigner(private val underlying: FundingSigner) : FundingSigner {
    val nonceCalls = AtomicLong(0)
    val signVerificationCalls = AtomicLong(0)
    val signFreshCalls = AtomicLong(0)
    val closeeNonceCalls = AtomicLong(0)
    val signCloseeCalls = AtomicLong(0)

    override val publicKey: PublicKey = underlying.publicKey
    override val privateKeyOrNull: PrivateKey? = underlying.privateKeyOrNull

    /** Records one wrapped call against its counter. This class only counts; a subclass may also time it. */
    protected open fun <A> record(counter: AtomicLong, call: () -> A): A {
        counter.incrementAndGet()
        return call()
    }

    override fun verificationNonce(id: FundingSigner.VerificationNonceId): IndividualNonce =
        record(nonceCalls) { underlying.verificationNonce(id) }

    override fun signWithVerificationNonce(tx: Transactions.ChannelSpendTransaction, remoteFundingPubKey: PublicKey, extraUtxos: Map<OutPoint, TxOut>, id: FundingSigner.VerificationNonceId, remoteNonce: IndividualNonce): Either<Throwable, ChannelSpendSignature.PartialSignatureWithNonce> =
        record(signVerificationCalls) { underlying.signWithVerificationNonce(tx, remoteFundingPubKey, extraUtxos, id, remoteNonce) }

    override fun signWithFreshNonce(tx: Transactions.ChannelSpendTransaction, remoteFundingPubKey: PublicKey, extraUtxos: Map<OutPoint, TxOut>, fundingTxId: TxId, remoteNonce: IndividualNonce): Either<Throwable, ChannelSpendSignature.PartialSignatureWithNonce> =
        record(signFreshCalls) { underlying.signWithFreshNonce(tx, remoteFundingPubKey, extraUtxos, fundingTxId, remoteNonce) }

    override fun closeeNonce(fundingTxId: TxId, remoteFundingPubKey: PublicKey): FundingSigner.CloseeNonceSession =
        record(closeeNonceCalls) { underlying.closeeNonce(fundingTxId, remoteFundingPubKey) }

    override fun signWithCloseeNonce(tx: Transactions.ChannelSpendTransaction, remoteFundingPubKey: PublicKey, extraUtxos: Map<OutPoint, TxOut>, session: FundingSigner.CloseeNonceSession, remoteNonce: IndividualNonce): Either<Throwable, ChannelSpendSignature.PartialSignatureWithNonce> =
        record(signCloseeCalls) { underlying.signWithCloseeNonce(tx, remoteFundingPubKey, extraUtxos, session, remoteNonce) }

    /** Every method enters round one. */
    val roundOneCalls: Long get() = nonceCalls.get() + signVerificationCalls.get() + signFreshCalls.get() + closeeNonceCalls.get() + signCloseeCalls.get()
    /** Only the signing methods reach round two. */
    val roundTwoCalls: Long get() = signVerificationCalls.get() + signFreshCalls.get() + signCloseeCalls.get()
    /** Round ones that recompute a nonce an earlier call already published. */
    val redundantRoundOneCalls: Long get() = signVerificationCalls.get()
    fun resetCounts() {
        nonceCalls.set(0); signVerificationCalls.set(0); signFreshCalls.set(0); closeeNonceCalls.set(0); signCloseeCalls.set(0)
    }
}
