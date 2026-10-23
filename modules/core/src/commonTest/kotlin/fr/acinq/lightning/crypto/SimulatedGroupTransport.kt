package fr.acinq.lightning.crypto

import fr.acinq.bitcoin.ByteVector32
import fr.acinq.bitcoin.TxId
import fr.acinq.bitcoin.crypto.iceberg.Iceberg
import fr.acinq.bitcoin.crypto.iceberg.NonceContribution
import fr.acinq.bitcoin.crypto.iceberg.SignatureShare
import fr.acinq.bitcoin.utils.Either
import kotlinx.coroutines.awaitCancellation
import kotlinx.coroutines.delay
import kotlin.random.Random

/**
 * An [IcebergGroupTransport] over an in-process [IcebergGroup], standing in for members on other
 * devices: it answers round two after a random delay, can be told to never answer, and records every
 * label it was asked to sign under so a test can assert the one rule that leaks a share if broken --
 * one label, one message.
 *
 * Round one is computed on demand, which is what a fully provisioned pool looks like from the signer.
 * [unprovisioned] makes a label look like one the group never published.
 */
class SimulatedGroupTransport(
    val group: IcebergGroup,
    private val maxDelayMillis: Long = 0,
    private val random: Random = Random(42),
) : IcebergGroupTransport {
    override val n: Int = group.n
    override val t: Int = group.t

    private val contributors = (1..group.quorum).toList()
    private val counters = mutableMapOf<TxId, Long>()

    /** Every label round two was asked under, with the message it was asked to sign. */
    val signedUnder = mutableMapOf<ByteVector32, MutableSet<ByteVector32>>()
    val requests = mutableListOf<IcebergRoundTwoRequest>()
    val unprovisioned = mutableSetOf<ByteVector32>()
    var silent = false

    override fun contributions(label: ByteVector32): List<NonceContribution>? =
        if (label in unprovisioned) null else contributors.map { k -> Iceberg.generateNonce(group.shares[k - 1], group.caches[k - 1], label) }

    override fun nextFreshLabel(fundingTxId: TxId): ByteVector32 {
        val counter = counters.getOrElse(fundingTxId) { 0L }
        counters[fundingTxId] = counter + 1
        return RemoteIcebergFundingSigner.freshLabel(fundingTxId, counter)
    }

    override suspend fun roundTwo(request: IcebergRoundTwoRequest): Either<Throwable, List<SignatureShare>> {
        requests += request
        signedUnder.getOrPut(request.label) { mutableSetOf() } += request.message
        if (silent) awaitCancellation()
        if (maxDelayMillis > 0) delay(random.nextLong(0, maxDelayMillis + 1))
        // Members past the round-one set sign too, which iceberg.md says they may.
        val signers = (1..group.n).shuffled(random).take(group.quorum)
        val outerCache = IcebergSigner.keyAggCacheFor(
            fr.acinq.lightning.transactions.Scripts.sort(listOf(group.groupPublicKey, request.remoteFundingPubKey)),
            fr.acinq.lightning.transactions.Scripts.Taproot.musig2Aggregate(group.groupPublicKey, request.remoteFundingPubKey).tweak(fr.acinq.bitcoin.Crypto.TaprootTweak.KeyPathTweak)
        )
        val keyAggCache = when (outerCache) {
            is Either.Left -> return outerCache
            is Either.Right -> outerCache.value
        }
        return Either.Right(signers.map { k ->
            when (val share = Iceberg.partialSign(group.shares[k - 1], group.caches[k - 1], request.label, request.contributions, group.groupPublicKey, keyAggCache, request.message, request.cosignerAggregatedNonce)) {
                is Either.Left -> return share
                is Either.Right -> share.value
            }
        })
    }

    /** Labels that were asked to sign more than one message: must always be empty. */
    fun reusedLabels(): Map<ByteVector32, Set<ByteVector32>> = signedUnder.filterValues { it.size > 1 }
}
