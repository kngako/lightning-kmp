package fr.acinq.lightning.crypto

import fr.acinq.bitcoin.ByteVector
import fr.acinq.bitcoin.ByteVector32
import fr.acinq.bitcoin.Crypto
import fr.acinq.bitcoin.OutPoint
import fr.acinq.bitcoin.PrivateKey
import fr.acinq.bitcoin.PublicKey
import fr.acinq.bitcoin.TxId
import fr.acinq.bitcoin.TxOut
import fr.acinq.bitcoin.byteVector32
import fr.acinq.bitcoin.crypto.iceberg.Iceberg
import fr.acinq.bitcoin.crypto.iceberg.NonceContribution
import fr.acinq.bitcoin.crypto.iceberg.PublicShare
import fr.acinq.bitcoin.crypto.iceberg.Share
import fr.acinq.bitcoin.crypto.iceberg.ShareCache
import fr.acinq.bitcoin.crypto.musig2.AggregatedNonce
import fr.acinq.bitcoin.crypto.musig2.IndividualNonce
import fr.acinq.bitcoin.crypto.musig2.KeyAggCache
import fr.acinq.bitcoin.utils.Either
import fr.acinq.bitcoin.utils.flatMap
import fr.acinq.bitcoin.utils.getOrElse
import fr.acinq.lightning.Lightning.randomBytes32
import fr.acinq.lightning.channel.ChannelSpendSignature
import fr.acinq.lightning.transactions.Scripts
import fr.acinq.lightning.transactions.Transactions

/**
 * A group's key material, from a simulated Iceberg trusted-dealer keygen. [groupPublicKey] is an
 * ordinary compressed public key occupying ONE MuSig2 participant's slot; each of the [n] members
 * holds one [shares] entry (1-based member index k -> `shares[k - 1]`), with its matching
 * [publicShares] and precomputation [caches] at the same index.
 *
 * [Share] keeps itself out of logs (its `toString` is `<iceberg_share>`), so this class needs no
 * hand-written `toString` -- unlike the reference port, which held shares as bare `ByteArray`s.
 */
data class IcebergGroup(
    val n: Int,
    val t: Int,
    val groupPublicKey: PublicKey,
    val shares: List<Share>,
    val publicShares: List<PublicShare>,
    val caches: List<ShareCache>
) {
    /** Round one needs this many members online. Round two needs only [t]. */
    val quorum: Int = 2 * t - 1
}

/**
 * Local, in-process simulation of an Iceberg t-of-n threshold signer occupying ONE MuSig2
 * participant slot: all `n` members are simulated in this process, and the object presents their
 * combined output as a single participant's public nonce ([roundOne]) and partial signature
 * ([roundTwo]), shaped exactly as the channel's taproot signing seam expects.
 *
 * Port of the reference's `IcebergSigner` (`sources/lightning-kmp/.../jvmMain/.../IcebergSigner.kt`),
 * rewritten against `fr.acinq.bitcoin.crypto.iceberg.Iceberg`. Two differences from the reference,
 * both from the API rather than the design:
 *
 *  - THIS IS commonMain, NOT jvmMain. The reference's Iceberg API is JVM-only JNI, so its signer
 *    could never leave `jvmMain`. Here the API is bitcoin-kmp `commonMain` over an `expect` surface
 *    with both a JNI and a cinterop actual, so the signer -- and the channel suites that drive it --
 *    run on every target lightning-kmp supports.
 *  - NO `requireConfig`. A bad `(n, t)` aborts the process inside the reference's C module, so it
 *    had to check first. Here `Secp256k1Jni`/`Secp256k1Native` validate `n <= 10` and
 *    `1 <= t <= (n+1)/2` before entering C, and an illegal configuration throws. 2-of-2 and 3-of-4
 *    remain inexpressible; 2-of-4 is the smallest usable group.
 *
 * Three properties of the scheme constrain the call sites, and all three carry over unchanged:
 *
 *  - [roundTwo] takes the OUTER session's real key aggregation cache and the cosigners' real
 *    aggregate nonce. A fabricated pair yields a signature share that cannot aggregate, so building
 *    them correctly is the caller's job -- [keyAggCacheFor] and [cosignerAggregatedNonce] exist for
 *    it, and [Iceberg.keyAggregationCheck] catches getting it wrong.
 *  - The two rounds have different quorums: round one needs `2t-1` contributors, round two
 *    aggregates `t` signature shares.
 *  - SESSION LABELS MUST BE UNIQUE. Iceberg derives nonces from the label rather than storing them,
 *    so a label used twice across the group is a key-leaking path that raises no error at all.
 */
object IcebergSigner {

    /**
     * Simulated trusted-dealer keygen. For the duration of this call one process holds enough to
     * reconstruct the group's private key, which is exactly what a threshold scheme exists to
     * avoid -- fine for a benchmark, not a deployment. Nothing downstream depends on how a share was
     * produced, so a share from a real DKG would be used identically.
     */
    fun keygen(n: Int, t: Int, seed: ByteVector32): IcebergGroup {
        val shares = Iceberg.dealShares(n, t, seed)
        val caches = shares.map { Iceberg.shareCache(it) }
        val publicShares = shares.zip(caches).map { (share, cache) -> Iceberg.publicShare(share, cache) }
        // Key aggregation needs a quorum of 2t-1 public shares, not all n. Aggregating over the
        // quorum and over all n give the same key; IcebergSignerTestsCommon pins that, because the
        // group key ends up in the funding output and a disagreement would be unspendable.
        val groupPublicKey = Iceberg.groupPublicKey(publicShares.take(2 * t - 1), n, t).getOrElse { throw it }
        return IcebergGroup(n, t, groupPublicKey, shares, publicShares, caches)
    }

    /**
     * Round one's output. [publicNonce] is an ordinary MuSig2 public nonce, handed to the outer
     * session exactly like a real participant's; [contributions] are the group's internal per-member
     * nonces, which [roundTwo] needs -- every signer consumes the whole set.
     */
    data class RoundOneResult(val publicNonce: IndividualNonce, val contributions: List<NonceContribution>)

    /**
     * Round one: `2t-1` members each derive a nonce contribution from [sessionId], aggregated into
     * one ordinary MuSig2 public nonce. A pure function of [sessionId] -- which is what lets the
     * deterministic verification nonces be re-derived rather than stored.
     *
     * @param contributors 1-based member indices; at least `2t-1` of them.
     */
    fun roundOne(group: IcebergGroup, contributors: List<Int>, sessionId: ByteVector32): RoundOneResult {
        require(contributors.size >= group.quorum) { "round one needs ${group.quorum} (=2t-1) contributors, got ${contributors.size}" }
        require(contributors.all { it in 1..group.n }) { "member indices must be in [1, ${group.n}]" }
        require(contributors.distinct().size == contributors.size) { "duplicate member index in the contributor set" }
        val contributions = contributors.map { k -> Iceberg.generateNonce(group.shares[k - 1], group.caches[k - 1], sessionId) }
        val publicNonce = Iceberg.aggregateNonces(contributions, group.n, group.t, group.groupPublicKey).getOrElse { throw it }
        return RoundOneResult(publicNonce, contributions)
    }

    /**
     * Round two: `t` members each produce a signature share, combined into one ordinary MuSig2
     * partial signature ready for the outer session's `aggregateSigs`.
     *
     * @param signers 1-based member indices; at least `t`, and a SUBSET OF THE ROUND-ONE
     *                CONTRIBUTORS. The reference's port documents that a member absent from round
     *                one can still sign; nothing in bitcoin-kmp's suite exercises that, so this port
     *                does not rely on it. [IcebergFundingSigner] defaults keep the subset property.
     */
    fun roundTwo(
        group: IcebergGroup,
        signers: List<Int>,
        sessionId: ByteVector32,
        roundOneResult: RoundOneResult,
        keyAggCache: KeyAggCache,
        message: ByteVector32,
        cosignerAggregatedNonce: AggregatedNonce
    ): Either<Throwable, ChannelSpendSignature.PartialSignatureWithNonce> {
        require(signers.size >= group.t) { "round two needs ${group.t} signers, got ${signers.size}" }
        require(signers.all { it in 1..group.n }) { "member indices must be in [1, ${group.n}]" }
        require(signers.distinct().size == signers.size) { "duplicate member index in the signer set" }
        val shares = signers.map { k ->
            Iceberg.partialSign(group.shares[k - 1], group.caches[k - 1], sessionId, roundOneResult.contributions, group.groupPublicKey, keyAggCache, message, cosignerAggregatedNonce)
                .getOrElse { return Either.Left(it) }
        }
        return Iceberg.aggregatePartialSignatures(shares, group.n, group.t)
            .map { ChannelSpendSignature.PartialSignatureWithNonce(it, roundOneResult.publicNonce) }
    }

    /**
     * Builds the outer session's key aggregation cache. The public keys must be in the SAME ORDER
     * the outer session aggregates them ([Scripts.sort] order for channel funding outputs), and the
     * BIP341 key-path tweak must be applied identically, or the group's partial signature is
     * well-formed and simply does not combine with the cosigners'.
     */
    fun keyAggCacheFor(publicKeys: List<PublicKey>, tweak: ByteVector32?): Either<Throwable, KeyAggCache> {
        val (_, cache) = KeyAggCache.create(publicKeys)
        return when (tweak) {
            null -> Either.Right(cache)
            else -> cache.tweak(tweak, isXonly = true).map { it.first }
        }
    }

    /** Aggregate of the cosigners' public nonces alone -- what [roundTwo] consumes. */
    fun cosignerAggregatedNonce(publicNonces: List<IndividualNonce>): Either<Throwable, AggregatedNonce> =
        IndividualNonce.aggregate(publicNonces)
}

/**
 * A channel participant whose funding key is an Iceberg t-of-n group key, with no corresponding
 * private key anywhere. The group occupies ONE side of the channel's 2-of-2 MuSig2; the counterparty
 * is entirely stock and cannot tell the difference.
 *
 * THE SESSION MUST MATCH EXACTLY. lightning-kmp's taproot signing aggregates the two funding keys in
 * [Scripts.sort] order and then applies the BIP341 key-path tweak; a partial signature computed
 * under any other key order, or with no tweak at all, is well-formed and simply does not combine.
 * [Iceberg.keyAggregationCheck] is asserted on every signing call for exactly that reason -- it is
 * the one check the reference port could not make, and this is the failure class it catches.
 *
 * TAPROOT ONLY. An [Transactions.CommitmentFormat.AnchorOutputs] channel signs with ECDSA, which no
 * threshold signer here implements; those paths go through [privateKey] and fail loudly by name.
 *
 * @param contributors the `2t-1` members taking part in round one.
 * @param signers      the `t` members producing shares in round two; a subset of [contributors].
 */
class IcebergFundingSigner(
    val group: IcebergGroup,
    val contributors: List<Int> = (1..group.quorum).toList(),
    val signers: List<Int> = (1..group.t).toList()
) : FundingSigner {

    init {
        require(contributors.size >= group.quorum) { "contributors must be at least ${group.quorum} (=2t-1) members" }
        require(signers.size >= group.t) { "signers must be at least ${group.t} members" }
        require(contributors.containsAll(signers)) { "every round-two signer must have contributed to round one" }
    }

    override val publicKey: PublicKey = group.groupPublicKey
    override val privateKeyOrNull: PrivateKey? = null

    override fun verificationNonce(id: FundingSigner.VerificationNonceId): IndividualNonce =
        IcebergSigner.roundOne(group, contributors, verificationSessionId(id)).publicNonce

    override fun signWithVerificationNonce(
        tx: Transactions.ChannelSpendTransaction,
        remoteFundingPubKey: PublicKey,
        extraUtxos: Map<OutPoint, TxOut>,
        id: FundingSigner.VerificationNonceId,
        remoteNonce: IndividualNonce
    ): Either<Throwable, ChannelSpendSignature.PartialSignatureWithNonce> =
        sign(tx, remoteFundingPubKey, extraUtxos, verificationSessionId(id), remoteNonce)

    override fun signWithFreshNonce(
        tx: Transactions.ChannelSpendTransaction,
        remoteFundingPubKey: PublicKey,
        extraUtxos: Map<OutPoint, TxOut>,
        fundingTxId: TxId,
        remoteNonce: IndividualNonce
    ): Either<Throwable, ChannelSpendSignature.PartialSignatureWithNonce> =
        sign(tx, remoteFundingPubKey, extraUtxos, randomBytes32(), remoteNonce)

    override fun publishedNonceSession(fundingTxId: TxId, remoteFundingPubKey: PublicKey): FundingSigner.PublishedNonceSession {
        val sessionId = randomBytes32()
        return IcebergPublishedNonceSession(sessionId, IcebergSigner.roundOne(group, contributors, sessionId).publicNonce)
    }

    override fun signWithPublishedNonce(
        tx: Transactions.ChannelSpendTransaction,
        remoteFundingPubKey: PublicKey,
        extraUtxos: Map<OutPoint, TxOut>,
        session: FundingSigner.PublishedNonceSession,
        remoteNonce: IndividualNonce
    ): Either<Throwable, ChannelSpendSignature.PartialSignatureWithNonce> {
        require(session is IcebergPublishedNonceSession) { "published nonce session was not created by this signer" }
        // Round one is re-derived from the session label rather than stored: nonces are a function of
        // the label, so the label IS the session state. Callers must use each session at most once,
        // which both flows respect -- closing advances to a fresh session after every signature, and
        // each interactive-tx attempt (including each RBF attempt) builds its own.
        return sign(tx, remoteFundingPubKey, extraUtxos, session.sessionId, remoteNonce)
    }

    private fun sign(
        tx: Transactions.ChannelSpendTransaction,
        remoteFundingPubKey: PublicKey,
        extraUtxos: Map<OutPoint, TxOut>,
        sessionId: ByteVector32,
        remoteNonce: IndividualNonce
    ): Either<Throwable, ChannelSpendSignature.PartialSignatureWithNonce> = try {
        // Round one is a pure function of the session id, which is what makes the deterministic
        // verification-nonce case work: the same id re-derives the same nonce rather than needing the
        // secret part to have been kept across the gap.
        val roundOneResult = IcebergSigner.roundOne(group, contributors, sessionId)
        val message = tx.taprootSighash(extraUtxos)
        // The key aggregation cache must use the same key order and BIP341 tweak as the outer session
        // built by ChannelSpendTransaction.partialSign / aggregateSigs.
        val sortedKeys = Scripts.sort(listOf(publicKey, remoteFundingPubKey))
        val tweak = Scripts.Taproot.musig2Aggregate(publicKey, remoteFundingPubKey).tweak(Crypto.TaprootTweak.KeyPathTweak)
        IcebergSigner.cosignerAggregatedNonce(listOf(remoteNonce)).flatMap { cosignerAggnonce ->
            IcebergSigner.keyAggCacheFor(sortedKeys, tweak).flatMap { keyAggCache ->
                // The check the reference could not make: a cache over a different key set or order
                // produces a signature share that is well-formed and simply does not combine, which
                // is otherwise invisible until aggregation fails much later.
                if (!Iceberg.keyAggregationCheck(keyAggCache, sortedKeys, publicKey)) {
                    Either.Left(IllegalStateException("the key aggregation cache does not aggregate this group's key with $remoteFundingPubKey in Scripts.sort order"))
                } else {
                    IcebergSigner.roundTwo(group, signers, sessionId, roundOneResult, keyAggCache, message, cosignerAggnonce)
                }
            }
        }
    } catch (t: Throwable) {
        Either.Left(t)
    }

    private class IcebergPublishedNonceSession(val sessionId: ByteVector32, override val publicNonce: IndividualNonce) : FundingSigner.PublishedNonceSession()

    companion object {
        /**
         * Iceberg's session label is exactly 32 bytes and must never repeat, so the identity is
         * hashed rather than concatenated. It covers the SAME three things the private-key path's
         * nonce depends on -- funding txid, the peer's funding key, and the commit index -- so two
         * different identities can never derive the same session.
         */
        fun verificationSessionId(id: FundingSigner.VerificationNonceId): ByteVector32 {
            val indexBytes = ByteArray(8) { i -> (id.commitIndex ushr (56 - 8 * i)).toByte() }
            return Crypto.sha256(id.fundingTxId.value + id.remoteFundingPubKey.value + ByteVector(indexBytes)).byteVector32()
        }
    }
}
