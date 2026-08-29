package fr.acinq.lightning.crypto

import fr.acinq.bitcoin.ByteVector
import fr.acinq.bitcoin.ByteVector32
import fr.acinq.bitcoin.Crypto
import fr.acinq.bitcoin.OutPoint
import fr.acinq.bitcoin.PrivateKey
import fr.acinq.bitcoin.PublicKey
import fr.acinq.bitcoin.TxId
import fr.acinq.bitcoin.TxOut
import fr.acinq.bitcoin.XonlyPublicKey
import fr.acinq.bitcoin.crypto.musig2.IndividualNonce
import fr.acinq.bitcoin.crypto.musig2.KeyAggCache
import fr.acinq.bitcoin.utils.Either
import fr.acinq.bitcoin.utils.getOrElse
import fr.acinq.lightning.Lightning.randomBytes32
import fr.acinq.lightning.channel.ChannelSpendSignature
import fr.acinq.lightning.transactions.Scripts
import fr.acinq.lightning.transactions.Transactions
import fr.acinq.secp256k1.Iceberg
import fr.acinq.secp256k1.Secp256k1

/**
 * A group's key material, from a simulated Iceberg trusted-dealer keygen. [groupPubkey] is an
 * ordinary compressed public key that occupies ONE MuSig2 participant's slot; each of the [n]
 * members holds one [shares] entry (1-based member index k -> `shares[k - 1]`), with its matching
 * [pubshares] and precomputation [caches] at the same index.
 */
data class IcebergGroup(
    val n: Int,
    val t: Int,
    val groupPubkey: PublicKey,
    val shares: List<ByteArray>,
    val pubshares: List<ByteArray>,
    val caches: List<ByteArray>
) {
    /** Round one needs this many members online. Round two needs only [t]. */
    val quorum: Int = 2 * t - 1

    // Don't leak key material into logs.
    override fun toString(): String = "IcebergGroup(n=$n, t=$t, groupPubkey=$groupPubkey)"
}

/**
 * Local, in-process simulation of an Iceberg t-of-n threshold signer occupying ONE MuSig2
 * participant slot: all `n` members are simulated in this process, and the object presents their
 * combined output as a single participant's public nonce ([roundOne]) and partial signature
 * ([roundTwo]), shaped exactly as the channel's taproot signing seam expects. Backed by the Iceberg
 * C module, so these values are cryptographically valid and the resulting aggregate signature
 * verifies.
 *
 * Port of the eclair fork's `IcebergSigner.scala`. As there, three properties of the C API
 * constrain the call sites:
 *
 *  - [roundTwo] takes the OUTER session's real key aggregation cache and the cosigner's real
 *    aggregate nonce; a fabricated pair produces a partial signature that cannot aggregate, so
 *    building them correctly is the caller's job -- [keyaggCacheFor] and [cosignerAggnonce] are
 *    provided for it.
 *  - The two rounds have different quorums: round one needs `2t-1` contributors, round two
 *    aggregates `t` signature shares.
 *  - SESSION LABELS MUST BE UNIQUE. Iceberg derives nonces from `sid` rather than storing them, so
 *    a label used twice across the group is a key-leaking path that raises no error.
 */
object IcebergSigner {

    /**
     * Simulated trusted-dealer keygen. For the duration of this call one process holds enough to
     * reconstruct the group's private key, which is exactly what a threshold scheme exists to
     * avoid -- fine for a benchmark, not a deployment. Nothing downstream depends on how a share
     * was produced, so a share from a real DKG would be used identically.
     *
     * `t` must satisfy `1 <= t <= (n+1)/2` and `n <= 10`; violating that ABORTS THE JVM in the C
     * module, so [Iceberg.requireConfig] checks first. Note that 2-of-2 and 3-of-4 are NOT
     * expressible.
     */
    fun keygen(n: Int, t: Int, seed32: ByteArray): IcebergGroup {
        Iceberg.requireConfig(n, t)
        val shares = Iceberg.sharesGen(n, t, seed32).toList()
        val caches = shares.map { Iceberg.shareCacheCreate(it) }
        val pubshares = shares.zip(caches).map { (s, c) -> Iceberg.pubshareGen(s, c) }
        // pubkey_agg needs a quorum of 2t-1 pubshares, not all n.
        val groupPubkey = Iceberg.pubkeyAgg(pubshares.take(2 * t - 1).toTypedArray(), n, t)
        return IcebergGroup(n, t, PublicKey(groupPubkey), shares, pubshares, caches)
    }

    /**
     * Round one output. [publicNonce] is an ordinary MuSig2 public nonce, handed to the outer
     * session exactly like a real participant's; [contributions] are the group's internal
     * per-member nonces, which [roundTwo] needs (every signer consumes the whole set).
     */
    data class RoundOneResult(val publicNonce: IndividualNonce, val contributions: List<ByteArray>)

    /**
     * Round one: `2t-1` members each derive a nonce contribution from [sid], aggregated into one
     * ordinary MuSig2 public nonce.
     *
     * @param contributors 1-based member indices; at least `2t-1` of them.
     */
    fun roundOne(group: IcebergGroup, contributors: List<Int>, sid: ByteArray): RoundOneResult {
        require(contributors.size >= group.quorum) { "round one needs ${group.quorum} (=2t-1) contributors, got ${contributors.size}" }
        require(contributors.all { it in 1..group.n }) { "member indices must be in [1, ${group.n}]" }
        require(contributors.distinct().size == contributors.size) { "duplicate member index in the contributor set" }
        val contributions = contributors.map { k -> Iceberg.nonceGen(group.shares[k - 1], sid, group.caches[k - 1]) }
        val groupNonce = Iceberg.nonceAgg(contributions.toTypedArray(), group.n, group.t, group.groupPubkey.value.toByteArray())
        return RoundOneResult(IndividualNonce(groupNonce), contributions)
    }

    /**
     * Round two: `t` members each produce a signature share, combined into one ordinary MuSig2
     * partial signature ready for the outer session's `aggregateSigs`.
     *
     * @param signers          1-based member indices; at least `t`. They need not be the round-one
     *                         contributors -- a member that was offline for round one can still sign.
     * @param keyaggCache      the OUTER session's key aggregation cache, including the BIP341
     *                         key-path tweak. Must be the real one; see [keyaggCacheFor].
     * @param cosignerAggnonce the aggregate of the COSIGNERS' public nonces alone (not including
     *                         this group's); see [cosignerAggnonce].
     */
    fun roundTwo(
        group: IcebergGroup,
        signers: List<Int>,
        sid: ByteArray,
        roundOneResult: RoundOneResult,
        keyaggCache: ByteArray,
        msg32: ByteArray,
        cosignerAggnonce: ByteArray
    ): ChannelSpendSignature.PartialSignatureWithNonce {
        require(signers.size >= group.t) { "round two needs ${group.t} signers, got ${signers.size}" }
        require(signers.all { it in 1..group.n }) { "member indices must be in [1, ${group.n}]" }
        require(signers.distinct().size == signers.size) { "duplicate member index in the signer set" }
        val contributions = roundOneResult.contributions.toTypedArray()
        val partials = signers.map { k ->
            Iceberg.partialSign(group.shares[k - 1], sid, contributions, group.n, group.t, group.groupPubkey.value.toByteArray(), keyaggCache, msg32, cosignerAggnonce, group.caches[k - 1])
        }.toTypedArray()
        val groupPartial = Iceberg.partialSigAgg(partials, group.n, group.t)
        return ChannelSpendSignature.PartialSignatureWithNonce(ByteVector32(groupPartial), roundOneResult.publicNonce)
    }

    /**
     * Builds the outer session's key aggregation cache. The public keys must be in the SAME ORDER
     * the outer session aggregates them ([Scripts.sort] order for channel funding outputs), and the
     * BIP341 key-path tweak must be applied identically, or the group's partial signature will not
     * combine with the cosigners'.
     *
     * @return the cache (197 bytes) and the aggregate x-only public key.
     */
    fun keyaggCacheFor(pubkeys: List<PublicKey>, tweak: ByteArray?): Pair<ByteArray, XonlyPublicKey> {
        val (aggregateKey, cache) = KeyAggCache.create(pubkeys)
        return when (tweak) {
            null -> Pair(cache.toByteArray(), aggregateKey)
            else -> {
                val tweaked = cache.tweak(ByteVector32(tweak), isXonly = true).getOrElse { throw it }
                Pair(tweaked.first.toByteArray(), tweaked.second.xOnly())
            }
        }
    }

    /** Aggregate of the cosigners' public nonces alone -- what [roundTwo] consumes. */
    fun cosignerAggnonce(pubnonces: List<IndividualNonce>): ByteArray =
        Secp256k1.musigNonceAgg(pubnonces.map { it.toByteArray() }.toTypedArray())
}

/**
 * A channel participant whose funding key is an Iceberg t-of-n group key, with no corresponding
 * private key anywhere. The group occupies ONE side of the channel's 2-of-2 MuSig2; the
 * counterparty is entirely stock and cannot tell the difference.
 *
 * JVM-only: the Iceberg API is backed by JNI and deliberately does not exist on the other KMP
 * targets, so this class lives in jvmMain while the [FundingSigner] seam it implements is in
 * commonMain.
 *
 * THE SESSION MUST MATCH EXACTLY. lightning-kmp's taproot signing aggregates the two funding keys
 * in [Scripts.sort] order and then applies the BIP341 key-path tweak; a partial signature computed
 * under any other key order, or with no tweak at all, is well-formed and simply does not combine.
 * IcebergTaprootSessionSpec pins this down end to end.
 *
 * @param contributors the `2t-1` members taking part in round one; [signers] are the `t` members
 *                     producing shares in round two.
 */
class IcebergFundingSigner(
    val group: IcebergGroup,
    val contributors: List<Int> = (1..group.quorum).toList(),
    val signers: List<Int> = (1..group.t).toList()
) : FundingSigner {

    init {
        require(contributors.size >= group.quorum) { "contributors must be at least ${group.quorum} (=2t-1) members" }
        require(signers.size >= group.t) { "signers must be at least ${group.t} members" }
    }

    override val publicKey: PublicKey = group.groupPubkey
    override val privateKeyOrNull: PrivateKey? = null

    override fun verificationNonce(id: FundingSigner.VerificationNonceId): IndividualNonce =
        IcebergSigner.roundOne(group, contributors, verificationSid(id)).publicNonce

    override fun signWithVerificationNonce(
        tx: Transactions.ChannelSpendTransaction,
        remoteFundingPubKey: PublicKey,
        extraUtxos: Map<OutPoint, TxOut>,
        id: FundingSigner.VerificationNonceId,
        remoteNonce: IndividualNonce
    ): Either<Throwable, ChannelSpendSignature.PartialSignatureWithNonce> =
        sign(tx, remoteFundingPubKey, extraUtxos, verificationSid(id), remoteNonce)

    override fun signWithFreshNonce(
        tx: Transactions.ChannelSpendTransaction,
        remoteFundingPubKey: PublicKey,
        extraUtxos: Map<OutPoint, TxOut>,
        fundingTxId: TxId,
        remoteNonce: IndividualNonce
    ): Either<Throwable, ChannelSpendSignature.PartialSignatureWithNonce> =
        sign(tx, remoteFundingPubKey, extraUtxos, randomBytes32().toByteArray(), remoteNonce)

    override fun closeeNonce(fundingTxId: TxId, remoteFundingPubKey: PublicKey): FundingSigner.CloseeNonceSession {
        val sid = randomBytes32().toByteArray()
        return IcebergCloseeNonceSession(sid, IcebergSigner.roundOne(group, contributors, sid).publicNonce)
    }

    override fun signWithCloseeNonce(
        tx: Transactions.ChannelSpendTransaction,
        remoteFundingPubKey: PublicKey,
        extraUtxos: Map<OutPoint, TxOut>,
        session: FundingSigner.CloseeNonceSession,
        remoteNonce: IndividualNonce
    ): Either<Throwable, ChannelSpendSignature.PartialSignatureWithNonce> {
        require(session is IcebergCloseeNonceSession) { "closee nonce session was not created by this signer" }
        // Round one is re-derived from the session label rather than stored: the C module derives
        // nonces from the sid, so the label IS the session state. Callers must use each session at
        // most once (the closing flow does: it advances to a fresh session after every signature).
        return sign(tx, remoteFundingPubKey, extraUtxos, session.sid, remoteNonce)
    }

    private fun sign(
        tx: Transactions.ChannelSpendTransaction,
        remoteFundingPubKey: PublicKey,
        extraUtxos: Map<OutPoint, TxOut>,
        sid: ByteArray,
        remoteNonce: IndividualNonce
    ): Either<Throwable, ChannelSpendSignature.PartialSignatureWithNonce> = try {
        // Round one is a pure function of `sid`, which is what makes the deterministic
        // verification-nonce case work: the same sid re-derives the same nonce rather than needing
        // the secret part to have been kept.
        val roundOneResult = IcebergSigner.roundOne(group, contributors, sid)
        val msg32 = tx.taprootSighash(extraUtxos).toByteArray()
        val cosignerAggnonce = IcebergSigner.cosignerAggnonce(listOf(remoteNonce))
        // The key aggregation cache must use the same key order and BIP341 tweak as the outer
        // session built by lightning-kmp's ChannelSpendTransaction.partialSign / aggregateSigs.
        val sortedKeys = Scripts.sort(listOf(publicKey, remoteFundingPubKey))
        val tweak = Scripts.Taproot.musig2Aggregate(publicKey, remoteFundingPubKey).tweak(Crypto.TaprootTweak.KeyPathTweak)
        val (keyaggCache, _) = IcebergSigner.keyaggCacheFor(sortedKeys, tweak.toByteArray())
        Either.Right(IcebergSigner.roundTwo(group, signers, sid, roundOneResult, keyaggCache, msg32, cosignerAggnonce))
    } catch (t: Throwable) {
        Either.Left(t)
    }

    private class IcebergCloseeNonceSession(val sid: ByteArray, override val publicNonce: IndividualNonce) : FundingSigner.CloseeNonceSession()

    companion object {
        /**
         * Iceberg's session label is exactly 32 bytes and must never repeat, so the identity is
         * hashed rather than concatenated. It covers the SAME three things the private-key path's
         * nonce depends on -- funding txid, the peer's funding key, and the commit index -- so two
         * different identities can never derive the same session.
         */
        fun verificationSid(id: FundingSigner.VerificationNonceId): ByteArray {
            val indexBytes = ByteArray(8) { i -> (id.commitIndex ushr (56 - 8 * i)).toByte() }
            return Crypto.sha256(id.fundingTxId.value + id.remoteFundingPubKey.value + ByteVector(indexBytes))
        }
    }
}
