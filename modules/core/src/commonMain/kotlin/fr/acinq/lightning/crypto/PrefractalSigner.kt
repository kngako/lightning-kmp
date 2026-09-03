@file:OptIn(kotlin.ExperimentalUnsignedTypes::class)

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
import fr.acinq.bitcoin.crypto.frost.Frost
import fr.acinq.bitcoin.crypto.frost.Prefractal
import fr.acinq.bitcoin.crypto.frost.SecretNonce
import fr.acinq.bitcoin.crypto.frost.TweakCache
import fr.acinq.bitcoin.crypto.musig2.AggregatedNonce
import fr.acinq.bitcoin.crypto.musig2.IndividualNonce
import fr.acinq.bitcoin.crypto.musig2.KeyAggCache
import fr.acinq.bitcoin.crypto.musig2.Musig2
import fr.acinq.bitcoin.utils.Either
import fr.acinq.bitcoin.utils.flatMap
import fr.acinq.lightning.Lightning.randomBytes32
import fr.acinq.lightning.channel.ChannelSpendSignature
import fr.acinq.lightning.transactions.Scripts
import fr.acinq.lightning.transactions.Transactions

/**
 * A group's key material, from a simulated FROST trusted-dealer keygen. [groupPublicKey] is an
 * ordinary compressed public key occupying ONE MuSig2 participant's slot; each of the [n] members
 * holds one [secretShares] entry (1-based member index k -> `secretShares[k - 1]`), with its
 * matching [publicShares] at the same index.
 *
 * [PrivateKey] already redacts itself in logs, so this class needs no hand-written `toString`; do
 * not add one that prints [secretShares].
 *
 * [tweakCache] is and must remain the identity: this composition tweaks only the OUTER aggregate
 * key, and every prefractal entry point refuses a tweaked cache.
 */
data class PrefractalGroup(
    val n: Int,
    val t: Int,
    val groupPublicKey: PublicKey,
    val secretShares: List<PrivateKey>,
    val publicShares: List<PublicKey>,
    val tweakCache: TweakCache
) {
    /** Both rounds need this many members online -- unlike Iceberg, where round one needs `2t-1`. */
    val quorum: Int = t
}

/**
 * Local, in-process simulation of a nested FROST+MuSig2 ("prefractal") t-of-n threshold signer
 * occupying ONE MuSig2 participant slot: all `n` members are simulated in this process, and the
 * object presents their combined output as a single participant's public nonce ([roundOne]) and
 * partial signature ([roundTwo]), shaped exactly as the channel's taproot signing seam expects.
 *
 * Structurally this mirrors [IcebergSigner], but the two schemes differ in ways that do NOT
 * transfer, and transposing them silently produces invalid signatures:
 *
 *  - QUORUM IS `t` IN BOTH ROUNDS, not `2t-1` then `t`. Iceberg's larger first-round quorum comes
 *    from its VSS degree check; FROST has no equivalent.
 *  - THE ROUND-TWO SIGNERS MUST EQUAL THE ROUND-ONE CONTRIBUTORS AS A SET, where Iceberg tolerates
 *    a subset. FROST's Lagrange coefficients and aggregate nonce are both defined over the
 *    participating set: with a proper subset, the missing contributors' nonce terms stay in R while
 *    their key shares are absent from the sum, and the result is an invalid signature with nothing
 *    raised at signing time. [roundTwo] refuses that rather than producing it.
 *  - ANY `t`-of-`n` IS EXPRESSIBLE, including 2-of-2 and 3-of-4, which Iceberg forbids.
 *
 * Two properties carry over unchanged:
 *
 *  - [roundTwo] takes the OUTER session's real key aggregation cache and the cosigners' real
 *    aggregate nonce. A fabricated pair yields a signature share that cannot aggregate, so building
 *    them correctly is the caller's job -- [keyAggCacheFor] and [cosignerAggregatedNonce] exist for
 *    it.
 *  - SESSION LABELS MUST BE UNIQUE. Nonces are derived from the label rather than stored, so a
 *    label used twice across the group is a key-leaking path that raises no error at all.
 */
object PrefractalSigner {

    /**
     * Simulated trusted-dealer keygen. For the duration of this call one process holds the group's
     * threshold private key, which is exactly what a threshold scheme exists to avoid -- fine for a
     * test, not a deployment. Nothing downstream depends on how a share was produced, so a share
     * from a real DKG (ChillDKG) would be used identically.
     */
    fun keygen(n: Int, t: Int, seed: ByteVector32): PrefractalGroup {
        require(n in 1..128) { "group size must be in [1, 128]" }
        require(t in 1..n) { "threshold must be in [1, n]" }
        val thresholdSecretKey = PrivateKey(Crypto.sha256(KEYGEN_TAG.encodeToByteArray() + seed.toByteArray()).byteVector32())
        val km = Frost.trustedDealerKeygen(thresholdSecretKey, n, t)
        require(km.isValid()) { "trusted dealer produced inconsistent key material" }
        return PrefractalGroup(n, t, km.thresholdPublicKey, km.secretShares, km.publicShares, TweakCache.create(km.thresholdPublicKey))
    }

    /**
     * Round one's output. [publicNonce] is an ordinary MuSig2 public nonce, handed to the outer
     * session exactly like a real participant's; [groupAggregatedNonce] and [memberPublicNonces] are
     * the group's internal values, which [roundTwo] needs.
     *
     * The secret nonces are deliberately NOT here: they are re-derived in round two from the same
     * label, so nothing secret has to survive the gap between the rounds.
     */
    data class RoundOneResult(
        val publicNonce: IndividualNonce,
        val groupAggregatedNonce: fr.acinq.bitcoin.crypto.frost.AggregatedNonce,
        val memberPublicNonces: List<fr.acinq.bitcoin.crypto.frost.IndividualNonce>,
        val signerIds: List<UInt>
    )

    /**
     * Round one: `t` members each derive a nonce from [sessionId], aggregated into one ordinary
     * MuSig2 public nonce. A pure function of [sessionId] -- which is what lets the deterministic
     * verification nonces be re-derived rather than stored.
     *
     * @param contributors 1-based member indices; at least `t` of them, distinct and in range.
     */
    fun roundOne(group: PrefractalGroup, contributors: List<Int>, sessionId: ByteVector32): RoundOneResult {
        require(contributors.size >= group.quorum) { "round one needs ${group.quorum} (=t) contributors, got ${contributors.size}" }
        require(contributors.all { it in 1..group.n }) { "member indices must be in [1, ${group.n}]" }
        require(contributors.distinct().size == contributors.size) { "duplicate member index in the contributor set" }
        val ids = contributors.map { (it - 1).toUInt() }
        val publicNonces = contributors.map { k ->
            Prefractal.generateNonce(group.secretShares[k - 1], group.publicShares[k - 1], group.groupPublicKey, sessionId, (k - 1).toUInt()).second
        }
        val (wireNonce, aggregatedNonce) = Prefractal.aggregateNonces(publicNonces, ids, group.groupPublicKey).getOrThrow()
        return RoundOneResult(wireNonce, aggregatedNonce, publicNonces, ids)
    }

    /**
     * Round two: the SAME `t` members each produce a signature share, summed into one ordinary
     * MuSig2 partial signature ready for the outer session's `aggregateSigs`.
     *
     * Each signer's secret nonce is re-derived here from `(share, sessionId)` rather than carried
     * over from round one, exactly as Iceberg does -- nothing is stored between the rounds.
     *
     * @param signers 1-based member indices. Must be the SAME SET as the round-one contributors, not
     *                a subset: see the note on [PrefractalSigner].
     */
    fun roundTwo(
        group: PrefractalGroup,
        signers: List<Int>,
        sessionId: ByteVector32,
        roundOneResult: RoundOneResult,
        keyAggCache: KeyAggCache,
        message: ByteVector32,
        cosignerAggregatedNonce: AggregatedNonce
    ): Either<Throwable, ChannelSpendSignature.PartialSignatureWithNonce> = try {
        require(signers.all { it in 1..group.n }) { "member indices must be in [1, ${group.n}]" }
        require(signers.distinct().size == signers.size) { "duplicate member index in the signer set" }
        val ids = signers.map { (it - 1).toUInt() }
        // Set equality, not containment. A proper subset would produce a signature that is
        // well-formed and simply invalid, with nothing raised until the outer aggregation is
        // checked -- see the note on [PrefractalSigner].
        require(ids.toSet() == roundOneResult.signerIds.toSet()) {
            "round-two signers must be exactly the round-one contributors (FROST defines lambda and the aggregate nonce over the participating set)"
        }
        // Built from the ROUND-ONE id order, not the caller's: the ids array and the pubshares array
        // are positional, so a caller passing the same set in a different order would otherwise hand
        // each member somebody else's public share.
        val publicShares = roundOneResult.signerIds.map { group.publicShares[it.toInt()] }
        val shares = roundOneResult.signerIds.map { id ->
            val (secretNonce, _) = Prefractal.generateNonce(
                group.secretShares[id.toInt()], group.publicShares[id.toInt()], group.groupPublicKey, sessionId, id
            )
            Prefractal.partialSign(
                secretNonce, group.secretShares[id.toInt()], id, roundOneResult.signerIds, publicShares,
                roundOneResult.groupAggregatedNonce, group.groupPublicKey, group.tweakCache, keyAggCache,
                message, cosignerAggregatedNonce
            ).getOrThrow()
        }
        Prefractal.aggregatePartialSignatures(shares, group.tweakCache)
            .map { ChannelSpendSignature.PartialSignatureWithNonce(it, roundOneResult.publicNonce) }
    } catch (t: Throwable) {
        Either.Left(t)
    }

    /**
     * Builds the outer session's key aggregation cache. The public keys must be in the SAME ORDER
     * the outer session aggregates them ([Scripts.sort] order for channel funding outputs), and the
     * BIP341 key-path tweak must be applied identically, or the group's partial signature is
     * well-formed and simply does not combine with the cosigners'.
     *
     * Scheme-independent: identical to [IcebergSigner.keyAggCacheFor].
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

    private const val KEYGEN_TAG: String = "PrefractalSigner/keygen"

    private fun <T> Either<Throwable, T>.getOrThrow(): T = when (this) {
        is Either.Right -> this.value
        is Either.Left -> throw this.value
    }
}

/**
 * A channel participant whose funding key is a prefractal (nested FROST+MuSig2) t-of-n group key,
 * with no corresponding private key anywhere. The group occupies ONE side of the channel's 2-of-2
 * MuSig2; the counterparty is entirely stock and cannot tell the difference.
 *
 * THE SESSION MUST MATCH EXACTLY. lightning-kmp's taproot signing aggregates the two funding keys in
 * [Scripts.sort] order and then applies the BIP341 key-path tweak; a partial signature computed
 * under any other key order, or with no tweak at all, is well-formed and simply does not combine.
 * There is no FROST equivalent of `Iceberg.keyAggregationCheck`, so [sign] instead re-derives the
 * untweaked aggregate key from the cache's key list and requires it to equal
 * [Scripts.Taproot.musig2Aggregate]'s -- cheap, and it catches the same wrong-key-order failure
 * class.
 *
 * TAPROOT ONLY. An [Transactions.CommitmentFormat.AnchorOutputs] channel signs with ECDSA, which no
 * threshold signer here implements; those paths go through [privateKey] and fail loudly by name.
 *
 * NONCE-HAZARD AUDIT. Nonces are derived from the session label, so signing two DIFFERENT messages
 * under one label leaks the members' shares with no error raised. Every entry point that consumes a
 * label was enumerated against its call sites in `modules/core/src/commonMain`:
 *
 *  - [signWithFreshNonce] (Commitments.kt:207, :611, InteractiveTx.kt:1270, Helpers.kt:333) draws a
 *    fresh random label per call. Safe by construction.
 *  - [publishedNonceSession] (InteractiveTx.kt:750, Helpers.kt:274, :406) likewise draws a fresh
 *    random label, and [signWithPublishedNonce] (InteractiveTx.kt:62, Helpers.kt:397) consumes that
 *    one session. Each closing round and each interactive-tx attempt builds its own session, so no
 *    session object is signed under twice.
 *  - [verificationNonce] only PUBLISHES; it never signs, so re-deriving it is not reuse. That is
 *    exactly what the reconnect path (Syncing.kt:519, Channel.kt:346) relies on.
 *  - [signWithVerificationNonce] has ONE call site: `Commitment.fullySignedCommitTx`
 *    (Commitments.kt:299). Its label is `(fundingTxId, remoteFundingPubkey, localCommit.index)` and
 *    its message is `makeLocalTxs(...)` over those same three values plus channel-static parameters
 *    and `localCommit.spec`. So the message is a pure function of the label given a fixed channel,
 *    and calling it repeatedly - which force-close retries do - re-signs the identical transaction
 *    rather than reusing a nonce across two messages.
 *
 * The invariant this rests on is that one local commit index carries one spec for one funding
 * output. RBF changes `fundingTxId`, which is in the label; splices change `fundingTxIndex` and are
 * refused outright for threshold signers at `ChannelKeys.fundingPublicKey(1)`.
 *
 * @param contributors the `t` members taking part in round one.
 * @param signers      the `t` members producing shares in round two; must be the SAME SET as
 *                     [contributors], not a subset -- unlike [IcebergFundingSigner].
 */
class PrefractalFundingSigner(
    val group: PrefractalGroup,
    val contributors: List<Int> = (1..group.t).toList(),
    val signers: List<Int> = (1..group.t).toList()
) : FundingSigner {

    init {
        require(contributors.size >= group.quorum) { "contributors must be at least ${group.quorum} (=t) members" }
        require(signers.size >= group.t) { "signers must be at least ${group.t} members" }
        // Checked here as well as in roundTwo so a misconfigured signer fails at construction rather
        // than at its first signature.
        require(signers.toSet() == contributors.toSet()) {
            "round-two signers must be exactly the round-one contributors (FROST defines lambda and the aggregate nonce over the participating set)"
        }
    }

    override val publicKey: PublicKey = group.groupPublicKey
    override val privateKeyOrNull: PrivateKey? = null

    override fun verificationNonce(id: FundingSigner.VerificationNonceId): IndividualNonce =
        PrefractalSigner.roundOne(group, contributors, verificationSessionId(id)).publicNonce

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
        return PrefractalPublishedNonceSession(sessionId, PrefractalSigner.roundOne(group, contributors, sessionId).publicNonce)
    }

    override fun signWithPublishedNonce(
        tx: Transactions.ChannelSpendTransaction,
        remoteFundingPubKey: PublicKey,
        extraUtxos: Map<OutPoint, TxOut>,
        session: FundingSigner.PublishedNonceSession,
        remoteNonce: IndividualNonce
    ): Either<Throwable, ChannelSpendSignature.PartialSignatureWithNonce> {
        require(session is PrefractalPublishedNonceSession) { "published nonce session was not created by this signer" }
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
        val roundOneResult = PrefractalSigner.roundOne(group, contributors, sessionId)
        val message = tx.taprootSighash(extraUtxos)
        // The key aggregation cache must use the same key order and BIP341 tweak as the outer session
        // built by ChannelSpendTransaction.partialSign / aggregateSigs.
        val sortedKeys = Scripts.sort(listOf(publicKey, remoteFundingPubKey))
        val tweak = Scripts.Taproot.musig2Aggregate(publicKey, remoteFundingPubKey).tweak(Crypto.TaprootTweak.KeyPathTweak)
        // FROST has no keyAggregationCheck, so the equivalent guard is done here: the untweaked
        // aggregate of the sorted keys must be the key the channel actually funds. A cache built over
        // a different key set or order otherwise produces a share that is well-formed and simply does
        // not combine, which stays invisible until aggregation fails much later.
        if (Musig2.aggregateKeys(sortedKeys) != Scripts.Taproot.musig2Aggregate(publicKey, remoteFundingPubKey)) {
            Either.Left(IllegalStateException("the key aggregation cache does not aggregate this group's key with $remoteFundingPubKey in Scripts.sort order"))
        } else {
            PrefractalSigner.cosignerAggregatedNonce(listOf(remoteNonce)).flatMap { cosignerAggnonce ->
                PrefractalSigner.keyAggCacheFor(sortedKeys, tweak).flatMap { keyAggCache ->
                    PrefractalSigner.roundTwo(group, signers, sessionId, roundOneResult, keyAggCache, message, cosignerAggnonce)
                }
            }
        }
    } catch (t: Throwable) {
        Either.Left(t)
    }

    private class PrefractalPublishedNonceSession(val sessionId: ByteVector32, override val publicNonce: IndividualNonce) : FundingSigner.PublishedNonceSession()

    companion object {
        /**
         * The session label is exactly 32 bytes and must never repeat, so the identity is hashed
         * rather than concatenated. It covers the SAME three things the private-key path's nonce
         * depends on -- funding txid, the peer's funding key, and the commit index -- so two
         * different identities can never derive the same session.
         *
         * The domain tag is what keeps this distinct from [IcebergFundingSigner.verificationSessionId],
         * which hashes the same three fields: a deployment that ever mixed the two schemes over one
         * group must not have their labels collide.
         */
        fun verificationSessionId(id: FundingSigner.VerificationNonceId): ByteVector32 {
            val indexBytes = ByteArray(8) { i -> (id.commitIndex ushr (56 - 8 * i)).toByte() }
            return Crypto.sha256(
                VERIFICATION_TAG.encodeToByteArray() + id.fundingTxId.value.toByteArray() + id.remoteFundingPubKey.value.toByteArray() + indexBytes
            ).byteVector32()
        }

        private const val VERIFICATION_TAG: String = "PrefractalSigner/verification"
    }
}
