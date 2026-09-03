package fr.acinq.lightning.crypto

import fr.acinq.bitcoin.TxId
import fr.acinq.bitcoin.crypto.iceberg.Iceberg
import fr.acinq.bitcoin.crypto.musig2.KeyAggCache
import fr.acinq.bitcoin.utils.getOrElse
import fr.acinq.bitcoin.Crypto
import fr.acinq.lightning.Lightning.randomBytes32
import fr.acinq.lightning.Lightning.randomKey
import fr.acinq.lightning.tests.utils.LightningTestSuite
import fr.acinq.lightning.transactions.Scripts
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNotEquals
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * The properties [IcebergSigner] and [IcebergFundingSigner] rest on, stated as assertions rather
 * than as comments. Everything here is about the scheme's contract with its caller; the end-to-end
 * proof that a group signature actually spends a funding output is
 * [IcebergTaprootSessionTestsCommon].
 */
class IcebergSignerTestsCommon : LightningTestSuite() {

    @Test
    fun `the group key over a 2t-1 quorum equals the one over all n`() {
        // keygen aggregates over the quorum, not all n. The group key ends up in the funding output,
        // so if the two disagreed the channel would be unspendable by whoever aggregated differently.
        for ((t, n) in listOf(2 to 4, 3 to 7, 2 to 10)) {
            val shares = Iceberg.dealShares(n, t, randomBytes32())
            val caches = shares.map { Iceberg.shareCache(it) }
            val publicShares = shares.mapIndexed { i, s -> Iceberg.publicShare(s, caches[i]) }
            val overAll = Iceberg.groupPublicKey(publicShares, n, t).getOrElse { throw it }
            val overQuorum = Iceberg.groupPublicKey(publicShares.take(2 * t - 1), n, t).getOrElse { throw it }
            assertEquals(overAll, overQuorum, "group key disagrees between a $t-of-$n quorum and all n")
        }
    }

    @Test
    fun `round one is a pure function of the session label`() {
        // The property the whole deterministic verification-nonce design rests on: round one is
        // re-derived at signing time rather than stored, so the same label must give the same nonce
        // after a restart, and two labels must never give the same one.
        val group = IcebergSigner.keygen(4, 2, randomBytes32())
        val contributors = (1..group.quorum).toList()
        val sessionId = randomBytes32()
        assertEquals(
            IcebergSigner.roundOne(group, contributors, sessionId).publicNonce,
            IcebergSigner.roundOne(group, contributors, sessionId).publicNonce
        )
        assertNotEquals(
            IcebergSigner.roundOne(group, contributors, sessionId).publicNonce,
            IcebergSigner.roundOne(group, contributors, randomBytes32()).publicNonce
        )
    }

    @Test
    fun `an illegal group configuration throws instead of aborting the process`() {
        // The reference port needed Iceberg.requireConfig because a bad (n, t) ABORTS THE PROCESS
        // inside its C module. Here Secp256k1Jni/Secp256k1Native validate before entering C, so
        // there is nothing to check first and an illegal configuration is an ordinary exception.
        assertFailsWith<IllegalArgumentException> { IcebergSigner.keygen(2, 2, randomBytes32()) }  // 2-of-2 inexpressible
        assertFailsWith<IllegalArgumentException> { IcebergSigner.keygen(4, 3, randomBytes32()) }  // 3-of-4 inexpressible
        assertFailsWith<IllegalArgumentException> { IcebergSigner.keygen(11, 2, randomBytes32()) } // n <= 10
        // 2-of-4 is the smallest usable group.
        assertEquals(3, IcebergSigner.keygen(4, 2, randomBytes32()).quorum)
    }

    @Test
    fun `reusing a session label under two messages raises no error`() {
        // Documents the hazard rather than a behaviour. Two signature shares under one label are both
        // well-formed and nothing complains, which is why the label is derived from a
        // VerificationNonceId and why a PublishedNonceSession is never signed with twice.
        val group = IcebergSigner.keygen(4, 2, randomBytes32())
        val cosigner = randomKey().publicKey()
        val sorted = Scripts.sort(listOf(group.groupPublicKey, cosigner))
        val cache = IcebergSigner.keyAggCacheFor(sorted, null).getOrElse { throw it }
        val sessionId = randomBytes32()
        val r1 = IcebergSigner.roundOne(group, (1..group.quorum).toList(), sessionId)
        val cosignerAggnonce = IcebergSigner.cosignerAggregatedNonce(listOf(r1.publicNonce)).getOrElse { throw it }
        val first = IcebergSigner.roundTwo(group, (1..group.t).toList(), sessionId, r1, cache, randomBytes32(), cosignerAggnonce)
        val second = IcebergSigner.roundTwo(group, (1..group.t).toList(), sessionId, r1, cache, randomBytes32(), cosignerAggnonce)
        assertTrue(first.isRight && second.isRight)
        assertNotEquals(first.right, second.right)
    }

    @Test
    fun `keyAggregationCheck catches a wrong key order but NOT a missing tweak`() {
        // The boundary of the one check the reference port could not make. It validates the key set
        // and its order; it passes on tweaked and untweaked caches alike. That is why
        // IcebergTaprootSessionTestsCommon exists and why its untweaked negative control is not
        // optional -- this check would never catch that bug.
        val group = IcebergSigner.keygen(4, 2, randomBytes32())
        val cosigner = randomKey().publicKey()
        val sorted = Scripts.sort(listOf(group.groupPublicKey, cosigner))
        val untweaked = IcebergSigner.keyAggCacheFor(sorted, null).getOrElse { throw it }
        val tweak = Scripts.Taproot.musig2Aggregate(group.groupPublicKey, cosigner).tweak(Crypto.TaprootTweak.KeyPathTweak)
        val tweaked = IcebergSigner.keyAggCacheFor(sorted, tweak).getOrElse { throw it }

        assertTrue(Iceberg.keyAggregationCheck(untweaked, sorted, group.groupPublicKey))
        assertTrue(Iceberg.keyAggregationCheck(tweaked, sorted, group.groupPublicKey), "the tweak must not invalidate the check -- the signer runs it on the tweaked cache")
        // What it does catch:
        assertFalse(Iceberg.keyAggregationCheck(tweaked, sorted.reversed(), group.groupPublicKey), "a reversed key order must be caught")
        assertFalse(Iceberg.keyAggregationCheck(tweaked, sorted, randomKey().publicKey()), "a key that is not the group's must be caught")
    }

    @Test
    fun `round two signers must be a subset of the round one contributors`() {
        // bitcoin-kmp's own suite only ever signs with round-one contributors, so the reference's
        // claim that an absent member can still sign is untested. This port does not rely on it.
        val group = IcebergSigner.keygen(7, 3, randomBytes32())
        assertEquals(5, group.quorum)
        // The defaults keep the property: signers (1..t) are the first t of contributors (1..2t-1).
        val signer = IcebergFundingSigner(group)
        assertTrue(signer.contributors.containsAll(signer.signers))
        assertFailsWith<IllegalArgumentException> { IcebergFundingSigner(group, contributors = listOf(1, 2, 3, 4, 5), signers = listOf(6, 7, 1)) }
        // Too few of either is refused by name.
        assertFailsWith<IllegalArgumentException> { IcebergFundingSigner(group, contributors = listOf(1, 2, 3, 4)) }
        assertFailsWith<IllegalArgumentException> { IcebergFundingSigner(group, signers = listOf(1, 2)) }
    }

    @Test
    fun `round one refuses a short, out-of-range or duplicated contributor set`() {
        val group = IcebergSigner.keygen(4, 2, randomBytes32())
        assertFailsWith<IllegalArgumentException> { IcebergSigner.roundOne(group, listOf(1, 2), randomBytes32()) }
        assertFailsWith<IllegalArgumentException> { IcebergSigner.roundOne(group, listOf(1, 2, 5), randomBytes32()) }
        assertFailsWith<IllegalArgumentException> { IcebergSigner.roundOne(group, listOf(1, 2, 2), randomBytes32()) }
        assertFailsWith<IllegalArgumentException> { IcebergSigner.roundOne(group, listOf(0, 1, 2), randomBytes32()) }
    }

    @Test
    fun `the funding signer has no private key and refuses by name`() {
        val group = IcebergSigner.keygen(4, 2, randomBytes32())
        val signer = IcebergFundingSigner(group)
        assertEquals(group.groupPublicKey, signer.publicKey)
        assertNull(signer.privateKeyOrNull)
        val e = assertFailsWith<IllegalStateException> { signer.privateKey("sign remote commit tx (segwit-v0)") }
        assertTrue(e.message!!.contains("sign remote commit tx (segwit-v0)"), "the refusal must name the operation: ${e.message}")
        assertTrue(e.message!!.contains("IcebergFundingSigner"), "the refusal must name the signer: ${e.message}")
    }

    @Test
    fun `the verification session label is a function of exactly the three fields it identifies`() {
        val txId = TxId(randomBytes32())
        val key = randomKey().publicKey()
        val id = FundingSigner.VerificationNonceId(txId, key, 7L)
        assertEquals(IcebergFundingSigner.verificationSessionId(id), IcebergFundingSigner.verificationSessionId(FundingSigner.VerificationNonceId(txId, key, 7L)))
        assertNotEquals(IcebergFundingSigner.verificationSessionId(id), IcebergFundingSigner.verificationSessionId(FundingSigner.VerificationNonceId(TxId(randomBytes32()), key, 7L)))
        assertNotEquals(IcebergFundingSigner.verificationSessionId(id), IcebergFundingSigner.verificationSessionId(FundingSigner.VerificationNonceId(txId, randomKey().publicKey(), 7L)))
        assertNotEquals(IcebergFundingSigner.verificationSessionId(id), IcebergFundingSigner.verificationSessionId(FundingSigner.VerificationNonceId(txId, key, 8L)))
        // Consecutive commit indices must not collide: the index is hashed, not truncated.
        val labels = (0L until 1000L).map { IcebergFundingSigner.verificationSessionId(FundingSigner.VerificationNonceId(txId, key, it)) }
        assertEquals(1000, labels.toSet().size)
    }

    @Test
    fun `a published nonce session from another signer is refused`() {
        val group = IcebergSigner.keygen(4, 2, randomBytes32())
        val signer = IcebergFundingSigner(group)
        val other = FundingSigner.PrivateKeyFundingSigner(randomKey())
        val txId = TxId(randomBytes32())
        val remoteKey = randomKey().publicKey()
        val foreign = other.publishedNonceSession(txId, remoteKey)
        val (spendTx, _) = FundingSignerTestHelpers.buildFundingSpend(remoteKey, group.groupPublicKey)
        assertFailsWith<IllegalArgumentException> {
            signer.signWithPublishedNonce(spendTx, remoteKey, mapOf(), foreign, signer.verificationNonce(FundingSigner.VerificationNonceId(txId, remoteKey, 0L)))
        }
    }

    @Test
    fun `a published nonce session publishes the nonce it will later sign under`() {
        val group = IcebergSigner.keygen(4, 2, randomBytes32())
        val signer = IcebergFundingSigner(group)
        val cosignerPriv = randomKey()
        val (spendTx, _) = FundingSignerTestHelpers.buildFundingSpend(cosignerPriv.publicKey(), group.groupPublicKey)
        val session = signer.publishedNonceSession(TxId(randomBytes32()), cosignerPriv.publicKey())
        val remoteNonce = KeyAggCache.create(listOf(group.groupPublicKey, cosignerPriv.publicKey())).let {
            fr.acinq.bitcoin.crypto.musig2.Musig2.generateNonce(randomBytes32(), fr.acinq.bitcoin.utils.Either.Left(cosignerPriv), listOf(cosignerPriv.publicKey(), group.groupPublicKey), null, null).second
        }
        val sig = signer.signWithPublishedNonce(spendTx, cosignerPriv.publicKey(), mapOf(), session, remoteNonce)
        assertTrue(sig.isRight, "signing under the published session failed: $sig")
        // The signature carries the nonce that was published in advance: that is what makes the
        // session a session rather than a call.
        assertEquals(session.publicNonce, sig.right!!.nonce)
    }
}
