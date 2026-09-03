package fr.acinq.lightning.crypto

import fr.acinq.bitcoin.ByteVector32
import fr.acinq.bitcoin.Crypto
import fr.acinq.bitcoin.PrivateKey
import fr.acinq.bitcoin.byteVector32
import fr.acinq.bitcoin.crypto.iceberg.Iceberg
import fr.acinq.bitcoin.crypto.musig2.IndividualNonce
import fr.acinq.bitcoin.crypto.musig2.KeyAggCache
import fr.acinq.bitcoin.crypto.musig2.SecretNonce
import fr.acinq.bitcoin.crypto.musig2.Session
import fr.acinq.bitcoin.utils.Either
import fr.acinq.lightning.Lightning.randomBytes32
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFails
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

/**
 * SCRATCH -- phase 0 of FEATURE-PARITY.md, deleted once phase 3 lands its real equivalent.
 *
 * Proves that the Iceberg API is reachable from lightning-kmp's own test classpath through the
 * composite build, with no build changes: the failure this is here to catch is an
 * UnsatisfiedLinkError from a substituted secp256k1-kmp whose native library has no Iceberg
 * symbols, which is what the reference port's whole mavenLocal/resolutionStrategy apparatus existed
 * to prevent.
 */
class IcebergToolchainScratchTest {

    private val cosignerPrivateKey = PrivateKey.fromHex("487356F98AA7A0DC5E0E0F61B4CDA5D1A5B4C59F1B1E5A70E0D55C11FE0A99A1")

    @Test
    fun `the Iceberg API is reachable and deals a 2-of-4 group`() {
        val shares = Iceberg.dealShares(4, 2, randomBytes32())
        assertEquals(4, shares.size)
        val caches = shares.map { Iceberg.shareCache(it) }
        val publicShares = shares.mapIndexed { i, share -> Iceberg.publicShare(share, caches[i]) }
        assertNotNull(Iceberg.groupPublicKey(publicShares, 4, 2).right)
    }

    @Test
    fun `the group key aggregated over a 2t-1 quorum equals the one over all n`() {
        // The port's keygen aggregates over the quorum rather than all n (as the reference does);
        // this is the check that the two agree, since the group key ends up in the funding output.
        val shares = Iceberg.dealShares(4, 2, randomBytes32())
        val caches = shares.map { Iceberg.shareCache(it) }
        val publicShares = shares.mapIndexed { i, share -> Iceberg.publicShare(share, caches[i]) }
        val overAll = Iceberg.groupPublicKey(publicShares, 4, 2).right
        val overQuorum = Iceberg.groupPublicKey(publicShares.take(2 * 2 - 1), 4, 2).right
        assertNotNull(overAll)
        assertEquals(overAll, overQuorum)
    }

    @Test
    fun `a 2-of-4 group and a stock cosigner produce a BIP340 signature that verifies`() {
        val shares = Iceberg.dealShares(4, 2, randomBytes32())
        val caches = shares.map { Iceberg.shareCache(it) }
        val publicShares = shares.mapIndexed { i, share -> Iceberg.publicShare(share, caches[i]) }
        val groupPublicKey = Iceberg.groupPublicKey(publicShares, 4, 2).right
        assertNotNull(groupPublicKey)

        val message = randomBytes32()
        val sessionId = randomBytes32()

        // The outer session is plain musig2: the group occupies one participant slot.
        val publicKeys = listOf(groupPublicKey, cosignerPrivateKey.publicKey())
        val (aggregatePublicKey, keyAggCache) = KeyAggCache.create(publicKeys)
        assertTrue(Iceberg.keyAggregationCheck(keyAggCache, publicKeys, groupPublicKey))
        // The check the port relies on: a cache built over a different key ORDER is rejected.
        assertTrue(!Iceberg.keyAggregationCheck(keyAggCache, publicKeys.reversed(), groupPublicKey))

        // Round one: 2t-1 = 3 members contribute, aggregated into one ordinary musig2 public nonce.
        val contributors = listOf(0, 1, 2)
        val contributions = contributors.map { Iceberg.generateNonce(shares[it], caches[it], sessionId) }
        val groupPublicNonce = Iceberg.aggregateNonces(contributions, 4, 2, groupPublicKey).right
        assertNotNull(groupPublicNonce)

        val (cosignerSecretNonce, cosignerPublicNonce) = SecretNonce.generate(randomBytes32(), Either.Left(cosignerPrivateKey), message, keyAggCache, null)
        val aggregatedNonce = IndividualNonce.aggregate(listOf(groupPublicNonce, cosignerPublicNonce)).right
        val cosignerAggregatedNonce = IndividualNonce.aggregate(listOf(cosignerPublicNonce)).right
        assertNotNull(aggregatedNonce)
        assertNotNull(cosignerAggregatedNonce)
        val session = Session.create(aggregatedNonce, message, keyAggCache)

        // Round two: only t = 2 of the round-one contributors produce signature shares.
        val signers = contributors.take(2)
        val signatureShares = signers.map {
            Iceberg.partialSign(shares[it], caches[it], sessionId, contributions, groupPublicKey, keyAggCache, message, cosignerAggregatedNonce).right!!
        }
        val groupPartialSig = Iceberg.aggregatePartialSignatures(signatureShares, 4, 2).right
        assertNotNull(groupPartialSig)
        assertTrue(session.verify(groupPartialSig, groupPublicNonce, groupPublicKey))

        val cosignerPartialSig = session.sign(cosignerSecretNonce, cosignerPrivateKey).right
        assertNotNull(cosignerPartialSig)
        val sig = session.aggregateSigs(listOf(groupPartialSig, cosignerPartialSig)).right
        assertNotNull(sig)
        assertTrue(Crypto.verifySignatureSchnorr(message, sig, aggregatePublicKey))
    }

    @Test
    fun `round one is a pure function of the session label`() {
        // The property the whole deterministic verification-nonce design rests on.
        val shares = Iceberg.dealShares(4, 2, randomBytes32())
        val sessionId = randomBytes32()
        val once = listOf(0, 1, 2).map { Iceberg.generateNonce(shares[it], null, sessionId) }
        val twice = listOf(0, 1, 2).map { Iceberg.generateNonce(shares[it], null, sessionId) }
        assertEquals(once, twice)
        val other = listOf(0, 1, 2).map { Iceberg.generateNonce(shares[it], null, randomBytes32()) }
        assertTrue(once != other)
    }

    @Test
    fun `an illegal group configuration throws instead of aborting the process`() {
        // The reference needed Iceberg.requireConfig because a bad (n, t) aborts the JVM inside its
        // C module. Here Secp256k1Jni/Secp256k1Native validate first, so this is a plain exception.
        assertFails { Iceberg.dealShares(2, 2, randomBytes32()) }  // 2-of-2 is inexpressible
        assertFails { Iceberg.dealShares(4, 3, randomBytes32()) }  // 3-of-4 is inexpressible
        assertFails { Iceberg.dealShares(11, 2, randomBytes32()) } // n <= 10
        // 2-of-4 is the smallest usable group.
        assertEquals(4, Iceberg.dealShares(4, 2, randomBytes32()).size)
    }

    @Test
    fun `reusing a session label under two messages raises no error`() {
        // Documents the hazard rather than a behaviour: two signature shares under one label are
        // both well-formed and nothing complains. This is why the port hashes a VerificationNonceId
        // into the label and never signs twice under one PublishedNonceSession.
        val shares = Iceberg.dealShares(4, 2, randomBytes32())
        val caches = shares.map { Iceberg.shareCache(it) }
        val publicShares = shares.mapIndexed { i, s -> Iceberg.publicShare(s, caches[i]) }
        val groupPublicKey = Iceberg.groupPublicKey(publicShares, 4, 2).right!!
        val (_, keyAggCache) = KeyAggCache.create(listOf(groupPublicKey, cosignerPrivateKey.publicKey()))
        val sessionId = randomBytes32()
        val contributions = listOf(0, 1, 2).map { Iceberg.generateNonce(shares[it], caches[it], sessionId) }
        val cosignerNonce = SecretNonce.generate(randomBytes32(), Either.Left(cosignerPrivateKey), null, keyAggCache, null).second
        val cosignerAggnonce = IndividualNonce.aggregate(listOf(cosignerNonce)).right!!
        val first = Iceberg.partialSign(shares[0], caches[0], sessionId, contributions, groupPublicKey, keyAggCache, randomBytes32(), cosignerAggnonce)
        val second = Iceberg.partialSign(shares[0], caches[0], sessionId, contributions, groupPublicKey, keyAggCache, randomBytes32(), cosignerAggnonce)
        assertTrue(first.isRight && second.isRight)
        assertTrue(first.right != second.right)
    }

    @Test
    fun `ByteVector32 conversions used by the port round-trip`() {
        val v: ByteVector32 = randomBytes32()
        assertEquals(v, v.toByteArray().byteVector32())
    }
}
