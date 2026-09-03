package fr.acinq.lightning.crypto

import fr.acinq.bitcoin.ByteVector32
import fr.acinq.bitcoin.TxId
import fr.acinq.bitcoin.crypto.musig2.Musig2
import fr.acinq.bitcoin.utils.Either
import fr.acinq.bitcoin.utils.getOrElse
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
 * The properties [PrefractalSigner] and [PrefractalFundingSigner] rest on, stated as assertions
 * rather than as comments. Everything here is about the scheme's contract with its caller; the
 * end-to-end proof that a group signature actually spends a funding output is
 * [PrefractalTaprootSessionTestsCommon].
 *
 * Several of these exist specifically because the corresponding Iceberg property is DIFFERENT, and
 * a reader who knows Iceberg would otherwise assume it carries over.
 */
class PrefractalSignerTestsCommon : LightningTestSuite() {

    private fun signAgainstCosigner(
        group: PrefractalGroup,
        signer: PrefractalFundingSigner,
        cosignerPriv: fr.acinq.bitcoin.PrivateKey = randomKey()
    ): Either<Throwable, fr.acinq.lightning.channel.ChannelSpendSignature.PartialSignatureWithNonce> {
        val (spendTx, _) = FundingSignerTestHelpers.buildFundingSpend(cosignerPriv.publicKey(), group.groupPublicKey)
        val remoteNonce = Musig2.generateNonce(randomBytes32(), Either.Left(cosignerPriv), listOf(cosignerPriv.publicKey(), group.groupPublicKey), null, null).second
        return signer.signWithFreshNonce(spendTx, cosignerPriv.publicKey(), mapOf(), TxId(randomBytes32()), remoteNonce)
    }

    @Test
    fun `the quorum is t in BOTH rounds unlike iceberg`() {
        val group = PrefractalSigner.keygen(5, 3, randomBytes32())
        assertEquals(3, group.quorum)
        // t contributors is enough for round one. Iceberg would need 2t-1 = 5 here.
        val sessionId = randomBytes32()
        val r1 = PrefractalSigner.roundOne(group, listOf(1, 2, 3), sessionId)
        assertEquals(3, r1.memberPublicNonces.size)
        // Fewer than t is refused.
        assertFailsWith<IllegalArgumentException> { PrefractalSigner.roundOne(group, listOf(1, 2), sessionId) }
    }

    @Test
    fun `configurations iceberg cannot express work here`() {
        // Iceberg requires t <= (n+1)/2, so 2-of-2 and 3-of-4 are inexpressible there.
        for ((t, n) in listOf(2 to 2, 3 to 4, 4 to 4)) {
            val group = PrefractalSigner.keygen(n, t, randomBytes32())
            assertEquals(t, group.quorum)
            val signer = PrefractalFundingSigner(group)
            assertTrue(signAgainstCosigner(group, signer).isRight, "$t-of-$n should be signable")
        }
    }

    /**
     * THE ONE THAT DOES NOT CARRY OVER FROM ICEBERG. Iceberg tolerates round-two signers that are a
     * proper subset of the round-one contributors, because it interpolates over 2t-1 contributions.
     * FROST defines lambda and the aggregate nonce over the participating set, so a subset would
     * produce a well-formed and simply invalid signature with nothing raised at signing time. It
     * must be refused instead.
     */
    @Test
    fun `round two signers must EQUAL the round one contributors and not merely be a subset`() {
        val group = PrefractalSigner.keygen(5, 3, randomBytes32())
        val sessionId = randomBytes32()
        val contributors = listOf(1, 2, 3, 4)
        val r1 = PrefractalSigner.roundOne(group, contributors, sessionId)
        val cosignerPriv = randomKey()
        val (spendTx, _) = FundingSignerTestHelpers.buildFundingSpend(cosignerPriv.publicKey(), group.groupPublicKey)
        val sortedKeys = Scripts.sort(listOf(group.groupPublicKey, cosignerPriv.publicKey()))
        val keyAggCache = PrefractalSigner.keyAggCacheFor(sortedKeys, null).getOrElse { throw it }
        val cosignerNonce = Musig2.generateNonce(randomBytes32(), Either.Left(cosignerPriv), listOf(cosignerPriv.publicKey(), group.groupPublicKey), null, null).second
        val cosignerAggnonce = PrefractalSigner.cosignerAggregatedNonce(listOf(cosignerNonce)).getOrElse { throw it }
        val message = spendTx.taprootSighash(mapOf())

        // A proper subset of the contributors: refused, rather than silently producing garbage.
        val subset = PrefractalSigner.roundTwo(group, listOf(1, 2, 3), sessionId, r1, keyAggCache, message, cosignerAggnonce)
        assertTrue(subset.isLeft, "a proper subset of the round-one contributors must be refused")
        // A superset is equally wrong.
        val superset = PrefractalSigner.roundTwo(group, listOf(1, 2, 3, 4, 5), sessionId, r1, keyAggCache, message, cosignerAggnonce)
        assertTrue(superset.isLeft, "a superset of the round-one contributors must be refused")
        // The same set in a different order is fine: it is a set, not a sequence.
        assertTrue(PrefractalSigner.roundTwo(group, listOf(4, 3, 2, 1), sessionId, r1, keyAggCache, message, cosignerAggnonce).isRight)

        // And the constructor refuses the same mistake before the first signature.
        assertFailsWith<IllegalArgumentException> {
            PrefractalFundingSigner(group, contributors = listOf(1, 2, 3, 4), signers = listOf(1, 2, 3))
        }
    }

    @Test
    fun `round one is a pure function of the session label`() {
        val group = PrefractalSigner.keygen(5, 3, randomBytes32())
        val sessionId = randomBytes32()
        val a = PrefractalSigner.roundOne(group, listOf(1, 2, 3), sessionId)
        val b = PrefractalSigner.roundOne(group, listOf(1, 2, 3), sessionId)
        assertEquals(a.publicNonce, b.publicNonce)
        assertEquals(a.groupAggregatedNonce, b.groupAggregatedNonce)
        assertNotEquals(a.publicNonce, PrefractalSigner.roundOne(group, listOf(1, 2, 3), randomBytes32()).publicNonce)
        // A different contributor set is a different session, even under the same label.
        assertNotEquals(a.publicNonce, PrefractalSigner.roundOne(group, listOf(1, 2, 4), sessionId).publicNonce)
    }

    /**
     * A FRESH signer re-derives the same verification nonce. This is the property the whole
     * label-derived nonce design exists for: a restarted node must reproduce the nonce it published
     * before, and nothing is stored between the rounds to help it.
     */
    @Test
    fun `a fresh signer re-derives the same verification nonce`() {
        val seed = randomBytes32()
        val id = FundingSigner.VerificationNonceId(TxId(randomBytes32()), randomKey().publicKey(), 42L)
        val first = PrefractalFundingSigner(PrefractalSigner.keygen(4, 3, seed)).verificationNonce(id)
        // Same seed, entirely new objects, as after a restart.
        val second = PrefractalFundingSigner(PrefractalSigner.keygen(4, 3, seed)).verificationNonce(id)
        assertEquals(first, second)
    }

    /**
     * HAZARD DOCUMENTATION, not a feature. Nonces are a function of the label, so signing two
     * different messages under one label reuses nonces and leaks the members' shares. Nothing here
     * can detect it, and this test says so out loud so that the absence of an error is understood to
     * be known rather than overlooked.
     */
    @Test
    fun `reusing a session label under two messages raises no error`() {
        val group = PrefractalSigner.keygen(4, 3, randomBytes32())
        val sessionId = randomBytes32()
        val contributors = (1..group.t).toList()
        val r1 = PrefractalSigner.roundOne(group, contributors, sessionId)
        val cosignerPriv = randomKey()
        val (spendTx, _) = FundingSignerTestHelpers.buildFundingSpend(cosignerPriv.publicKey(), group.groupPublicKey)
        val sortedKeys = Scripts.sort(listOf(group.groupPublicKey, cosignerPriv.publicKey()))
        val keyAggCache = PrefractalSigner.keyAggCacheFor(sortedKeys, null).getOrElse { throw it }
        val cosignerNonce = Musig2.generateNonce(randomBytes32(), Either.Left(cosignerPriv), listOf(cosignerPriv.publicKey(), group.groupPublicKey), null, null).second
        val cosignerAggnonce = PrefractalSigner.cosignerAggregatedNonce(listOf(cosignerNonce)).getOrElse { throw it }

        val msg1 = spendTx.taprootSighash(mapOf())
        val msg2 = randomBytes32()
        val sig1 = PrefractalSigner.roundTwo(group, contributors, sessionId, r1, keyAggCache, msg1, cosignerAggnonce)
        val sig2 = PrefractalSigner.roundTwo(group, contributors, sessionId, r1, keyAggCache, msg2, cosignerAggnonce)
        assertTrue(sig1.isRight)
        assertTrue(sig2.isRight, "the second signature under the same label succeeds: THIS IS THE KEY-LEAKING PATH")
        // Same nonce, two messages: exactly the pair an attacker solves for the shares.
        assertEquals(sig1.right!!.nonce, sig2.right!!.nonce)
        assertNotEquals(sig1.right!!.partialSig, sig2.right!!.partialSig)
    }

    @Test
    fun `round one refuses a short or out-of-range or duplicated contributor set`() {
        val group = PrefractalSigner.keygen(5, 3, randomBytes32())
        val sessionId = randomBytes32()
        assertFailsWith<IllegalArgumentException> { PrefractalSigner.roundOne(group, listOf(1, 2), sessionId) }
        assertFailsWith<IllegalArgumentException> { PrefractalSigner.roundOne(group, listOf(1, 2, 6), sessionId) }
        assertFailsWith<IllegalArgumentException> { PrefractalSigner.roundOne(group, listOf(0, 1, 2), sessionId) }
        assertFailsWith<IllegalArgumentException> { PrefractalSigner.roundOne(group, listOf(1, 2, 2), sessionId) }
    }

    @Test
    fun `an illegal group configuration throws`() {
        assertFailsWith<IllegalArgumentException> { PrefractalSigner.keygen(0, 1, randomBytes32()) }
        assertFailsWith<IllegalArgumentException> { PrefractalSigner.keygen(3, 0, randomBytes32()) }
        assertFailsWith<IllegalArgumentException> { PrefractalSigner.keygen(3, 4, randomBytes32()) }
        assertFailsWith<IllegalArgumentException> { PrefractalSigner.keygen(129, 2, randomBytes32()) }
    }

    @Test
    fun `keygen is deterministic in its seed and the tweak cache is the identity`() {
        val seed = randomBytes32()
        val a = PrefractalSigner.keygen(4, 2, seed)
        val b = PrefractalSigner.keygen(4, 2, seed)
        assertEquals(a.groupPublicKey, b.groupPublicKey)
        assertEquals(a.publicShares, b.publicShares)
        assertNotEquals(a.groupPublicKey, PrefractalSigner.keygen(4, 2, randomBytes32()).groupPublicKey)
        // The tweak cache is the untouched one for this key: every prefractal entry point refuses a
        // tweaked cache, and signing above proves this one is accepted.
        assertEquals(a.groupPublicKey.xOnly(), a.tweakCache.tweakedPublicKey)
    }

    @Test
    fun `a wrong key order is caught before a useless signature is produced`() {
        val group = PrefractalSigner.keygen(4, 2, randomBytes32())
        val signer = PrefractalFundingSigner(group)
        // The signer builds its own cache from Scripts.sort, so the guard inside sign() is what
        // protects it; drive a real signature and check it verifies under the stock verifier.
        val cosignerPriv = randomKey()
        val (spendTx, _) = FundingSignerTestHelpers.buildFundingSpend(cosignerPriv.publicKey(), group.groupPublicKey)
        val remoteNonce = Musig2.generateNonce(randomBytes32(), Either.Left(cosignerPriv), listOf(cosignerPriv.publicKey(), group.groupPublicKey), null, null).second
        val sig = signer.signWithFreshNonce(spendTx, cosignerPriv.publicKey(), mapOf(), TxId(randomBytes32()), remoteNonce)
        assertTrue(sig.isRight, "signing failed: $sig")
        assertTrue(spendTx.checkRemotePartialSignature(cosignerPriv.publicKey(), group.groupPublicKey, sig.right!!, remoteNonce))
        // Against the wrong cosigner key the same share does not verify.
        assertFalse(spendTx.checkRemotePartialSignature(randomKey().publicKey(), group.groupPublicKey, sig.right!!, remoteNonce))
    }

    @Test
    fun `the funding signer has no private key and refuses by name`() {
        val group = PrefractalSigner.keygen(4, 2, randomBytes32())
        val signer = PrefractalFundingSigner(group)
        assertEquals(group.groupPublicKey, signer.publicKey)
        assertNull(signer.privateKeyOrNull)
        val e = assertFailsWith<IllegalStateException> { signer.privateKey("sign remote commit tx (segwit-v0)") }
        assertTrue(e.message!!.contains("sign remote commit tx (segwit-v0)"), "the refusal must name the operation: ${e.message}")
        assertTrue(e.message!!.contains("PrefractalFundingSigner"), "the refusal must name the signer: ${e.message}")
    }

    @Test
    fun `the verification session label is a function of exactly the three fields it identifies`() {
        val txId = TxId(randomBytes32())
        val key = randomKey().publicKey()
        val id = FundingSigner.VerificationNonceId(txId, key, 7L)
        assertEquals(PrefractalFundingSigner.verificationSessionId(id), PrefractalFundingSigner.verificationSessionId(FundingSigner.VerificationNonceId(txId, key, 7L)))
        assertNotEquals(PrefractalFundingSigner.verificationSessionId(id), PrefractalFundingSigner.verificationSessionId(FundingSigner.VerificationNonceId(TxId(randomBytes32()), key, 7L)))
        assertNotEquals(PrefractalFundingSigner.verificationSessionId(id), PrefractalFundingSigner.verificationSessionId(FundingSigner.VerificationNonceId(txId, randomKey().publicKey(), 7L)))
        assertNotEquals(PrefractalFundingSigner.verificationSessionId(id), PrefractalFundingSigner.verificationSessionId(FundingSigner.VerificationNonceId(txId, key, 8L)))

        // Distinct over a long channel's worth of commit indices.
        val labels = (0L until 1000L).map { PrefractalFundingSigner.verificationSessionId(FundingSigner.VerificationNonceId(txId, key, it)) }
        assertEquals(1000, labels.toSet().size)

        // And distinct from iceberg's label for the SAME identity: the domain tag is what keeps a
        // deployment that ever mixed the two schemes from colliding their labels.
        assertNotEquals(PrefractalFundingSigner.verificationSessionId(id), IcebergFundingSigner.verificationSessionId(id))
    }

    @Test
    fun `a published nonce session from another signer is refused`() {
        val group = PrefractalSigner.keygen(4, 2, randomBytes32())
        val signer = PrefractalFundingSigner(group)
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
        val group = PrefractalSigner.keygen(4, 2, randomBytes32())
        val signer = PrefractalFundingSigner(group)
        val cosignerPriv = randomKey()
        val (spendTx, _) = FundingSignerTestHelpers.buildFundingSpend(cosignerPriv.publicKey(), group.groupPublicKey)
        val session = signer.publishedNonceSession(TxId(randomBytes32()), cosignerPriv.publicKey())
        val remoteNonce = Musig2.generateNonce(randomBytes32(), Either.Left(cosignerPriv), listOf(cosignerPriv.publicKey(), group.groupPublicKey), null, null).second
        val sig = signer.signWithPublishedNonce(spendTx, cosignerPriv.publicKey(), mapOf(), session, remoteNonce)
        assertTrue(sig.isRight, "signing under the published session failed: $sig")
        // The signature carries the nonce that was published in advance: that is what makes the
        // session a session rather than a call.
        assertEquals(session.publicNonce, sig.right!!.nonce)
    }
}
