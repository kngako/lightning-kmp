package fr.acinq.lightning.crypto

import fr.acinq.bitcoin.ByteVector
import fr.acinq.bitcoin.ByteVector32
import fr.acinq.bitcoin.Crypto
import fr.acinq.bitcoin.ScriptFlags
import fr.acinq.bitcoin.Transaction
import fr.acinq.bitcoin.crypto.musig2.KeyAggCache
import fr.acinq.bitcoin.crypto.musig2.Musig2
import fr.acinq.bitcoin.utils.Either
import fr.acinq.bitcoin.utils.getOrElse
import fr.acinq.lightning.Lightning.randomBytes32
import fr.acinq.lightning.Lightning.randomKey
import fr.acinq.lightning.tests.utils.LightningTestSuite
import fr.acinq.lightning.transactions.Scripts
import fr.acinq.lightning.transactions.Transactions
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotEquals
import kotlin.test.assertTrue

/**
 * The load-bearing proof for the prefractal signer: a nested FROST+MuSig2 group signing under
 * EXACTLY the session lightning-kmp builds for a taproot channel, producing an aggregate Schnorr
 * signature that spends the real funding output.
 *
 * Mirror of [IcebergTaprootSessionTestsCommon], and it exists for the same reason: two partial
 * signatures combine only if the group's share is computed against the same key aggregation cache
 * lightning-kmp builds internally, which means the same [Scripts.sort] key order AND the same BIP341
 * taproot tweak. Supplying no tweak while lightning-kmp applies `KeyPathTweak` puts the two sides in
 * different sessions, and the aggregate verifies against nothing.
 *
 * THE SELF-CHECK IS THE POINT. Step 2 asserts the tweaked aggregate key equals the 32 bytes inside
 * the P2TR `pubkeyScript` that lightning-kmp itself generated. A wrong tweak or key order would
 * otherwise surface only as an opaque "signature did not verify" much later, in channel code.
 *
 * THE GROUP-KEY PARITY MATTERS HERE TOO. The nested equation carries no frost-level key parity
 * factor; anything that reintroduced it would produce a group whose signatures work about half the
 * time, depending on the Y parity of a randomly dealt threshold key. [runSession] therefore takes a
 * fixed seed of each parity rather than a random one.
 */
class PrefractalTaprootSessionTestsCommon : LightningTestSuite() {

    // Seeds chosen so that PrefractalSigner.keygen's derived threshold key has the stated Y parity.
    // These are asserted below, so they cannot quietly stop testing what they are named after.
    private val seedEvenY = ByteVector32.fromValidHex("0000000000000000000000000000000000000000000000000000000000000001")
    private val seedOddY = ByteVector32.fromValidHex("0000000000000000000000000000000000000000000000000000000000000002")

    /**
     * BIP341 key-path tweak: t = taggedHash("TapTweak", internalKey), where a BIP340 tagged hash is
     * SHA256(SHA256(tag) || SHA256(tag) || msg).
     *
     * Computed from the specification rather than taken from a library call, so the assertion
     * against lightning-kmp's own `pubkeyScript` is a genuine cross-check of two independent
     * derivations rather than the same function compared with itself.
     */
    private fun taprootKeyPathTweak(internalKey: ByteVector32): ByteVector32 {
        val tagHash = Crypto.sha256(ByteVector("TapTweak".encodeToByteArray()))
        return ByteVector32(Crypto.sha256(ByteVector(tagHash) + tagHash + internalKey))
    }

    /**
     * One complete session. [cosignerFirst] selects which key [Scripts.sort] places first, so both
     * orderings get exercised: BIP327 gives the second distinct key a coefficient of exactly 1, so
     * the two cases are genuinely different arithmetic for the group.
     */
    private fun runSession(n: Int, t: Int, cosignerFirst: Boolean, seed: ByteVector32) {
        val group = PrefractalSigner.keygen(n, t, seed)
        var cosignerPriv = randomKey()
        var guard = 0
        while ((Scripts.sort(listOf(group.groupPublicKey, cosignerPriv.publicKey())).first() == cosignerPriv.publicKey()) != cosignerFirst && guard < 200) {
            cosignerPriv = randomKey()
            guard += 1
        }
        assertTrue(guard < 200, "could not find a cosigner key on the requested side of the group key")

        val groupPubkey = group.groupPublicKey
        val cosignerPubkey = cosignerPriv.publicKey()
        val (spendTx, _) = FundingSignerTestHelpers.buildFundingSpend(cosignerPubkey, groupPubkey)

        // ---- 1. lightning-kmp's session, reproduced exactly ------------------------------------
        val sortedKeys = Scripts.sort(listOf(cosignerPubkey, groupPubkey))
        val (internalKey, _) = KeyAggCache.create(sortedKeys)
        val tweak = taprootKeyPathTweak(internalKey.value)
        val keyAggCache = PrefractalSigner.keyAggCacheFor(sortedKeys, tweak).getOrElse { throw it }
        val outputKey = KeyAggCache.create(sortedKeys).second.tweak(tweak, isXonly = true).getOrElse { throw it }.second.xOnly()

        // ---- 2. the self-check ------------------------------------------------------------------
        val scriptOutputKey = spendTx.input.txOut.publicKeyScript.drop(2)
        assertEquals(scriptOutputKey.toByteArray().toList(), outputKey.value.toByteArray().toList(), "tweaked aggregate key does not match the funding output script")

        // ---- 3. round one: the group publishes an ordinary MuSig2 nonce --------------------------
        val sessionId = randomBytes32()
        // Quorum is t in BOTH rounds here, unlike iceberg's 2t-1 then t.
        val contributors = (1..group.t).toList()
        val r1 = PrefractalSigner.roundOne(group, contributors, sessionId)

        val cosignerNonce = Musig2.generateNonce(randomBytes32(), Either.Left(cosignerPriv), listOf(cosignerPubkey, groupPubkey), null, null)
        val publicNonces = listOf(cosignerNonce.second, r1.publicNonce)

        // ---- 4. round two: the group signs the real sighash --------------------------------------
        val message = spendTx.taprootSighash(mapOf())
        val cosignerAggnonce = PrefractalSigner.cosignerAggregatedNonce(listOf(cosignerNonce.second)).getOrElse { throw it }
        // The signers are the SAME SET as the contributors, which this scheme requires.
        val groupSig = PrefractalSigner.roundTwo(group, contributors, sessionId, r1, keyAggCache, message, cosignerAggnonce).getOrElse { throw it }

        // ---- 5. stock lightning-kmp verifies the group's partial signature ------------------------
        assertTrue(
            spendTx.checkRemotePartialSignature(cosignerPubkey, groupPubkey, groupSig, cosignerNonce.second),
            "stock lightning-kmp rejected the group's partial signature (n=$n, t=$t, cosignerFirst=$cosignerFirst)"
        )

        // ---- 6. the cosigner signs stock, and the two aggregate ------------------------------------
        val cosignerSig = spendTx.partialSign(cosignerPriv, groupPubkey, mapOf(), Transactions.LocalNonce(cosignerNonce.first, cosignerNonce.second), publicNonces)
        assertTrue(cosignerSig.isRight, "cosigner partial sign failed: $cosignerSig")
        val signedTx = spendTx.aggregateSigs(cosignerPubkey, groupPubkey, cosignerSig.right!!, groupSig, mapOf())
        assertTrue(signedTx.isRight, "aggregateSigs failed: $signedTx")

        // ---- 7. the script interpreter is the judge -------------------------------------------------
        Transaction.correctlySpends(signedTx.right ?: error("aggregateSigs failed"), mapOf(spendTx.input.outPoint to spendTx.input.txOut), ScriptFlags.STANDARD_SCRIPT_VERIFY_FLAGS)
    }

    /** The fixtures really do have the Y parities their names claim. */
    @Test
    fun `the parity fixtures are what they say they are`() {
        assertEquals(0x02.toByte(), PrefractalSigner.keygen(3, 2, seedEvenY).groupPublicKey.value[0], "seedEvenY should yield an even-Y group key")
        assertEquals(0x03.toByte(), PrefractalSigner.keygen(3, 2, seedOddY).groupPublicKey.value[0], "seedOddY should yield an odd-Y group key")
    }

    @Test
    fun `prefractal group signs lightning-kmp's taproot session and the aggregate signature spends the funding output`() {
        for (seed in listOf(seedEvenY, seedOddY)) {
            runSession(n = 3, t = 2, cosignerFirst = true, seed = seed)
            runSession(n = 3, t = 2, cosignerFirst = false, seed = seed)
        }
    }

    @Test
    fun `the same holds across the t-of-n matrix`() {
        // 2-of-2 and 3-of-4 are inexpressible in iceberg; they work here.
        for ((t, n) in listOf(2 to 2, 2 to 3, 2 to 4, 3 to 4, 3 to 5)) {
            for (cosignerFirst in listOf(true, false)) {
                for (seed in listOf(seedEvenY, seedOddY)) {
                    runSession(n, t, cosignerFirst, seed)
                }
            }
        }
    }

    @Test
    fun `an untweaked session is rejected`() {
        val group = PrefractalSigner.keygen(3, 2, seedOddY)
        val groupPubkey = group.groupPublicKey
        val cosignerPriv = randomKey()
        val (spendTx, _) = FundingSignerTestHelpers.buildFundingSpend(cosignerPriv.publicKey(), groupPubkey)

        val sortedKeys = Scripts.sort(listOf(cosignerPriv.publicKey(), groupPubkey))
        // The negative control: no tweak, so the aggregate key must NOT be the one in the output.
        val untweakedCache = PrefractalSigner.keyAggCacheFor(sortedKeys, null).getOrElse { throw it }
        val untweakedKey = KeyAggCache.create(sortedKeys).first
        assertNotEquals(spendTx.input.txOut.publicKeyScript.drop(2).toByteArray().toList(), untweakedKey.value.toByteArray().toList(), "an untweaked aggregate key should NOT match the funding output script")

        val sessionId = randomBytes32()
        val contributors = (1..group.t).toList()
        val r1 = PrefractalSigner.roundOne(group, contributors, sessionId)
        val cosignerNonce = Musig2.generateNonce(randomBytes32(), Either.Left(cosignerPriv), listOf(cosignerPriv.publicKey(), groupPubkey), null, null)
        val message = spendTx.taprootSighash(mapOf())
        val cosignerAggnonce = PrefractalSigner.cosignerAggregatedNonce(listOf(cosignerNonce.second)).getOrElse { throw it }
        val groupSig = PrefractalSigner.roundTwo(group, contributors, sessionId, r1, untweakedCache, message, cosignerAggnonce).getOrElse { throw it }

        assertFalse(
            spendTx.checkRemotePartialSignature(cosignerPriv.publicKey(), groupPubkey, groupSig, cosignerNonce.second),
            "stock lightning-kmp should reject a partial signature computed without the taproot tweak"
        )
    }
}
