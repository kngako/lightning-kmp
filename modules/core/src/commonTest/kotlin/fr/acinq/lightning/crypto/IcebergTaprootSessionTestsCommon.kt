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
 * The load-bearing proof, ported from the reference's IcebergTaprootSessionTestsJvm: an Iceberg
 * group signing under EXACTLY the session lightning-kmp builds for a taproot channel, producing an
 * aggregate Schnorr signature that spends the real funding output.
 *
 * commonTest, not jvmTest -- the signer is commonMain here, so this runs on every target.
 *
 * WHY THIS EXISTS AS ITS OWN FILE. Two partial signatures combine only if Iceberg's share is
 * computed against the same key aggregation cache lightning-kmp builds internally, which means the
 * same [Scripts.sort] key order AND the same BIP341 taproot tweak. Supplying no tweak while
 * lightning-kmp applies `KeyPathTweak` puts the two sides in different sessions, and the aggregate
 * then verifies against nothing.
 *
 * [fr.acinq.bitcoin.crypto.iceberg.Iceberg.keyAggregationCheck] covers only half of that: it
 * validates the key set and order, and passes on tweaked and untweaked caches alike
 * (IcebergSignerTestsCommon pins that). The TWEAK is what this file covers, and it is why the
 * negative control below is not optional.
 *
 * THE SELF-CHECK IS THE POINT. Step 2 asserts the tweaked aggregate key equals the 32 bytes inside
 * the P2TR `pubkeyScript` that lightning-kmp itself generated. A wrong tweak or a wrong key order
 * would otherwise surface only as an opaque "signature did not verify" much later, in channel code,
 * with nothing pointing at the cause.
 */
class IcebergTaprootSessionTestsCommon : LightningTestSuite() {

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
     * orderings get exercised: a random group key lands second about half the time, and a test that
     * does not pin this only covers one of the two cases, and does so by luck.
     */
    private fun runSession(n: Int, t: Int, cosignerFirst: Boolean) {
        // Find a keypair on the requested side of the group key under lightning-kmp's own ordering.
        val group = IcebergSigner.keygen(n, t, randomBytes32())
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
        // Key order is lightning-kmp's, not ours: partialSign/checkRemotePartialSignature/aggregateSigs
        // all use Scripts.sort internally, so anything else silently produces a different session.
        val sortedKeys = Scripts.sort(listOf(cosignerPubkey, groupPubkey))
        // The untweaked aggregate IS the taproot internal key.
        val (internalKey, _) = KeyAggCache.create(sortedKeys)
        val tweak = taprootKeyPathTweak(internalKey.value)
        val keyAggCache = IcebergSigner.keyAggCacheFor(sortedKeys, tweak).getOrElse { throw it }
        val outputKey = KeyAggCache.create(sortedKeys).second.tweak(tweak, isXonly = true).getOrElse { throw it }.second.xOnly()

        // ---- 2. the self-check ------------------------------------------------------------------
        // A taproot key-path output script is OP_1 <32-byte output key>. If our tweak or key order is
        // wrong, this fails here rather than as an unexplained signature failure inside channel code.
        val scriptOutputKey = spendTx.input.txOut.publicKeyScript.drop(2)
        assertEquals(scriptOutputKey.toByteArray().toList(), outputKey.value.toByteArray().toList(), "tweaked aggregate key does not match the funding output script")

        // ---- 3. round one: the group publishes an ordinary MuSig2 nonce --------------------------
        val sessionId = randomBytes32()
        val contributors = (1..group.quorum).toList()
        val r1 = IcebergSigner.roundOne(group, contributors, sessionId)

        // the cosigner is completely stock
        val cosignerNonce = Musig2.generateNonce(randomBytes32(), Either.Left(cosignerPriv), listOf(cosignerPubkey, groupPubkey), null, null)
        val publicNonces = listOf(cosignerNonce.second, r1.publicNonce)

        // ---- 4. round two: the group signs the real sighash --------------------------------------
        val message = spendTx.taprootSighash(mapOf())
        val cosignerAggnonce = IcebergSigner.cosignerAggregatedNonce(listOf(cosignerNonce.second)).getOrElse { throw it }
        val groupSig = IcebergSigner.roundTwo(group, (1..group.t).toList(), sessionId, r1, keyAggCache, message, cosignerAggnonce).getOrElse { throw it }

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

    @Test
    fun `iceberg group signs lightning-kmp's taproot session and the aggregate signature spends the funding output`() {
        runSession(n = 4, t = 2, cosignerFirst = true)
        runSession(n = 4, t = 2, cosignerFirst = false)
    }

    @Test
    fun `the same holds at the configurations the paper reports`() {
        for ((t, n) in listOf(2 to 4, 3 to 7)) {
            for (cosignerFirst in listOf(true, false)) {
                runSession(n, t, cosignerFirst)
            }
        }
    }

    @Test
    fun `an untweaked session is rejected -- this is the bug that made every previous attempt fail`() {
        val group = IcebergSigner.keygen(4, 2, randomBytes32())
        val groupPubkey = group.groupPublicKey
        val cosignerPriv = randomKey()
        val (spendTx, _) = FundingSignerTestHelpers.buildFundingSpend(cosignerPriv.publicKey(), groupPubkey)

        val sortedKeys = Scripts.sort(listOf(cosignerPriv.publicKey(), groupPubkey))
        // The negative control: no tweak, so the aggregate key must NOT be the one in the output.
        val untweakedCache = IcebergSigner.keyAggCacheFor(sortedKeys, null).getOrElse { throw it }
        val untweakedKey = KeyAggCache.create(sortedKeys).first
        assertNotEquals(spendTx.input.txOut.publicKeyScript.drop(2).toByteArray().toList(), untweakedKey.value.toByteArray().toList(), "an untweaked aggregate key should NOT match the funding output script")

        val sessionId = randomBytes32()
        val r1 = IcebergSigner.roundOne(group, (1..group.quorum).toList(), sessionId)
        val cosignerNonce = Musig2.generateNonce(randomBytes32(), Either.Left(cosignerPriv), listOf(cosignerPriv.publicKey(), groupPubkey), null, null)
        val message = spendTx.taprootSighash(mapOf())
        val cosignerAggnonce = IcebergSigner.cosignerAggregatedNonce(listOf(cosignerNonce.second)).getOrElse { throw it }
        val groupSig = IcebergSigner.roundTwo(group, (1..group.t).toList(), sessionId, r1, untweakedCache, message, cosignerAggnonce).getOrElse { throw it }

        assertFalse(
            spendTx.checkRemotePartialSignature(cosignerPriv.publicKey(), groupPubkey, groupSig, cosignerNonce.second),
            "stock lightning-kmp should reject a partial signature computed without the taproot tweak"
        )
    }
}
