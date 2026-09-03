package fr.acinq.lightning.crypto

import fr.acinq.bitcoin.KeyPath
import fr.acinq.bitcoin.OutPoint
import fr.acinq.bitcoin.PrivateKey
import fr.acinq.bitcoin.PublicKey
import fr.acinq.bitcoin.TxId
import fr.acinq.bitcoin.TxOut
import fr.acinq.bitcoin.crypto.musig2.IndividualNonce
import fr.acinq.lightning.Lightning.randomBytes32
import fr.acinq.lightning.Lightning.randomKey
import fr.acinq.lightning.tests.TestConstants
import fr.acinq.lightning.tests.utils.LightningTestSuite
import fr.acinq.lightning.transactions.Transactions
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

/**
 * The seam's regression proof: [FundingSigner.PrivateKeyFundingSigner] must be byte-for-byte the
 * pre-existing behaviour, and [ChannelKeys] with an injected signer must fail loudly where the raw
 * key would be needed.
 */
class FundingSignerTestsCommon : LightningTestSuite() {

    private val fundingKey = randomKey()
    private val remoteFundingKey = randomKey().publicKey()
    private val signer = FundingSigner.PrivateKeyFundingSigner(fundingKey)

    @Test
    fun `private-key signer reproduces upstream verification nonces bit for bit`() {
        val fundingTxId = TxId(randomBytes32())
        for (commitIndex in listOf(0L, 1L, 42L)) {
            val expected = NonceGenerator.verificationNonce(fundingTxId, fundingKey, remoteFundingKey, commitIndex).publicNonce
            val actual = signer.verificationNonce(FundingSigner.VerificationNonceId(fundingTxId, remoteFundingKey, commitIndex))
            assertEquals(expected, actual, "verification nonce mismatch at commit index $commitIndex")
        }
    }

    @Test
    fun `private-key signer partial signatures verify against the counterparty session`() {
        val (spendTx, _) = FundingSignerTestHelpers.buildFundingSpend(fundingKey.publicKey(), remoteFundingKey)
        val fundingTxId = spendTx.input.outPoint.txid
        val remoteNonce = NonceGenerator.signingNonce(remoteFundingKey, fundingKey.publicKey(), fundingTxId)

        // Signing with a fresh nonce (the counterparty's commit tx case).
        val psigFresh = signer.signWithFreshNonce(spendTx, remoteFundingKey, mapOf(), fundingTxId, remoteNonce.publicNonce)
        assertTrue(psigFresh.isRight, "signWithFreshNonce failed: $psigFresh")
        assertTrue(spendTx.checkRemotePartialSignature(remoteFundingKey, fundingKey.publicKey(), psigFresh.right!!, remoteNonce.publicNonce))

        // Signing with the deterministic verification nonce (our own commit tx case): the nonce
        // published ahead of time and the nonce used to sign must be the same.
        val id = FundingSigner.VerificationNonceId(fundingTxId, remoteFundingKey, commitIndex = 3)
        val publishedNonce = signer.verificationNonce(id)
        val psigVerification = signer.signWithVerificationNonce(spendTx, remoteFundingKey, mapOf(), id, remoteNonce.publicNonce)
        assertTrue(psigVerification.isRight, "signWithVerificationNonce failed: $psigVerification")
        assertEquals(publishedNonce, psigVerification.right!!.nonce)
        assertTrue(spendTx.checkRemotePartialSignature(remoteFundingKey, fundingKey.publicKey(), psigVerification.right!!, remoteNonce.publicNonce))
    }

    @Test
    fun `private-key published nonce session signs the transaction it was published for`() {
        val (spendTx, _) = FundingSignerTestHelpers.buildFundingSpend(fundingKey.publicKey(), remoteFundingKey)
        val fundingTxId = spendTx.input.outPoint.txid
        val remoteNonce = NonceGenerator.signingNonce(remoteFundingKey, fundingKey.publicKey(), fundingTxId)

        val session = signer.publishedNonceSession(fundingTxId, remoteFundingKey)
        val psig = signer.signWithPublishedNonce(spendTx, remoteFundingKey, mapOf(), session, remoteNonce.publicNonce)
        assertTrue(psig.isRight, "signWithPublishedNonce failed: $psig")
        assertEquals(session.publicNonce, psig.right!!.nonce)
        assertTrue(spendTx.checkRemotePartialSignature(remoteFundingKey, fundingKey.publicKey(), psig.right!!, remoteNonce.publicNonce))
    }

    @Test
    fun `private-key signer exposes the raw key`() {
        assertEquals(fundingKey, signer.privateKeyOrNull)
        assertEquals(fundingKey, signer.privateKey("test"))
    }

    @Test
    fun `injected signer turns fundingKey into a poison pill`() {
        // Any placeholder signer works: we never sign, we only check which calls survive.
        val thresholdSigner = object : FundingSigner {
            override val publicKey = randomKey().publicKey()
            override val privateKeyOrNull: PrivateKey? = null
            override fun verificationNonce(id: FundingSigner.VerificationNonceId): IndividualNonce = TODO()
            override fun signWithVerificationNonce(tx: Transactions.ChannelSpendTransaction, remoteFundingPubKey: PublicKey, extraUtxos: Map<OutPoint, TxOut>, id: FundingSigner.VerificationNonceId, remoteNonce: IndividualNonce) = TODO()
            override fun signWithFreshNonce(tx: Transactions.ChannelSpendTransaction, remoteFundingPubKey: PublicKey, extraUtxos: Map<OutPoint, TxOut>, fundingTxId: TxId, remoteNonce: IndividualNonce) = TODO()
            override fun publishedNonceSession(fundingTxId: TxId, remoteFundingPubKey: PublicKey): FundingSigner.PublishedNonceSession = TODO()
            override fun signWithPublishedNonce(tx: Transactions.ChannelSpendTransaction, remoteFundingPubKey: PublicKey, extraUtxos: Map<OutPoint, TxOut>, session: FundingSigner.PublishedNonceSession, remoteNonce: IndividualNonce) = TODO()
        }
        val thresholdChannelKeys = TestConstants.Alice.keyManager.channelKeys(KeyPath.empty).withFundingSigner(thresholdSigner)

        // The public key comes from the signer, not from local derivation.
        assertEquals(thresholdSigner.publicKey, thresholdChannelKeys.fundingPublicKey(0))
        assertEquals(thresholdSigner, thresholdChannelKeys.fundingSigner(0))
        // The raw key is unreachable: a wrong answer is worse than a loud failure.
        assertFailsWith<IllegalArgumentException> { thresholdChannelKeys.fundingKey(0) }
        assertFailsWith<IllegalStateException> { thresholdChannelKeys.fundingSigner(0).privateKey("some operation") }
        // Splicing derives the key at the next index: it must fail loudly rather than reuse index 0.
        assertFailsWith<IllegalArgumentException> { thresholdChannelKeys.fundingPublicKey(1) }
        assertFailsWith<IllegalArgumentException> { thresholdChannelKeys.fundingSigner(1) }
    }
}
