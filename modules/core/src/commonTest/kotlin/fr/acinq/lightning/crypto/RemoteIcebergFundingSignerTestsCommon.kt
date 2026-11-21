package fr.acinq.lightning.crypto

import fr.acinq.bitcoin.TxId
import fr.acinq.bitcoin.crypto.iceberg.SignatureShare
import fr.acinq.bitcoin.utils.Either
import fr.acinq.lightning.Lightning.randomBytes32
import fr.acinq.lightning.channel.TestsHelper.reachNormal
import fr.acinq.lightning.tests.utils.LightningTestSuite
import fr.acinq.lightning.tests.utils.runSuspendTest
import fr.acinq.lightning.transactions.Transactions
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertIs
import kotlin.test.assertNotEquals
import kotlin.test.assertTrue
import kotlin.time.Duration.Companion.milliseconds
import kotlin.time.Duration.Companion.seconds

/**
 * The remote signer on its own, against a simulated group: the labels it derives, and the three ways
 * a group that is somewhere else can let it down -- it never provisioned round one, it does not answer
 * in time, or it answers with shares that do not combine.
 */
class RemoteIcebergFundingSignerTestsCommon : LightningTestSuite() {

    private fun signer(transport: IcebergGroupTransport, group: IcebergGroup) =
        RemoteIcebergFundingSigner(group.groupPublicKey, transport, deadline = 2.seconds)

    @Test
    fun `fresh labels are distinct per counter and per channel, and never a verification label`() {
        val a = TxId(randomBytes32())
        val b = TxId(randomBytes32())
        val labels = (0L until 100L).map { RemoteIcebergFundingSigner.freshLabel(a, it) } + (0L until 100L).map { RemoteIcebergFundingSigner.freshLabel(b, it) }
        assertEquals(labels.size, labels.toSet().size)
        assertEquals(RemoteIcebergFundingSigner.freshLabel(a, 7), RemoteIcebergFundingSigner.freshLabel(a, 7))
        val key = fr.acinq.lightning.Lightning.randomKey().publicKey()
        val verification = (0L until 100L).map { IcebergFundingSigner.verificationSessionId(FundingSigner.VerificationNonceId(a, key, it)) }
        assertTrue(labels.intersect(verification.toSet()).isEmpty())
    }

    @Test
    fun `a remote group signs exactly what the in-process group signs`() {
        // Verification nonces are a pure function of the label, so the remote signer and the simulation
        // must publish the same nonce for the same commitment.
        val group = IcebergSigner.keygen(4, 2, randomBytes32())
        val remote = signer(SimulatedGroupTransport(group), group)
        val local = IcebergFundingSigner(group)
        val id = FundingSigner.VerificationNonceId(TxId(randomBytes32()), fr.acinq.lightning.Lightning.randomKey().publicKey(), 3)
        assertEquals(local.verificationNonce(id), remote.verificationNonce(id))
    }

    @Test
    fun `an unprovisioned label fails by name`() {
        val group = IcebergSigner.keygen(4, 2, randomBytes32())
        val transport = SimulatedGroupTransport(group)
        val id = FundingSigner.VerificationNonceId(TxId(randomBytes32()), fr.acinq.lightning.Lightning.randomKey().publicKey(), 0)
        transport.unprovisioned += IcebergFundingSigner.verificationSessionId(id)
        assertFailsWith<IcebergNonceNotProvisioned> { signer(transport, group).verificationNonce(id) }
    }

    @Test
    fun `a group that does not answer times out, and the retry asks for a new label`() = runSuspendTest {
        val group = IcebergSigner.keygen(4, 2, randomBytes32())
        val transport = SimulatedGroupTransport(group)
        val remote = RemoteIcebergFundingSigner(group.groupPublicKey, transport, deadline = 200.milliseconds)
        val (alice, _) = reachNormal(aliceFundingSigner = IcebergFundingSigner(group))
        val commitment = alice.commitments.latest
        // Which transaction does not matter here: what is under test is what happens around it.
        val spend = Transactions.CommitTx(commitment.commitInput(alice.channelKeys), alice.signCommitTx())
        val remoteNonce = IcebergFundingSigner(IcebergSigner.keygen(4, 2, randomBytes32())).verificationNonce(FundingSigner.VerificationNonceId(commitment.fundingTxId, group.groupPublicKey, 0))

        transport.silent = true
        val first = remote.signWithFreshNonce(spend, commitment.remoteFundingPubkey, mapOf(), commitment.fundingTxId, remoteNonce)
        assertIs<IcebergSigningTimeout>(assertIs<Either.Left<Throwable>>(first).value)

        transport.silent = false
        val second = remote.signWithFreshNonce(spend, commitment.remoteFundingPubkey, mapOf(), commitment.fundingTxId, remoteNonce)
        assertIs<Either.Right<*>>(second)
        assertEquals(2, transport.requests.size)
        assertNotEquals(transport.requests[0].label, transport.requests[1].label)
        assertTrue(transport.reusedLabels().isEmpty())
    }

    @Test
    fun `shares that do not combine are refused before they reach the counterparty`() = runSuspendTest {
        val group = IcebergSigner.keygen(4, 2, randomBytes32())
        val honest = SimulatedGroupTransport(group)
        val lying = object : IcebergGroupTransport by honest {
            override suspend fun roundTwo(request: IcebergRoundTwoRequest): Either<Throwable, List<SignatureShare>> =
                // Shares for another message: each is well-formed, and they aggregate, to the wrong thing.
                honest.roundTwo(request.copy(message = randomBytes32()))
        }
        val remote = signer(lying, group)
        val (alice, _) = reachNormal(aliceFundingSigner = IcebergFundingSigner(group))
        val commitment = alice.commitments.latest
        val spend = Transactions.CommitTx(commitment.commitInput(alice.channelKeys), alice.signCommitTx())
        val remoteNonce = IcebergFundingSigner(IcebergSigner.keygen(4, 2, randomBytes32())).verificationNonce(FundingSigner.VerificationNonceId(commitment.fundingTxId, group.groupPublicKey, 0))
        val result = remote.signWithFreshNonce(spend, commitment.remoteFundingPubkey, mapOf(), commitment.fundingTxId, remoteNonce)
        assertIs<Either.Left<Throwable>>(result)
    }
}
