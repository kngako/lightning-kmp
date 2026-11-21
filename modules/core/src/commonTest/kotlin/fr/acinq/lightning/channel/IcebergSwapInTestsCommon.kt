package fr.acinq.lightning.channel

import fr.acinq.bitcoin.*
import fr.acinq.bitcoin.crypto.musig2.IndividualNonce
import fr.acinq.bitcoin.utils.Either
import fr.acinq.lightning.Lightning.randomBytes32
import fr.acinq.lightning.Lightning.randomKey
import fr.acinq.lightning.blockchain.electrum.WalletState
import fr.acinq.lightning.blockchain.fee.FeeratePerKw
import fr.acinq.lightning.crypto.IcebergGroup
import fr.acinq.lightning.crypto.IcebergSigner
import fr.acinq.lightning.crypto.IcebergSwapInSigner
import fr.acinq.lightning.crypto.KeyManager
import fr.acinq.lightning.crypto.SwapInKeys
import fr.acinq.lightning.crypto.SwapInSigner
import fr.acinq.lightning.tests.TestConstants
import fr.acinq.lightning.tests.utils.LightningTestSuite
import fr.acinq.lightning.tests.utils.runSuspendTest
import fr.acinq.lightning.transactions.SwapInProtocol
import fr.acinq.lightning.transactions.Transactions
import fr.acinq.lightning.utils.msat
import fr.acinq.lightning.utils.sat
import fr.acinq.lightning.wire.InteractiveTxConstructionMessage
import fr.acinq.lightning.wire.TxComplete
import kotlin.test.*

/**
 * A swap-in whose user key is an Iceberg group's: `docs/group-lightning-swap-in.md` (in the app), Phase 2.
 *
 * Alice's only contribution to a dual-funded channel is a coin on a group swap-in address -- the group's
 * key first in the key path, a refund key of its own in the leaf -- and Bob plays the LSP, signing as the
 * server with his own key for Alice's node, as an LSP does. The group signs Alice's swap-in input through
 * [SwapInKeys.signer] and nothing else; no private key for the user side exists anywhere. The result has to
 * be a transaction bitcoin accepts.
 */
class IcebergSwapInTestsCommon : LightningTestSuite() {

    /** A group's swap-in keys, as a group node's key manager hands them out: no legacy address, never a server. */
    private class GroupSwapInKeys(
        group: IcebergGroup,
        override val remoteServerPublicKey: PublicKey,
        override val refundDelay: Int,
        private val refundKeys: (Int) -> PublicKey,
    ) : SwapInKeys {
        override val userPublicKey: PublicKey = group.groupPublicKey
        override val signer: SwapInSigner = IcebergSwapInSigner(group)
        override fun getSwapInProtocol(addressIndex: Int): SwapInProtocol = SwapInProtocol(userPublicKey, remoteServerPublicKey, refundKeys(addressIndex), refundDelay)
        override fun signSwapInputUserLegacy(fundingTx: Transaction, index: Int, parentTxOuts: List<TxOut>): ByteVector64 = error("a group has no legacy swap-in address")
        override fun localServerPrivateKey(remoteNodeId: PublicKey): PrivateKey = error("a group node never serves a swap-in")
    }

    /** Alice's key manager, with the group's swap-in keys in place of her seed's. */
    private class GroupSwapInKeyManager(delegate: KeyManager, override val swapInOnChainWallet: SwapInKeys) : KeyManager by delegate

    private val group = IcebergSigner.keygen(n = 4, t = 2, seed = ByteVector32.fromValidHex("5a".repeat(32)))

    /** A signer that counts what it is asked, to show the session went through it. */
    private class Counting(val underlying: SwapInSigner) : SwapInSigner by underlying {
        var nonces = 0
        var signatures = 0
        override fun nonceSession(outPoint: OutPoint, protocol: SwapInProtocol): SwapInSigner.NonceSession = underlying.nonceSession(outPoint, protocol).also { nonces++ }
        override suspend fun sign(tx: Transaction, inputIndex: Int, spentOutputs: List<TxOut>, protocol: SwapInProtocol, session: SwapInSigner.NonceSession, serverNonce: IndividualNonce): Either<Throwable, ByteVector32> =
            underlying.sign(tx, inputIndex, spentOutputs, protocol, session, serverNonce).also { signatures++ }
    }

    @Test
    fun `a group signs its swap-in input through the signer, and bitcoin accepts the funding transaction`() = runSuspendTest {
        val channelId = randomBytes32()
        val localParamsA = TestConstants.Alice.channelParams(payCommitTxFees = true)
        val localParamsB = TestConstants.Bob.channelParams(payCommitTxFees = false)
        val channelKeysA = localParamsA.channelKeys(TestConstants.Alice.keyManager)
        val channelKeysB = localParamsB.channelKeys(TestConstants.Bob.keyManager)

        // The LSP's server key for Alice's node, as it derives it; and a refund key per address, as the group's would be.
        val serverKey = TestConstants.Bob.keyManager.swapInOnChainWallet.localServerPrivateKey(localParamsA.nodeId).publicKey()
        val refundKeys = (0..3).map { randomKey().publicKey() }
        val counting = Counting(IcebergSwapInSigner(group))
        val groupKeys = object : SwapInKeys by GroupSwapInKeys(group, serverKey, 144, refundKeys::get) {
            override val signer: SwapInSigner = counting
        }
        val keyManagerA = GroupSwapInKeyManager(TestConstants.Alice.keyManager, groupKeys)

        // One coin on the group's address 2, the way the app's watcher would hand it over.
        val protocol = groupKeys.getSwapInProtocol(2)
        val coinTx = Transaction(2, listOf(TxIn(OutPoint(TxId(randomBytes32()), 0), 0)), listOf(TxOut(100_000.sat, protocol.pubkeyScript)), 0)
        val wallet = listOf(WalletState.Utxo(coinTx.txid, 0, 800_000, coinTx, WalletState.AddressMeta.Derived(2)))

        val feerate = FeeratePerKw(2500.sat)
        val fundingA = 80_000.sat
        val fundingPubkeyA = channelKeysA.fundingKey(0).publicKey()
        val fundingPubkeyB = channelKeysB.fundingKey(0).publicKey()
        val format = Transactions.CommitmentFormat.SimpleTaprootChannels
        val paramsA = InteractiveTxParams(channelId, true, fundingA, 0.sat, fundingPubkeyB, 0, 330.sat, format, feerate)
        val paramsB = InteractiveTxParams(channelId, false, 0.sat, fundingA, fundingPubkeyA, 0, 330.sat, format, feerate)
        val contributionsA = FundingContributions.create(channelKeysA, groupKeys, paramsA, null, wallet, listOf(), null, randomKey().publicKey()).right!!
        val contributionsB = FundingContributions.create(channelKeysB, TestConstants.Bob.keyManager.swapInOnChainWallet, paramsB, null, listOf(), listOf(), null, randomKey().publicKey()).right!!
        val swapIn = contributionsA.inputs.filterIsInstance<InteractiveTxInput.LocalSwapIn>().single()
        assertEquals(group.groupPublicKey, swapIn.userKey, "the input's user key is the group's")

        val alice0 = InteractiveTxSession(localParamsB.nodeId, channelKeysA, groupKeys, paramsA, 0, 0.msat, 0.msat, emptySet(), contributionsA)
        val bob0 = InteractiveTxSession(localParamsA.nodeId, channelKeysB, TestConstants.Bob.keyManager.swapInOnChainWallet, paramsB, 0, 0.msat, 0.msat, emptySet(), contributionsB)
        val (alice, bob) = negotiate(alice0, bob0)
        assertEquals(1, counting.nonces, "the nonce came from the signer, when tx_add_input went out")

        val signedA = alice.second.sharedTx.sign(alice.first, keyManagerA, paramsA, localParamsB.nodeId).right
        assertNotNull(signedA)
        assertEquals(1, counting.signatures, "the partial signature came from the signer")
        assertEquals(1, signedA.localSigs.swapInUserPartialSigs.size)

        val signedB = bob.second.sharedTx.sign(bob.first, TestConstants.Bob.keyManager, paramsB, localParamsA.nodeId).right
        assertNotNull(signedB)
        assertEquals(1, signedB.localSigs.swapInServerPartialSigs.size)
        val full = signedB.addRemoteSigs(channelKeysB, paramsB, signedA.localSigs)
        assertIs<FullySignedSharedTransaction>(full, "Bob combines the group's partial signature with his own")
        Transaction.correctlySpends(full.signedTx, listOf(coinTx), ScriptFlags.STANDARD_SCRIPT_VERIFY_FLAGS)
    }

    /** Drives the two sessions until both have completed, returning each one's final state and action. */
    private fun negotiate(alice0: InteractiveTxSession, bob0: InteractiveTxSession): Pair<Pair<InteractiveTxSession, InteractiveTxSessionAction.SignSharedTx>, Pair<InteractiveTxSession, InteractiveTxSessionAction.SignSharedTx>> {
        var sessions = mutableMapOf(true to alice0, false to bob0)
        val done = mutableMapOf<Boolean, InteractiveTxSessionAction.SignSharedTx>()
        val (first, action) = alice0.send()
        sessions[true] = first
        var pending: InteractiveTxConstructionMessage = (action as InteractiveTxSessionAction.SendMessage).msg
        var toAlice = false
        repeat(20) {
            val (next, reply) = sessions.getValue(toAlice).receive(pending)
            sessions[toAlice] = next
            when (reply) {
                is InteractiveTxSessionAction.SendMessage -> pending = reply.msg
                is InteractiveTxSessionAction.SignSharedTx -> {
                    done[toAlice] = reply
                    val complete: TxComplete = reply.txComplete ?: return Pair(sessions.getValue(true) to done.getValue(true), sessions.getValue(false) to done.getValue(false))
                    pending = complete
                }
                else -> fail("the negotiation failed: $reply")
            }
            toAlice = !toAlice
        }
        fail("the negotiation did not finish")
    }
}
