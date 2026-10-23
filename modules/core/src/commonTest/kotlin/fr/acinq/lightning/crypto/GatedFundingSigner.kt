package fr.acinq.lightning.crypto

import fr.acinq.bitcoin.OutPoint
import fr.acinq.bitcoin.PublicKey
import fr.acinq.bitcoin.TxId
import fr.acinq.bitcoin.TxOut
import fr.acinq.bitcoin.crypto.musig2.IndividualNonce
import fr.acinq.bitcoin.utils.Either
import fr.acinq.lightning.channel.ChannelSpendSignature
import fr.acinq.lightning.transactions.Transactions
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.first

/**
 * A [FundingSigner] whose signing methods wait while [open] is false: a group whose devices have not
 * answered yet. [waiting] counts the calls currently held, so a test can tell the channel is stuck in
 * one rather than guess with a delay.
 */
class GatedFundingSigner(private val underlying: FundingSigner, private val open: StateFlow<Boolean>) : FundingSigner by underlying {
    private val _waiting = MutableStateFlow(0)
    val waiting: StateFlow<Int> = _waiting

    private suspend fun <A> gate(call: suspend () -> A): A {
        _waiting.value += 1
        try {
            open.first { it }
        } finally {
            _waiting.value -= 1
        }
        return call()
    }

    override suspend fun signWithVerificationNonce(tx: Transactions.ChannelSpendTransaction, remoteFundingPubKey: PublicKey, extraUtxos: Map<OutPoint, TxOut>, id: FundingSigner.VerificationNonceId, remoteNonce: IndividualNonce): Either<Throwable, ChannelSpendSignature.PartialSignatureWithNonce> =
        gate { underlying.signWithVerificationNonce(tx, remoteFundingPubKey, extraUtxos, id, remoteNonce) }

    override suspend fun signWithFreshNonce(tx: Transactions.ChannelSpendTransaction, remoteFundingPubKey: PublicKey, extraUtxos: Map<OutPoint, TxOut>, fundingTxId: TxId, remoteNonce: IndividualNonce): Either<Throwable, ChannelSpendSignature.PartialSignatureWithNonce> =
        gate { underlying.signWithFreshNonce(tx, remoteFundingPubKey, extraUtxos, fundingTxId, remoteNonce) }

    override suspend fun signWithPublishedNonce(tx: Transactions.ChannelSpendTransaction, remoteFundingPubKey: PublicKey, extraUtxos: Map<OutPoint, TxOut>, session: FundingSigner.PublishedNonceSession, remoteNonce: IndividualNonce): Either<Throwable, ChannelSpendSignature.PartialSignatureWithNonce> =
        gate { underlying.signWithPublishedNonce(tx, remoteFundingPubKey, extraUtxos, session, remoteNonce) }
}
