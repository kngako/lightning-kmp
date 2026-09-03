package fr.acinq.lightning.crypto

import fr.acinq.bitcoin.ByteVector
import fr.acinq.bitcoin.PublicKey
import fr.acinq.bitcoin.Satoshi
import fr.acinq.bitcoin.Script
import fr.acinq.bitcoin.Transaction
import fr.acinq.bitcoin.TxIn
import fr.acinq.bitcoin.TxOut
import fr.acinq.lightning.Lightning.randomKey
import fr.acinq.lightning.transactions.Transactions
import fr.acinq.lightning.utils.sat

/**
 * Shared helpers for the FundingSigner tests: building a transaction that spends a 2-of-2 taproot
 * funding output, without needing a whole channel.
 */
object FundingSignerTestHelpers {

    /** The funding output a real taproot channel creates, and a transaction spending it. */
    fun buildFundingSpend(localPubkey: PublicKey, remotePubkey: PublicKey): Pair<Transactions.SpliceTx, Satoshi> {
        val commitmentFormat = Transactions.CommitmentFormat.SimpleTaprootChannels
        val fundingScript = Transactions.makeFundingScript(localPubkey, remotePubkey, commitmentFormat)
        val amount = 1_000_000.sat
        val fundingTx = Transaction(version = 2, txIn = listOf(), txOut = listOf(TxOut(amount, fundingScript.pubkeyScript)), lockTime = 0)
        val fundingInput = Transactions.makeFundingInputInfo(fundingTx.txid, 0, amount, localPubkey, remotePubkey, commitmentFormat)
        val destScript = Script.pay2wpkh(randomKey().publicKey()).let { Script.write(it) }
        val unsignedTx = Transaction(version = 2, txIn = listOf(TxIn(fundingInput.outPoint, ByteVector.empty, 0)), txOut = listOf(TxOut(amount - 1000.sat, destScript)), lockTime = 0)
        return Pair(Transactions.SpliceTx(fundingInput, unsignedTx), amount)
    }
}
