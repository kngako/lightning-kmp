package fr.acinq.lightning.crypto

import fr.acinq.bitcoin.KeyPath

/**
 * A [KeyManager] that hands out [ChannelKeys] whose funding key is held by [fundingSigner] instead
 * of a locally-derived private key. Used to plug an Iceberg threshold group (jvmTest) or a test
 * double (commonTest) into the channel state machine without changing any of its code.
 */
class SignerInjectingKeyManager(private val delegate: KeyManager, private val fundingSigner: FundingSigner) : KeyManager by delegate {
    override fun channelKeys(fundingKeyPath: KeyPath): ChannelKeys = delegate.channelKeys(fundingKeyPath).withFundingSigner(fundingSigner)
}
