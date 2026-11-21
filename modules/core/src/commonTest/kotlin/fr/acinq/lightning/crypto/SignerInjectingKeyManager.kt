package fr.acinq.lightning.crypto

import fr.acinq.bitcoin.ByteVector
import fr.acinq.bitcoin.KeyPath

/**
 * A [KeyManager] that hands out [ChannelKeys] whose funding key is held by [fundingSigner] instead
 * of a locally-derived private key. Used to plug an Iceberg threshold group (jvmTest) or a test
 * double (commonTest) into the channel state machine without changing any of its code.
 *
 * When the signer is a [GroupBackedFundingSigner] it also carries the group's basepoints and closing
 * script, and those are applied too: that is a whole group node, as the app builds one.
 */
class SignerInjectingKeyManager(private val delegate: KeyManager, private val fundingSigner: FundingSigner) : KeyManager by delegate {
    override fun channelKeys(fundingKeyPath: KeyPath): ChannelKeys = delegate.channelKeys(fundingKeyPath).withFundingSigner(fundingSigner).let { keys ->
        (fundingSigner as? GroupBackedFundingSigner)?.let { keys.withGroupBasepoints(it.basepoints) } ?: keys
    }

    override val defaultFinalScriptPubKey: ByteVector
        get() = (fundingSigner as? GroupBackedFundingSigner)?.finalScriptPubKey ?: delegate.defaultFinalScriptPubKey
}

/** A [FundingSigner] that brings the rest of a group node with it: its [basepoints] and where it closes to. */
class GroupBackedFundingSigner(
    private val underlying: FundingSigner,
    val basepoints: GroupBasepoints,
    val finalScriptPubKey: ByteVector,
) : FundingSigner by underlying
