# Splice routing for threshold-backed channels -- plan

Date: 2026-08-29
Status: plan. Splicing on a group-backed channel is blocked loudly today (see
`ICEBERG-PORT.md`, "Explicit exclusions"); this document is the design for unblocking it.

Currently blocked loudly, exactly as planned: `SpliceInit`/`SpliceAck` derive the funding key at
index n+1 (`states/Normal.kt:424,471`), which hits the injected-signer index-0 guard in
`ChannelKeys.fundingPublicKey`/`fundingSigner`, and the shared-input signing of the previous funding
output (`channel/InteractiveTx.kt:49`) goes through the `privateKey` escape hatch, which a threshold
signer refuses by name.

**What a splice needs from the funding key.** Three touch points:

1. The new funding pubkey at index n+1, announced in `splice_init`/`splice_ack`
   (`states/Normal.kt:424,471`).
2. The signature on the shared input spending the PREVIOUS funding output
   (`SharedFundingInput.sign`, `channel/InteractiveTx.kt:46-61`), under a nonce created when the
   interactive-tx session starts (`InteractiveTx.kt:739-742`) and published in `tx_complete`'s
   funding-nonce TLV -- i.e. published before the shared transaction it will sign is final. This is
   exactly the closee-nonce shape from mutual close.
3. Everything downstream of the new funding output: commitment signing, mutual close, force-close.
   All of it is already routed through the seam and works as soon as the index guard is lifted,
   because the verification-nonce identity `(fundingTxId, remoteFundingPubKey, commitIndex)` changes
   with the new funding txid (and commit indices keep increasing across splices), so no session
   label is ever reused.

**Design A: generalize the closee-nonce session into a published-nonce session.** The funding nonce
and the closee nonce differ only in which wire message carries them. Rename
`FundingSigner.CloseeNonceSession` to `PublishedNonceSession`, `closeeNonce(...)` to
`publishedNonceSession(fundingTxId, remoteFundingPubKey)`, and `signWithCloseeNonce(...)` to
`signWithPublishedNonce(tx, remoteFundingPubKey, extraUtxos, session, remoteNonce)`; the closing
call sites (`Helpers.Closing.createShutdown`/`signClosingTx`, the `localCloseeNonce` fields in
Normal/ShuttingDown/Negotiating, the JSON serializer) are renamed mechanically. Then:

- `InteractiveTxSession.localFundingNonce: Transactions.LocalNonce?`
  (`channel/InteractiveTx.kt:739`) becomes a `PublishedNonceSession?`, created via
  `channelKeys.fundingSigner(sharedInput.fundingTxIndex).publishedNonceSession(...)`; the
  `tx_complete` funding-nonce TLV publishes `session.publicNonce`.
- `SharedFundingInput.sign`'s taproot branch becomes
  `signWithPublishedNonce(spliceTx, remoteFundingPubkey, spentUtxos, session, remoteFundingNonce)`.
  The segwit-v0 branch stays on the `privateKey` escape hatch: ECDSA splices remain
  private-key-only and are correctly refused for threshold-backed channels.
- No persistence work: `InteractiveTxSession` is never serialized (only `InteractiveTxSigningSession`
  is, and it carries the produced `TxSignatures`, not the nonce -- see
  `serialization/channel/v5/Serialization.kt`, `writeWaitForFundingConfirmed`/`writeNormal`). On
  disconnect mid-splice the interactive-tx session is discarded and rebuilt with a fresh nonce,
  the same lifecycle the closee session already has.
- For `PrivateKeyFundingSigner` the session wraps the existing `LocalNonce`: byte-for-byte today's
  behaviour, with the existing splice suites as the regression proof.
- For `IcebergFundingSigner` the session is again just the 32-byte label; round one is re-derived
  from it at signing time, and each session signs at most once (RBF attempts each build a fresh
  interactive-tx session, hence a fresh session).

**Design B: serve the same group key at every index.** The original plan's cheap option, and the
right one for the benchmark:

- `ChannelKeys.fundingPublicKey`/`fundingSigner` drop the index-0 guard when a signer is injected
  and answer every index with the injected signer. The private `fundingKey` stays a poison pill at
  all indices.
- Consequence: the local side of the funding output does not rotate across splices. Rotation is a
  privacy habit, not a protocol requirement -- BOLT 2 does not ask for a fresh key and nothing in
  the splice flow validates it (verify this during implementation: read the `splice_init` handling
  in `states/Normal.kt` and the interactive-tx parameter validation for any comparison against the
  previous key).
- The rejected alternative: a fresh group per index. The in-process simulation could do it (a keygen
  callback per index), but the rotation semantics a real deployment would want (deterministic
  re-derivation from the seed) do not map onto a DKG, and it changes nothing the benchmark measures.
- The fail-loud tests change sign: the index-guard unit tests in `FundingSignerTestsCommon` and the
  channel-level `splice on a group-backed channel fails loudly` go away, replaced by the positive
  tests below. What is still refused loudly is anything needing the raw private key.

**Test plan** (jvmTest, alongside `IcebergChannelTestsJvm`):

1. Splice-in and splice-out on a group-backed channel, with the group as splice initiator and as
   accepter: the new funding output script contains the group key; `tx_signatures` complete (the
   shared-input signature is checked by the stock counterparty); payments work before and after;
   both sides' commitments on the new funding output pass `correctlySpends`.
2. Mutual close after a splice (group as closer and as closee) against the new funding output.
3. RBF of a splice: a fresh funding-nonce session per attempt, no reuse.
4. Disconnect mid-splice and resume: the rebuilt session publishes a fresh nonce.
5. The existing splice suites (`SpliceTestsCommon` et al.) pass unmodified -- the stock-channel
   regression proof.

**Effort.** Design A ~1 day (the closee session is the working template), design B ~half a day,
tests ~1-2 days: inside the original +1 week estimate.
