# Porting Iceberg threshold signing to lightning-kmp

Date: 2026-08-27
Status: **implemented** (2026-08-29). The plan below was carried out as written; see
"Implementation notes" at the end for what actually happened, including two places where
lightning-kmp differed from what the plan assumed.

## What this is

Iceberg is a t-of-n threshold Schnorr scheme. In the sibling fork of eclair
(`sources/eclair/`, reviewed in `.idea/docs/eclair-fork-review.md`), an Iceberg group occupies ONE
side of a channel's 2-of-2 MuSig2 funding output: the channel's funding key has no private key
anywhere, and every funding-key signature is a two-round group protocol (round one needs `2t-1`
members online, round two needs `t`). The counterparty is entirely stock and cannot tell the
difference. The eclair fork exists to measure the cost of that per-payment, and the same questions
can be asked of lightning-kmp.

This document estimates and plans that port. The eclair fork is the reference implementation; its
design transfers essentially unchanged, and where lightning-kmp differs it is almost always in the
porter's favour.

## Summary estimate

| work item | effort |
|---|---|
| `FundingSigner` seam in `commonMain` + `ChannelKeys` integration | ~1 week |
| Kotlin port of `IcebergSigner` / `IcebergFundingSigner` (jvmMain) | ~2–3 days |
| Mutual close routing | ~1–2 days |
| Force-close / claim paths | ~½ day (pubkey-only swaps) |
| Test harness (signer injection, channel spec, session spec) | ~2–3 days |
| **Total, benchmark-grade** | **~2–3 weeks** |
| Splice routing (optional, deferrable) | + ~1 week |
| Native/iOS targets, production deployment | out of scope (see below) |

## Why lightning-kmp is a smaller surface than eclair

Three of the problems that dominate the eclair review do not exist here:

1. **No channel announcements.** lightning-kmp is Phoenix-oriented and never generates
   `announcement_signatures` (the wire type exists at
   `modules/core/src/commonMain/kotlin/fr/acinq/lightning/wire/LightningMessages.kt:1518`, unused).
   Liquidity-ads `will_fund` is signed with the *node* key
   (`wire/LiquidityAds.kt:198`). In eclair, announcement signatures are ECDSA over the funding
   private key — impossible for a Schnorr threshold scheme — forcing the "unannounced channels
   only" restriction. Here that restriction is the default state of the codebase.
2. **Force-close claims never use the funding key.** All claim transactions (main delayed output,
   HTLC success/timeout, penalty, anchor) are signed with per-commitment keys derived from the
   commitment master key. The funding key appears in the claim paths only as a *public* key, for
   locating outputs and building the funding input. A threshold-backed channel's unilateral-exit
   story therefore needs no threshold signing at all — only pubkey plumbing. (The one
   private-key use is publishing our own commitment, `Commitment.fullySignedCommitTx` at
   `channel/Commitments.kt:282-299`, which the seam covers.)
3. **Taproot is fully implemented and there is no segwit-v0 legacy surface to defend.**
   `Transactions.CommitmentFormat` has exactly two variants (`AnchorOutputs`,
   `SimpleTaprootChannels` at `transactions/Transactions.kt:86,106`); taproot commit signing
   (`partialSign`/`aggregateSigs`/`checkRemotePartialSignature`, `Transactions.kt:239-303`), taproot
   mutual close with nonce TLVs (`ShutdownTlv.ShutdownNonce` at `wire/ChannelTlv.kt:324`,
   `ClosingSigTlv.NextCloseeNonce` at `:520`; logic at `channel/Helpers.kt:269-440`), and taproot
   splicing with nonce exchange all exist upstream. The port can be taproot-only from day one
   without giving anything up.

One more simplification: `NonceGenerator.signingNonce`
(`crypto/NonceGenerator.kt:24-28`) is already random and pubkey-only, so the "fresh nonce" signer
method needs no behavioural adaptation — unlike the deterministic-verification-nonce side, it never
touches the funding private key.

## Architecture of the port

Same shape as the eclair fork: ONE seam that supplies both the funding public key and every
funding-key signature, so the two cannot disagree.

### The seam (commonMain)

A `FundingSigner` interface in `fr.acinq.lightning.crypto`, defined in `commonMain` so all channel
logic can compile against it:

```kotlin
interface FundingSigner {
    /** The funding public key that goes into the channel's 2-of-2 funding output. */
    val publicKey: PublicKey

    /** Deterministic public nonce for OUR local commit, published ahead of time and re-derived
     *  (never cached) when we later sign that same commitment. */
    fun verificationNonce(id: VerificationNonceId): IndividualNonce

    /** Sign OUR OWN commit/closing tx under the already-published deterministic nonce. */
    fun signWithVerificationNonce(tx: ChannelSpendTransaction, remoteFundingPubKey: PublicKey,
        id: VerificationNonceId, remoteNonce: IndividualNonce): Either<Throwable, PartialSignatureWithNonce>

    /** Sign the COUNTERPARTY's commit/closing tx with a fresh, never-published nonce. */
    fun signWithFreshNonce(tx: ChannelSpendTransaction, remoteFundingPubKey: PublicKey,
        fundingTxId: TxId, remoteNonce: IndividualNonce): Either<Throwable, PartialSignatureWithNonce>

    /** Escape hatch for paths that genuinely need the raw key; fails loudly with [operation]
     *  named when the key is threshold-held. */
    val privateKeyOrNull: PrivateKey?
    fun privateKey(operation: String): PrivateKey
}
```

with `VerificationNonceId(fundingTxId, remoteFundingPubKey, commitIndex)` and a
`PrivateKeyFundingSigner` default that reproduces today's behaviour call-for-call (its
`verificationNonce` delegates to the existing `NonceGenerator.verificationNonce`).

Notes that carry over from the eclair fork verbatim:

- **Type the nonce identity.** At channel establishment the first verification nonce is derived
  from placeholder values (the funding txid and peer funding key are not yet known when
  `open_channel`/`accept_channel` go out) while the signature itself is against the peer's real
  key — so a signing call carries two different `(TxId, PublicKey)` pairs. A dedicated
  `VerificationNonceId` keeps them from being swapped.
- **Generalize over `ChannelSpendTransaction`, not `CommitTx`.** The eclair seam typed its signing
  methods to `CommitTx`, which is exactly what makes mutual close unreachable there. Typing to the
  common supertype from the start costs nothing and makes mutual close a same-week item.

### `ChannelKeys` integration

`crypto/KeyManager.kt:107-111`: `ChannelKeys` gains an optional `fundingSigner: FundingSigner?`
(default null). `fundingKey(fundingTxIndex)` becomes a poison pill when a signer is injected (throw
with the operation named — there is no private key to return and a wrong answer is worse than a
loud failure). Add a `fundingPublicKey(fundingTxIndex)` accessor: today every pubkey use goes
through `fundingKey(i).publicKey()`, and each of those call sites must be audited and swapped
(mechanical, but numerous — see the inventory below). Injection happens through
`LocalKeyManager.channelKeys` (`crypto/LocalKeyManager.kt:70-75`) or an added parameter on
`LocalChannelParams`; `RecoveredChannelKeys` (`LocalKeyManager.kt:84-97`) already proves a
pubkey-only channel-keys mode is a supported concept in this codebase.

Splicing derives index `n+1` keys (`states/Normal.kt:423,470`); an injected signer carries one
key. Guard with the eclair fork's `requireIndexZero` equivalent (fail loudly) until splice routing
is done — do NOT silently reuse index 0's key, which produces a funding output nobody can spend.
The cheap long-term option is to let an injected signer serve the *same* group key at every index.

### The Iceberg implementation (jvmMain)

Port of `crypto/IcebergSigner.scala` + `FundingSigner.IcebergFundingSigner` from
`sources/eclair/eclair-core/src/main/scala/fr/acinq/eclair/crypto/` (~400 lines of Scala, and the
JNI calls translate almost literally):

- `IcebergGroup(n, t, groupPubkey, shares, pubshares, caches)` — key material from simulated
  trusted-dealer keygen (`Iceberg.sharesGen` / `shareCacheCreate` / `pubshareGen` / `pubkeyAgg`
  over `2t-1` pubshares). 1-based member indexing, round one quorum `2t-1`, round two quorum `t`.
- Round one: per-member `nonceGen(share, sid, cache)` aggregated with `nonceAgg` — a pure function
  of the session id `sid`, which is what makes deterministic verification nonces work without
  storing secrets.
- Round two: `partialSign` per signer + `partialSigAgg`, consuming the OUTER session's real
  key-aggregation cache and the cosigner's aggregate nonce — both must be built with the same key
  order (`Scripts.Taproot.musig2Aggregate` sorts internally) and the same BIP341 key-path tweak the
  outer session applies, or the partial signature is well-formed and simply does not combine.
- Session labels: `sid = sha256(fundingTxId || remoteFundingPubKey || commitIndex)` for
  verification nonces (32 bytes, must never repeat — reuse across two messages is a key-leaking
  path that raises no error), `randomBytes32()` for fresh nonces, matching upstream
  `signingNonce` semantics exactly.

This lives in `jvmMain` (or is injected from the app layer) because the Iceberg API is JVM-only —
see "Build and platform notes".

## Call-site inventory (what actually gets touched)

Private-key uses of the funding key, grouped by feature. **[P]** = the private key is used as a
secret; everything else needs only the public key and swaps to `fundingPublicKey(...)`.

**Channel open (single- and dual-funded share the interactive-tx code)**
- `channel/states/WaitForInit.kt:49`, `WaitForOpenChannel.kt:52-53`, `WaitForAcceptChannel.kt:47,55`,
  `channel/InteractiveTx.kt:115-119,745,1233` — pubkey only.
- `channel/InteractiveTx.kt:1257-1259` — **[P]** first-commit partial sign (fresh nonce);
  `:784-785` — **[P]** verification nonces.

**Normal operation (`commit_sig`)**
- `channel/Commitments.kt:176-205` (`RemoteCommit.sign`), `:584-617` (`Commitment.sendCommit`),
  `:106-143` (`LocalCommit.fromCommitSig`, re-derives the verification nonce at `:142`),
  `:911-946` (`receiveCommit`, publishes next nonce at `:940`) — **[P]**, all routed through the
  two seam signing methods.

**Reconnection / retransmit**
- `channel/states/Channel.kt:305-315,342-365,422-426`, `channel/states/Syncing.kt:519-520`,
  `channel/states/WaitForFundingSigned.kt:171` — **[P]** verification-nonce re-derivation. Must
  produce bit-identical nonces after a restart; this is why round one being a pure function of
  `sid` matters.

**Force-close**
- `channel/Commitments.kt:282-299` (`fullySignedCommitTx`) — **[P]**, seam-covered.
- `Commitments.kt:303-308,1178`, `channel/Helpers.kt:552,756` — pubkey only.
- Everything else (HTLC, delayed, penalty, anchors) — commitment keys, untouched.

**Mutual close (taproot)**
- `channel/Helpers.kt:314-340` (closer), `:390-440` (closee), `:479-500` (finalize) — **[P]**
  partial signs; nonce TLVs already on the wire. Route through the seam as in eclair's plan.

**Splice**
- `channel/InteractiveTx.kt:44-60` (shared-input partial sign of the *previous* funding output),
  `states/Normal.kt:423,470` (pubkey rotation) — **[P]**; blocked by `requireIndexZero` until
  routed.

**Channel announcement** — does not exist in lightning-kmp.

## Build and platform notes

- lightning-kmp pins `fr.acinq.secp256k1:secp256k1-kmp-jni-jvm:0.23.0` in `jvmMain`
  (`modules/core/build.gradle.kts:115`, version in `gradle/libs.versions.toml:7`) — the exact
  version of the vendored fork at `sources/secp256k1-kmp`, whose `Iceberg` object
  (`jni/src/main/kotlin/fr/acinq/secp256k1/Iceberg.kt`) is deliberately JVM-only. So the seam
  interface must live in `commonMain` and the Iceberg implementation in `jvmMain`; channel logic
  (all in `commonMain`) never names the JNI API.
- The port therefore needs the locally built secp256k1-kmp fork artifacts published to the local
  Maven repository, same as the eclair build. Give the rebuilt artifacts a distinct version
  (e.g. `0.23.0-iceberg`) rather than shadowing `0.23.0` — the eclair fork shadows the upstream
  version and a pristine `~/.m2` then fails late (at the first JNI call) instead of at resolution
  time. Don't repeat that.
- Targets: `jvm` (also serving Android), `linuxX64/Arm64`, and on macOS hosts `iosX64/Arm64/
  SimulatorArm64`. The port supports **JVM only**; native/iOS would need new cinterop bindings
  against the C module at `sources/secp256k1-kmp/native/secp256k1/src/modules/iceberg/` — possible
  (the C is there) but new work, and irrelevant for a benchmark harness since `commonTest` runs on
  `jvmTest`.
- `Iceberg.requireConfig` enforces `1 <= t <= (n+1)/2`, `n <= 10` — note that 2-of-2 and 3-of-4
  are NOT expressible; violating the check aborts the JVM inside the C module, so check first.

## Testing plan

Mirrors the eclair harness, all runnable in `commonTest` on the JVM:

1. **Session spec** (port of `IcebergTaprootSessionSpec`): a group partial signature must combine
   with a stock counterparty under `musig2Aggregate` key order + BIP341 tweak, with the script
   interpreter (`correctlySpends`) as the final judge, plus a negative control (untweaked session
   must fail).
2. **Channel spec** (port of `IcebergChannelSpec`): inject signers via
   `TestsHelper.init` (`commonTest/.../channel/TestsHelper.kt:194`) by overriding the key managers
   in `TestConstants` (`tests/TestConstants.kt:62,111`), then open a taproot channel, make
   payments both directions, force-close, and verify the commitment tx spends on-chain. Assert the
   exact signer-call count per payment if the eclair parity check ("exactly six") is wanted.
3. **Seam spec**: a private-key-backed signer must be byte-for-byte upstream behaviour; the
   existing state-machine suite (`states/*TestsCommon.kt`, `CommitmentsTestsCommon.kt`,
   `NonceGeneratorTestsCommon.kt`) should pass unmodified with the default signer, which is the
   regression proof that the seam changes nothing for stock channels.
4. **Reconnect spec**: restart mid-channel and confirm verification nonces re-derive identically.

## Explicit exclusions

- **Splicing** — defer; block loudly at first (one `require`), route later for ~+1 week.
- **Native/iOS** — JVM-only for the benchmark.
- **Production deployment** — this estimate is for an in-process simulated group holding all
  shares in one JVM, exactly like the eclair fork. A real deployment (distributed members, a
  signing protocol over the wire, persistence of in-flight signing sessions, HSM/KMS integration)
  is a different and much larger project; nothing here is a down payment on it beyond the seam.
- **The known establishment-v1 nonce double-use** (one deterministic nonce identity signs both the
  peer's first commit tx in the open flow and our own first commit tx when finalizing) is upstream
  behaviour on an experimental channel type in eclair; check whether lightning-kmp shares it before
  relying on nonce-reuse arguments in either codebase. It is documented in the eclair review and
  in `FundingSigner.scala`'s `VerificationNonceId.firstSingleFunded` comment.

## Implementation notes (2026-08-29)

The port was carried out as planned above. Where reality differed from the plan:

- **The establishment-v1 nonce double-use does not exist here.** lightning-kmp only has the
  dual-funded flow, in which the funding txid and the peer's funding key are both known before the
  first verification nonce is published (in `tx_complete`): `VerificationNonceId` never carries
  placeholder values, so `FundingSigner.VerificationNonceId.firstSingleFunded` has no counterpart.
- **Mutual close needed one seam concept eclair did not have.** The closee's nonce is published in
  `shutdown` before the transaction it will sign exists, so it can be neither a fresh in-call nonce
  nor a commitment-indexed deterministic one (a retried negotiation could pair it with two different
  closing transactions). The seam therefore has `closeeNonce` / `signWithCloseeNonce` with an opaque
  `CloseeNonceSession` carried by the state machine exactly where `Transactions.LocalNonce` used to
  sit (in-memory only, dropped on disconnection, never persisted -- the binary serializers already
  discard it). For `PrivateKeyFundingSigner` the session wraps the existing `LocalNonce`; for
  `IcebergFundingSigner` it is just the 32-byte session label, round one being re-derived from it.
- **The fork artifacts are published as `0.23.0-iceberg`** (see `publish-iceberg-secp256k1.sh` at the
  repository root of this tree), not shadowing `0.23.0`. One wrinkle: Gradle ranks `0.23.0` *above*
  `0.23.0-iceberg`, so upstream's artifacts would silently win version resolution against the fork;
  `modules/core/build.gradle.kts` therefore depends on the three fork artifacts directly (not the
  `secp256k1-kmp-jni-jvm` aggregator), excludes the transitive secp256k1 deps of the darwin/mingw
  natives, and `force`s the three fork versions. On macOS/Windows the stock native library is used
  and Iceberg calls fail loudly with `UnsatisfiedLinkError`; the benchmark targets JVM/linux.
- **Splice is blocked** exactly as planned: `ChannelKeys.fundingPublicKey`/`fundingSigner` throw for
  any index other than 0 when a signer is injected, which is where `SpliceInit`/`SpliceAck` and the
  shared-input signing hit it.

Layout of the implementation:

- `modules/core/src/commonMain/kotlin/fr/acinq/lightning/crypto/FundingSigner.kt` -- the seam
  (`FundingSigner`, `VerificationNonceId`, `CloseeNonceSession`, `PrivateKeyFundingSigner`).
- `modules/core/src/commonMain/kotlin/fr/acinq/lightning/crypto/KeyManager.kt` -- `ChannelKeys`
  gains the injected signer, the poison-pill `fundingKey`, `fundingPublicKey`, `fundingSigner`,
  `withFundingSigner`, and the index-0 splice guard.
- `modules/core/src/jvmMain/kotlin/fr/acinq/lightning/crypto/IcebergSigner.kt` -- `IcebergGroup`,
  `IcebergSigner` (keygen/round one/round two/keyagg cache/cosigner aggnonce) and
  `IcebergFundingSigner`, over the JNI `Iceberg` object. The key aggregation cache and BIP341 tweak
  are built with bitcoin-kmp's public `KeyAggCache` API, so no JNI musig calls are needed.
- Tests: `jvmTest/.../crypto/IcebergTaprootSessionTestsJvm.kt` (session pinned end to end, both key
  orderings, untweaked negative control), `jvmTest/.../iceberg/IcebergChannelTestsJvm.kt` (open both
  sides, payments both directions, nonce progression over ten payments, reconnect with re-derived
  nonces, mutual close as closer and as closee, force-close, splice guard, per-payment operation
  counts via `CountingFundingSigner`), and `commonTest/.../crypto/FundingSignerTestsCommon.kt`
  (private-key signer byte-for-byte upstream behaviour + poison pill). Signer injection in tests is
  `SignerInjectingKeyManager` (commonTest), threaded through `TestsHelper.init`/`reachNormal` via
  optional `aliceFundingSigner`/`bobFundingSigner` parameters.

## Remaining work (2026-08-29)

The port and its measurement harness are complete and verified; what remains is splice routing
(deliberately blocked rather than routed, with a detailed plan below), the report/pipeline
integration of the lightning-kmp numbers, and some coverage gaps. In order:

### Splice routing (deferred, ~1 week) -- detailed plan

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

### The measurement harness (the point of the exercise)

**Done 2026-08-29** (inner-repo commit `e995295a`): the paired measurement exists and has run.

- `CountingFundingSigner` (`jvmTest/.../iceberg/CountingFundingSigner.kt`) counts, per seam method,
  what one payment costs in group operations, with the counters routed through an overridable
  `record` hook. The mapping to rounds is documented on the class: every method enters round one;
  only the signing methods reach round two; `signWithVerificationNonce`'s round one re-derives a
  nonce an earlier `verificationNonce` already published (the redundancy a cache would remove).
- `IcebergCycleMeasurementRun` (`jvmTest/.../iceberg/IcebergCycleMeasurementRun.kt`, run via the
  `:lightning-kmp-core:icebergMeasurement` Gradle task, or `scripts/measure_lightning_kmp.sh` in
  the benchmark repository) opens a bare channel and a group-backed channel, pays on both per
  iteration (counterbalanced), and computes the per-iteration delta. `TimingFundingSigner` times
  the seam calls of both arms. Statistics are the eclair side's verbatim (Bessel-corrected stddev,
  nearest-rank percentiles, lag-1 autocorrelation widening the iid 95% CI by sqrt((1+r)/(1-r))).
  Output matches the pipeline's contract: `cost_per_payment.csv` (readable by
  `scripts/compare_runs.py` as-is), `paired_samples.csv`, the `cycle_stages_*.csv` splits,
  `provenance.txt`, a generated README, and a COMPLETE marker; the run is registered in
  `outputs/runs.json` under the `lightning-kmp-cost-per-payment` label.
- First full run: `outputs/2026-08-29-091030-lightning-kmp-cost-per-payment` (all 20 legal
  configurations, 1500 paired iterations each). Headline: 2-of-4 adds 1799 µs/payment (ci95 29 µs,
  17.7% of the bare cycle), 3-of-7 adds 4021 µs (ci95 20 µs, 39.6%), and the residual after
  subtracting the measured signer crypto is 30-172 µs -- the added cost is almost entirely the
  signer swap, as it should be. The paired stage split at 3-of-7 lands the entire delta in the two
  cross_sign stages, exactly where the signing happens. One payment costs the group 6 seam calls:
  6 round-ones (nonce derivations) and 2 round-twos (signatures), matching the eclair count.
- One honest cross-implementation caveat: `scripts/compare_runs.py` shows the two harnesses do NOT
  agree within intervals (lightning-kmp's deltas are ~68% lower in raw microseconds, and the
  machine-invariant ratio misses by 6-15% at the headline configurations). The reason is visible in
  the data: eclair's bare crypto costs ~1650 µs/payment against lightning-kmp's ~643 µs -- each
  stack's single-signer path has very different per-call overhead (scala wrappers vs direct
  calls), and the paired delta inherits that difference. The two numbers answer the same question
  relative to two different baselines; neither is wrong.
- What remains: a summariser (the existing `summarise_measurement.py` is deeply hardcoded to the
  eclair experiment), a section of `docs/report.html` for the lightning-kmp numbers (the
  `data-from` machinery is generic; the prose is not), and the docker stage below.

### Repository integration (bookkeeping this port created)

- `PINS.txt` does not mention lightning-kmp. It should record the upstream base
  (ACINQ/lightning-kmp master `db0674bd`) plus the port commits (`92f41b90..9abec431` in the
  embedded repository), with the same "not fetchable yet" caveat the eclair fork carries: the port
  commits exist only in this tree.
- `sources/README.md` likewise needs a table row, and should explain that unlike the other three
  trees, lightning-kmp's "source of truth" history lives in the embedded git repository, which is
  not published with the file copy.
- `scripts/check_vendor_sync.sh` does not cover lightning-kmp. The other trees are compared against
  sibling checkouts that development happens in; lightning-kmp IS its own live checkout (the
  embedded repo at `sources/lightning-kmp/.git`), so there is nothing to sync against -- the script
  should either say so explicitly or gain a different rule for it.
- `docker/run.sh` has no lightning-kmp stage: it builds secp256k1-kmp and bitcoin-kmp, publishes
  them, and builds/tests/measures eclair. A clone-and-docker run never compiles this port. A stage
  would publish the fork as `0.23.0-iceberg` into the container's Maven repository via
  `publish-iceberg-secp256k1.sh`, run the suites (`gradlew :lightning-kmp-core:jvmTest`), and then
  the measurement run above. `REPRODUCING.md` needs the matching line once that exists.

### Test coverage gaps

- RBF and zero-conf with an injected signer work by construction (both keep funding index 0, so the
  index guard never fires) but have no group-backed test.
- The splice block is tested at the `ChannelKeys` level (the guard throws for index != 0), not by
  driving a splice command into a group-backed channel and watching it fail.

### Explicitly still out of scope

Unchanged from the plan: native/iOS targets (possible -- the C module is there -- but new cinterop
work, and irrelevant to a JVM benchmark), and anything resembling production deployment
(distributed members, a signing protocol over the wire, persistence of in-flight signing sessions,
HSM/KMS integration). Nothing here is a down payment on those beyond the seam itself.
