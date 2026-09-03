# Porting Iceberg threshold signing to the `threshold` fork

Date: 2026-09-03
Status: **plan**

## What this is

The target is feature parity with `benchmark-iceberg/sources/lightning-kmp` (branch `master`, HEAD
`592f3844`), which carries a complete Iceberg t-of-n threshold-signing port of lightning-kmp — 15
commits, 36 files, +2687/-149 — together with its per-payment cost measurement harness.

Iceberg is a t-of-n threshold Schnorr scheme. A group occupies **one** side of a channel's 2-of-2
MuSig2 taproot funding output: the channel's funding key has no private key anywhere, and every
funding-key signature is a two-round group protocol (round one needs `2t-1` members, round two
needs `t`). The counterparty is entirely stock and cannot tell the difference.

This fork reaches the same feature set over **different plumbing**. The reference links against a
locally published binary `secp256k1-kmp` fork (`0.23.0-iceberg` in `~/.m2`) and calls a JVM-only JNI
object. This fork already resolves `bitcoin-kmp` and `secp256k1-kmp` from source through composite
builds, and its `bitcoin-kmp` fork ships a typed, **multiplatform** Iceberg API. That difference
removes work rather than adding it, and it lifts the reference's hard JVM-only ceiling.

## Where the two trees stand

| | this fork (`threshold`) | reference (`benchmark-iceberg/sources/lightning-kmp`) |
|---|---|---|
| HEAD | `9d3197fb` (`v1.13.0-7`) | `592f3844` (`v1.13.0-21`) |
| base | `db0674bd` | `db0674bd` |
| commits on base | 1, build wiring only | 15, the port |
| `modules/` vs base | **byte-identical** | 20 files changed |
| bitcoin-kmp | `experimental/bitcoin-kmp` (submodule, `includeBuild`) | Maven Central `0.31.0` |
| secp256k1-kmp | `experimental/bitcoin-kmp/experimental/secp256k1-kmp`, recursive `includeBuild` | mavenLocal `0.23.0-iceberg`, published by a script |
| Iceberg API | `fr.acinq.bitcoin.crypto.iceberg.Iceberg`, bitcoin-kmp **commonMain** | `fr.acinq.secp256k1.Iceberg`, JNI, **JVM only** |
| platform reach | jvm + linuxX64/Arm64 + macos/ios (cinterop) | jvm/linux only |

**The base is shared, so the port applies as a clean patch.** Both trees sit on `db0674bd`; this
fork's single commit touches only `settings.gradle.kts`, `.gitmodules` and `experimental/`, so
`git diff db0674bd HEAD -- modules/` is empty. Spot-checked by hashing `Commitments.kt`,
`Helpers.kt` and `KeyManager.kt` at `db0674bd` here against `92f41b90~1` there: identical. Every
Kotlin hunk in the reference port therefore applies here without conflict resolution.

## What is already done, and what drops out

The reference's first port commit, `f5cfd8f5` ("Resolve the Iceberg secp256k1-kmp fork as
`0.23.0-iceberg`"), exists to make a forked native library reachable from a Gradle build. This fork
solved that problem a different way in `9d3197fb`, and solved it better. **The entire commit is
dropped**, and with it:

- `publish-iceberg-secp256k1.sh` (74 lines) — no local publishing step at all.
- `secpjnijvm = "0.23.0-iceberg"` / `secpjnijvmupstream` in the version catalog.
- The split into three individual JNI artifacts instead of the `secp256k1-kmp-jni-jvm` aggregator.
- The `exclude(group = "fr.acinq.secp256k1")` blocks on the darwin/mingw natives.
- The `resolutionStrategy.force(...)` block guarding against Gradle ranking `0.23.0` above
  `0.23.0-iceberg`.
- `mavenLocal()` in `settings.gradle.kts`.

Why none of it is needed: `modules/core/build.gradle.kts:88` declares
`api("fr.acinq.bitcoin:bitcoin-kmp:${libs.versions.bitcoinkmp.get()}")` in **commonMain**;
`settings.gradle.kts` substitutes that module with `includeBuild("experimental/bitcoin-kmp")`; and
that build's own `settings.gradle.kts` substitutes `secp256k1-kmp` plus every JNI artifact —
including `secp256k1-kmp-jni-jvm`, which `jvmMain` names directly (bitcoin-kmp commit `dc3d25e`).
The JNI shared object carrying the Iceberg symbols is already built at
`experimental/bitcoin-kmp/experimental/secp256k1-kmp/jni/jvm/linux/build/resources/main/fr/acinq/secp256k1/jni/native/linux-x86_64/libsecp256k1-jni.so`.

**Net: the Iceberg API is reachable from lightning-kmp commonMain today, with zero build changes.**
The only build edit in this whole plan is the `icebergMeasurement` Gradle task in Phase 5.

## The one architectural difference: Iceberg is commonMain here

The reference is explicit that its Iceberg implementation must live in `jvmMain`, because
`fr.acinq.secp256k1.Iceberg` is "deliberately JVM-only" (`IcebergSigner.kt` class docs,
`ICEBERG-PORT.md` "Build and platform notes"). That constraint does not exist in this fork:

- `Iceberg` is `fr.acinq.bitcoin.crypto.iceberg.Iceberg` in bitcoin-kmp `commonMain`.
- It calls `Secp256k1.iceberg*`, an `expect` surface in secp256k1-kmp `commonMain`
  (`Secp256k1.kt:687-804`).
- Both actuals exist: `Secp256k1Jni.kt:490-566` (JNI) and `Secp256k1Native.kt:1129+` (cinterop).
- The cinterop def lists `secp256k1_iceberg.h` and `secp256k1_iceberg_dealer.h`, and
  `native/secp256k1/src/modules/iceberg/` is checked out.

**Decision: put `IcebergSigner` and `IcebergFundingSigner` in `commonMain`, not `jvmMain`.** It
costs nothing (the code is identical), it makes the session and channel suites `commonTest` rather
than `jvmTest`, and it turns the reference's permanent "native/iOS out of scope" into a Phase 7 that
is mostly a matter of running the existing tests on another target. Only the measurement harness
stays JVM-side, because it needs `JavaExec`, a fixed heap and wall-clock timing.

A second, smaller win: the JNI and native layers here **validate the group configuration in Kotlin**
before entering C (`require(n in 1..ICEBERG_MAX_PARTICIPANTS)`, `require(t in 1..(n + 1) / 2)`). The
reference needed `Iceberg.requireConfig` because a bad `(n, t)` **aborts the JVM** inside its C
module. That hazard is gone; the check that still needs a home on this side is the `2t-1` round-one
quorum, which is a lightning-kmp-level concept either way.

## API mapping

The whole of the rewrite is this table. Left is what the reference calls, right is what replaces it.

| reference — `fr.acinq.secp256k1.Iceberg` | this fork — `fr.acinq.bitcoin.crypto.iceberg.Iceberg` |
|---|---|
| `sharesGen(n, t, seed32): Array<ByteArray>` | `dealShares(n, t, seed: ByteVector32): List<Share>` |
| `shareCacheCreate(share): ByteArray` | `shareCache(share: Share): ShareCache` |
| `pubshareGen(share, cache?): ByteArray` | `publicShare(share, cache?): PublicShare` |
| `pubkeyAgg(pubshares, n, t): ByteArray` | `groupPublicKey(shares, n, t): Either<Throwable, PublicKey>` |
| `nonceGen(share, sid32, cache?): ByteArray` | `generateNonce(share, cache?, sessionId): NonceContribution` — **argument order differs** |
| `nonceAgg(pubnonces, n, t, groupPubkey): ByteArray` | `aggregateNonces(contributions, n, t, groupPublicKey): Either<Throwable, IndividualNonce>` |
| `partialSign(share, sid32, pubnonces, n, t, groupPubkey, keyaggCache, msg32, cosignerAggnonce, cache?)` | `partialSign(share, cache?, sessionId, contributions, groupPublicKey, keyAggCache, message, cosignerAggregatedNonce): Either<Throwable, SignatureShare>` — **no `n`/`t`, different order, typed `KeyAggCache`/`AggregatedNonce`** |
| `partialSigAgg(psigs, n, t): ByteArray` | `aggregatePartialSignatures(shares, n, t): Either<Throwable, ByteVector32>` |
| `partialSigVerify(...): Int` | `verifyPartialSignature(...): Boolean` |
| `requireConfig(n, t)` | — enforced in `Secp256k1Jni`/`Secp256k1Native` |
| `quorum(t) = 2t - 1` | — **must be reintroduced** in `IcebergGroup` |
| — | `keyAggregationCheck(keyAggCache, publicKeys, groupPublicKey): Boolean` — **new; wire it in** |
| `Secp256k1.musigNonceAgg(...)` (raw) | `IndividualNonce.aggregate(list): Either<Throwable, AggregatedNonce>` |

Consequences for the port:

- Opaque `ByteArray`s become `Share` / `ShareCache` / `PublicShare` / `NonceContribution` /
  `SignatureShare`. `Share.toString()` is `"<iceberg_share>"`, so `IcebergGroup` no longer needs its
  hand-written `toString` to keep key material out of logs.
- `keyaggCacheFor` stops round-tripping through `ByteArray`: `partialSign` takes a `KeyAggCache`
  directly, so it returns the typed cache from `KeyAggCache.create` / `KeyAggCache.tweak`.
- The failure style changes from throw-and-catch to `Either`. `fr.acinq.bitcoin.utils` provides
  `map` / `flatMap` / `getOrElse`; the seam's methods already return
  `Either<Throwable, PartialSignatureWithNonce>`, so the plumbing gets shorter, not longer.
- `keyAggregationCheck` is a genuinely new safety net the reference could not use: it asserts the
  outer cache aggregates exactly the expected key list, in order, with the group key among them.
  Call it once per signing session. The failure it catches — a partial signature that is well-formed
  and simply does not combine, because the key order or the BIP341 tweak differed — is the single
  most expensive class of bug in this port, and it is otherwise invisible until aggregation.

---

# Phases

Effort figures assume one engineer who has read `ICEBERG-PORT.md` and `ICEBERG-SPLICE.md` in the
reference tree. Each phase ends at a green build and is independently committable.

## Phase 0 — Prove the toolchain reaches Iceberg (gate) — ~0.5 day

**Status: done.** `IcebergToolchainScratchTest` (commonTest, run on jvmTest) is green, 7/7, with no
build changes. Four things it established, beyond "the symbols are there":

- The group key aggregated over a `2t-1` quorum of public shares **equals** the one over all `n`, so
  the port's keygen may aggregate over the quorum as the reference does.
- Round one really is a pure function of the session label — the same label re-derives the same
  contributions, a different label does not.
- An illegal `(n, t)` throws a plain exception rather than aborting the process, so
  `Iceberg.requireConfig` has no counterpart to port.
- Signing twice under one session label raises no error at all, and produces two different signature
  shares. The hazard is real and entirely the caller's to avoid.

One thing it did **not** establish: whether a member that sat out round one can still sign in round
two. bitcoin-kmp's own suite only ever signs with round-one contributors, so the reference's
`roundTwo` doc claim to the contrary is untested. Phase 3 keeps `signers ⊆ contributors` and drops
the claim.

Nothing below is worth starting until a JVM test inside `modules/core` can deal shares and produce
an aggregate signature. This phase writes throwaway code and deletes it.

1. `./gradlew :lightning-kmp-core:jvmTest --tests '*Musig2*'` — confirms the composite build resolves
   and the substituted bitcoin-kmp still satisfies lightning-kmp's existing MuSig2 use. The fork is
   `0.32.0-SNAPSHOT` against upstream's `0.31.0`, and the substitution ignores versions, so this is
   also the check that no bitcoin-kmp API drifted under lightning-kmp.
2. Add a scratch `commonTest` that calls `Iceberg.dealShares(4, 2, randomBytes32())`,
   `shareCache`, `publicShare`, `groupPublicKey`, and asserts a valid `PublicKey` comes back. Run it
   on `jvmTest`. This proves the JNI `.so` on the substituted classpath carries the Iceberg symbols —
   the failure mode being an `UnsatisfiedLinkError`, which is exactly what the reference's whole
   `resolutionStrategy.force` apparatus existed to prevent.
3. Extend it to a full 2-of-4 sign-and-verify against a stock MuSig2 cosigner, straight out of
   bitcoin-kmp's own `IcebergTestsCommon.kt`. Delete the scratch test once Phase 3 lands its real
   equivalent.

**Exit criterion:** a 2-of-4 group and a single-key cosigner produce a BIP340 signature that
verifies, from within `modules/core`'s test classpath.

**If this fails**, everything downstream is blocked, and the fallback is the reference's approach
(publish the fork to mavenLocal under a distinct version). Do not start Phase 1 before knowing which
world you are in.

## Phase 1 — The seam: `FundingSigner` + `ChannelKeys` — ~0.5 day

**Status: done.** Copied verbatim from the reference at `592f3844`; the diffstat matched its
`623179f4` exactly (KeyManager +61, Transactions +5), confirming the shared-base claim in practice
rather than only by hashing. `FundingSigner.kt` was taken at HEAD state, so design A's
`PublishedNonceSession` is already in place and `78b7718e` never needs replaying. Full jvmTest suite
green at **918** (911 baseline + the 7 phase-0 probes), and `compileKotlinLinuxX64` green — the new
commonMain code is target-agnostic, which is what phase 3 will depend on.

Port the reference's `623179f4`, **at its HEAD state** — that is, with `78b7718e`
("Generalize the closee-nonce session into a published-nonce session") already folded in. Taking
`78b7718e` as a separate later commit, as the reference's history does, means writing
`CloseeNonceSession` and then renaming it; there is no reason to repeat that here.

Files (copy verbatim from the reference at `592f3844`):

- `modules/core/src/commonMain/kotlin/fr/acinq/lightning/crypto/FundingSigner.kt` — **new**, 207
  lines. The interface, `VerificationNonceId`, `PublishedNonceSession`, `PrivateKeyFundingSigner`.
- `modules/core/src/commonMain/kotlin/fr/acinq/lightning/crypto/KeyManager.kt` — `ChannelKeys` gains
  `injectedFundingSigner: FundingSigner? = null`, the poison-pill `fundingKey`, plus
  `fundingPublicKey`, `fundingSigner`, `withFundingSigner`, `requireIndexZero`.
- `modules/core/src/commonMain/kotlin/fr/acinq/lightning/transactions/Transactions.kt` — +5 lines,
  `ChannelSpendTransaction.taprootSighash(extraUtxos)`.

Three design points to preserve rather than re-derive — each is a scar from the eclair port:

- **One seam, not two.** The same object supplies the funding *public* key and every funding-key
  *signature*, so they cannot disagree. An abstraction covering only signing leaves the on-chain
  pubkey as `fundingKey(i).publicKey()`, and the mismatch surfaces much later as an unexplained
  invalid signature.
- **`fundingKey` is a poison pill, not a fallback.** When a signer is injected it throws. Returning a
  locally derived key would be the wrong key.
- **Sign against `ChannelSpendTransaction`, not `CommitTx`.** Typing to the common supertype is what
  makes mutual close and splice reachable through the same two methods.

**Verification:** full suite green with no behaviour change — `PrivateKeyFundingSigner` is call-for-
call the previous code. At this point nothing calls the seam yet.

## Phase 2 — Route every funding-key call site — ~0.5–1 day

**Status: done.** Both grep gates pass exactly as specified below: no `fundingKey(` survives outside
`crypto/KeyManager.kt`, and all 8 `privateKey("...")` escape hatches are segwit-v0 ECDSA branches.
The coverage probe reproduced the reference's result to the test — planting `error()` in the routed
taproot shared-input branch fails **39 of 54** `SpliceTestsCommon` tests, the same 39 the reference
reports. Full suite green at 918.

Two test-side call sites were forced by the routing and fixed here rather than in phase 4, because
they are call sites rather than injection plumbing: `TestsHelper.useAlternativeCommitSig` and
`AnchorOutputsTestsCommon` both pass a funding key to `Commitments.makeLocalTxs`, whose parameter
became `localFundingPubkey`.

Port `5e44eac7` at HEAD state, which folds in `78b7718e`'s renames and `592f3844`'s taproot
shared-input routing (splice design A). 13 files:

| file | what changes |
|---|---|
| `channel/Commitments.kt` | **[P]** `RemoteCommit.sign` (`:176-205`), `Commitment.sendCommit` (`:584-617`), `LocalCommit.fromCommitSig` (`:106-143`), `receiveCommit` (`:911-946`), `fullySignedCommitTx` (`:282-299`); pubkey swaps at `:303-308,1178` |
| `channel/Helpers.kt` | **[P]** mutual close: closer (`:314-340`), closee (`:390-440`), finalize (`:479-500`); pubkey at `:552,756` |
| `channel/InteractiveTx.kt` | **[P]** first-commit fresh-nonce sign (`:1257-1259`), verification nonces (`:784-785`), shared-input taproot sign via `signWithPublishedNonce` (`:46-61`); `localFundingNonce` becomes a `PublishedNonceSession?`; pubkey at `:115-119,745,1233` |
| `channel/states/Channel.kt` | **[P]** verification-nonce re-derivation (`:305-315,342-365,422-426`) |
| `channel/states/Syncing.kt` | **[P]** `:519-520` |
| `channel/states/WaitForFundingSigned.kt` | **[P]** `:171` |
| `channel/states/Normal.kt`, `ShuttingDown.kt`, `Negotiating.kt` | `localCloseeNonce` retyped to `FundingSigner.PublishedNonceSession?`; splice pubkeys at `Normal.kt:423,470` |
| `channel/states/WaitForInit.kt`, `WaitForOpenChannel.kt` | `fundingKey(0).publicKey()` → `fundingPublicKey(0)` |
| `json/JsonSerializers.kt` | `PublishedNonceSessionSerializer` |

**Do not shortcut the pubkey swaps.** Every surviving `fundingKey(i).publicKey()` is a place a
threshold-backed channel throws at runtime instead of failing to compile. The exit criterion is a
grep, and it is exact — at the reference's HEAD, the only `fundingKey(` occurrences left anywhere in
`commonMain` are the three inside `KeyManager.kt` itself (its declaration, and the two null branches
of `fundingPublicKey`/`fundingSigner`), plus one in a comment:

```bash
grep -rn 'fundingKey(' modules/core/src/commonMain/kotlin/fr/acinq/lightning/ | grep -v fundingKeyPath
```

Anything outside `crypto/KeyManager.kt` in that output is an unrouted call site.

The private key survives only behind the named escape hatch, and at the reference's HEAD all **eight**
of those sites are segwit-v0 ECDSA branches: `Commitments.kt:201,292,607`, `InteractiveTx.kt:56,1267`,
`Helpers.kt:317,432,486`. Every one names `(segwit-v0)` in its operation string. If a ninth appears,
or one of these loses its `AnchorOutputs` guard, a taproot path has been left on the private key.

**Verification:** the existing suite is the regression proof. The reference reports **931 tests
green** after the equivalent change, and confirms the rewritten taproot shared-input branch is really
exercised by probing it with `error()` and watching 39 of `SpliceTestsCommon`'s 54 tests fail. Repeat
that probe here; a refactor that no test covers is not a refactor that passed.

One inert behaviour change to expect: `Transactions.LocalNonce` compares structurally while
`PublishedNonceSession` compares by identity, so `InteractiveTxSession` stops comparing equal across
two independently built sessions. Nothing depends on it — `SpliceTestsCommon` never names the type,
and only `InteractiveTxSigningSession` is serialized.

## Phase 3 — The Iceberg signer (the only genuinely new code) — ~1–2 days

Rewrite `IcebergSigner.kt` (272 lines) against the typed API, **into `commonMain`**:

`modules/core/src/commonMain/kotlin/fr/acinq/lightning/crypto/IcebergSigner.kt`

Structure carries over unchanged: `IcebergGroup` (key material), `IcebergSigner` (keygen / round one
/ round two / cache / cosigner aggnonce), `IcebergFundingSigner` (the `FundingSigner` impl). Sketch:

```kotlin
data class IcebergGroup(
    val n: Int, val t: Int,
    val groupPublicKey: PublicKey,
    val shares: List<Share>,          // 1-based member k -> shares[k - 1]
    val publicShares: List<PublicShare>,
    val caches: List<ShareCache>
) {
    /** Round one needs this many members online. Round two needs only [t]. */
    val quorum: Int = 2 * t - 1
}

object IcebergSigner {
    fun keygen(n: Int, t: Int, seed: ByteVector32): IcebergGroup {
        // (n, t) is validated inside Secp256k1Jni/Secp256k1Native -- no requireConfig needed.
        val shares = Iceberg.dealShares(n, t, seed)
        val caches = shares.map { Iceberg.shareCache(it) }
        val publicShares = shares.zip(caches).map { (s, c) -> Iceberg.publicShare(s, c) }
        // pubkey aggregation needs a quorum of 2t-1 public shares, not all n.
        val groupKey = Iceberg.groupPublicKey(publicShares.take(2 * t - 1), n, t).getOrElse { throw it }
        return IcebergGroup(n, t, groupKey, shares, publicShares, caches)
    }

    data class RoundOneResult(val publicNonce: IndividualNonce, val contributions: List<NonceContribution>)

    fun roundOne(group: IcebergGroup, contributors: List<Int>, sid: ByteVector32): RoundOneResult { ... }

    fun roundTwo(
        group: IcebergGroup, signers: List<Int>, sid: ByteVector32,
        roundOne: RoundOneResult, keyAggCache: KeyAggCache,
        message: ByteVector32, cosignerAggregatedNonce: AggregatedNonce
    ): Either<Throwable, ChannelSpendSignature.PartialSignatureWithNonce> { ... }

    /** Outer session cache: same key order and BIP341 tweak the channel's own session applies. */
    fun keyAggCacheFor(publicKeys: List<PublicKey>, tweak: ByteVector32?): Either<Throwable, KeyAggCache> { ... }
}
```

Points that must not drift:

1. **Quorums differ per round.** Round one needs `2t-1` contributors; round two aggregates `t`
   signature shares. `IcebergGroup.quorum` replaces the reference's `Iceberg.quorum(t)` helper.
2. **Session labels must be unique.** Iceberg derives nonces from `sid` instead of storing them, so
   the same label answered twice leaks the share by elimination — and raises no error. Keep the
   reference's `verificationSid(id) = sha256(fundingTxId || remoteFundingPubKey || commitIndex)`
   verbatim (big-endian 8-byte index): it covers exactly the three things the private-key path's
   nonce depends on, hashed rather than concatenated because the label is exactly 32 bytes. Fresh
   and published-nonce sessions use `randomBytes32()`.
3. **The outer session must match exactly.** Aggregate in `Scripts.sort` order and apply the BIP341
   key-path tweak via `Scripts.Taproot.musig2Aggregate(publicKey, remoteFundingPubKey).tweak(Crypto.TaprootTweak.KeyPathTweak)`.
   A partial signature under any other key order, or with no tweak, is well-formed and simply does
   not combine.
4. **New here: assert it.** After building the cache, call
   `Iceberg.keyAggregationCheck(cache, sortedKeys, publicKey)` and fail loudly if false. This is the
   check the reference could not make.
5. **`privateKeyOrNull` is `null`, always.** Every path needing a raw key must fail by name.

`IcebergFundingSigner` implements the five seam methods; `verificationNonce` and
`publishedNonceSession` are round one only, the three signing methods are round one (re-derived from
the label) plus round two.

**Verification:** port `IcebergTaprootSessionTestsJvm.kt` (158 lines) into **`commonTest`** as
`IcebergTaprootSessionTestsCommon.kt`: a group partial signature must combine with a stock
counterparty under `musig2Aggregate` key order and the BIP341 tweak, judged by the script
interpreter (`correctlySpends`), in **both lexicographic key positions**, with an **untweaked
negative control** that must fail. Do not skip the negative control — without it the test passes for
a signer that ignores the tweak on both sides.

## Phase 4 — Test suites and signer injection — ~1–2 days

Port `2c3490ad`, moving what the reference had to keep in `jvmTest` down into `commonTest`.

`commonTest` (verbatim from the reference):
- `crypto/SignerInjectingKeyManager.kt` (12 lines) — a `KeyManager` by-delegation wrapper whose
  `channelKeys` applies `withFundingSigner`.
- `crypto/FundingSignerTestHelpers.kt` (31 lines).
- `crypto/FundingSignerTestsCommon.kt` (105 lines) — `PrivateKeyFundingSigner` is byte-for-byte
  upstream behaviour, plus the poison pill and index guard.
- `channel/TestsHelper.kt` — optional `aliceFundingSigner` / `bobFundingSigner` parameters threaded
  through `init` and `reachNormal`, applied by copying the node params' `keyManager`.
- Signature updates in `WaitForChannelReady/FundingConfirmed/FundingCreated/FundingSignedTestsCommon`
  and `AnchorOutputsTestsCommon` (mechanical, a few lines each).

`commonTest` (moved down from the reference's `jvmTest`): `IcebergChannelTestsJvm.kt` (264 lines) →
`iceberg/IcebergChannelTestsCommon.kt`. Its twelve cases are the parity checklist:

1. group operations one payment costs (the "exactly six" parity check)
2. a 2-of-4 group holds one side's funding key; the group key is in the funding output
3. a payment added and resolved; the commitment still spends the funding output
4. ten sequential payments, every commitment deriving its own non-colliding nonce
5. the group key works in **both** lexicographic positions
6. the paper's configurations, 2-of-4 and 3-of-7
7. the channel **initiator** can be group-backed, not just the non-initiator
8. force-close — the group signs its own commitment transaction
9. mutual close, group-backed side as **closee**
10. mutual close, group-backed side as **closer**
11. reconnect — verification nonces re-derive identically and the channel keeps working
12. splice on a group-backed channel fails loudly *(deleted in Phase 6, replaced by positive tests)*

**Verification:** these plus the full existing suite. Case 11 is the one that most repays attention:
it is the proof that round one really is a pure function of the session label, which is the property
the whole deterministic-nonce design rests on.

## Phase 5 — Per-payment cost measurement harness — ~1–2 days

Port `e995295a`. This is the point of the exercise and the reason the reference exists.

`modules/core/src/jvmTest/kotlin/fr/acinq/lightning/iceberg/`:
- `CountingFundingSigner.kt` (71 lines) — one counter per seam method, all routed through an
  overridable `record` hook. The round split is *observed*, not assumed: `verificationNonce` and
  `publishedNonceSession` are round one only; the three signing methods are round one plus round two.
- `IcebergBenchmark.kt` (84 lines).
- `IcebergCycleMeasurementRun.kt` (532 lines) — opens a bare channel and a group-backed channel, pays
  on both per iteration (counterbalanced), computes the per-iteration delta. `TimingFundingSigner`
  subclasses `CountingFundingSigner` to time the same counted calls.

`modules/core/build.gradle.kts` — the `icebergMeasurement` `JavaExec` task (+25 lines): jvmTest
classpath, `mainClass = fr.acinq.lightning.iceberg.IcebergCycleMeasurementRun`, `iceberg.*` system
properties passed through, `-Xms4g -Xmx4g` for a stable heap. **This is the only build change in the
plan.**

Keep these JVM-side even though Phase 3 made the signer multiplatform: the task needs `JavaExec`, and
a timing measurement wants one fixed environment.

Two adaptations for a standalone fork:

- **Output location.** The reference's runner walks up from the working directory looking for
  `PINS.txt` and falls back to `<benchmark repo>/outputs/<timestamp>-lightning-kmp-cost-per-payment`.
  There is no `PINS.txt` here. Either make `-Piceberg.out` mandatory, or default to
  `build/iceberg-measurements/<timestamp>` and keep the `PINS.txt` walk as a fallback so a run
  launched from inside a checkout of the benchmark repo still lands in its `outputs/`.
- **Pipeline contract.** Preserve the output shape exactly — `cost_per_payment.csv` (the contract
  `scripts/compare_runs.py` keys on), `paired_samples.csv`, the `cycle_stages_*.csv` splits,
  `provenance.txt`, a generated README, a `COMPLETE` marker. Keeping it means this fork's numbers
  remain comparable with the reference's `outputs/2026-08-29-091030-lightning-kmp-cost-per-payment`,
  which is the only way to tell whether the plumbing change moved the measurement.

Statistics are the eclair side's verbatim and should stay so: Bessel-corrected stddev, nearest-rank
percentiles, and a lag-1 autocorrelation widening the iid 95% CI by `sqrt((1+r)/(1-r))`.

**Verification:** a smoke run (tiny counts, thinned grid) end to end, then one full run — all 20 legal
configurations, 1500 paired iterations. Sanity gates from the reference's first full run: **exactly
six seam calls per payment** (six round-ones, two round-twos), and the residual after subtracting the
measured signer crypto should be small (30–172 µs there) — a large residual means the delta is coming
from somewhere other than the signer swap, and the measurement is measuring the wrong thing.

Expect the absolute numbers to differ from the reference's (2-of-4: +1799 µs/payment; 3-of-7:
+4021 µs). Different secp256k1 build flags and a different JNI path change per-call overhead. The
reference already documents that its own two harnesses disagree by ~68% in raw microseconds while
agreeing on structure; **compare structure, not absolute microseconds**, unless both runs are on the
same machine.

## Phase 6 — Splice: lift the index guard (design B) — ~1.5–2 days

Design A — routing the shared-input signature through the seam — arrives free in Phase 2, because it
is already at the reference's HEAD (`592f3844`). What remains is the reference's own open item.

An injected signer carries one key, so `ChannelKeys.fundingPublicKey` / `fundingSigner` currently
throw for any index other than 0, which is where `SpliceInit` / `SpliceAck` (`Normal.kt:423,470`)
hit it.

**Design B: serve the same group key at every index.**

- Drop `requireIndexZero` from `fundingPublicKey` and `fundingSigner`. `fundingKey` stays a poison
  pill at every index.
- Consequence: the local side of the funding output does not rotate across splices. Rotation is a
  privacy habit, not a protocol requirement. **Verify this before relying on it** — read the
  `splice_init` handling in `Normal.kt` and the interactive-tx parameter validation for any
  comparison against the previous funding key.
- No session-label collision: the verification-nonce identity is
  `(fundingTxId, remoteFundingPubKey, commitIndex)`, the funding txid changes with the splice, and
  commit indices keep increasing.
- Rejected alternative: a fresh group per index. The in-process simulation could do it, but the
  deterministic re-derivation a real deployment would want does not map onto a DKG, and it changes
  nothing measurable.

Tests (replacing case 12 from Phase 4):

1. Splice-in and splice-out on a group-backed channel, group as initiator **and** as accepter: the
   new funding output script contains the group key, `tx_signatures` complete (the stock counterparty
   checks the shared-input signature), payments work before and after, both sides' commitments on the
   new funding output pass `correctlySpends`.
2. Mutual close after a splice, group as closer and as closee, against the new funding output.
3. RBF of a splice — a fresh funding-nonce session per attempt, no reuse.
4. Disconnect mid-splice and resume — the rebuilt session publishes a fresh nonce.
5. `SpliceTestsCommon` et al. pass unmodified.

This is where this fork can **exceed** the reference, which still blocks splices loudly.

## Phase 7 — Native and iOS targets (beyond parity) — ~1–2 days

Not available to the reference at all, and cheap here because Phase 3 put the signer in `commonMain`.

1. Run `IcebergTaprootSessionTestsCommon` and `IcebergChannelTestsCommon` on `linuxX64Test`. The
   native actuals and the cinterop bindings exist; the static `libsecp256k1.a` is already built at
   `native/build/linux/`. This is a "does it run" step, not a porting step.
2. Then `linuxArm64`, then (on a macOS host) `macosArm64` and the iOS simulator targets.
3. Watch for the one known native-side fix in the fork's history — `07f7dcc` "Fix native FROST
   bindings collapsing empty messages to absent ones" — as evidence that the native bindings have had
   less exercise than the JNI ones. Empty/absent argument handling is the place to look first if a
   test passes on JVM and fails on native.

Nothing about the channel state machine is JVM-specific, so a green run here means threshold-backed
channels work on every target lightning-kmp supports.

## Phase 8 — Documentation — ~0.5 day

Update this file to `Status: implemented` with an implementation-notes section recording where
reality differed, as the reference does. Port `ICEBERG-SPLICE.md` with design B marked implemented.
Record the measurement run and its headline numbers.

---

# Risks and open questions

| risk | why it matters | mitigation |
|---|---|---|
| The bitcoin-kmp fork (`0.32.0-SNAPSHOT`) has drifted from `0.31.0` under lightning-kmp | Phase 2 touches 13 channel files; a bitcoin-kmp API change would be diagnosed as a port bug | Phase 0 step 1 runs the existing suite against the substituted fork **before** any port code exists |
| Native Iceberg bindings less exercised than JNI | Phase 7 could turn from a test run into a debugging exercise | Phase 7 is explicitly beyond parity — descope without affecting the deliverable |
| Absolute measurement numbers will not match the reference | Someone reads a difference as a regression | Compare structure (seam-call counts, stage split, ratio) not raw microseconds; run both on one machine if a direct comparison is genuinely needed |
| Session-label reuse | Silent share leakage; no error is raised | Keep the reference's `verificationSid`; keep the one-session-signs-once rule on `PublishedNonceSession`; case 4 of Phase 4 tests nonce distinctness over ten payments |
| Splice key rotation may be validated somewhere | Design B produces a funding output the peer rejects | Explicit read of `splice_init` handling and interactive-tx parameter validation before removing the guard |
| `n <= 10`, `1 <= t <= (n+1)/2` | 2-of-2 and 3-of-4 are inexpressible; 2-of-4 is the smallest usable group | Validated in Kotlin here, unlike the reference — a bad config throws instead of aborting the process |

**Out of scope, same as the reference.** This is an in-process simulated group holding all shares in
one process. A real deployment — distributed members, a signing protocol over the wire, persistence of
in-flight sessions, HSM/KMS integration — is a different and much larger project, and nothing here is
a down payment on it beyond the seam. The scheme itself is experimental: neither Iceberg nor its
implementation has been reviewed outside the project, and it must not protect anything of value.

# Effort summary

| phase | work | estimate |
|---|---|---|
| 0 | Prove the toolchain reaches Iceberg | ~0.5 day |
| 1 | `FundingSigner` seam + `ChannelKeys` (cherry-pick) | ~0.5 day |
| 2 | Route every funding-key call site (cherry-pick) | ~0.5–1 day |
| 3 | `IcebergSigner` rewritten against the typed API, in commonMain | ~1–2 days |
| 4 | Test suites and signer injection | ~1–2 days |
| 5 | Per-payment cost measurement harness | ~1–2 days |
| **subtotal — parity with the reference** | | **~1–1.5 weeks** |
| 6 | Splice design B + tests (exceeds the reference) | ~1.5–2 days |
| 7 | Native/iOS targets (exceeds the reference) | ~1–2 days |
| 8 | Documentation | ~0.5 day |
| **total** | | **~2–2.5 weeks** |

The reference estimated 2–3 weeks for the same parity scope and spent roughly that. This fork gets
Phases 1, 2 and most of 4 as clean cherry-picks off a shared base, and skips the whole build-plumbing
commit, which is where the saving comes from.

# Parity checklist

Feature parity with `592f3844` means all of the following:

- [ ] `FundingSigner` seam in `commonMain`, with `PrivateKeyFundingSigner` byte-for-byte upstream
- [ ] `ChannelKeys` poison pill, `fundingPublicKey`, `fundingSigner`, `withFundingSigner`
- [ ] Every funding-key call site routed; no unaudited `fundingKey(` on a taproot path
- [ ] `IcebergSigner` / `IcebergFundingSigner` producing signatures that combine with a stock peer
- [ ] Taproot session pinned end to end, both key orderings, untweaked negative control
- [ ] Channel suite: open, pay both directions, ten payments, force-close, mutual close both roles,
      reconnect, initiator and non-initiator group-backed, 2-of-4 and 3-of-7
- [ ] Existing suite green with the default signer (the stock-channel regression proof)
- [ ] `CountingFundingSigner` reporting exactly six seam calls per payment
- [ ] `icebergMeasurement` task producing the pipeline's output contract
- [ ] One full run: 20 configurations × 1500 paired iterations
- [ ] Splice design A routed through the seam (free from Phase 2)

Beyond parity: splice design B with positive tests, and the signer running on native/iOS targets.
