# Nested FROST+MuSig2 threshold signer — implementation plan

Goal: let a FROST `t`-of-`n` group occupy ONE participant slot of a taproot channel's 2-of-2
MuSig2 funding output, as a second `FundingSigner` implementation next to the existing Iceberg
one (`modules/core/src/commonMain/kotlin/fr/acinq/lightning/crypto/IcebergSigner.kt`).

Construction: the nested signing scheme from <https://github.com/jesseposner/frosty-musig>
(`docs/FROSTyMuSig.pdf` there), whose signing equation is

    s_i = k_1,i + b_frost · b_musig · k_2,i + e_musig · a_musig · λ_i · d_i

where `b_frost` is the FROST group's nonce-binding coefficient, `b_musig`/`e_musig`/`a_musig`
belong to the OUTER MuSig2 session (challenge over the aggregate key, key-aggregation
coefficient of the group pubkey), and `λ_i` is signer `i`'s Lagrange interpolating value. The
group's wire nonce is its FROST aggregate nonce with the second component pre-multiplied by
`b_frost`. The vendored secp256k1 fork already contains a working example of this exact
architecture — the iceberg module — so every nesting mechanic below has an in-tree template.

## Design decisions (read first)

1. **`b_frost` must NOT commit to the message.** BIP 445's nonce coefficient commits to `msg`,
   but lightning's `FundingSigner` publishes nonces BEFORE the transaction exists
   (`verificationNonce`, `publishedNonceSession`). The iceberg module solves the same problem
   with its own `Iceberg/noncecoef` tag over `(R1, R2', P)` and lets the OUTER `b_musig` (which
   does commit to the message, via `secp256k1_musig_nonce_process_internal`) bind it. We do the
   same: `b_frost = tagged_hash("NestedFrost/noncecoef", ser32(u) || sorted ids || aggnonce66 ||
   xbytes(thresh_pk))`. This deviates from BIP 445's coefficient and must be called out in the
   security notes; the outer challenge still binds the message, as in iceberg.
2. **Label-derived deterministic nonces, iceberg-style.** FROST's `SecretNonce` is random and
   single-use, which does not fit `FundingSigner.verificationNonce` (published early, re-derived
   later by a possibly fresh signer instance). Fix: drive `secp256k1_frost_nonce_gen` with
   `session_secrand32 = tagged_hash("NestedFrost/session", sessionId || member_id)` and
   `msg = NULL` both at publication and at signing time, making each member's nonce a pure
   function of `(secshare, sessionId)`. The safety invariant is identical to iceberg's: ONE
   sessionId signs ONE message, group-wide, or keys leak without any error being raised.
   `Frost.deterministicSign` (BIP 445 DeterministicSign) is NOT usable: it binds the message,
   which is unknown when the nonce is published.
3. **No FROST-level key tweak in the channel flow.** The group's threshold pubkey enters the
   outer `Scripts.sort` key aggregation untweaked; the BIP341 key-path tweak is applied to the
   MuSig2 aggregate key and is handled by the stock outer session (`keyagg_cache.s_part`). The
   nested aggregator is therefore a plain sum of partial signatures in v1, and must FAIL if
   handed a tweaked FROST tweak cache (`tacc != 0`); a tweak-aware aggregation variant
   (folding `e_musig · g_musig · tacc` like frosty-musig's `nested_frost_partial_sig_agg`) is
   an optional later extension.
4. **No new opaque C types.** Follow iceberg's sessionless API: every call takes all session
   parameters explicitly (ids, pubshares, aggnonce, group key, outer keyagg cache, cosigner
   aggnonce, msg32). This avoids new `data[N]` blobs, new magics, and new `*_SIZE` constants in
   three synced places. All new functions live in the EXISTING frost module/header so neither
   `libsecp256k1.def` nor the gradle/CMake wiring changes.
5. **Quorum is `t` in BOTH rounds** (vs iceberg's `2t-1`/`t`), and any `t`-of-`n` is expressible
   — 2-of-2 and 3-of-4, which iceberg forbids, become available. `n` is bounded by
   `SECP256K1_FROST_MAX_PARTICIPANTS` (128).

## Repo layout reminder

- Vendored C fork (git submodule): `experimental/bitcoin-kmp/experimental/secp256k1-kmp/native/secp256k1`
  (upstream `code.sigidli.com/frost/secp256k1-zkp.git`, HEAD `03db8281`, has `frost`,
  `chilldkg`, `iceberg` modules).
- KMP wrapper: `experimental/bitcoin-kmp/experimental/secp256k1-kmp` — common `interface
  Secp256k1`, JNI actual (`jni/`), cinterop actual (`src/nativeMain`), tests in `tests/`.
- bitcoin-kmp fork: `experimental/bitcoin-kmp` — `fr.acinq.bitcoin.crypto.frost.Frost` and
  `crypto.iceberg.Iceberg` already exist; composite build substitutes it into lightning-kmp.
- lightning-kmp: `modules/core` (gradle name `:lightning-kmp-core`); the `FundingSigner` seam
  is in `modules/core/src/commonMain/kotlin/fr/acinq/lightning/crypto/FundingSigner.kt`.

---

## Phase 1 — C fork: nested-signing functions in the frost module

All work in `experimental/bitcoin-kmp/experimental/secp256k1-kmp/native/secp256k1` (a submodule:
commit there, on a branch, first). Everything lives in the frost module so it compiles into the
same translation unit as the musig module and can call its `static` internals — exactly what
`src/modules/iceberg/session_impl.h` does (`#include "../musig/keyagg.h"`, calls
`secp256k1_musig_nonce_process_internal`, `secp256k1_musig_keyaggcoef`,
`secp256k1_musig_pubnonce_save`, `secp256k1_musig_aggnonce_load`, `secp256k1_keyagg_cache_load`).

### 1.1 Public API — declare in `include/secp256k1_frost.h`

Copy the annotation style of `secp256k1_frost_sign` (`SECP256K1_API SECP256K1_WARN_UNUSED_RESULT
int`, `SECP256K1_ARG_NONNULL(...)`).

```c
/* Aggregate member pubnonces and export the group's OUTER-wire nonce:
 * pubnonce_out = (R1, b_frost · R2) as an ordinary musig pubnonce (this is what
 * goes on the lightning wire); aggnonce_out = the UNSCALED frost aggnonce,
 * which signers need later for partial signing.
 * b_frost = tagged_hash("NestedFrost/noncecoef", u || sorted ids || aggnonce || thresh_pk).
 * Fails if a scaled component is infinity (a musig pubnonce cannot encode it —
 * same guard as iceberg's publish_nonce). */
int secp256k1_frost_nested_nonce_agg(
    const secp256k1_context *ctx,
    secp256k1_musig_pubnonce *pubnonce_out,
    secp256k1_frost_aggnonce *aggnonce_out,
    const secp256k1_frost_pubnonce *const *pubnonces,
    const uint32_t *ids, size_t n_signers,
    const secp256k1_pubkey *thresh_pk);

/* One member's nested partial signature: s_i = k1 + b_frost·b_musig·k2
 *   + e_musig · a_musig · λ_i · g_musig · gacc_musig · d_i
 * with both k's negated iff the OUTER final nonce has odd Y. keyagg_cache is
 * the OUTER (already BIP341-tweaked) musig cache; cosigner_aggnonce aggregates
 * the non-frost participants only. secnonce is wiped. Self-verify the share
 * before returning, like secp256k1_frost_sign_internal does. */
int secp256k1_frost_nested_sign(
    const secp256k1_context *ctx,
    secp256k1_frost_partial_sig *partial_sig,
    secp256k1_frost_secnonce *secnonce,
    const unsigned char *secshare32,
    uint32_t my_id,
    const uint32_t *ids, const secp256k1_pubkey *pubshares, size_t n_signers,
    const secp256k1_frost_aggnonce *aggnonce,
    const secp256k1_pubkey *thresh_pk,
    const secp256k1_musig_keyagg_cache *keyagg_cache,
    const secp256k1_musig_aggnonce *cosigner_aggnonce,
    const unsigned char *msg32);

/* Verify member i's nested share:
 * s_i·G == R1_i + b_frost·b_musig·R2_i + e·a·λ_i·g·gacc·P_i  (nonce points
 * negated iff outer fin-nonce odd). Recomputes the full session from the
 * same params as secp256k1_frost_nested_sign. */
int secp256k1_frost_nested_partial_sig_verify(
    const secp256k1_context *ctx,
    const secp256k1_frost_partial_sig *partial_sig,
    const secp256k1_frost_pubnonce *pubnonce,
    const secp256k1_pubkey *pubshare,
    uint32_t my_id,
    const uint32_t *ids, size_t n_signers,
    const secp256k1_frost_aggnonce *aggnonce,
    const secp256k1_pubkey *thresh_pk,
    const secp256k1_musig_keyagg_cache *keyagg_cache,
    const secp256k1_musig_aggnonce *cosigner_aggnonce,
    const unsigned char *msg32);

/* Sum member shares and export the result as a stock musig partial signature,
 * ready for secp256k1_musig_partial_sig_agg alongside the cosigner's.
 * tweak_cache is the FROST tweak cache of thresh_pk and MUST be the identity
 * (tacc == 0, gacc_parity == 0) — the channel flow tweaks only the outer
 * aggregate key, and the outer musig session already adds its own
 * e·g·tweak term. Fails otherwise (see Design decision 3). */
int secp256k1_frost_nested_partial_sig_agg(
    const secp256k1_context *ctx,
    secp256k1_musig_partial_sig *sig_out,
    size_t *error_index,
    const secp256k1_frost_partial_sig *const *partial_sigs, size_t n_sigs,
    const secp256k1_frost_tweak_cache *tweak_cache);
```

### 1.2 Implementation — `src/modules/frost/session_impl.h` (or a new
`nested_impl.h` included from `src/modules/frost/main_impl.h`)

Reuse, do not re-implement:

- λ_i: `secp256k1_frost_derive_interpolating_value` (`src/modules/frost/keygen_impl.h:103`).
- Frost session values for shape reference: `secp256k1_frost_get_session_values`
  (`session_impl.h:590`) — but we need our own `secp256k1_frost_nested_session_values` that
  computes b_frost WITHOUT msg, scales the second aggnonce component by b_frost
  (`secp256k1_frost_effective_nonce`-style ecmult), then adds the cosigner aggnonce points and
  calls `secp256k1_musig_nonce_process_internal` (`musig/session_impl.h:566`) for b_musig,
  fin_nonce and its parity, and finally `secp256k1_schnorrsig_challenge` for e_musig. Iceberg's
  `secp256k1_iceberg_session_values` (`iceberg/session_impl.h:429`) is a line-for-line template.
- a_musig: `secp256k1_musig_keyaggcoef_internal` (`musig/keyagg_impl.h:106`) on the group
  pubkey; key-side parity: negate iff `fe_is_odd(cache_i.pk.y) != cache_i.parity_acc`
  (`musig/session_impl.h:685`).
- Export: `secp256k1_musig_pubnonce_save` / `secp256k1_musig_partial_sig_save` /
  `secp256k1_frost_partial_sig_save`; load counterparts for inputs.
- Wire format: the exported musig pubnonce serializes to the standard 66 bytes
  (`secp256k1_musig_pubnonce_serialize`), so the remote peer needs nothing new.

Parity checklist (the main trap — three independent negations interact):

1. Nonce side: negate `k1`, `k2` iff the OUTER session's final nonce R has odd Y.
2. Key side (musig): coefficient on `d_i` is `e_musig · a_musig · λ_i`, times −1 iff
   `odd(agg_tweaked_pk.y) != parity_acc` of the OUTER keyagg cache.
3. Frost key-side tweak (`g_frost·gacc_frost`) is absent in v1 because the frost tweak cache is
   the identity (decision 3) — but ASSERT that, rather than silently ignoring a tweaked cache.

### 1.3 C tests — `src/modules/frost/tests_impl.h`

Model on `iceberg/tests_impl.h` (`tests.c` picks them up under the existing
`ENABLE_MODULE_FROST` guard — no build wiring change):

- Round-trip: 2-of-3 nested group + one stock musig cosigner; `musig_nonce_agg` over
  [group pubnonce, cosigner pubnonce], stock `musig_nonce_process`, stock
  `musig_partial_sign` for the cosigner, `secp256k1_frost_nested_sign` × 2,
  `secp256k1_frost_nested_partial_sig_agg`, stock `secp256k1_musig_partial_sig_agg`, then
  `secp256k1_schnorrsig_verify` against the tweaked aggregate xonly key. Cover t-of-n =
  {2-of-2, 2-of-3, 3-of-5} and both lexicographic positions of the group key.
- With an xonly tweak applied to the OUTER keyagg cache (the BIP341 case).
- `nested_partial_sig_verify` accepts valid shares, rejects a tampered share and a share
  signed under the wrong id set.
- Infinity guard: crafted aggnonce whose scaled second component is infinity fails
  `nested_nonce_agg` (mirror iceberg's publish-nonce failure path).
- Wrong-key-order / missing-tweak shares are well-formed but fail final schnorr verification
  (negative control).
- Nonce reuse: calling `nested_sign` twice with the same secnonce fails (secnonce wiped).

### 1.4 Optional in this phase

- `examples/frost_nested.c` (mirror `examples/iceberg.c`) and a `doc/frost_nested.md` — the
  doc is worth doing because decision 1 deviates from BIP 445 and decision 2 redefines nonce
  derivation; both must be written down where reviewers will find them.
- ctime test entry (iceberg has one in `ctime_tests.c`).

### Phase 1 verification

```
cd experimental/bitcoin-kmp/experimental/secp256k1-kmp/native/secp256k1
cmake -B build -DSECP256K1_ENABLE_MODULE_FROST=ON -DSECP256K1_ENABLE_MODULE_MUSIG=ON \
      -DSECP256K1_BUILD_TESTS=ON -DSECP256K1_BUILD_EXAMPLES=ON
cmake --build build && ./build/bin/tests
```

Deliverable: submodule commit with header decls, impl, tests green.

---

## Phase 2 — secp256k1-kmp bindings (JVM + Native)

In `experimental/bitcoin-kmp/experimental/secp256k1-kmp/`. No gradle or `.def` changes: the
frost module is already CMake-enabled (`native/build.gradle.kts:12`) and `secp256k1_frost.h` is
already in `src/nativeInterop/cinterop/libsecp256k1.def`, so cinterop picks the new functions
up automatically. Four functions to expose, plus `frost_nonce_gen` reuse.

1. `src/commonMain/kotlin/fr/acinq/secp256k1/Secp256k1.kt` — add to `interface Secp256k1`
   (KDoc style of `frostSign`, line 454):
   - `fun frostNestedNonceAgg(pubnonces: Array<ByteArray>, ids: UIntArray, threshPk: ByteArray): Pair<ByteArray, ByteArray>` — returns (66-byte musig pubnonce, 66-byte frost aggnonce serialization).
   - `fun frostNestedSign(secnonce: ByteArray, secshare32: ByteArray, myId: UInt, ids: UIntArray, pubshares: Array<ByteArray>?, aggnonce: ByteArray, threshPk: ByteArray, keyaggCache: ByteArray, cosignerAggnonce: ByteArray, msg32: ByteArray): ByteArray`
   - `fun frostNestedPartialSigVerify(partialSig: ByteArray, pubnonce: ByteArray, pubshare: ByteArray, myId: UInt, ids: UIntArray, aggnonce: ByteArray, threshPk: ByteArray, keyaggCache: ByteArray, cosignerAggnonce: ByteArray, msg32: ByteArray): Int`
   - `fun frostNestedPartialSigAgg(partialSigs: Array<ByteArray>, tweakCache: ByteArray): ByteArray` (32-byte musig partial sig).
   - No new `const val`/magic needed (decision 4). Note: the aggnonce crossing the ABI is its
     66-byte SERIALIZATION — parse/serialize with the existing
     `secp256k1_frost_aggnonce_parse/serialize` inside the glue.
2. `src/nativeMain/kotlin/fr/acinq/secp256k1/Secp256k1Native.kt` — overrides next to
   `frostSign` (line 761): `require` size checks, `checkMagic` on the opaque inputs
   (frost secnonce/aggnonce, musig keyagg cache — magics already in the companion), `memScoped`
   + `alloc` helpers (reuse `allocFrostPubnonce`, `allocFrostTweakCache`, `allocPubshares`;
   add `allocFrostAggnonce`, `allocMusigKeyaggCache`/`allocMusigAggnonce` if absent),
   `.requireSuccess("secp256k1_frost_nested_sign() failed")`.
3. `jni/src/main/java/fr/acinq/secp256k1/Secp256k1CFunctions.java` — native declarations
   (`long ctx`, `byte[]`, `byte[][]`, `int[]`, `int` args; no new size constants).
4. `jni/c/headers/java/fr_acinq_secp256k1_Secp256k1CFunctions.h` — regenerate with
   `./gradlew :jni:generateHeaders` and CHECK IN the refreshed copy: `jni/jvm/build.sh`
   compiles against this checked-in header, not the generated one.
5. `jni/c/src/fr_acinq_secp256k1_Secp256k1CFunctions.c` — four `JNIEXPORT` functions copying
   the `frost_sign` body (lines 1663-1709): `get_bytes`/`get_bytes32`/`get_signer_ids`/
   `get_pubshares` marshalling, `CHECKMAGIC` on opaque inputs BEFORE any C call (the default
   ARG_CHECK aborts the process), `free` on every path before `CHECKRESULT`, results via
   `copy_bytes_to_java`. The musig pubnonce output of `nested_nonce_agg` is returned via
   `secp256k1_musig_pubnonce_serialize`.
6. `jni/src/main/kotlin/fr/acinq/secp256k1/Secp256k1Jni.kt` — overrides with `require`
   validation and `UIntArray → IntArray` mapping, forwarding through
   `Secp256k1Context.getContext()`.
7. `tests/src/commonTest/kotlin/fr/acinq/secp256k1/FrostNestedTest.kt` — port the C
   round-trip test (2-of-3 + stock musig cosigner, tweaked and untweaked, negative cases).
   This automatically runs on JVM and all native targets. Watch the empty/absent-argument
   paths on native — FEATURE-PARITY.md flags `07f7dcc` (native FROST bindings collapsing empty
   messages to absent ones); our nonce-gen reuse passes `msg = NULL`, which is exactly that
   hazard class.

Verification:

```
cd experimental/bitcoin-kmp/experimental/secp256k1-kmp
./gradlew :native:buildSecp256k1Host :jni:jvm:buildNativeHost :tests:jvmTest
./gradlew :tests:linuxX64Test   # or the host-appropriate native target
```

---

## Phase 3 — bitcoin-kmp: `FrostNested` API

New file `experimental/bitcoin-kmp/src/commonMain/kotlin/fr/acinq/bitcoin/crypto/frost/FrostNested.kt`
(same package as `Frost.kt`; deliberately separate from it because this composition is NOT BIP
445 — see design decisions 1–2). Shape it on `crypto/iceberg/Iceberg.kt`:

```kotlin
object FrostNested {
    /** Deterministic per-member nonce from a unique session label (msg omitted). */
    fun generateNonce(secretShare: PrivateKey, publicShare: PublicKey, groupPublicKey: PublicKey,
                      sessionId: ByteVector32, myId: UInt): Pair<Frost.SecretNonce, Frost.IndividualNonce>

    /** Group's wire nonce (a musig2 IndividualNonce) + the unscaled frost AggregatedNonce. */
    fun aggregateNonces(publicNonces: List<Frost.IndividualNonce>, signerIds: List<UInt>,
                        groupPublicKey: PublicKey
    ): Either<Throwable, Pair<fr.acinq.bitcoin.crypto.musig2.IndividualNonce, Frost.AggregatedNonce>>

    fun partialSign(secretNonce: Frost.SecretNonce, secretShare: PrivateKey, myId: UInt,
                    signerIds: List<UInt>, signerPublicShares: List<PublicKey>,
                    groupAggregatedNonce: Frost.AggregatedNonce, groupPublicKey: PublicKey,
                    keyAggCache: KeyAggCache, message: ByteVector32,
                    cosignerAggregatedNonce: musig2.AggregatedNonce): Either<Throwable, ByteVector32>

    fun verifyPartialSignature(partialSig: ByteVector32, publicNonce: Frost.IndividualNonce,
                               publicShare: PublicKey, myId: UInt, signerIds: List<UInt>, ...same session params...): Boolean

    /** Sum of member shares as a musig2 partial signature; requires the identity tweak cache. */
    fun aggregatePartialSignatures(partialSigs: List<ByteVector32>, tweakCache: Frost.TweakCache
    ): Either<Throwable, ByteVector32>
}
```

- `session_secrand32 = Crypto.sha256("NestedFrost/session" || sessionId || ser32(myId))` —
  document that `sessionId` uniqueness group-wide is the key-leak invariant, same as iceberg.
- Keygen is NOT here: reuse `Frost.trustedDealerKeygen` (ChillDKG later for dealerless).

New tests `experimental/bitcoin-kmp/src/commonTest/kotlin/fr/acinq/bitcoin/crypto/frost/FrostNestedTestsCommon.kt`
(there is no iceberg reference-vector set and no frosty-musig vector set, so behavioral tests):
full nested session against a stock `Musig2` cosigner judged by
`Crypto.verifySignatureSchnorr` on the tweaked aggregate key (mirror
`IcebergTestsCommon.kt`'s group-session test); t-of-n matrix {2-of-2, 2-of-3, 3-of-5}; label
re-derivation determinism (same sessionId → same nonce, fresh objects); tampered-share
rejection; nonce single-use enforcement; wrong-key-order negative control. If frosty-musig
publishes test vectors later, add a vectors runner like `FrostVectorsTestsCommon.kt`.

Verification: in `experimental/bitcoin-kmp`: `./gradlew jvmTest --tests "*FrostNested*"` plus
the host native test target.

---

## Phase 4 — lightning-kmp: `FrostSigner` + `FrostFundingSigner`

New file `modules/core/src/commonMain/kotlin/fr/acinq/lightning/crypto/FrostSigner.kt`,
mirroring `IcebergSigner.kt` section for section. No changes to `FundingSigner.kt`,
`KeyManager.kt`, `Transactions.kt`, or `Scripts.kt` — the seam is signer-agnostic.

- `data class FrostGroup(val n: Int, val t: Int, val groupPublicKey: PublicKey, val secretShares: List<PrivateKey>, val publicShares: List<PublicKey>, val tweakCache: Frost.TweakCache)`;
  `quorum = t` for both rounds. Keep shares out of logs (`toString` discipline — `PrivateKey`
  already redacts, but state it).
- `object FrostSigner`:
  - `keygen(n, t, seed: ByteVector32): FrostGroup` — derive the threshold secret key from the
    seed (`Crypto.sha256("FrostSigner/keygen" || seed)`), `Frost.trustedDealerKeygen`, assert
    `KeyMaterial.isValid()`. Same trusted-dealer caveat as iceberg's keygen: fine for tests,
    not a deployment.
  - `roundOne(group, contributors: List<Int>, sessionId): RoundOneResult(publicNonce: musig2
    IndividualNonce, groupAggregatedNonce, memberPublicNonces)` — `contributors.size >= t`
    (NOT 2t-1), ids distinct and in range; per-member `FrostNested.generateNonce`;
    `FrostNested.aggregateNonces`.
  - `roundTwo(group, signers, sessionId, roundOneResult, keyAggCache, message,
    cosignerAggregatedNonce): Either<Throwable, ChannelSpendSignature.PartialSignatureWithNonce>` —
    re-derive each signer's nonce from `(share, sessionId)` (decision 2 — nothing is stored
    between rounds, exactly like iceberg), `FrostNested.partialSign` per signer,
    `FrostNested.aggregatePartialSignatures`. Keep iceberg's `signers ⊆ contributors`
    requirement.
  - `keyAggCacheFor` / `cosignerAggregatedNonce` — copy verbatim from `IcebergSigner` (they
    are scheme-independent; consider hoisting them into a shared internal helper file
    `crypto/ThresholdSignerHelpers.kt` and pointing both signers at it).
- `class FrostFundingSigner(group, contributors = 1..t, signers = 1..t) : FundingSigner` —
  copy `IcebergFundingSigner`'s structure: `publicKey = group.groupPublicKey`,
  `privateKeyOrNull = null`, `verificationNonce` via `roundOne(verificationSessionId(id))`,
  all four signing entry points funnel into one private `sign(...)` that builds the session
  exactly like `Transactions.partialSign` does: `Scripts.sort(listOf(publicKey,
  remoteFundingPubKey))`, BIP341 `KeyPathTweak` from `Scripts.Taproot.musig2Aggregate(...)`,
  `tx.taprootSighash(extraUtxos)`, cosigner-only aggregated nonce. Iceberg asserts
  `Iceberg.keyAggregationCheck` on every call; there is no frost equivalent, so instead
  re-derive the aggregate key from `KeyAggCache.create(sortedKeys)` and require it equals
  `Scripts.Taproot.musig2Aggregate(...)`'s untweaked key (cheap, catches the same
  wrong-key-order failure class).
  - `verificationSessionId(id)`: same sha256 construction as iceberg's companion but with a
    distinct domain tag (e.g. prepend `"FrostSigner/verification"`) so an iceberg label and a
    frost label can never collide if a deployment ever mixes schemes.
  - `PublishedNonceSession` subclass carrying only the `sessionId` (round one re-derived from
    the label), with the same ONE-SESSION-ONE-SIGNATURE contract.

Unit/taproot tests (all `commonTest`, mirroring the iceberg files):

- `crypto/FrostSignerTestsCommon.kt` ← `IcebergSignerTestsCommon.kt`: quorum `t` (not 2t-1)
  in both rounds; expressible configs iceberg rejects (2-of-2, 3-of-4) now work; label reuse
  raises no error (hazard documentation); wrong key order caught; `privateKey(op)` refusal
  names the op; `verificationSessionId` collision-freeness over 1000 commit indices;
  foreign `PublishedNonceSession` refused; published-session nonce matches.
- `crypto/FrostTaprootSessionTestsCommon.kt` ← `IcebergTaprootSessionTestsCommon.kt` (nearly
  verbatim): reproduce the channel session by hand (`Scripts.sort`, BIP341 tweak from spec,
  self-check tweaked key == `pubkeyScript.drop(2)`), both lexicographic key positions,
  (2-of-3, 2-of-4, 3-of-5), stock `checkRemotePartialSignature`, stock `aggregateSigs`,
  judged by `Transaction.correctlySpends`, plus the untweaked negative control. Reuse
  `FundingSignerTestHelpers.buildFundingSpend` unchanged.

Verification: `./gradlew :lightning-kmp-core:jvmTest --tests "*FrostSigner*" --tests "*FrostTaprootSession*"` from the repo root.

---

## Phase 5 — channel end-to-end tests

Mirror `modules/core/src/commonTest/kotlin/fr/acinq/lightning/iceberg/IcebergChannelTestsCommon.kt`
as `modules/core/src/commonTest/kotlin/fr/acinq/lightning/frost/FrostChannelTestsCommon.kt`,
reusing the generic harness unchanged: `TestsHelper.init`/`reachNormal` already accept
`aliceFundingSigner`/`bobFundingSigner`, wrapped by `SignerInjectingKeyManager`.

Port all 12 iceberg channel tests: open with group backing (both sides), payment +
`correctlySpends` on both commitment flavors, 10 sequential payments (label advancement),
both lexicographic key positions, {2-of-3, 3-of-5}, force-close both directions, mutual close
as closee and as closer (exercises `publishedNonceSession`/`signWithPublishedNonce`),
reconnect re-derivation (a FRESH `FrostFundingSigner` must re-derive the same verification
nonce — this is the test that pins down decision 2), splice refusing loudly via
`fundingPublicKey(1)`.

Two deliberate adaptations:

- The op-count measurement test needs new expectations: FROST round one is `t`
  `generateNonce` calls + 1 `nested_nonce_agg`, round two is `t` signs + 1 agg — no 2t-1.
- `CountingFundingSigner` is already generic; consider moving it from the `iceberg` package
  to a neutral `crypto` test package and letting both suites use it.

Verification: `./gradlew :lightning-kmp-core:jvmTest --tests "*frost*"` and the host native
test target (`:lightning-kmp-core:linuxX64Test` or macOS equivalent).

---

## Phase 6 — hardening, docs, and release mechanics

1. **Security review gate.** The C code is new consensus-critical crypto: the b_frost-without-
   msg deviation (decision 1) and label-derived nonces (decision 2) need written justification
   in `doc/frost_nested.md` and external review. frosty-musig is unaudited research code; the
   vendored frost module is itself marked experimental. Keep the Kotlin API tagged with the
   same WARNING docblocks the existing `Frost` object carries. Cross-check against
   `docs/FROSTyMuSig.pdf` and confirm whether a security proof exists for the nested
   construction before any mainnet use.
2. **Nonce-hazard audit.** Every site that can call the signer twice under one sessionId must
   be enumerated (the channel flows already guarantee one-message-per-id for iceberg; re-verify
   each call site for frost, especially reconnection and RBF paths that rebuild sessions).
3. **Upstream/submodule hygiene.** The C work lands on a branch of the
   `code.sigidli.com/frost/secp256k1-zkp.git` fork; bump the submodule pointer in
   secp256k1-kmp deliberately, not accidentally.
4. **Publishing.** Consumers outside this composite build need a new secp256k1-kmp release
   (current 0.24.0) and a bitcoin-kmp release carrying `FrostNested`; lightning-kmp's
   `gradle/libs.versions.toml` pins (`secpjnijvm`, `bitcoinkmp`) must then be bumped.
5. **Docs.** Update `FEATURE-PARITY.md` (currently iceberg-only) with the frost signer scope,
   and add a short section to the iceberg/frost Kotlin docblocks cross-referencing the two
   signers' different quorum rules (`t` vs `2t-1`) so future callers don't transpose them.
6. **Optional extensions (not in scope):** ChillDKG dealerless keygen wiring; tweak-aware
   nested aggregation (`e_musig·g_musig·tacc`) for frost-level key tweaks; identifiable-abort
   blame at the channel layer using `verifyPartialSignature`.

## Risk register

- **Nonce reuse = key loss, silently.** Mitigations: single-use `SecretNonce` in Kotlin
  (already atomic), secnonce wipe in C, label-derivation documented in both layers, and the
  one-session-one-signature contract asserted in tests.
- **Parity bugs pass unit tests and fail only at aggregation.** Mitigation: the taproot
  session tests judge with `correctlySpends` on both lexicographic key positions, plus the
  untweaked negative control.
- **JNI/native marshalling skew** (magics duplicated in three places; empty-vs-null args on
  native). Mitigation: no new magics (decision 4); port the full test matrix to both
  platforms in phase 2; keep `07f7dcc`'s lesson in view for the `msg = NULL` nonce-gen path.
- **frost module API churn upstream.** The fork is pinned; any upstream BIP 445 update must
  be merged consciously since we now depend on module internals (`static` functions) that have
  no stability guarantee.
