# Nested FROST+MuSig2 threshold signer (the `fractal` module) — implementation plan

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
   same: `b_frost = tagged_hash("Fractal/noncecoef", ser32(u) || sorted ids || aggnonce66 ||
   ext33(thresh_pk))`, hashing the group key's full 33-byte extended serialization
   (`secp256k1_musig_ge_serialize_ext`) exactly like iceberg's noncecoef — NOT its x-only
   encoding, since the key is used as a full point everywhere downstream. This deviates from
   BIP 445's coefficient and must be called out in the security notes; the outer challenge
   still binds the message, as in iceberg.
2. **Label-derived deterministic nonces, iceberg-style.** FROST's `SecretNonce` is random and
   single-use, which does not fit `FundingSigner.verificationNonce` (published early, re-derived
   later by a possibly fresh signer instance). Fix: drive `secp256k1_frost_nonce_gen` with
   `session_secrand32 = tagged_hash("Fractal/session", sessionId || member_id)` and
   `msg = NULL` both at publication and at signing time, making each member's nonce a pure
   function of `(secshare, sessionId)`. The safety invariant is identical to iceberg's: ONE
   sessionId signs ONE message, group-wide, or keys leak without any error being raised.
   `Frost.deterministicSign` (BIP 445 DeterministicSign) is NOT usable: it binds the message,
   which is unknown when the nonce is published.
3. **No FROST-level key tweak AND no FROST-level parity normalization in the channel flow.**
   The group's threshold pubkey enters the outer `Scripts.sort` key aggregation untweaked AND
   as a full 33-byte point: the BIP341 key-path tweak is applied to the MuSig2 aggregate key
   and handled by the stock outer session (`keyagg_cache.s_part`), and all key-side parity
   normalization happens once at the aggregate level — iceberg's session values negate the key
   coefficient only on `fe_is_odd(cache_i.pk.y) != cache_i.parity_acc` of the OUTER keyagg
   cache (`iceberg/session_impl.h:468-475`) and never read the group key's own Y parity. This
   means the `g_frost` factor must be ABSENT from the nested signing equation even though it
   is NOT 1 in general: stock FROST computes `g_times_gacc_parity = gacc_parity ^ pk_odd`
   (`frost/session_impl.h:664`) and negates `d` on it (`frost/session_impl.h:797-800`), so
   with an identity tweak cache the factor is -1 whenever the group key has odd Y — roughly
   half of all generated groups. Do NOT copy `secp256k1_frost_get_session_values`'s key-side
   parity handling into the fractal session; "the tweak cache is the identity" is NOT the
   reason `g_frost` is absent, and an implementer who believes it is will import the `pk_odd`
   negation and produce a signer that works for even-Y group keys and fails for odd-Y ones.
   The fractal aggregator is a plain sum of partial signatures in v1, and every entry point
   that receives a FROST tweak cache must FAIL if it is not the identity (`tacc != 0` or
   `gacc_parity != 0`); a tweak-aware aggregation variant (folding `e_musig · g_musig · tacc`
   like frosty-musig's `nested_frost_partial_sig_agg`) is an optional later extension.
4. **No new opaque C types, and a NEW experimental module named `fractal`.** Follow iceberg's
   sessionless API: every call takes all session parameters explicitly (ids, pubshares,
   aggnonce, group key, outer keyagg cache, cosigner aggnonce, msg32). This avoids new
   `data[N]` blobs, new magics, and new `*_SIZE` constants in three synced places. The
   functions live in a new experimental module `src/modules/fractal` (public header
   `include/secp256k1_fractal.h`, functions namespaced `secp256k1_fractal_*`) that depends on
   BOTH the frost and musig modules — the same architecture iceberg uses for musig: a
   standalone module included late in `secp256k1.c` (iceberg is at `:965`, after musig at
   `:921` and frost at `:957`) can call the earlier modules' `static` internals, because the
   whole library is one translation unit. Two reasons for NOT putting this in the frost
   module: (a) the frost module stays pure, vector-pinned BIP 445 — the deliberately
   non-compliant nested scheme (decisions 1-3) lives behind its own opt-in flag, giving
   auditors a clean scope boundary; (b) the dependency graph stays honest — frost keeps
   depending only on schnorrsig instead of absorbing a musig dependency that every pure-FROST
   consumer would have to build. The cost is new-module boilerplate everywhere iceberg is
   listed: the CMake/configure.ac module blocks (fractal force-enables frost AND musig,
   mirroring `src/CMakeLists.txt:76-83` and `configure.ac:576-582`), `Makefile.am.include`,
   include blocks in `src/secp256k1.c` (AFTER frost — the module relies on frost and musig
   statics) and `src/tests.c`, one header line in `libsecp256k1.def`, one flag in
   `native/build.gradle.kts`. `include/secp256k1_fractal.h` includes BOTH `secp256k1_frost.h`
   and `secp256k1_musig.h`; no existing header changes.
5. **Quorum is `t` in BOTH rounds** (vs iceberg's `2t-1`/`t`), and any `t`-of-`n` is expressible
   — 2-of-2 and 3-of-4, which iceberg forbids, become available. `n` is bounded by
   `SECP256K1_FROST_MAX_PARTICIPANTS` (128). Unlike iceberg, the round-two signers must be
   EXACTLY the round-one contributors (same set, not a subset): FROST's `λ_i` and aggregate
   nonce are defined over the participating set, with no VSS interpolation to absorb dropouts
   (see Phase 4).

## Repo layout reminder

- Vendored C fork (git submodule): `experimental/bitcoin-kmp/experimental/secp256k1-kmp/native/secp256k1`
  (upstream `code.sigidli.com/frost/secp256k1-zkp.git`, HEAD `03db8281`, has `frost`,
  `chilldkg`, `iceberg` modules; this plan adds a fourth, `fractal`).
- KMP wrapper: `experimental/bitcoin-kmp/experimental/secp256k1-kmp` — common `interface
  Secp256k1`, JNI actual (`jni/`), cinterop actual (`src/nativeMain`), tests in `tests/`.
- bitcoin-kmp fork: `experimental/bitcoin-kmp` — `fr.acinq.bitcoin.crypto.frost.Frost` and
  `crypto.iceberg.Iceberg` already exist; composite build substitutes it into lightning-kmp.
- lightning-kmp: `modules/core` (gradle name `:lightning-kmp-core`); the `FundingSigner` seam
  is in `modules/core/src/commonMain/kotlin/fr/acinq/lightning/crypto/FundingSigner.kt`.

---

## Phase 1 — C fork: the `fractal` module

All work in `experimental/bitcoin-kmp/experimental/secp256k1-kmp/native/secp256k1` (a submodule:
commit there, on a branch, first). Everything lives in a NEW experimental module,
`src/modules/fractal/`, included AFTER frost in `src/secp256k1.c` so it compiles into the same
translation unit as the frost and musig modules and can call their `static` internals — the
same mechanism iceberg (its own module, `secp256k1.c:965`) uses to call
`secp256k1_musig_nonce_process_internal`, `secp256k1_musig_keyaggcoef`,
`secp256k1_musig_pubnonce_save`, `secp256k1_musig_aggnonce_load` and
`secp256k1_keyagg_cache_load` from `src/modules/iceberg/session_impl.h`.

### 1.1 Public API — new header `include/secp256k1_fractal.h`

Copy the annotation style of `secp256k1_frost_sign` (`SECP256K1_API SECP256K1_WARN_UNUSED_RESULT
int`, `SECP256K1_ARG_NONNULL(...)`). The header includes BOTH `secp256k1_frost.h` and
`secp256k1_musig.h` (as `secp256k1_iceberg.h:4` includes the musig header); no existing header
changes. The module is declared experimental and its CMake/configure.ac blocks force-enable
frost AND musig, mirroring iceberg's blocks (`src/CMakeLists.txt:76-83`,
`configure.ac:576-582`) — see decision 4.

```c
/* Aggregate member pubnonces and export the group's OUTER-wire nonce:
 * pubnonce_out = (R1, b_frost · R2) as an ordinary musig pubnonce (this is what
 * goes on the lightning wire); aggnonce_out = the UNSCALED frost aggnonce,
 * which signers need later for partial signing.
 * b_frost = tagged_hash("Fractal/noncecoef", u || sorted ids || aggnonce ||
 * ext33(thresh_pk)) — full extended serialization, as in iceberg's noncecoef.
 * Fails if EITHER output component is infinity (a musig pubnonce cannot encode
 * it, and either frost aggnonce column sum may be infinity per BIP 445
 * NonceAgg) — same guard as iceberg's publish_nonce, which checks both out[0]
 * and out[1] (iceberg/session_impl.h:124). */
int secp256k1_fractal_nonce_agg(
    const secp256k1_context *ctx,
    secp256k1_musig_pubnonce *pubnonce_out,
    secp256k1_frost_aggnonce *aggnonce_out,
    const secp256k1_frost_pubnonce *const *pubnonces,
    const uint32_t *ids, size_t n_signers,
    const secp256k1_pubkey *thresh_pk);

/* One member's nested partial signature: s_i = k1 + b_frost·b_musig·k2
 *   + e_musig · a_musig · λ_i · g_musig · gacc_musig · d_i
 * with both k's negated iff the OUTER final nonce has odd Y. There is NO
 * g_frost factor: thresh_pk enters the outer keyagg as a full point, so no
 * inner x-only normalization applies (design decision 3). keyagg_cache is
 * the OUTER (already BIP341-tweaked) musig cache; cosigner_aggnonce aggregates
 * the non-frost participants only. tweak_cache is the FROST tweak cache of
 * thresh_pk and MUST be the identity — checked HERE, at signing time, so the
 * key being signed under is tied to the cache being validated and the check in
 * fractal_partial_sig_agg is not the only enforcement. secnonce is wiped.
 * Self-verify the share before returning, like secp256k1_frost_sign_internal
 * does. */
int secp256k1_fractal_sign(
    const secp256k1_context *ctx,
    secp256k1_frost_partial_sig *partial_sig,
    secp256k1_frost_secnonce *secnonce,
    const unsigned char *secshare32,
    uint32_t my_id,
    const uint32_t *ids, const secp256k1_pubkey *pubshares, size_t n_signers,
    const secp256k1_frost_aggnonce *aggnonce,
    const secp256k1_pubkey *thresh_pk,
    const secp256k1_frost_tweak_cache *tweak_cache,
    const secp256k1_musig_keyagg_cache *keyagg_cache,
    const secp256k1_musig_aggnonce *cosigner_aggnonce,
    const unsigned char *msg32);

/* Verify member i's nested share:
 * s_i·G == R1_i + b_frost·b_musig·R2_i + e·a·λ_i·g·gacc·P_i  (nonce points
 * negated iff outer fin-nonce odd; g/gacc here are the OUTER musig factors).
 * Recomputes the full session from the same params as secp256k1_fractal_sign,
 * including the identity tweak_cache check. */
int secp256k1_fractal_partial_sig_verify(
    const secp256k1_context *ctx,
    const secp256k1_frost_partial_sig *partial_sig,
    const secp256k1_frost_pubnonce *pubnonce,
    const secp256k1_pubkey *pubshare,
    uint32_t my_id,
    const uint32_t *ids, size_t n_signers,
    const secp256k1_frost_aggnonce *aggnonce,
    const secp256k1_pubkey *thresh_pk,
    const secp256k1_frost_tweak_cache *tweak_cache,
    const secp256k1_musig_keyagg_cache *keyagg_cache,
    const secp256k1_musig_aggnonce *cosigner_aggnonce,
    const unsigned char *msg32);

/* Sum member shares and export the result as a stock musig partial signature,
 * ready for secp256k1_musig_partial_sig_agg alongside the cosigner's.
 * tweak_cache is the FROST tweak cache of thresh_pk and MUST be the identity
 * (tacc == 0, gacc_parity == 0) — the channel flow tweaks only the outer
 * aggregate key, and the outer musig session already adds its own
 * e·g·tweak term. Fails otherwise (see Design decision 3). Export with
 * secp256k1_musig_partial_sig_save (as iceberg does, iceberg/session_impl.h:838),
 * NEVER a raw struct copy: frost and musig partial-sig structs are both
 * data[36] but carry different magics, so a memcpy'd struct fails ARG_CHECK. */
int secp256k1_fractal_partial_sig_agg(
    const secp256k1_context *ctx,
    secp256k1_musig_partial_sig *sig_out,
    size_t *error_index,
    const secp256k1_frost_partial_sig *const *partial_sigs, size_t n_sigs,
    const secp256k1_frost_tweak_cache *tweak_cache);
```

### 1.2 Implementation — `src/modules/fractal/session_impl.h` (included from
`src/modules/fractal/main_impl.h`)

Reuse, do not re-implement:

- λ_i: `secp256k1_frost_derive_interpolating_value` (`src/modules/frost/keygen_impl.h:103`).
- Frost session values for shape reference: `secp256k1_frost_get_session_values`
  (`frost/session_impl.h:590`) — but we need our own `secp256k1_fractal_session_values` that
  computes b_frost WITHOUT msg (hashing ext33(thresh_pk), not xbytes — see decision 1), scales
  the second aggnonce component by b_frost (`secp256k1_effective_nonce`-style ecmult,
  `musig/session_impl.h:558`; there is no frost variant of that helper), then adds the cosigner
  aggnonce points and calls `secp256k1_musig_nonce_process_internal` (`musig/session_impl.h:566`)
  for b_musig, fin_nonce and its parity, and finally `secp256k1_schnorrsig_challenge` for
  e_musig. Iceberg's `secp256k1_iceberg_session_values` (`iceberg/session_impl.h:429`) is a
  line-for-line template. Do NOT lift the key-side parity handling from
  `secp256k1_frost_get_session_values`: its `g_times_gacc_parity = gacc_parity ^ pk_odd`
  (`frost/session_impl.h:664`) is the x-only normalization of a STANDALONE frost key and has
  no place here (decision 3).
- a_musig: `secp256k1_musig_keyaggcoef_internal` (`musig/keyagg_impl.h:106`) on the group
  pubkey; key-side parity: negate iff `fe_is_odd(cache_i.pk.y) != cache_i.parity_acc`
  (`musig/session_impl.h:685`).
- Export: `secp256k1_musig_pubnonce_save` / `secp256k1_musig_partial_sig_save` /
  `secp256k1_frost_partial_sig_save`; load counterparts for inputs. Save through these helpers,
  never raw struct copies — frost and musig partial-sig structs share `data[36]` but carry
  different magics.
- Wire format: the exported musig pubnonce serializes to the standard 66 bytes
  (`secp256k1_musig_pubnonce_serialize`), so the remote peer needs nothing new.

Parity checklist (the main trap — two independent negations interact, plus one factor that
must stay absent):

1. Nonce side: negate `k1`, `k2` iff the OUTER session's final nonce R has odd Y.
2. Key side (musig): coefficient on `d_i` is `e_musig · a_musig · λ_i`, times −1 iff
   `odd(agg_tweaked_pk.y) != parity_acc` of the OUTER keyagg cache.
3. Frost key-side factors (`g_frost`, `gacc_frost`) are BOTH absent, for different reasons:
   `gacc_frost` because the tweak cache is the identity, `g_frost` because the group key
   enters the outer keyagg as a full 33-byte point and is never x-only-normalized at the
   frost level (iceberg does the same — `iceberg/session_impl.h:468-475` reads only the OUTER
   aggregate's parity). Note that `g_frost` would be −1 for odd-Y group keys if copied from
   stock frost (`frost/session_impl.h:664`, `:797-800`): an implementer who reasons "identity
   cache ⇒ no frost key term" and copies `frost_get_session_values` gets a signer that works
   for even-Y group keys and fails for odd-Y ones. ASSERT the identity cache at signing AND
   aggregation, rather than silently ignoring a tweaked cache.

### 1.3 C tests — `src/modules/fractal/tests_impl.h`

Model on `iceberg/tests_impl.h`; `src/tests.c` gains an include block under a new
`ENABLE_MODULE_FRACTAL` guard, mirroring the iceberg one (`tests.c:7932`):

- Round-trip: 2-of-3 nested group + one stock musig cosigner; `musig_nonce_agg` over
  [group pubnonce, cosigner pubnonce], stock `musig_nonce_process`, stock
  `musig_partial_sign` for the cosigner, `secp256k1_fractal_sign` × 2,
  `secp256k1_fractal_partial_sig_agg`, stock `secp256k1_musig_partial_sig_agg`, then
  `secp256k1_schnorrsig_verify` against the tweaked aggregate xonly key. Cover t-of-n =
  {2-of-2, 2-of-3, 3-of-5} and both lexicographic positions of the group key. Pin at least
  one FIXED group key with odd Y (not a randomly regenerated fixture) so the decision-3
  parity trap cannot hide behind a lucky even-Y seed.
- With an xonly tweak applied to the OUTER keyagg cache (the BIP341 case).
- `fractal_partial_sig_verify` accepts valid shares, rejects a tampered share and a share
  signed under the wrong id set.
- Identity-cache enforcement: a non-identity frost tweak cache fails `fractal_sign`,
  `fractal_partial_sig_verify` AND `fractal_partial_sig_agg` (decision 3).
- Infinity guard: crafted aggnonces whose FIRST or (scaled) SECOND component is infinity both
  fail `fractal_nonce_agg` (mirror iceberg's publish-nonce failure path, which guards both
  outputs).
- Wrong-key-order / missing-tweak shares are well-formed but fail final schnorr verification
  (negative control).
- Nonce reuse: calling `fractal_sign` twice with the same secnonce fails (secnonce wiped).

### 1.4 Optional in this phase

- `examples/fractal.c` (mirror `examples/iceberg.c`) and a `doc/fractal.md` — the
  doc is worth doing because decision 1 deviates from BIP 445, decision 2 redefines nonce
  derivation, and decision 3 drops FROST-level parity normalization; all three must be written
  down where reviewers will find them.
- ctime test entry (iceberg has one in `ctime_tests.c`).

### Phase 1 verification

```
cd experimental/bitcoin-kmp/experimental/secp256k1-kmp/native/secp256k1
cmake -B build -DSECP256K1_ENABLE_MODULE_FRACTAL=ON \
      -DSECP256K1_BUILD_TESTS=ON -DSECP256K1_BUILD_EXAMPLES=ON
cmake --build build && ./build/bin/tests
```

Configuring with only `-DSECP256K1_ENABLE_MODULE_FRACTAL=ON` (no explicit frost/musig flags)
must succeed and force-enable both dependency modules, exactly as iceberg does for musig
(decision 4); a default build with FRACTAL off must remain unchanged and the frost module's
BIP 445 vectors stay green either way.

Deliverable: submodule commit adding the fractal module (header, impl, tests, and the build
wiring in `src/CMakeLists.txt`, `configure.ac`, `Makefile.am.include`, `src/secp256k1.c`,
`src/tests.c`), tests green.

---

## Phase 2 — secp256k1-kmp bindings (JVM + Native)

In `experimental/bitcoin-kmp/experimental/secp256k1-kmp/`. Two one-line wiring changes here:
`-DSECP256K1_ENABLE_MODULE_FRACTAL=ON` joins `CMAKE_DEFAULT_OPTS` (`native/build.gradle.kts:12`)
and `secp256k1_fractal.h` joins `src/nativeInterop/cinterop/libsecp256k1.def`, so cinterop picks
the new functions up automatically. Four functions to expose, plus `frost_nonce_gen` reuse —
with one caveat: the existing binding takes the group key as a nullable `XonlyPublicKey`
(`Frost.kt:328`), so `FrostNested.generateNonce` forwards `groupPublicKey.xOnly()` through it
(Phase 3) and no new binding is needed. The Kotlin binding names below stay `frostNested*`
(they describe the composition); only the C names carry the `fractal` module namespace.

1. `src/commonMain/kotlin/fr/acinq/secp256k1/Secp256k1.kt` — add to `interface Secp256k1`
   (KDoc style of `frostSign`, line 454):
   - `fun frostNestedNonceAgg(pubnonces: Array<ByteArray>, ids: UIntArray, threshPk: ByteArray): Pair<ByteArray, ByteArray>` — returns (66-byte musig pubnonce, 66-byte frost aggnonce serialization).
   - `fun frostNestedSign(secnonce: ByteArray, secshare32: ByteArray, myId: UInt, ids: UIntArray, pubshares: Array<ByteArray>?, aggnonce: ByteArray, threshPk: ByteArray, tweakCache: ByteArray, keyaggCache: ByteArray, cosignerAggnonce: ByteArray, msg32: ByteArray): ByteArray`
   - `fun frostNestedPartialSigVerify(partialSig: ByteArray, pubnonce: ByteArray, pubshare: ByteArray, myId: UInt, ids: UIntArray, aggnonce: ByteArray, threshPk: ByteArray, tweakCache: ByteArray, keyaggCache: ByteArray, cosignerAggnonce: ByteArray, msg32: ByteArray): Int`
   - `fun frostNestedPartialSigAgg(partialSigs: Array<ByteArray>, tweakCache: ByteArray): ByteArray` (32-byte musig partial sig).
   - No new `const val`/magic needed (decision 4). Note: the aggnonce crossing the ABI is its
     66-byte SERIALIZATION — parse/serialize with the existing
     `secp256k1_frost_aggnonce_parse/serialize` inside the glue.
2. `src/nativeMain/kotlin/fr/acinq/secp256k1/Secp256k1Native.kt` — overrides next to
   `frostSign` (line 761): `require` size checks, `checkMagic` on the opaque inputs
   (frost secnonce/aggnonce/tweak cache, musig keyagg cache — magics already in the companion), `memScoped`
   + `alloc` helpers (reuse `allocFrostPubnonce`, `allocFrostTweakCache`, `allocPubshares`;
   add `allocFrostAggnonce`, `allocMusigKeyaggCache`/`allocMusigAggnonce` if absent),
   `.requireSuccess("secp256k1_fractal_sign() failed")`.
3. `jni/src/main/java/fr/acinq/secp256k1/Secp256k1CFunctions.java` — native declarations
   (`long ctx`, `byte[]`, `byte[][]`, `int[]`, `int` args; no new size constants).
4. `jni/c/headers/java/fr_acinq_secp256k1_Secp256k1CFunctions.h` — regenerate with
   `./gradlew :jni:generateHeaders` and CHECK IN the refreshed copy: `jni/jvm/build.sh`
   compiles against this checked-in header, not the generated one.
5. `jni/c/src/fr_acinq_secp256k1_Secp256k1CFunctions.c` — four `JNIEXPORT` functions copying
   the `frost_sign` body (lines 1663-1709): `get_bytes`/`get_bytes32`/`get_signer_ids`/
   `get_pubshares` marshalling, `CHECKMAGIC` on opaque inputs BEFORE any C call (the default
   ARG_CHECK aborts the process), `free` on every path before `CHECKRESULT`, results via
   `copy_bytes_to_java`. The musig pubnonce output of `fractal_nonce_agg` is returned via
   `secp256k1_musig_pubnonce_serialize`.
6. `jni/src/main/kotlin/fr/acinq/secp256k1/Secp256k1Jni.kt` — overrides with `require`
   validation and `UIntArray → IntArray` mapping, forwarding through
   `Secp256k1Context.getContext()`.
7. `tests/src/commonTest/kotlin/fr/acinq/secp256k1/FrostNestedTest.kt` — port the C
   round-trip test (2-of-3 + stock musig cosigner, tweaked and untweaked, negative cases,
   FIXED odd-Y group key fixture). This automatically runs on JVM and all native targets.
   Watch the empty/absent-argument paths on native — FEATURE-PARITY.md flags `07f7dcc`
   (native FROST bindings collapsing empty messages to absent ones); our nonce-gen reuse
   passes `msg = NULL`, which is exactly that hazard class.

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
445 — see design decisions 1–2). Shape it on `crypto/iceberg/Iceberg.kt`. This object wraps the
fractal module's C functions via the Phase 2 bindings.

```kotlin
object FrostNested {
    /** Deterministic per-member nonce from a unique session label (msg omitted).
     *  Forwards groupPublicKey.xOnly() to Frost.SecretNonce.generate, whose binding takes the
     *  group key as a nullable XonlyPublicKey (Frost.kt:328) — no new binding needed. */
    fun generateNonce(secretShare: PrivateKey, publicShare: PublicKey, groupPublicKey: PublicKey,
                      sessionId: ByteVector32, myId: UInt): Pair<Frost.SecretNonce, Frost.IndividualNonce>

    /** Group's wire nonce (a musig2 IndividualNonce) + the unscaled frost AggregatedNonce. */
    fun aggregateNonces(publicNonces: List<Frost.IndividualNonce>, signerIds: List<UInt>,
                        groupPublicKey: PublicKey
    ): Either<Throwable, Pair<fr.acinq.bitcoin.crypto.musig2.IndividualNonce, Frost.AggregatedNonce>>

    fun partialSign(secretNonce: Frost.SecretNonce, secretShare: PrivateKey, myId: UInt,
                    signerIds: List<UInt>, signerPublicShares: List<PublicKey>,
                    groupAggregatedNonce: Frost.AggregatedNonce, groupPublicKey: PublicKey,
                    tweakCache: Frost.TweakCache, keyAggCache: KeyAggCache, message: ByteVector32,
                    cosignerAggregatedNonce: musig2.AggregatedNonce): Either<Throwable, ByteVector32>

    fun verifyPartialSignature(partialSig: ByteVector32, publicNonce: Frost.IndividualNonce,
                               publicShare: PublicKey, myId: UInt, signerIds: List<UInt>, ...same session params...): Boolean

    /** Sum of member shares as a musig2 partial signature; requires the identity tweak cache. */
    fun aggregatePartialSignatures(partialSigs: List<ByteVector32>, tweakCache: Frost.TweakCache
    ): Either<Throwable, ByteVector32>
}
```

- `session_secrand32 = Crypto.sha256("Fractal/session" || sessionId || ser32(myId))` —
  document that `sessionId` uniqueness group-wide is the key-leak invariant, same as iceberg.
  With this label-derived randomness, the group-key input to `nonce_gen` is redundant domain
  separation anyway (iceberg's `generateNonce` takes no group key at all), which is why the
  x-only hand-off above costs nothing.
- Keygen is NOT here: reuse `Frost.trustedDealerKeygen` (ChillDKG later for dealerless).

New tests `experimental/bitcoin-kmp/src/commonTest/kotlin/fr/acinq/bitcoin/crypto/frost/FrostNestedTestsCommon.kt`
(there is no iceberg reference-vector set and no frosty-musig vector set, so behavioral tests):
full nested session against a stock `Musig2` cosigner judged by
`Crypto.verifySignatureSchnorr` on the tweaked aggregate key (mirror
`IcebergTestsCommon.kt`'s group-session test); t-of-n matrix {2-of-2, 2-of-3, 3-of-5} with
FIXED group keys of BOTH Y parities (at least one odd-Y — pins decision 3); label
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
    `FrostNested.aggregatePartialSignatures`. Require `signers == contributors` AS SETS —
    NOT iceberg's `signers ⊆ contributors`: FROST's `λ_i` and the aggregate nonce are defined
    over the exact participating set, so with a proper subset the nonce terms of the missing
    contributors stay in R while their key shares are absent from Σs_i, and the resulting
    signature is invalid with no error raised at signing time (iceberg's subset tolerance
    comes from its VSS interpolation over 2t-1 contributions; FROST has no equivalent).
  - `keyAggCacheFor` / `cosignerAggregatedNonce` — copy verbatim from `IcebergSigner` (they
    are scheme-independent; consider hoisting them into a shared internal helper file
    `crypto/ThresholdSignerHelpers.kt` and pointing both signers at it).
- `class FrostFundingSigner(group, contributors = 1..t, signers = 1..t) : FundingSigner` —
  with an `init`-time `require(signers.toSet() == contributors.toSet())` (the defaults keep
  them equal; the check catches explicit misuse — see `roundTwo` above). Otherwise copy
  `IcebergFundingSigner`'s structure: `publicKey = group.groupPublicKey`,
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
  in both rounds; expressible configs iceberg rejects (2-of-2, 3-of-4) now work; `signers` ≠
  `contributors` is REJECTED by the require (a proper subset must fail loudly, never produce
  an invalid signature — iceberg's subset tolerance does not transfer); label reuse
  raises no error (hazard documentation); wrong key order caught; `privateKey(op)` refusal
  names the op; `verificationSessionId` collision-freeness over 1000 commit indices;
  foreign `PublishedNonceSession` refused; published-session nonce matches.
- `crypto/FrostTaprootSessionTestsCommon.kt` ← `IcebergTaprootSessionTestsCommon.kt` (nearly
  verbatim): reproduce the channel session by hand (`Scripts.sort`, BIP341 tweak from spec,
  self-check tweaked key == `pubkeyScript.drop(2)`), both lexicographic key positions,
  (2-of-3, 2-of-4, 3-of-5) with at least one FIXED odd-Y group key (pins decision 3 — a
  randomly seeded fixture can hide a wrong `g_frost` behind a lucky even-Y draw), stock
  `checkRemotePartialSignature`, stock `aggregateSigs`, judged by
  `Transaction.correctlySpends`, plus the untweaked negative control. Reuse
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

Three deliberate adaptations:

- The op-count measurement test needs new expectations: FROST round one is `t`
  `generateNonce` calls + 1 `fractal_nonce_agg`, round two is `t` signs + 1 agg — no 2t-1.
- `CountingFundingSigner` is already generic; consider moving it from the `iceberg` package
  to a neutral `crypto` test package and letting both suites use it.
- The group-key fixtures must include at least one FIXED key with odd Y — iceberg's inherited
  fixtures were never chosen for parity, and a wrong `g_frost` (decision 3) passes for even-Y
  keys and fails for odd-Y ones, so a randomly seeded or inherited fixture is a coin flip.

Verification: `./gradlew :lightning-kmp-core:jvmTest --tests "*frost*"` and the host native
test target (`:lightning-kmp-core:linuxX64Test` or macOS equivalent).

---

## Phase 6 — hardening, docs, and release mechanics

1. **Security review gate.** The C code is new consensus-critical crypto: the b_frost-without-
   msg deviation (decision 1), the label-derived nonces (decision 2) and the absent `g_frost`
   parity normalization (decision 3) need written justification in `doc/fractal.md` and
   external review. frosty-musig is unaudited research code; the
   vendored frost module is itself marked experimental. Keep the Kotlin API tagged with the
   same WARNING docblocks the existing `Frost` object carries. Cross-check against
   `docs/FROSTyMuSig.pdf` and confirm whether a security proof exists for the nested
   construction before any mainnet use.
2. **Nonce-hazard audit.** Every site that can call the signer twice under one sessionId must
   be enumerated (the channel flows already guarantee one-message-per-id for iceberg; re-verify
   each call site for frost, especially reconnection and RBF paths that rebuild sessions).
3. **Upstream/submodule hygiene.** The C work lands on a branch of the
   `code.sigidli.com/frost/secp256k1-zkp.git` fork as one self-contained module directory
   (no edits interleaved into frost or musig); bump the submodule pointer in
   secp256k1-kmp deliberately, not accidentally.
4. **Publishing.** Consumers outside this composite build need a new secp256k1-kmp release
   (current 0.24.0) and a bitcoin-kmp release carrying `FrostNested`; lightning-kmp's
   `gradle/libs.versions.toml` pins (`secpjnijvm`, `bitcoinkmp`) must then be bumped.
5. **Docs.** Update `FEATURE-PARITY.md` (currently iceberg-only) with the frost signer scope,
   and add a short section to the iceberg/frost Kotlin docblocks cross-referencing the two
   signers' different quorum rules (`t` vs `2t-1`) and different signer-set rules (frost
   requires round-two signers == round-one contributors; iceberg tolerates a subset) so future
   callers don't transpose them.
6. **Optional extensions (not in scope):** ChillDKG dealerless keygen wiring; tweak-aware
   nested aggregation (`e_musig·g_musig·tacc`) for frost-level key tweaks; identifiable-abort
   blame at the channel layer using `verifyPartialSignature`.

## Risk register

- **Nonce reuse = key loss, silently.** Mitigations: single-use `SecretNonce` in Kotlin
  (already atomic), secnonce wipe in C, label-derivation documented in both layers, and the
  one-session-one-signature contract asserted in tests.
- **Parity bugs pass unit tests and fail only at aggregation.** Mitigation: the taproot
  session tests judge with `correctlySpends` on both lexicographic key positions, FIXED odd-Y
  group-key fixtures (the `g_frost`/`pk_odd` trap of decision 3 passes for even-Y keys — a
  coin flip that random or inherited fixtures may never surface), plus the untweaked negative
  control.
- **Round-two signer set ≠ round-one contributors.** Produces an invalid signature with no
  error at signing time (the missing contributors' nonce terms stay in R, and λ was computed
  for the wrong set). Mitigation: set-equality `require` in `FrostSigner.roundTwo` and
  `FrostFundingSigner.init`, plus a rejection test (Phase 4).
- **JNI/native marshalling skew** (magics duplicated in three places; empty-vs-null args on
  native). Mitigation: no new magics (decision 4); port the full test matrix to both
  platforms in phase 2; keep `07f7dcc`'s lesson in view for the `msg = NULL` nonce-gen path.
- **frost/musig module API churn upstream.** The fork is pinned; any upstream BIP 445 (or
  musig) update must be merged consciously since fractal depends on BOTH modules' internals
  (`static` functions with no stability guarantee) and on its include position AFTER both in
  `src/secp256k1.c` — a reordering breaks the build, not just the tests.
