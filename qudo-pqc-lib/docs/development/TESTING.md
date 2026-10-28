# Testing

## Quick Start

```bash
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j
ctest --test-dir build --output-on-failure
```

For the FIPS-only test groups, add `-DQUDO_FIPS_MODULE=ON` to the configure step (use a separate `build-fips/` directory to keep both builds available).

## Test Suite

The principal self-test infrastructure binaries and their CTest entries are listed below (the wider library suite also includes algorithm and wrapper tests). Some tests are registered conditionally: the POST, PCT, integrity, indicator, CAST and init-error groups need `-DQUDO_FIPS_MODULE=ON`, the OpenSSL PEM interop test needs OpenSSL 4.0 or later, and one test is TSan-only. Run `ctest -N` in the build directory to list the tests for your configuration:

### test_pqc_post — POST and Module Lifecycle

| CTest Name | What It Tests |
|-----------|--------------|
| `pqc_post` | Full POST (all sections) |
| `pqc_post_init` | Module initialization, state transitions, FIPS flag |
| `pqc_post_kats` | KAT pass, algorithm family coverage, event pairing, null callback |
| `pqc_post_negative` | Corruption detection (keygen, KEM, signature KATs) |
| `pqc_post_selftest` | On-demand re-test, error state recovery |
| `pqc_post_statemachine` | Exhaustive state transitions: ERROR latch, PCT conditional, double init, fini/re-init |

### test_pqc_pct — Pairwise Consistency Tests

| CTest Name | What It Tests |
|-----------|--------------|
| `pqc_pct` | Full PCT suite |
| `pqc_pct_mlkem` | ML-KEM encaps/decaps roundtrip (all 3 levels) |
| `pqc_pct_mldsa` | ML-DSA sign/verify roundtrip (all 3 levels) |
| `pqc_pct_slhdsa` | SLH-DSA sign/verify roundtrip |
| `pqc_pct_edge` | Edge cases: NULL pointers, error state behavior |

### test_pqc_integrity — Module Integrity Verification

| CTest Name | What It Tests |
|-----------|--------------|
| `pqc_integrity` | Full integrity suite |
| `pqc_integrity_hmac` | HMAC algorithm self-test (KAT) |
| `pqc_integrity_synthetic` | Synthetic binary verification |
| `pqc_integrity_real` | Real binary HMAC computation |
| `pqc_integrity_fipsinstall` | fipsinstall tool simulation |
| `pqc_integrity_init` | Integrity during module init |
| `pqc_integrity_negative` | Tampered binary detection |
| `pqc_integrity_path_pinning` | Module image resolved by pinned path; substituted-image rejected (separate binary `tests/test_integrity_path_pinning.c`) |

### test_pqc_drbg — CTR-DRBG and FIPS RNG (SP 800-90A/90B)

| CTest Name | What It Tests |
|-----------|--------------|
| `pqc_drbg` | Full DRBG suite (all sections) |
| `pqc_drbg_ctrdrbg` | CTR-DRBG init, all AES key sizes, deterministic output, reseed, additional input, zeroization |
| `pqc_drbg_edge` | NULL parameters, max request (65536), zero-length generate |
| `pqc_drbg_rand` | FIPS RNG lifecycle: init (explicit/platform), reseed, cleanup, zero-length |
| `pqc_drbg_api` | Public API: `qudo_pqc_rand_bytes()`, output uniqueness |
| `pqc_drbg_kat` | CTR-DRBG Known Answer Test (AES-256, deterministic vector) |
| `pqc_drbg_stress` | 1000 sequential generate calls |

### test_pqc_drbg_limits — CTR-DRBG Reseed and Request Limits

| CTest Name | What It Tests |
|-----------|--------------|
| `pqc_drbg_reseed_interval` | Reseed forced after `2²⁰` generate calls |
| `pqc_drbg_chunking` | Output chunking for requests larger than the per-call max |
| `pqc_drbg_explicit_reseed` | Explicit `reseed()` with fresh entropy |
| `pqc_drbg_adin` | Additional-input handling on generate/reseed |
| `pqc_drbg_sequential` | Sequential output continuity across calls |
| `pqc_drbg_is_ready` | DRBG readiness gating before generate |

### test_pqc_indicator — FIPS Indicator

| CTest Name | What It Tests |
|-----------|--------------|
| `pqc_indicator` | Full indicator suite (all sections) |
| `pqc_indicator_init` | Indicator init (approved=1), strict/tolerant modes |
| `pqc_indicator_unapproved` | Set unapproved: strict returns 0, tolerant returns 1, sticky status |
| `pqc_indicator_approval` | The 18 ML-KEM/ML-DSA/SLH-DSA parameter-set names (the list in `qudo_pqc_is_fips_approved()` also contains `HashML-DSA-44/65/87`), non-approved rejection, NULL safety |
| `pqc_indicator_check` | `check_operation()` combined check (module state + algorithm + DRBG) |
| `pqc_indicator_security` | Security level enforcement with indicator integration |

### test_pqc_cast — Conditional Algorithm Self-Tests

| CTest Name | What It Tests |
|-----------|--------------|
| `pqc_cast` | Full CAST suite (all sections) |
| `pqc_cast_init` | All 12 CAST IDs status after module init (FIPS vs standard) |
| `pqc_cast_individual` | Per-algorithm CAST: ML-KEM (3), ML-DSA (3), SLH-DSA (6) |
| `pqc_cast_runall` | `run_all_casts()` on-demand, repeated execution |
| `pqc_cast_invalid` | Invalid CAST ID rejection, CAST_COUNT constant |

### test_pqc_audit — Audit/Logging

| CTest Name | What It Tests |
|-----------|--------------|
| `pqc_audit` | Full audit suite (all sections) |
| `pqc_audit_basic` | Callback registration, event emission, NULL callback |
| `pqc_audit_severity` | All 4 severity levels (INFO, WARN, ERROR, FATAL) |
| `pqc_audit_components` | All 8 component identifiers (STATE, POST, PCT, CAST, DRBG, KEY, INDICATOR, INTEGRITY) |
| `pqc_audit_rate` | Rate limiting (100 events/severity threshold) |
| `pqc_audit_errstr` | Error string lookup for all error codes |
| `pqc_audit_init` | Audit events during module initialization |

### test_pqc_threading — Thread Safety

| CTest Name | What It Tests |
|-----------|--------------|
| `pqc_threading` | 8 threads × 100 iterations: concurrent `rand_bytes`, state queries, CAST status, algorithm approval; plus 8 threads × 10 iterations of concurrent ML-KEM / ML-DSA / SLH-DSA keygen + encaps/sign + decaps/verify roundtrips (TSAN-clean) |

### test_pqc_endurance — Long-Running Soak (opt-in)

Deterministic chained walk over ML-KEM-768, ML-DSA-65, and SLH-DSA-SHA2-128f: each iteration derives its seeds from the previous iteration's outputs, runs the full operate cycle (keygen → encaps/sign → decaps/verify), checks the per-iteration correctness oracle (shared-secret agreement for KEM; valid-signature acceptance plus tampered-signature rejection for the signatures), and folds the results into a reproducible 64-byte final digest. Opt-in: skipped unless `QUDO_ENDURANCE` is set.

| CTest Name | What It Tests |
|-----------|--------------|
| `pqc_endurance` | Skipped by default (exit 77). With `QUDO_ENDURANCE=1`, runs the soak walk for all three families (default 100000 iterations each) |

```bash
# Run the soak walk (all families, default count)
QUDO_ENDURANCE=1 ctest -R pqc_endurance

# Direct invocation with a custom count / single family
QUDO_ENDURANCE=1 ./tests/test_pqc_endurance --num 1000000
QUDO_ENDURANCE=1 ./tests/test_pqc_endurance --num 50000 --slhdsa

# Leak/soak check: run a smaller count under the sanitizer/valgrind flow
QUDO_ENDURANCE=1 valgrind --leak-check=full ./tests/test_pqc_endurance --num 5000
```

## Running Individual Tests

```bash
# Run one section
./tests/test_pqc_post --kats
./tests/test_pqc_post --statemachine
./tests/test_pqc_pct --mlkem
./tests/test_pqc_integrity --hmac
./tests/test_pqc_drbg --kat
./tests/test_pqc_indicator --security
./tests/test_pqc_cast --runall
./tests/test_pqc_audit --rate

# Run all sections of one binary
./tests/test_pqc_post
./tests/test_pqc_drbg
```

## Constant-Time Validation (Valgrind secret poisoning)

ML-KEM and ML-DSA secret independence is checked with Valgrind secret
poisoning: secret material
is marked with Valgrind's `VALGRIND_MAKE_MEM_UNDEFINED` (via the upstreams'
`MLK_CONFIG_CT_TESTING_ENABLED` / `MLD_CONFIG_CT_TESTING_ENABLED`), and any
secret-dependent branch or memory index is reported by Valgrind. The check is
deterministic and does not depend on timing measurements.

Enable the flag (off by default) and run the test under Valgrind. Run from the
library root. The ML-DSA check runs against the C reference backend, so it also
needs `-DMLDSA_DIST_BUILD=OFF -DENABLE_AVX2=OFF`:

```bash
# ML-KEM — keygen + encaps + decaps + FO implicit rejection
cmake -S qudo-mlkem -B qudo-mlkem/build-ct -DMLKEM_CT_VALGRIND=ON
cmake --build qudo-mlkem/build-ct
ctest --test-dir qudo-mlkem/build-ct -R constant_time_valgrind --output-on-failure

# ML-DSA — keygen + sign (rejection-sampling loop)
cmake -S qudo-mldsa -B qudo-mldsa/build-ct \
      -DMLDSA_DIST_BUILD=OFF -DENABLE_AVX2=OFF -DMLDSA_CT_VALGRIND=ON
cmake --build qudo-mldsa/build-ct
ctest --test-dir qudo-mldsa/build-ct -R constant_time_valgrind --output-on-failure
```

A clean run (exit 0) indicates no secret-dependent control flow or memory
access on the exercised paths.

### SLH-DSA

SLH-DSA does not use Valgrind poisoning. It is hash-based (SHA-2/SHAKE only,
no secret-dependent branches or secret-indexed memory), and slhdsa-native has no
declassify annotations; signing derives public signature values from `SK.seed`
through WOTS/FORS hash chains, which poisoning would report as findings. SLH-DSA
uses the statistical timing test `qudo-slhdsa/tests/test_constant_time.c`.

## FIPS vs Standard Build

FIPS builds additionally build and run the POST, PCT, integrity, indicator, CAST and init-error test binaries, and these checks are active:
- POST KATs verify deterministic outputs against stored test vectors
- Integrity check runs against the real binary
- PCT skips during POST (prevents re-entrancy), runs on subsequent keygen
- DRBG readiness enforced before all crypto operations
- CAST status set to SUCCESS after POST (standard build: remains INIT until explicit run)
- FIPS indicator default strict mode = 1 (standard build: 0)

## Standalone Subproject Suites

Each algorithm subproject (`qudo-mlkem`, `qudo-mldsa`, `qudo-slhdsa`) is
buildable on its own and carries its own tests and examples. The top-level
build does not compile these suites, so they are exercised separately:

```bash
./scripts/test_standalone.sh     # configure + build + ctest for all three
```

The standalone test
and example builds treat implicit function declarations and int/pointer
conversions as errors, so API drift in standalone-only sources fails the
build instead of compiling into undefined behavior.

## Sanitizers

```bash
cmake -S . -B build-asan -DENABLE_SANITIZERS=ON -DCMAKE_BUILD_TYPE=Debug
cmake --build build-asan -j
ctest --test-dir build-asan --output-on-failure
```

Runs all tests under AddressSanitizer + UndefinedBehaviorSanitizer. `ENABLE_MSAN` and `ENABLE_TSAN` are also available (each mutually exclusive with the others and with ASan/UBSan).

## Valgrind

Per-family Valgrind harnesses live inside each algorithm subdirectory:

```bash
bash qudo-mlkem/tests/test_valgrind.sh
bash qudo-mldsa/tests/test_valgrind.sh
bash qudo-slhdsa/tests/test_valgrind.sh
```

## Code Coverage

```bash
cmake -S . -B build-cov -DENABLE_COVERAGE=ON -DCMAKE_BUILD_TYPE=Debug
cmake --build build-cov -j
ctest --test-dir build-cov
./coverage.sh                # generates coverage-report/ (HTML)
```

`coverage.sh` writes its HTML report to `coverage-report/`; use the `-o`/`--output` flag to redirect it.

## Static Analysis

`./run_all_tests.sh --full` runs `clang-tidy` and `cppcheck`. The Clang Static Analyzer is available locally via `scan-build.sh`, which adds path-sensitive checks (null-deref, use-after-free, leaks, dead stores) over the qudo-authored shipping sources only — vendored native code, tests, examples and ACVP harnesses are excluded.

```bash
./scan-build.sh                # analyze, write HTML to scan-report/
./scan-build.sh --fips         # analyze the FIPS-module build
./scan-build.sh -o report/     # custom output directory
```

Requires `scan-build` (Debian/Ubuntu: `apt-get install clang-tools`; macOS: `brew install llvm`).
