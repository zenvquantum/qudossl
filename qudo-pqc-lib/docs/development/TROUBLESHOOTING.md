# Troubleshooting

Symptom → cause → fix for `libqudo-pqc`. For developer tooling (sanitizers,
valgrind, coverage, fuzzing) see [Debugging](DEBUGGING.md); for the
FIPS build/integrity flow see [INSTALL.md](../../INSTALL.md); for platform
specifics see [Notes — Unix](../reference/NOTES_UNIX.md) / [Windows](../reference/NOTES_WINDOWS.md).

## First step: read the module state and the audit log

Most runtime problems are diagnosable from the module state plus the structured
audit callback — register it before `qudo_pqc_init()`:

```c
qudo_pqc_get_state();   /* 0 INIT · 1 SELFTEST · 2 RUNNING · 3 ERROR */
```

| Diagnostic | API |
|---|---|
| Module state | `qudo_pqc_get_state()` |
| Granular POST results | `qudo_pqc_post_integrity_passed()`, `qudo_pqc_post_drbg_kat_passed()` |
| Per-algorithm CAST status | `qudo_pqc_get_cast_status(id)` |
| Last thread-local error | `QUDO_<FAMILY>_get_last_error()` → `{code, func, detail, line}` |
| Event stream | `audit_cb` in `qudo_pqc_config_t` (STATE/POST/INTEGRITY/PCT/CAST/DRBG/KEY/INDICATOR) |

The audit event carries a `qudo_err_t` code (see [Module error codes](#module-error-codes)) that pinpoints the cause.

## Build & link issues

| Symptom | Cause | Fix |
|---|---|---|
| CMake `FATAL_ERROR` mentioning `-ffunction-sections` or LTO | A FIPS build (`QUDO_FIPS_MODULE=ON`) was configured with `CMAKE_INTERPROCEDURAL_OPTIMIZATION=ON` or `-ffunction-sections` in `CMAKE_C_FLAGS` | Remove them — the integrity HMAC covers a contiguous `.text`; the FIPS build forbids both |
| FIPS-gated tests (POST/CAST/integrity/PCT) not registered | Built without `-DQUDO_FIPS_MODULE=ON` | Configure with `-DQUDO_FIPS_MODULE=ON` |
| `QUDO_MLDSA_*_der_format` / `*_pem_format` return `-8` | Those explicit PKCS#8-format variants need OpenSSL, which the combined `libqudo-pqc` build does not use | Use the plain DER/PEM functions, or build ML-DSA standalone with `MLDSA_USE_OPENSSL=ON` |
| Undefined references to internal `qudo_*` symbols | Internal symbols are hidden by the version script `config/libqudo-pqc.map` | Use only the documented public API ([C API Reference](../reference/API.md)) |
| MSVC build: VLA / `_Thread_local` errors | Non-C99 construct | The codebase is C99 + no VLAs; check local edits |

## Initialization — `qudo_pqc_init()` returns 0

`qudo_pqc_init()` returns `1` on success, `0` on failure. On failure the module
is in `ERROR`. Check the audit log for the component that failed:

| Audit code (`qudo_err_t`) | Cause | Fix |
|---|---|---|
| `QUDO_ERR_INTEGRITY_MISMATCH` (0x0206, embedded HMAC) / `QUDO_ERR_POST_INTEGRITY_FAIL` (0x0200, external cnf) | Module binary was modified after the HMAC was finalised (strip/sign/package) | Re-run `qudo_fipsinstall` after the **last** binary mutation |
| `QUDO_ERR_INTEGRITY_NO_CONFIG` (0x0207) | External-config deployment, but `module_path`/`module_checksum_hex` not supplied | Populate the integrity fields in `qudo_pqc_config_t` from `qudofipsmodule.cnf` before init |
| `QUDO_ERR_POST_KAT_FAIL` / `_KEYGEN_/_KEM_/_SIG_KAT_FAIL` | A power-on KAT failed (build/optimizer drift, miscompile) | Rebuild clean; verify the toolchain; do not ship a module that fails POST |
| `QUDO_ERR_DRBG_SEED_FAIL` / `_NOT_SEEDED` | Platform entropy source unavailable | Ensure the platform entropy source (`getentropy`/`getrandom`/`BCryptGenRandom`) is reachable |
| `QUDO_ERR_INIT_LOCK_FAIL` / `_ONCE_FAIL` | Once-init/lock failure; `qudo_pqc_init()` returns 0 with no audit event | Environmental; check the platform threading layer |

Calling init again while in `ERROR` returns `0`. A latched `ERROR` persists
until the library is unloaded and reloaded (or the process restarts);
`qudo_pqc_fini()` does not clear it.

## Operations rejected even though init succeeded

| Symptom | Cause | Fix |
|---|---|---|
| Every crypto call fails immediately | Module is in `ERROR` (latched) or not `RUNNING` | `qudo_pqc_get_state()`; recover by reloading the library or restarting the process |
| A specific algorithm is refused | Its parameter set is below the configured minimum security level | Lower the floor with `qudo_pqc_set_min_security_level()` or use an approved set (KEM cat 1/3/5, DSA 2/3/5, SLH-DSA 1/3/5) |
| Operation reports not-approved via the FIPS indicator | DRBG not ready, or the parameter set is below the configured minimum security level | Check `qudo_fips_ind_is_approved()`; ensure a primary entropy source |

## Self-test (POST / CAST) failures

- **POST** runs at init; any failure latches `ERROR` and blocks all operations.
  Use `qudo_pqc_post_integrity_passed()` / `qudo_pqc_post_drbg_kat_passed()` to
  localise. A failing POST KAT on a previously-good binary almost always means a
  toolchain/optimization change — rebuild clean and re-verify.
- **CAST** failures log `QUDO_ERR_CAST_KEYGEN_FAIL` (keygen step) or
  `QUDO_ERR_CAST_FAIL` (consistency mismatch); inspect per-algorithm status with
  `qudo_pqc_get_cast_status(id)`.

## Pairwise Consistency Test (PCT) failures on keygen/import

In FIPS builds a PCT runs after each Object-API key generation and **zeroizes**
the keys on failure (`QUDO_ERR_PCT_KEYGEN_FAIL` / `_IMPORT_FAIL` /
`_ENCAPS_FAIL` / `_SIGN_FAIL`).

Whether a keygen PCT failure is fatal depends on how the module was initialised
(`src/qudo_pqc_init.c`):

- `qudo_pqc_init(NULL)` — the default config sets `conditional_errors = 1`, so a
  PCT failure is **fatal**: the module enters `ERROR`.
- `qudo_pqc_init(&cfg)` with a caller-supplied config — a PCT failure is fatal
  **only when `cfg.conditional_errors = 1`**. With `0` (the value a
  zero-initialised struct carries) the failure is logged as a warning, the
  keypair is discarded, and the module stays `RUNNING`.

Recommendation: set `conditional_errors = 1` in any config you supply. (An
import-PCT failure, `QUDO_ERR_PCT_IMPORT_FAIL`, is always reported as transient
and does not change the module state.)

| Behaviour | Cause | Fix |
|---|---|---|
| Keygen fails, module stays `RUNNING` | `conditional_errors = 0` was set in the config (warn-only; `qudo_pqc_init(NULL)` defaults to 1) | Expected; the bad keypair is discarded — retry keygen |
| Keygen fails and module enters `ERROR` | `conditional_errors = 1` was set | Intended hard-fail policy; reload the library or restart the process |
| Persistent PCT failures | Corrupted entropy or a miscompiled algorithm | Rebuild clean; run the test suite ([Testing](TESTING.md)) |

## DRBG / entropy issues

| Symptom | Cause | Fix |
|---|---|---|
| `QUDO_ERR_DRBG_HEALTH_FAIL` (0x0502) | SP 800-90B RCT/APT health test tripped on the noise source | Health test failed; the failure is sticky and the module latches `ERROR` — investigate the platform RNG, then reload the library |
| `*_ERROR_RNG` (`-5`) from a wrapper op | DRBG not seeded / generate failed | Confirm init succeeded and an entropy source is present |
| Request rejected as too large | `qudo_pqc_ctrdrbg_generate()` rejects requests over 65,536 bytes | Split into multiple calls (`qudo_pqc_rand_bytes()` chunks automatically) |

## Wrapper operation errors (per-call status codes)

Wrapper functions return `0` on success, negative on error (thread-local detail
via `QUDO_<FAMILY>_get_last_error()`):

| Code | Meaning | Typical fix |
|---|---|---|
| `-2 INVALID_ARG` / `-3 NULL_PTR` | Bad argument / NULL buffer | Check arguments and buffer sizes against [API](../reference/API.md) |
| `-4 ALLOC` | Allocation failure | Memory pressure / oversized request |
| `-5 RNG` | DRBG unavailable | See DRBG section above |
| `-6 VERIFY` / `-14 INVALID_SIGNATURE` | `-6`: signature verification failed (ML-DSA/SLH-DSA) or KEM key check failed; `-14`: ML-DSA signature of wrong length | Wrong key, tampered/mismatched data, or wrong context string |
| `-7 DECODE` / `-12 ENCODE` | DER/PEM (de)serialization failed | Malformed input, or wrong parameter set for the blob |
| `-8 NOT_IMPL` | Feature not built (e.g. ML-DSA explicit-format DER/PEM without OpenSSL) | See Build issues |
| `-13 BUFFER_TOO_SMALL` | Output buffer too small | Size from the `*_BYTES` macros / size-query APIs ([Algorithms](../reference/ALGORITHMS.md)) |

## Loader / runtime / platform

| Symptom | Cause | Fix |
|---|---|---|
| `cannot open shared object` / `library not found` | Loader can't find `libqudo-pqc.so/.dylib/.dll` | Linux `ldconfig` / `LD_LIBRARY_PATH`; macOS `DYLD_LIBRARY_PATH` or rpath; Windows add dir to `PATH` |
| macOS: library refuses to load after `-embed` | `-embed` invalidated the Mach-O code signature | Sign after `qudo_fipsinstall -embed`: `codesign --remove-signature <lib>; codesign -s - -f <lib>` (see [Notes — Unix](../reference/NOTES_UNIX.md)) |
| Windows: integrity error at init | App didn't load `qudofipsmodule.cnf` into `qudo_pqc_config_t`, or the cnf doesn't match the DLL | Regenerate the cnf after all mutations and supply it before init ([Notes — Windows](../reference/NOTES_WINDOWS.md)) |
| Wrong/slow SIMD path | CPU feature not exposed (VM/container) | `QUDO_KEM_get_features()` / `print_system_info()` to confirm AVX2/NEON detection |

## Module error codes

Module-level `qudo_err_t` values (`include/qudo_pqc_err.h`) carried in audit
events and reason strings:

| Group | Codes |
|---|---|
| State (0x01xx) | `STATE_INVALID`, `MODULE_NOT_RUNNING`, `MODULE_ERROR_STATE`, `INIT_LOCK_FAIL`, `INIT_ONCE_FAIL` |
| POST / integrity (0x02xx) | `POST_INTEGRITY_FAIL`, `POST_KAT_FAIL`, `POST_KEYGEN/KEM/SIG_KAT_FAIL`, `INTEGRITY_HMAC_FAIL`, `INTEGRITY_MISMATCH`, `INTEGRITY_NO_CONFIG` |
| PCT (0x03xx) | `PCT_KEYGEN_FAIL`, `PCT_IMPORT_FAIL`, `PCT_ENCAPS_FAIL`, `PCT_SIGN_FAIL` |
| CAST (0x04xx) | `CAST_NOT_RUN`, `CAST_FAIL`, `CAST_KEYGEN_FAIL` |
| DRBG (0x05xx) | `DRBG_NOT_SEEDED`, `DRBG_SEED_FAIL`, `DRBG_HEALTH_FAIL`, `DRBG_RESEED_FAIL`, `DRBG_GENERATE_FAIL` |
| Key (0x06xx) | `KEY_INVALID`, `KEY_SIZE_MISMATCH`, `KEY_ZEROIZE_FAIL` |
| General (0x0Fxx) | `ALLOC`, `PARAM_INVALID`, `PARAM_NULL`, `NOT_SUPPORTED`, `INTERNAL` |

## When to escalate

If POST, a CAST, or an integrity check fails on a clean, unmodified build of a
known-good commit, treat it as a potential defect, not an environment issue:
capture the audit log and the build configuration and follow
[CONTRIBUTING.md](../../CONTRIBUTING.md) / [SECURITY.md](../../SECURITY.md) (for
anything security-relevant).
