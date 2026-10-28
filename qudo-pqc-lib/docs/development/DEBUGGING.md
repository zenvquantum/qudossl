# Debugging

Debugging `libqudo-pqc`: sanitizers, memory checking, coverage, fuzzing, error
inspection, and FIPS-state diagnosis.

## Sanitizers (ASan + UBSan / MSan / TSan)

```bash
./build.sh -s          # ASan + UBSan        (-DENABLE_SANITIZERS=ON)
./build.sh -m          # MemorySanitizer     (-DENABLE_MSAN=ON, Clang only)
./build.sh --tsan      # ThreadSanitizer     (-DENABLE_TSAN=ON)
ctest --test-dir build-asan --output-on-failure
```

Library tests run directly under the sanitizer with no special flags (the module
allocates and frees its own buffers, so there are no benign exit leaks to mask).
TSan coverage includes `test_pct_concurrent_tsan` (concurrent keygen/PCT).

## Valgrind

Per sub-library memcheck scripts:

```bash
bash qudo-mlkem/tests/test_valgrind.sh
bash qudo-mldsa/tests/test_valgrind.sh
bash qudo-slhdsa/tests/test_valgrind.sh
```

Or manually against a built test binary (`test_pqc_post` exists only in the
FIPS build, `-DQUDO_FIPS_MODULE=ON`):

```bash
valgrind --leak-check=full --error-exitcode=1 build-fips/tests/test_pqc_post
```

## Code Coverage

```bash
./build.sh --coverage          # or  cmake -DENABLE_COVERAGE=ON
bash coverage.sh               # capture + filter + HTML (lcov)
```

`coverage.sh` removes external/test/native code from the report so coverage
reflects the QUDO wrapper and FIPS-module sources.

## Fuzzing

- Per-sub-library libFuzzer harnesses under `qudo-{mlkem,mldsa,slhdsa}/fuzz/`
  (DER/PEM/key import, sign/KEM ops) with `run_fuzz.sh` + seed corpora.
- Deterministic corpus replay: `tests/fuzz_corpus_replay.c`, enabled with
  `-DQUDO_FUZZ_REPLAY=ON`, feeds each corpus file to the harness so findings are
  reproducible without a fuzzing engine. The corpora are gitignored, so replay
  runs against a locally populated `corpus_*` directory; it is not part of CI.

## Library Error Inspection

Each family keeps thread-local error state:

```c
#include "mlkem_wrapper.h"

if (QUDO_KEM_keypair(kem, pk, sk) != QUDO_KEM_SUCCESS) {
    const QUDO_KEM_error_info_t *e = QUDO_KEM_get_last_error();  /* thread-local */
    fprintf(stderr, "%s in %s (line %d): %s\n",
            QUDO_KEM_get_error_string(e->code), e->func, e->line, e->detail);
}
```

Common status codes are negative (`QUDO_KEM_ERROR_*`, down to `-13`; ML-DSA/
SLH-DSA add `-14 INVALID_SIGNATURE`). See [C API Reference](../reference/API.md).

## FIPS State Debugging

When something fails during init or an operation is rejected, inspect the module
state and self-test results:

```c
qudo_pqc_get_state();              /* INIT=0, SELFTEST=1, RUNNING=2, ERROR=3 */
qudo_pqc_post_drbg_kat_passed();   /* granular POST results */
qudo_pqc_post_integrity_passed();
qudo_pqc_get_cast_status(id);      /* per-algorithm CAST status */
```

Register an `audit_cb` (in `qudo_pqc_config_t`) to receive STATE / POST /
INTEGRITY / PCT / CAST / DRBG events with severity — the fastest way to see why
the module latched `ERROR`.

## CPU Dispatch Verification

```c
QUDO_KEM_has_avx2();        /* which SIMD backend was selected */
QUDO_KEM_has_neon();
QUDO_KEM_get_features();    /* human-readable feature string */
QUDO_KEM_print_system_info();
```

## Debug Build & GDB

```bash
cmake -S . -B build-dbg -DCMAKE_BUILD_TYPE=Debug -DQUDO_FIPS_MODULE=ON && cmake --build build-dbg -j
gdb --args build-dbg/tests/test_pqc_post --kats
```

Build with `-DCMAKE_BUILD_TYPE=Debug` for unstripped symbols and no
optimisation. Note that a Debug build is **not** a valid FIPS module build (the
integrity boundary requires the Release/FIPS flags).
