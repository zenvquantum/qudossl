# ACVP Harness for libqudo-pqc

This directory runs NIST ACVP (Automated Cryptographic Validation
Protocol) test vectors against the post-quantum primitives in
`libqudo-pqc.so`.

## Purpose

NIST publishes algorithm test vectors in the ACVP JSON format
(see `https://pages.nist.gov/ACVP/`). This harness:

1. Fetches published NIST ACVP request / expected-result vector sets.
2. Replays every prompt against `libqudo-pqc.so` via small C drivers.
3. Compares each driver output field by field against the NIST
   expected-result file.

A run passes if no prompt fails; prompts without a matching expected result,
or with an unsupported parameter set, are reported as skipped.

## Layout

```
qudo-pqc-lib/acvp/
├── CMakeLists.txt           build rules for the C drivers
├── run_acvp.sh              driver script (ML-KEM, ML-DSA, SLH-DSA)
├── acvp_common.[ch]         JSON parsing and hex helpers
├── acvp_client_mlkem.py     ACVP client for FIPS 203 ML-KEM
├── acvp_client_mldsa.py     ACVP client for FIPS 204 ML-DSA
├── acvp_client_slhdsa.py    ACVP client for FIPS 205 SLH-DSA
├── acvp_mlkem.c             C driver invoking libqudo-pqc ML-KEM
├── acvp_mldsa.c             C driver invoking libqudo-pqc ML-DSA
├── acvp_slhdsa.c            C driver invoking libqudo-pqc SLH-DSA
└── .acvp-data/<version>/files/
                             locally cached NIST ACVP vector sets (created on first run)
```

## Vector source

The Python clients fetch test vectors from

```
https://raw.githubusercontent.com/usnistgov/ACVP-Server/<version>/gen-val/json-files
```

on first run and cache them under `.acvp-data/<version>/files/`.
`--version v1.1.0.41` is the default pinned revision. No credentials
and no live connection to the NIST ACVP server are required for
replay.

## Running

1. Build with the ACVP drivers enabled (from the `qudo-pqc-lib/` directory):

   ```sh
   cd qudo-pqc-lib
   ./build.sh --acvp
   ```

2. Run all three suites:

   ```sh
   bash acvp/run_acvp.sh
   ```

   Useful flags:
   - `--build-dir PATH`  select a non-default build tree
   - `--version v1.1.0.41`  pin an ACVP vector version
   - `--skip-slhdsa`  omit the SLH-DSA suite (slowest)

   The script sets `LD_LIBRARY_PATH` to the built `libqudo-pqc`,
   invokes each Python client against the matching C driver, and
   exits non-zero if any prompt fails to match the NIST expected
   result.

## Relationship to POST KATs

The power-on self-test KATs in `qudo-pqc-lib/src/qudo_self_test_data.inc`
(executed by `qudo_pqc_post.c` in `QUDO_FIPS_MODULE=ON` builds) serve a
different purpose:

| Concern          | POST KATs (`qudo_self_test_data.inc`) | ACVP harness (this dir) |
|------------------|---------------------------------------|-------------------------|
| When it runs     | `qudo_pqc_init()` / `qudo_pqc_self_test()` | On demand          |
| What it checks   | Implementation drift vs. frozen build | Algorithm correctness   |
| Vector source    | Deterministic, library-local seeds    | NIST ACVP vector sets   |
| Output           | Pass / fail at load time              | Pass / fail per prompt  |

The C drivers in this directory are test clients of the library and are
not part of it.
