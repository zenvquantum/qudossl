# QUDO PQC

Production C implementation of NIST Post-Quantum Cryptography — [FIPS 203][fips203]
(ML-KEM), [FIPS 204][fips204] (ML-DSA), and [FIPS 205][fips205] (SLH-DSA) — built as a
single, dependency-free library designed for FIPS 140-3.

**Version:** 1.0.0 · **License:** Apache-2.0 AND MIT · See [CHANGELOG.md](CHANGELOG.md)
for release notes.

## Architecture

QUDO PQC ships as a single library, `libqudo-pqc`, that aggregates three algorithm
families. Each family is a wrapper around an upstream implementation vendored
in-tree (`mlkem-native` and `mldsa-native`, which carry formal-verification
proofs, and `slhdsa-native`); see [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).

```
Application
    |
    v
libqudo-pqc  ──  qudo_pqc.h            (module lifecycle, FIPS state, audit)
    │            mlkem_wrapper.h       ──> mlkem-native    (FIPS 203)
    │            mldsa_wrapper.h       ──> mldsa-native    (FIPS 204)
    └──          slhdsa_wrapper.h      ──> slhdsa-native   (FIPS 205)
                 │
                 └──> internal AES-256-CTR-DRBG, HMAC-SHA-256, SHA-2, SHA-3
                      (no OpenSSL or external crypto)
```

## Algorithms

**18 FIPS-approved parameter sets.** Full sizes and selection guidance in
[docs/reference/ALGORITHMS.md](docs/reference/ALGORITHMS.md).

| Family   | FIPS | Parameter Sets                                              |
| -------- | ---- | ----------------------------------------------------------- |
| ML-KEM   | 203  | ML-KEM-512, ML-KEM-768, ML-KEM-1024                         |
| ML-DSA   | 204  | ML-DSA-44, ML-DSA-65, ML-DSA-87                             |
| SLH-DSA  | 205  | SLH-DSA-{SHA2,SHAKE}-{128,192,256}{s,f}  (12 sets)          |

Runtime CPU dispatch picks AVX2 on x86_64 Linux/macOS and NEON on ARM64
automatically; Windows x86_64 builds use the portable C code.

## Quick Start

```bash
./build.sh
cd build && ctest --output-on-failure
```

Or the manual CMake path:

```bash
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j
ctest --test-dir build --output-on-failure
```

See [INSTALL.md](INSTALL.md) for prerequisites (CMake 3.15+, C99 compiler) and
platform notes. Windows builds use [build_windows.bat](build_windows.bat).

## Build Options

| Option                      | Default | Purpose                                                                |
| --------------------------- | ------- | ---------------------------------------------------------------------- |
| `QUDO_FIPS_MODULE`          | OFF     | Build as FIPS 140-3 module (POST, KATs, integrity, state machine)      |
| `QUDO_PQC_MATH_ONLY`        | OFF     | PQC algorithm math only; the host supplies all FIPS services. Mutually exclusive with `QUDO_FIPS_MODULE` |
| `QUDO_PQC_BUILD_TESTS`      | ON      | Build the library test suite                                           |
| `BUILD_ACVP`                | OFF     | Build ACVP runners that replay published NIST ACVP test vectors        |
| `QUDO_BUILD_EMBEDDED_OBJ`   | OFF     | Static archive + partial-link object for embedded/firmware (FIPS only) |
| `BUILD_SHARED_LIBS`         | ON      | Shared (`.so`/`.dylib`/`.dll`) vs static library                       |
| `ENABLE_SANITIZERS`         | OFF     | ASan + UBSan                                                           |
| `ENABLE_MSAN`               | OFF     | MemorySanitizer (Clang only; mutually exclusive with the others)       |
| `ENABLE_TSAN`               | OFF     | ThreadSanitizer (mutually exclusive with the others)                   |
| `ENABLE_COVERAGE`           | OFF     | gcov/lcov instrumentation; see [coverage.sh](coverage.sh)              |

QudoSSL builds the library with `-DQUDO_PQC_MATH_ONLY=ON`: OpenSSL supplies the
FIPS services and this library supplies only the PQC mathematics.

## API at a Glance

Each algorithm family exposes two C APIs:

- **Object API** — heap-allocated handles, runtime algorithm selection, automatic
  resource management. Use this for general application code.
- **Direct API** — zero-allocation, caller-provided buffers, compile-time
  parameter selection. Use this for embedded and constrained systems.

```c
#include "qudo_pqc.h"
#include "mlkem_wrapper.h"

if (!qudo_pqc_init(NULL))                          // 1 = success, 0 = failure
    return EXIT_FAILURE;

QUDO_KEM *kem = QUDO_KEM_new("ML-KEM-768");
uint8_t pk[1184], sk[2400], ct[1088], ss_a[32], ss_b[32];

QUDO_KEM_keypair(kem, pk, sk);                     // wrappers: 0 = success
QUDO_KEM_encaps(kem, ct, ss_a, pk);
QUDO_KEM_decaps(kem, ss_b, ct, sk);                // ss_a == ss_b

QUDO_KEM_free(kem);
```

The full API for all three families — including DER/PEM serialization, deterministic
and hedged signing, and context strings — is in
[docs/reference/API.md](docs/reference/API.md).

## Use in QudoSSL

In QudoSSL this library supplies OpenSSL's ML-KEM / ML-DSA math; OpenSSL
supplies the self-tests, DRBG, integrity check and state machine. Neither this
library nor QudoSSL is FIPS 140-3 validated.

## FIPS 140-3 Module Build

With `-DQUDO_FIPS_MODULE=ON` the standalone library additionally builds power-on
self-tests, pairwise consistency tests, an HMAC-SHA-256 integrity check, an
`INIT → SELFTEST → RUNNING / ERROR` state machine, per-operation indicators and
an audit-log callback. After building, finalize the integrity HMAC:

```bash
# Embedded HMAC (Linux/macOS): patched into a reserved slot in the library.
./build/tools/qudo_fipsinstall -embed -module build/lib/libqudo-pqc.so

# External config (required on Windows; build_windows.bat does this). The
# application must read the cnf and populate qudo_pqc_config_t before
# calling qudo_pqc_init().
./build/tools/qudo_fipsinstall -module build/lib/libqudo-pqc.so \
                               -out   build/qudofipsmodule.cnf
```

## Examples

Each sub-library carries runnable examples:

- [qudo-mlkem/examples/](qudo-mlkem/examples) — `simple_kem`, `speed_mlkem`,
  client/server (object + direct APIs), DER/PEM round-trip, heap-allocation demo,
  speed benchmark.
- [qudo-mldsa/examples/](qudo-mldsa/examples) — deterministic keygen and signing,
  context strings, prehash (SHA-256), external mu, concat format, speed.
- [qudo-slhdsa/examples/](qudo-slhdsa/examples) — `simple_sign`, DER/PEM,
  `speed_slhdsa`.

## Testing

```bash
ctest --test-dir build --output-on-failure
```

30+ test binaries in [tests/](tests) cover POST, integrity path-pinning, PCT
fail-zeroize, DRBG limits and NIST test vectors, concurrent threading (TSan),
OpenSSL PEM interop, parameter-set bounds, sign/verify roundtrips, and full
wrapper-level coverage. See [docs/development/TESTING.md](docs/development/TESTING.md).

An ACVP test-vector harness is in [acvp/](acvp) — build with `-DBUILD_ACVP=ON`
and run via [acvp/run_acvp.sh](acvp/run_acvp.sh). See [acvp/README.md](acvp/README.md).

[run_all_tests.sh](run_all_tests.sh) wraps the local test passes: standard and
self-test (`QUDO_FIPS_MODULE=ON`) builds with CTest by default, `--sanitizers`
adds an ASan + UBSan build, and `--full` adds ASan + UBSan, valgrind, cppcheck,
clang-tidy and a clang-format check.

## Installation

```bash
cmake --install build --prefix /usr/local
```

This installs the library to `lib/`, headers to `include/qudo-pqc/`, and CMake
package config to `lib/cmake/qudo-pqc/`. Consume from another project with:

```cmake
find_package(qudo-pqc 1.0 REQUIRED)
target_link_libraries(myapp PRIVATE qudo::qudo-pqc)
```

## Documentation

### Using the library (`docs/reference/`)

- [INSTALL.md](INSTALL.md) — prerequisites, build, install (all platforms)
- [Algorithms & parameter sets](docs/reference/ALGORITHMS.md) — all 18 sets, sizes, selection
- [C API reference](docs/reference/API.md) — complete API for all three families
- [Usage examples](docs/reference/EXAMPLES.md) — task-oriented cookbook
- [Platform notes — Unix](docs/reference/NOTES_UNIX.md) · [Windows](docs/reference/NOTES_WINDOWS.md)

### Architecture & design (`docs/design/`)

- [Architecture & design](docs/design/ARCHITECTURE.md) — layers, components, algorithm flows, security design

### Development (`docs/development/`)

- [Development guide](docs/development/DEVELOPMENT.md) — dev workflow, build constraints
- [Test suite overview](docs/development/TESTING.md) — suite, test types, ACVP, self-tests
- [Debugging](docs/development/DEBUGGING.md) — sanitizers, valgrind, coverage, fuzzing
- [Troubleshooting](docs/development/TROUBLESHOOTING.md) — symptom → cause → fix
- [Porting & embedded](docs/development/PORTING.md) — cross-compile, embedded, entropy hookup

### Maintenance & release (`docs/maintenance/`)

- [Versioning policy](docs/maintenance/VERSIONING.md)
- [CHANGELOG.md](CHANGELOG.md)

## Support

- **Bugs and feature requests** — open an issue in the
  [QudoSSL repository](https://github.com/zenvquantum/qudossl/issues)
- **Security vulnerabilities** — see [SECURITY.md](SECURITY.md) for the
  responsible-disclosure policy. Do not file security issues publicly.

## Contributing

Pull requests are welcome. Please read [CONTRIBUTING.md](CONTRIBUTING.md) and
follow the [Code of Conduct](CODE_OF_CONDUCT.md). All contributions must include
SPDX license headers. Run [run_all_tests.sh](run_all_tests.sh) locally before
submitting.

## Legalities

QUDO PQC implements cryptographic algorithms. The use, import, and export of
cryptographic software may be restricted by the laws of your country. Check the
export-control regulations that apply in your jurisdiction before using or
distributing this software.

The NIST post-quantum algorithms implemented here (ML-KEM, ML-DSA, SLH-DSA) are
published standards. The upstream implementations vendored under
`qudo-mlkem/mlkem-native/`, `qudo-mldsa/mldsa-native/`, and
`qudo-slhdsa/slhdsa-native/` carry their own licenses — see the `LICENSE` file
inside each directory and the aggregated [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).

Copyright (c) 2024-2026 ZenV Quantum. Licensed under Apache-2.0 AND MIT — see
[LICENSE](LICENSE).

[fips203]: https://csrc.nist.gov/pubs/fips/203/final
[fips204]: https://csrc.nist.gov/pubs/fips/204/final
[fips205]: https://csrc.nist.gov/pubs/fips/205/final
[github-issues]: https://github.com/zenvquantum/qudossl/issues
