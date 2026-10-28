# Development Guide

Developer-workflow notes for working on the QUDO PQC **library** (`libqudo-pqc`)
in this repository. For the contribution process (pull requests, review) and
code style see the root [`CONTRIBUTING.md`](../../CONTRIBUTING.md); this guide
covers the build/test/debug loop and the constraints specific to a FIPS module
build (`QUDO_FIPS_MODULE=ON`).

## Related documents

| Topic | Document |
|-------|----------|
| Architecture & design | [design/ARCHITECTURE.md](../design/ARCHITECTURE.md) |
| C API | [reference/API.md](../reference/API.md) |
| Algorithms & parameter sets | [reference/ALGORITHMS.md](../reference/ALGORITHMS.md) |
| Building | [INSTALL.md](../../INSTALL.md) |
| Test suite & ACVP | [TESTING.md](TESTING.md) |
| Debugging | [DEBUGGING.md](DEBUGGING.md) |
| Versioning & release | [maintenance/VERSIONING.md](../maintenance/VERSIONING.md) |

## Build / test loop

```bash
# Standard build + tests
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
ctest --test-dir build --output-on-failure

# FIPS module build (adds POST / CAST / integrity / state machine + gated tests)
cmake -S . -B build-fips -DQUDO_FIPS_MODULE=ON && cmake --build build-fips -j
ctest --test-dir build-fips --output-on-failure
```

`build.sh` wraps these (`--fips`, `-t`, `-s`/`-m`/`--tsan`, `--acvp`); see
[INSTALL.md](../../INSTALL.md).

## FIPS-module constraints (read before changing the build)

In embedded-HMAC mode the integrity self-test computes an HMAC-SHA-256 over a
**contiguous `.text` region** bounded by sentinel symbols; in external-cnf mode
it covers the whole library file. The following toolchain options are
incompatible with a `QUDO_FIPS_MODULE=ON` build:

- **No LTO** (`-flto`) — it reorders/merges code across the boundary.
- **No `-ffunction-sections` / `-fdata-sections`** and no `--gc-sections` — the
  algorithm objects are aggregated **between** the boundary sentinels with
  `-fno-function-sections -fno-data-sections` so nothing is reordered out of the
  measured region (see the parent `CMakeLists.txt`).
- **Boundary ordering matters** — `boundary_start` must link first and
  `boundary_end` last among the module objects.
- After any change that affects the binary, re-finalise the integrity HMAC
  (`qudo_fipsinstall -embed`, then re-codesign on macOS). A stale HMAC makes
  `qudo_pqc_init()` fail POST and latch the module in `ERROR`.

The three sub-libraries are pulled in as CMake **OBJECT** libraries and merged
into a single `libqudo-pqc`, so all crypto code lands inside the boundary.

## Vendored upstreams (`*-native`)

The lattice/hash mathematics lives in vendored, formally-verified upstreams
(`qudo-mlkem/mlkem-native/`, etc.). Upstream sources are kept unmodified; QUDO
additions live in a `qudo_runtime_dispatch/` subdirectory, and upstream updates
import a pinned upstream commit. The algorithm set is fixed by FIPS 203/204/205.

## Coding standards

- Format with `clang-format` (`.clang-format`) and check with `clang-tidy`
  (`.clang-tidy`) before pushing; `./run_all_tests.sh --full` runs both.
- Every source file carries an SPDX licence header.
- Public symbols are restricted by `config/libqudo-pqc.map`; new internal symbols
  stay hidden (`local: *`).
- Sensitive material must be zeroized (`qudo_cleanse` / `qudo_secure_clear`)
  before free.

## Debugging

Sanitizers, Valgrind, coverage, fuzzing, error inspection and FIPS-state
diagnosis are covered in [DEBUGGING.md](DEBUGGING.md).
