# CI

GitHub Actions reads workflows from `.github/workflows/`, so the active
definitions live there — see `.github/workflows/ci.yml`.

This directory holds CI support material that is not a workflow file:
helper scripts, the ABI symbol baseline (`baselines/`), and the interop
harness (`interop/`).

## Matrix

| Job | Purpose |
|---|---|
| `linux-x86_64-fips` | FIPS build, delegation-linked check, OpenSSL test suite |
| `linux-aarch64-fips` | same, on arm64 |
| `macos-arm64-fips` | same, on macOS arm64 |
| `windows-x64-fips` | same, via MSVC / nmake (`build/build.ps1`) |
| `linux-x86_64-default` | non-FIPS build, delegation-linked check, test suite |
| `qudo-pqc-lib standalone tests` | full standalone build of `qudo-pqc-lib` with its tests, run under ctest (`make -C build test-pqc`) |
| `upstream-parity` | every divergence of `openssl/` from the `openssl-3.5.7` release export is inside the permitted delegation seam |
| `reproducible-build` | two clean builds, byte-compare — Linux x86_64, Linux aarch64 and macOS arm64 |
| `boundary-gates` | builds the math-only `qudo-pqc` archive, then runs `check-mlkem-constructible.sh`, `check-boundary-symbols.sh` and `check-seeded-entrypoints.sh` |
| `abi-compat` | exported `libcrypto.so` symbols must match `baselines/libcrypto.syms` |

The four supported platforms are Linux x86_64, Linux aarch64, macOS arm64 and
Windows x64.

Windows uses MSVC and nmake, driven by `build/build.ps1` instead of
`build/Makefile`.

## Reproducibility per platform

`reproducible-build` runs as a matrix over Linux and macOS. Per-platform
mechanisms are described in `docs/reproducibility.md`. Windows reproducibility
is not verified.
