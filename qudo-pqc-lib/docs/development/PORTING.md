# Porting & Embedded Guide

`libqudo-pqc` is portable C99 with no external cryptographic dependency, which
makes it straightforward to bring up on new targets. This guide covers
cross-compilation, embedded/firmware builds, and platform entropy on bare-metal
targets.

For desktop/server platforms see [Notes — Unix](../reference/NOTES_UNIX.md) /
[Windows](../reference/NOTES_WINDOWS.md); for the FIPS build see
[INSTALL.md](../../INSTALL.md).

## Cross-compilation

Toolchain files live in `cmake/toolchains/` (aarch64, armhf, riscv64, x86,
arm64-windows-msvc):

```bash
cmake -S . -B build-arm \
      -DCMAKE_TOOLCHAIN_FILE=cmake/toolchains/aarch64-linux-gnu.cmake \
      -DCMAKE_BUILD_TYPE=Release -DQUDO_FIPS_MODULE=ON
cmake --build build-arm -j
qemu-aarch64-static build-arm/tests/test_pqc_post   # test under emulation
```

Runtime CPU dispatch (AVX2/NEON for the lattice families) is detected at run
time, so a single cross-built binary runs across micro-architectures of the same
ISA. SLH-DSA has no lattice SIMD dispatch; it uses SHA-NI (selected at run time
via CPUID) on Linux x86-64 and assembly Keccak on Linux/macOS x86-64. Windows
builds use the portable C code.

## Embedded / firmware builds

Two build options target constrained environments:

| Option | Effect |
|--------|--------|
| `MLKEM_EMBEDDED_BUILD` (per sub-library) | Builds for systems without a full stdlib; drops the RELRO/BIND_NOW/noexecstack linker hardening that doesn't apply to firmware (`qudo-mlkem/CMakeLists.txt`; `MLDSA_EMBEDDED_BUILD` in `qudo-mldsa/CMakeLists.txt` is the ML-DSA equivalent) |
| `QUDO_BUILD_EMBEDDED_OBJ` (top level, `QUDO_FIPS_MODULE=ON` only) | Produces a static archive plus a partial-linked `qudo_fips_module.o` for linking the library into firmware (`CMakeLists.txt`) |

```bash
# FIPS module as a partial-link object for firmware integration
cmake -S . -B build-emb -DQUDO_FIPS_MODULE=ON -DQUDO_BUILD_EMBEDDED_OBJ=ON
cmake --build build-emb -j
# -> static archive + qudo_fips_module.o  (see CMakeLists.txt "Usage (embedded firmware)")
```

Guidance:
- **No OpenSSL.** The library links no external crypto; DER and PEM both work
  without OpenSSL. Only the ML-DSA explicit-format functions
  (`QUDO_MLDSA_*_der_format` / `*_pem_format`) return `*_ERROR_NOT_IMPL`.
- **Prefer the Direct API** (zero-allocation, caller-provided buffers) on targets
  with constrained or no heap; the Object API needs a heap allocator.
- **Stack usage.** Signature operations (especially SLH-DSA, and ML-DSA rejection
  sampling) use non-trivial stack; size task/thread stacks accordingly and test
  with your toolchain's stack-usage reporting.

## Platform entropy

The library seeds its SP 800-90A CTR_DRBG from the OS CSPRNG via
`raw_platform_entropy()` (`src/fips/qudo_fips_rand.c`), which uses
`getentropy`/`getrandom` (Linux/macOS) or `BCryptGenRandom` (Windows). A
bare-metal/RTOS port must provide a cryptographically secure entropy source for
that path; without it `qudo_pqc_init()`
fails (`QUDO_ERR_DRBG_SEED_FAIL`) and the library stays in `ERROR`.

Requirements for a port's entropy source:
- Full-entropy output.
- Available before the first cryptographic call (the startup health test draws
  1,024 samples).
- A well-characterised source; an unconditioned hardware TRNG should be assessed
  under SP 800-90B.

The SP 800-90B health tests (RCT/APT) still run on whatever source you supply, so
a stuck or biased source is caught (`QUDO_ERR_DRBG_HEALTH_FAIL`).

## Thread safety

The module state machine, DRBG, and self-test paths are synchronised; wrapper
error state is thread-local. On an RTOS, ensure the locking primitives the
platform layer expects are available, or build single-threaded.

## Verify the port

```bash
ctest --test-dir <build> --output-on-failure      # full suite (POST/PCT in FIPS build)
bash acvp/run_acvp.sh --build-dir <build-acvp>     # NIST vectors, if reachable
```

A correct port matches the ACVP known-answer vectors bit-for-bit; in the FIPS
build (`-DQUDO_FIPS_MODULE=ON`) it also passes POST at init and runs the PCT on
keygen. See [Testing](TESTING.md) and
[Troubleshooting](TROUBLESHOOTING.md).
