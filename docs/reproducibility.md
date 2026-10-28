# Reproducible builds

Two clean builds of the same commit produce byte-identical artifacts on Linux
and macOS. The reproducible-build kit lets anyone rebuild QudoSSL and compare
the resulting artifacts.

Supported platforms: Linux x86_64, Linux aarch64, macOS arm64, Windows x64.

## Status

| Platform | Mechanism | Verified |
|---|---|---|
| Linux x86_64 | `SOURCE_DATE_EPOCH`, `-Wl,--build-id=none`, `-ffile-prefix-map` | CI |
| Linux aarch64 | same | CI |
| macOS arm64 | `SOURCE_DATE_EPOCH`, `ZERO_AR_DATE=1`, `-ffile-prefix-map` | CI |
| Windows x64 | `/Brepro` | Not verified |

## Per-platform notes

### Linux

`--build-id=none` suppresses the linker-generated build ID;
`SOURCE_DATE_EPOCH` fixes embedded timestamps; `-ffile-prefix-map` keeps
absolute build paths out of the binaries. GNU `ar` creates deterministic
archives by default in current toolchains (`D` flag).

### macOS

`-Wl,-no_uuid` is not used. Stripping `LC_UUID` from `libcrypto.dylib` causes
the macOS linker to refuse to link against it:

```
ld: missing LC_UUID load command in './libcrypto.dylib'
```

Determinism comes from:

- **`ZERO_AR_DATE=1`** — zeroes the timestamps `ar`/`libtool` embed in static
  archive members.
- **Content-derived `LC_UUID`** — ld64 computes the UUID from a hash of the
  linked image, so identical inputs yield an identical UUID.
- **`-ffile-prefix-map`** — as on Linux.

### Windows

Windows reproducibility is not verified. `build/build.ps1` passes `/Brepro`,
which asks the MSVC toolchain to emit a deterministic PE with no link
timestamp. Known limitations:

- MSVC does not honour `SOURCE_DATE_EPOCH`.
- PDB paths and the debug directory can embed absolute paths.
- `lib.exe` archive member ordering and timestamps are not checked.

`verify-reproducible.sh` has no PowerShell equivalent.

## Running the check

```sh
make -C build repro-check          # Linux / macOS
```

Or in the pinned container:

```sh
docker build -f reproducible-build/Dockerfile.reproducible -t qudossl-repro .
docker run --rm -v "$PWD:/src" -w /src qudossl-repro make -C build repro-check
```

## Scope

The check covers `libqudo-pqc.a`, the static `libcrypto.a` and `libssl.a` and,
on Linux and macOS, the FIPS module (`fips.so` / `fips.dylib`). The shared
`libcrypto` and `libssl` libraries are not compared.
