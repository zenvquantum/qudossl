# Notes for Windows

Library-side build, install, and FIPS-deployment notes for Windows. For generic
build instructions and the FIPS build (`QUDO_FIPS_MODULE=ON`)
see [INSTALL.md](../../INSTALL.md).

This document covers `libqudo-pqc` (built as `qudo-pqc.dll`). The
integrity-config sections below apply to any consumer of the library.

---

## Prerequisites

The library has **no external cryptographic dependency**. Only a C99
toolchain and CMake are required.

### Option 1 — MSVC (Visual Studio 2019+ / 2022)

1. Install **Visual Studio 2019 v16.11+** or **Visual Studio 2022** with
   the "Desktop development with C++" workload.
2. Install **CMake 3.15+** — bundled with VS, or from <https://cmake.org/download/>.

### Option 2 — MinGW-w64 (GCC on Windows)

1. Install **MSYS2** from <https://www.msys2.org/>.
2. From the MSYS2 MinGW 64-bit terminal:

   ```bash
   pacman -S mingw-w64-x86_64-gcc mingw-w64-x86_64-cmake \
             mingw-w64-x86_64-make git ninja
   ```

---

## Build

### With the wrapper script (recommended)

The repository ships `build_windows.bat`, which detects MSVC or MinGW
and applies the right flags. From the repository root in `cmd.exe`:

```bat
build_windows.bat              REM Standard build (build/)
build_windows.bat --fips       REM FIPS build (build-fips/) + generate qudofipsmodule.cnf
build_windows.bat --fips --test  REM FIPS build + run ctest
build_windows.bat --help       REM Full option list
```

With `--fips` the script additionally runs `qudo_fipsinstall -out` to
produce `build-fips\qudofipsmodule.cnf` — Windows uses the
external-config integrity path because MSVC's `/OPT:ICF` folding and
stripped COFF symbol tables make in-binary HMAC patching unreliable.

### Manual CMake (MSVC)

From a **Developer Command Prompt for VS 2022**:

```cmd
cmake -S . -B build -G "Visual Studio 17 2022" -A x64 ^
      -DCMAKE_BUILD_TYPE=Release
cmake --build build --config Release -j
```

For ARM64 add `-A ARM64` (VS 2022).

### Manual CMake (MinGW)

From the MSYS2 MinGW 64-bit shell:

```bash
cmake -S . -B build -G "MinGW Makefiles" -DCMAKE_BUILD_TYPE=Release
cmake --build build -j
```

`Ninja` is also supported (`-G Ninja`) on both MSVC and MinGW and is
faster.

---

## Install

```cmd
cmake --install build --config Release
```

By default this installs under `C:\Program Files\qudo-pqc\` (run from an
elevated prompt). Use `--prefix <path>` for a custom location.

The DLL must be discoverable by consumers — either keep it adjacent to
the consuming `.exe`, or add its directory to `PATH`:

```cmd
set PATH=C:\Program Files\qudo-pqc\bin;%PATH%
```

---

## FIPS integrity setup

The FIPS build verifies module integrity in `qudo_pqc_init()`
using HMAC-SHA-256. On Windows the **external-config** path is used (the
embedded-HMAC path is supported only on ELF / Mach-O).

### Step 1 — Generate the integrity config

Run AFTER all binary mutations (codesign / signtool, strip, package
build). For a standalone library deployment:

```bat
"C:\path\to\bin\qudo_fipsinstall.exe" ^
    -module "C:\path\to\bin\qudo-pqc.dll" ^
    -out    "C:\path\to\config\qudofipsmodule.cnf"
```

### Step 2 — Supply the config to `qudo_pqc_init()`

`libqudo-pqc.dll` does not locate the cnf itself. The application reads
`qudofipsmodule.cnf` and populates
`module_path` + `module_checksum_hex` in `qudo_pqc_config_t` before the
init call.

### Step 3 — Verify

```bat
qudo_fipsinstall.exe -verify ^
    -module "C:\path\to\bin\qudo-pqc.dll" ^
    -in     "C:\path\to\config\qudofipsmodule.cnf"
```

A successful run exits 0 with no error output. Re-run after every binary
mutation.

---

## Authenticode signing

If your deployment requires Authenticode-signed DLLs, sign the
DLL BEFORE running `qudo_fipsinstall -out` (signing modifies the PE
binary by appending the signature; the integrity HMAC must be computed
afterward).

```bat
REM 1. Build FIPS module
build_windows.bat --fips

REM 2. Sign the DLL
signtool sign /fd SHA256 /tr http://timestamp.digicert.com /td SHA256 ^
    /a build-fips\lib\qudo-pqc.dll

REM 3. Verify the signature
signtool verify /pa /v build-fips\lib\qudo-pqc.dll

REM 4. Recompute the integrity config AFTER signing
build-fips\tools\qudo_fipsinstall.exe ^
    -module build-fips\lib\qudo-pqc.dll ^
    -out    build-fips\qudofipsmodule.cnf
```

Any re-sign requires re-running `qudo_fipsinstall`.

---

## Testing

```cmd
ctest --test-dir build --output-on-failure -C Release
```

For the FIPS test groups:

```cmd
ctest --test-dir build-fips --output-on-failure -C Release
```

Sanitizers and ThreadSanitizer are available on Clang (Windows or
MinGW); MSVC supports ASan via `/fsanitize=address` in recent toolsets.

---

## Troubleshooting

### "`qudo-pqc.dll` was not found"

The DLL must be discoverable. Add its directory to `PATH`:

```cmd
set PATH=C:\Program Files\qudo-pqc\bin;%PATH%
```

Or copy `qudo-pqc.dll` next to the consuming `.exe`.

### "MSVCR140.dll missing" or similar VC++ runtime errors

Install the [Visual C++ Redistributable](https://aka.ms/vs/17/release/vc_redist.x64.exe).

### "`libgcc_s_seh-1.dll` missing" (MinGW builds)

Add the MinGW runtime to PATH:

```bash
export PATH=/mingw64/bin:$PATH
```

(MSYS2 shell), or copy the required MinGW DLLs alongside `qudo-pqc.dll`.

### `qudo_pqc_init()` fails with an integrity error

The application did not populate `module_path` and `module_checksum_hex`
from `qudofipsmodule.cnf` before calling init, the cnf path supplied
does not match the loaded DLL, or the DLL was modified after the cnf
was generated. Re-read the cnf and re-`fipsinstall -out` if needed.

---

## Linux ↔ Windows differences (for porters)

| Feature              | Linux                       | Windows (MSVC)                                | Windows (MinGW)               |
| -------------------- | --------------------------- | --------------------------------------------- | ----------------------------- |
| Compiler             | GCC / Clang                 | MSVC `cl.exe`                                 | GCC (MinGW-w64)               |
| Library file         | `libqudo-pqc.so`            | `qudo-pqc.dll`                                | `libqudo-pqc.dll`             |
| Integrity HMAC       | Embedded HMAC (recommended) | External `qudofipsmodule.cnf`                 | External `qudofipsmodule.cnf` |
| Boundary enforcement | `-fno-function-sections` + linker script + POST_BUILD check | Integrity verified via the external cnf (HMAC-SHA-256 over the full DLL file) | `-fno-function-sections` only |
| Build tool           | Make / Ninja                | MSBuild / Ninja                               | Make / Ninja                  |
| Path separator       | `/`                         | `\` or `/`                                    | `/` (MSYS shell)              |

Source uses `#ifdef _WIN32` / `#ifdef __APPLE__` etc. for platform
differences. The public API is identical on every platform.

---

## Build and test

To build the FIPS module and run the tests on Windows (MSVC or MinGW-w64), run
`build_windows.bat --fips --test`.

## Further Reading

- [CMake on Windows](https://cmake.org/cmake/help/latest/manual/cmake-generators.7.html#visual-studio-generators)
- [Authenticode signing — Microsoft Learn](https://learn.microsoft.com/en-us/windows/win32/seccrypto/authenticode)
