#!/bin/bash

# QUDO PQC Crypto Library Build Script
# Automated build for libqudo-pqc (ML-KEM, ML-DSA, SLH-DSA)
#
# Usage:
#   ./build.sh                - Standard build
#   ./build.sh --fips         - FIPS 140-3 module build
#   ./build.sh -f             - Clean rebuild
#   ./build.sh -t             - Build and run tests (tests always compiled)
#   ./build.sh -i             - Build and install; prefix is --prefix=<path>, else
#                               $OPENSSL_ROOT_DIR, else the parent of the
#                               directory holding the `openssl` binary in PATH
#   ./build.sh -s             - Build with ASan + UBSan
#   ./build.sh --coverage     - Build with code coverage
#   ./build.sh --fips -t      - FIPS build + run tests (always clean)
#   ./build.sh --fips -i      - FIPS build + install (same prefix selection as -i)
#   ./build.sh -c, --clean    - Remove all build directories (no rebuild)
#   ./build.sh --uninstall    - Remove old qudo-pqc from system
#
# Environment variables:
#   CMAKE_PARAMS             - Additional cmake parameters
#   OPENSSL_ROOT_DIR         - Path to OpenSSL installation (auto-detected if not set)

set -e  # Exit on any error

# Resolve script directory (works from any cwd)
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# Detect library extension based on OS (Linux/macOS only — Windows uses build_windows.bat).
if [[ "$OSTYPE" == "darwin"* ]]; then
    SHLIBEXT="dylib"
else
    SHLIBEXT="so"
fi

# Parse command-line arguments
CLEAN=0
CLEAN_ONLY=0
INSTALL=0
UNINSTALL=0
COVERAGE=0
FIPS_BUILD=0
RUN_TESTS=0
SANITIZERS=0
MSAN=0
TSAN=0
BUILD_ACVP=0
STATIC_BUILD=0
EMBEDDED_OBJ=0
FORCE_LIB_DOWNGRADE=0
INSTALL_PREFIX_USER=""
while [ $# -gt 0 ]; do
    case "$1" in
        -f|--force)    CLEAN=1 ;;
        -c|--clean)    CLEAN_ONLY=1 ;;
        -i|--install)  INSTALL=1 ;;
        --coverage)    COVERAGE=1 ;;
        -t|--test)     RUN_TESTS=1 ;;
        -s|--sanitize) SANITIZERS=1 ;;
        -m|--msan)     MSAN=1 ;;
        --tsan)        TSAN=1 ;;
        --fips|-F)     FIPS_BUILD=1 ;;
        --acvp)        BUILD_ACVP=1 ;;
        --static)      STATIC_BUILD=1 ;;
        --embedded-obj) EMBEDDED_OBJ=1 ;;
        --force-lib-downgrade) FORCE_LIB_DOWNGRADE=1 ;;
        --uninstall)   UNINSTALL=1 ;;
        --prefix=*)    INSTALL_PREFIX_USER="${1#*=}" ;;
        --prefix)      INSTALL_PREFIX_USER="$2"; shift ;;
        -h|--help)
            echo "Usage: $0 [OPTIONS]"
            echo ""
            echo "Options:"
            echo "  -f, --force         Clean build directory before building"
            echo "  -c, --clean         Remove all build directories and exit (no rebuild)"
            echo "  -t, --test          Run tests after build (tests always compiled)"
            echo "  -i, --install       Build and install to system"
            echo "  --prefix=<path>     Install to <path> instead of auto-detected location"
            echo "      --coverage      Enable code coverage (gcov/lcov)"
            echo "  -s, --sanitize      Enable AddressSanitizer + UBSan"
            echo "  -m, --msan          Enable MemorySanitizer (Clang only)"
            echo "  --tsan              Enable ThreadSanitizer"
            echo "  --fips, -F          Build as FIPS 140-3 module"
            echo "  --acvp              Build ACVP test runner binaries"
            echo "  --static            Build main library as static (.a) instead of shared (.so)"
            echo "  --embedded-obj      Build qudo_fips_module.o partial-link for embedded/firmware (FIPS only)"
            echo "  --force-lib-downgrade  Allow -i to overwrite a newer installed library"
            echo "  --uninstall         Remove old qudo-pqc installs from system"
            echo "  -h, --help          Show this help"
            echo ""
            echo "Environment variables:"
            echo "  CMAKE_PARAMS        Additional cmake parameters"
            echo "  OPENSSL_ROOT_DIR    Path to OpenSSL installation (used for install fallback)"
            exit 0
            ;;
        *) echo "Unknown option: $1"; echo "Usage: $0 [-c] [-f] [-t] [-i] [--prefix=<path>] [--coverage] [-s] [-m] [--tsan] [--fips] [--acvp] [--static] [-h|--help]"; echo "Run '$0 --help' for full option list."; exit 1 ;;
    esac
    shift
done

# ========================================================================== #
# Uninstall old installs                                                      #
# ========================================================================== #

if [ $UNINSTALL -eq 1 ]; then
    echo "Searching for qudo-pqc installations to remove..."
    echo ""
    FOUND=0

    # Check common locations where qudo-pqc may have been installed
    for DIR in /usr/local /usr /opt/openssl-*; do
        [ -d "$DIR" ] || continue
        if [ -f "$DIR/lib/libqudo-pqc.$SHLIBEXT" ] || \
           [ -f "$DIR/lib64/libqudo-pqc.$SHLIBEXT" ] || \
           [ -d "$DIR/include/qudo-pqc" ]; then
            FOUND=1
            echo "  Found: $DIR"
            # Show what will be removed
            ls -la "$DIR"/lib/libqudo-pqc.* "$DIR"/lib64/libqudo-pqc.* \
                   "$DIR"/lib/libqudo-pqc.a "$DIR"/lib64/libqudo-pqc.a 2>/dev/null | sed 's/^/    /'
            [ -d "$DIR/include/qudo-pqc" ] && echo "    $DIR/include/qudo-pqc/ (headers)"
            [ -d "$DIR/lib/cmake/qudo-pqc" ] && echo "    $DIR/lib/cmake/qudo-pqc/ (cmake config)"
            [ -d "$DIR/lib64/cmake/qudo-pqc" ] && echo "    $DIR/lib64/cmake/qudo-pqc/ (cmake config)"
            echo ""
        fi
    done

    if [ $FOUND -eq 0 ]; then
        echo "  No qudo-pqc installations found."
        exit 0
    fi

    echo "Remove all listed files? [y/N] "
    read -r CONFIRM
    if [ "$CONFIRM" != "y" ] && [ "$CONFIRM" != "Y" ]; then
        echo "Cancelled."
        exit 0
    fi

    for DIR in /usr/local /usr /opt/openssl-*; do
        [ -d "$DIR" ] || continue
        sudo rm -f "$DIR"/lib/libqudo-pqc.* "$DIR"/lib64/libqudo-pqc.* 2>/dev/null
        sudo rm -rf "$DIR/include/qudo-pqc" 2>/dev/null
        sudo rm -rf "$DIR/lib/cmake/qudo-pqc" "$DIR/lib64/cmake/qudo-pqc" 2>/dev/null
    done

    # Remove ldconfig conf if it exists
    if [ -f /etc/ld.so.conf.d/qudo-pqc.conf ]; then
        sudo rm -f /etc/ld.so.conf.d/qudo-pqc.conf
    fi

    # Refresh ldconfig cache
    if [[ "$OSTYPE" != "darwin"* ]]; then
        sudo ldconfig
    fi

    echo "Uninstall completed."
    # If only --uninstall was passed, exit (don't build)
    if [ $FIPS_BUILD -eq 0 ] && [ $INSTALL -eq 0 ] && [ $RUN_TESTS -eq 0 ]; then
        exit 0
    fi
fi

# ========================================================================== #
# Clean only (--clean): remove all build directories and exit                 #
# ========================================================================== #

if [ $CLEAN_ONLY -eq 1 ]; then
    echo "Removing all build directories..."

    # Top-level build directories
    for dir in build build-*; do
        if [ -d "$dir" ]; then
            echo "  Removing $dir/"
            rm -rf "$dir"
        fi
    done

    # Sub-project build directories (ML-KEM, ML-DSA, SLH-DSA)
    for subdir in qudo-mlkem qudo-mldsa qudo-slhdsa; do
        for dir in "$subdir"/build*; do
            if [ -d "$dir" ]; then
                echo "  Removing $dir/"
                rm -rf "$dir"
            fi
        done
    done

    # Coverage HTML reports (produced by coverage.sh; default OUTPUT_DIR
    # is coverage-report, FIPS/non-FIPS variants use coverage-report-{fips,nonfips}).
    for dir in coverage-report coverage-report-*; do
        if [ -d "$dir" ]; then
            echo "  Removing $dir/"
            rm -rf "$dir"
        fi
    done

    # Static-analysis HTML reports (produced by scan-build.sh).
    for dir in scan-report scan-report-*; do
        if [ -d "$dir" ]; then
            echo "  Removing $dir/"
            rm -rf "$dir"
        fi
    done

    echo "Clean complete."
    exit 0
fi

# ========================================================================== #
# Build directory selection                                                   #
# ========================================================================== #

# One build directory per flavor, so instrumented and plain builds stay separate.
if   [ $FIPS_BUILD -eq 1 ]; then BUILD_DIR="build-fips"
elif [ $SANITIZERS -eq 1 ]; then BUILD_DIR="build-asan"
elif [ $MSAN       -eq 1 ]; then BUILD_DIR="build-msan"
elif [ $TSAN       -eq 1 ]; then BUILD_DIR="build-tsan"
elif [ $COVERAGE   -eq 1 ]; then BUILD_DIR="build-coverage"
else                             BUILD_DIR="build"
fi

# Clean if requested
if [ $CLEAN -eq 1 ]; then
    echo "Cleaning $BUILD_DIR..."
    rm -rf "$BUILD_DIR"
fi

# FIPS builds always start from a clean directory
if [ $FIPS_BUILD -eq 1 ]; then
    echo "FIPS build: forcing clean build for reproducibility..."
    rm -rf "$BUILD_DIR"
fi

mkdir -p "$BUILD_DIR"

# ========================================================================== #
# Print build configuration                                                   #
# ========================================================================== #

echo "======================================"
if [ $FIPS_BUILD -eq 1 ]; then
    echo "  QUDO PQC — FIPS 140-3 Module Build"
    echo "  Output: libqudo-pqc.$SHLIBEXT"
    echo "  Algorithms: FIPS-approved only"
    echo "    ML-KEM-512/768/1024 (FIPS 203)"
    echo "    ML-DSA-44/65/87     (FIPS 204)"
    echo "    SLH-DSA (12 sets)   (FIPS 205)"
else
    echo "  QUDO PQC — Standard Build"
    echo "  Output: libqudo-pqc.$SHLIBEXT"
fi
echo "======================================"
echo ""

# ========================================================================== #
# Auto-detect OpenSSL                                                         #
# ========================================================================== #

if [ -z "$OPENSSL_ROOT_DIR" ] && command -v openssl &> /dev/null; then
    OPENSSL_BIN=$(which openssl)
    OPENSSL_ROOT_DIR=$(dirname "$(dirname "$OPENSSL_BIN")")
    OPENSSL_VERSION=$(openssl version 2>/dev/null | awk '{print $2}')
    echo "OpenSSL: $OPENSSL_VERSION ($OPENSSL_ROOT_DIR)"
else
    echo "OpenSSL: ${OPENSSL_ROOT_DIR:-not found}"
fi
echo ""

# ========================================================================== #
# Configure cmake options                                                     #
# ========================================================================== #

CMAKE_OPTS=""

# Build type
if [ $COVERAGE -eq 1 ]; then
    CMAKE_OPTS="$CMAKE_OPTS -DCMAKE_BUILD_TYPE=Debug -DENABLE_COVERAGE=ON"
    echo "Code coverage enabled (Debug build)"
elif [ $SANITIZERS -eq 1 ]; then
    CMAKE_OPTS="$CMAKE_OPTS -DCMAKE_BUILD_TYPE=Debug -DENABLE_SANITIZERS=ON"
    echo "Sanitizers enabled (ASan + UBSan, Debug build)"
elif [ $MSAN -eq 1 ]; then
    CMAKE_OPTS="$CMAKE_OPTS -DCMAKE_BUILD_TYPE=Debug -DENABLE_MSAN=ON"
    echo "MemorySanitizer enabled (Clang only, Debug build)"
elif [ $TSAN -eq 1 ]; then
    CMAKE_OPTS="$CMAKE_OPTS -DCMAKE_BUILD_TYPE=Debug -DENABLE_TSAN=ON"
    echo "ThreadSanitizer enabled (Debug build)"
else
    CMAKE_OPTS="$CMAKE_OPTS -DCMAKE_BUILD_TYPE=Release"
fi

# FIPS mode
if [ $FIPS_BUILD -eq 1 ]; then
    CMAKE_OPTS="$CMAKE_OPTS -DQUDO_FIPS_MODULE=ON"
fi

if [ $STATIC_BUILD -eq 1 ]; then
    CMAKE_OPTS="$CMAKE_OPTS -DBUILD_SHARED_LIBS=OFF"
    echo "Static build: main library will be libqudo-pqc.a"
else
    CMAKE_OPTS="$CMAKE_OPTS -DBUILD_SHARED_LIBS=ON"
fi

if [ $EMBEDDED_OBJ -eq 1 ]; then
    CMAKE_OPTS="$CMAKE_OPTS -DQUDO_BUILD_EMBEDDED_OBJ=ON"
    echo "Embedded artifact: qudo_fips_module.o will be built (run: make qudo-fips-module)"
fi

# Tests — always built, -t controls whether they run after build
CMAKE_OPTS="$CMAKE_OPTS -DQUDO_PQC_BUILD_TESTS=ON"

# ACVP test runner
if [ $BUILD_ACVP -eq 1 ]; then
    CMAKE_OPTS="$CMAKE_OPTS -DBUILD_ACVP=ON"
fi

# User-supplied extra params
if [ -n "$CMAKE_PARAMS" ]; then
    CMAKE_OPTS="$CMAKE_OPTS $CMAKE_PARAMS"
fi

# ========================================================================== #
# Configure and build                                                         #
# ========================================================================== #

# Always reconfigure to ensure options match current flags
echo "Configuring..."
cmake $CMAKE_OPTS -S . -B "$BUILD_DIR"
echo ""

echo "Building..."
cmake --build "$BUILD_DIR" -j"$(nproc 2>/dev/null || sysctl -n hw.ncpu 2>/dev/null || echo 4)"

if [ $? -ne 0 ]; then
    echo ""
    echo "BUILD FAILED"
    exit 1
fi

echo ""
echo "Build completed successfully."
echo "  Library: $BUILD_DIR/lib/libqudo-pqc.$SHLIBEXT"

# ========================================================================== #
# Strip binaries (release builds only); runs before the integrity HMAC step  #
# ========================================================================== #

if [ $COVERAGE -eq 0 ] && [ $SANITIZERS -eq 0 ] && [ $MSAN -eq 0 ] && [ $TSAN -eq 0 ]; then
    if command -v strip &> /dev/null; then
        # Select strip flags per platform:
        #   GNU strip (Linux): --strip-unneeded --remove-section=.comment
        #   BSD strip (macOS): -x (remove local symbols in dylib/exe)
        case "$(uname -s)" in
            Darwin) STRIP_LIB_FLAGS="-x";  STRIP_EXE_FLAGS="-x"  ;;
            *)      STRIP_LIB_FLAGS="--strip-unneeded --remove-section=.comment"
                    STRIP_EXE_FLAGS="--strip-unneeded --remove-section=.comment" ;;
        esac

        REAL_LIB=$(readlink -f "$BUILD_DIR/lib/libqudo-pqc.$SHLIBEXT" 2>/dev/null || echo "$BUILD_DIR/lib/libqudo-pqc.$SHLIBEXT")
        if [ -f "$REAL_LIB" ]; then
            strip $STRIP_LIB_FLAGS "$REAL_LIB"
        fi
        if [ -f "$BUILD_DIR/tools/qudo_fipsinstall" ]; then
            strip $STRIP_EXE_FLAGS "$BUILD_DIR/tools/qudo_fipsinstall"
        fi
    fi
fi

# ========================================================================== #
# Run tests                                                                   #
# ========================================================================== #

# FIPS: embed the integrity HMAC (required for qudo_pqc_init() to pass).
if [ $FIPS_BUILD -eq 1 ] && [ -x "$BUILD_DIR/tools/qudo_fipsinstall" ]; then
    echo ""
    echo "Embedding FIPS integrity HMAC..."
    "$BUILD_DIR/tools/qudo_fipsinstall" -embed -module "$BUILD_DIR/lib/libqudo-pqc.$SHLIBEXT"
fi

# macOS: strip and the HMAC embed invalidate the code signature, so re-sign
# ad-hoc last. The signature lies outside the integrity region.
if [ "$(uname -s)" = "Darwin" ] && command -v codesign &> /dev/null; then
    SIGN_LIB=$(readlink -f "$BUILD_DIR/lib/libqudo-pqc.$SHLIBEXT" 2>/dev/null || echo "$BUILD_DIR/lib/libqudo-pqc.$SHLIBEXT")
    echo ""
    echo "Re-signing module (ad-hoc): $SIGN_LIB"
    codesign --remove-signature "$SIGN_LIB" 2>/dev/null || true
    codesign -s - -f "$SIGN_LIB"
fi

if [ $RUN_TESTS -eq 1 ]; then

    echo ""
    echo "======================================"
    echo "  Running Tests"
    echo "======================================"
    echo ""
    cd "$BUILD_DIR"
    ctest --output-on-failure
    CTEST_RESULT=$?
    cd "$SCRIPT_DIR"

    if [ $CTEST_RESULT -ne 0 ]; then
        echo ""
        echo "TESTS FAILED"
        exit 1
    fi

    echo ""
    echo "All tests passed."
fi

# ========================================================================== #
# Install                                                                     #
#                                                                              #
# Prefix: --prefix, else OPENSSL_ROOT_DIR, else the openssl binary's prefix. #
# ========================================================================== #

if [ $INSTALL -eq 1 ]; then
    echo ""

    # --- Detect install prefix ---
    INSTALL_PREFIX=""
    INSTALL_LIBDIR=""

    # Method 1: --prefix=<path> (most explicit, user-supplied)
    if [ -n "$INSTALL_PREFIX_USER" ]; then
        INSTALL_PREFIX="$INSTALL_PREFIX_USER"
        mkdir -p "$INSTALL_PREFIX"

    # Method 2: OPENSSL_ROOT_DIR env var (install alongside OpenSSL)
    elif [ -n "$OPENSSL_ROOT_DIR" ] && [ -d "$OPENSSL_ROOT_DIR" ]; then
        INSTALL_PREFIX="$OPENSSL_ROOT_DIR"

    # Method 3: openssl binary in PATH (auto-detect OpenSSL location)
    elif command -v openssl &> /dev/null; then
        OPENSSL_BIN_PATH=$(command -v openssl)
        INSTALL_PREFIX=$(dirname "$(dirname "$OPENSSL_BIN_PATH")")
    fi

    # Validate prefix
    if [ -z "$INSTALL_PREFIX" ] || [ ! -d "$INSTALL_PREFIX" ]; then
        echo "ERROR: Cannot determine install location."
        echo ""
        echo "  Pass an explicit path:"
        echo "    ./build.sh -i --prefix=/path/to/install"
        echo ""
        echo "  Or install alongside OpenSSL:"
        echo "    OPENSSL_ROOT_DIR=/path/to/openssl ./build.sh -i"
        exit 1
    fi

    # --- Detect libdir (lib vs lib64) ---
    # Priority: existing libcrypto location (so we install alongside it),
    # then platform default (lib64 on most Linux, lib on macOS/standalone).
    if [ -f "$INSTALL_PREFIX/lib64/libcrypto.$SHLIBEXT" ] || \
       [ -f "$INSTALL_PREFIX/lib64/libcrypto.${SHLIBEXT}.3" ]; then
        INSTALL_LIBDIR="lib64"
    elif [ -f "$INSTALL_PREFIX/lib/libcrypto.$SHLIBEXT" ] || \
         [ -f "$INSTALL_PREFIX/lib/libcrypto.${SHLIBEXT}.3" ]; then
        INSTALL_LIBDIR="lib"
    elif [[ "$OSTYPE" == "darwin"* ]]; then
        INSTALL_LIBDIR="lib"
    elif [ -d "$INSTALL_PREFIX/lib64" ]; then
        INSTALL_LIBDIR="lib64"
    else
        INSTALL_LIBDIR="lib"
    fi

    # --- Version-aware install: compare against the library at the prefix ---
    lib_version() {
        local base
        base=$(basename "$1")
        case "$base" in
            libqudo-pqc.so.[0-9]*) echo "${base#libqudo-pqc.so.}" ;;
            libqudo-pqc.[0-9]*.dylib) base="${base#libqudo-pqc.}"; echo "${base%.dylib}" ;;
            *) echo "" ;;
        esac
    }
    file_sha() {
        if command -v sha256sum &> /dev/null; then
            sha256sum "$1" | cut -d' ' -f1
        else
            shasum -a 256 "$1" | cut -d' ' -f1
        fi
    }
    ver_lt() {
        [ "$1" != "$2" ] && \
        [ "$(printf '%s\n%s\n' "$1" "$2" | sort -t. -k1,1n -k2,2n -k3,3n | head -1)" = "$1" ]
    }

    BUILT_LIB=$(readlink -f "$BUILD_DIR/lib/libqudo-pqc.$SHLIBEXT" 2>/dev/null || echo "$BUILD_DIR/lib/libqudo-pqc.$SHLIBEXT")
    INSTALLED_LIB=""
    for f in "$INSTALL_PREFIX/$INSTALL_LIBDIR"/libqudo-pqc.$SHLIBEXT.[0-9]* \
             "$INSTALL_PREFIX/$INSTALL_LIBDIR"/libqudo-pqc.[0-9]*.$SHLIBEXT; do
        # Resolve SONAME symlinks (.so.1 -> .so.1.0.0) to the real file so the
        # full version is compared.
        [ -f "$f" ] && INSTALLED_LIB=$(readlink -f "$f" 2>/dev/null || echo "$f") && break
    done

    SKIP_INSTALL=0
    BUILT_VER=$(lib_version "$BUILT_LIB")
    if [ -n "$INSTALLED_LIB" ] && [ -f "$BUILT_LIB" ] && [ -n "$BUILT_VER" ]; then
        INSTALLED_VER=$(lib_version "$INSTALLED_LIB")
        if [ "$INSTALLED_VER" = "$BUILT_VER" ]; then
            if [ "$(file_sha "$INSTALLED_LIB")" = "$(file_sha "$BUILT_LIB")" ]; then
                SKIP_INSTALL=1
            else
                echo "Refreshing installed libqudo-pqc $INSTALLED_VER (same version, contents differ)."
            fi
        elif ver_lt "$INSTALLED_VER" "$BUILT_VER"; then
            echo "Upgrading installed libqudo-pqc $INSTALLED_VER -> $BUILT_VER."
        else
            echo "ERROR: installed libqudo-pqc $INSTALLED_VER at $INSTALL_PREFIX/$INSTALL_LIBDIR"
            echo "       is NEWER than this build ($BUILT_VER). Refusing to downgrade."
            echo "       Update your sources first, or pass"
            echo "       --force-lib-downgrade to override."
            if [ $FORCE_LIB_DOWNGRADE -eq 0 ]; then
                exit 1
            fi
            echo "       --force-lib-downgrade given: downgrading $INSTALLED_VER -> $BUILT_VER."
        fi
    fi

    if [ $SKIP_INSTALL -eq 1 ]; then
        echo ""
        echo "libqudo-pqc $BUILT_VER already installed @ $INSTALL_PREFIX/$INSTALL_LIBDIR (sha256 $(file_sha "$BUILT_LIB" | cut -c1-12)..., identical) — nothing to do."
    else
        # --- Reconfigure cmake with correct install paths ---
        echo "Install target:"
        echo "  Prefix: $INSTALL_PREFIX"
        echo "  Libdir: $INSTALL_LIBDIR"
        echo "  Library: $INSTALL_PREFIX/$INSTALL_LIBDIR/libqudo-pqc.$SHLIBEXT"
        echo "  Headers: $INSTALL_PREFIX/include/qudo-pqc/"
        echo "  CMake:   $INSTALL_PREFIX/$INSTALL_LIBDIR/cmake/qudo-pqc/"
        echo ""

        cmake $CMAKE_OPTS \
            -DCMAKE_INSTALL_PREFIX="$INSTALL_PREFIX" \
            -DCMAKE_INSTALL_LIBDIR="$INSTALL_LIBDIR" \
            -S . -B "$BUILD_DIR"

        # --- Install (system install requires root privileges) ---
        echo "Installing..."
        sudo cmake --install "$BUILD_DIR"

        if [ $? -eq 0 ]; then
            echo ""
            echo "Installation completed."
            echo "Installed: libqudo-pqc $BUILT_VER @ $INSTALL_PREFIX/$INSTALL_LIBDIR (sha256 $(file_sha "$BUILT_LIB" | cut -c1-12)...)"
        else
            echo "Installation failed."
            exit 1
        fi
    fi
fi

# ========================================================================== #
# FIPS post-build reminder                                                    #
# ========================================================================== #

if [ $FIPS_BUILD -eq 1 ]; then
    echo ""
    echo "======================================"
    echo "  FIPS Post-Build Steps"
    echo "======================================"
    echo ""
    echo "  1. Embed integrity HMAC into the module:"
    echo "     $BUILD_DIR/tools/qudo_fipsinstall \\"
    echo "       -embed -module $BUILD_DIR/lib/libqudo-pqc.$SHLIBEXT"
    echo ""
    echo "  2. Verify the embedded HMAC:"
    echo "     $BUILD_DIR/tools/qudo_fipsinstall \\"
    echo "       -verify-embed -module $BUILD_DIR/lib/libqudo-pqc.$SHLIBEXT"
    echo ""
    echo "  3. (Optional) Generate external integrity checksum:"
    echo "     $BUILD_DIR/tools/qudo_fipsinstall \\"
    echo "       -module $BUILD_DIR/lib/libqudo-pqc.$SHLIBEXT \\"
    echo "       -out qudofipsmodule.cnf"
    echo ""
    echo "  4. (Optional) Verify against external checksum:"
    echo "     $BUILD_DIR/tools/qudo_fipsinstall \\"
    echo "       -verify -module $BUILD_DIR/lib/libqudo-pqc.$SHLIBEXT \\"
    echo "       -in qudofipsmodule.cnf"
    echo ""
    echo "  NOTE: strip must run BEFORE the fipsinstall steps. External cnf:"
    echo "        sign first, then generate the cnf. Embedded HMAC on macOS:"
    echo "        embed first, then re-sign LAST (codesign --remove-signature"
    echo "        <lib> || true; codesign -s - -f <lib>)"
    echo "======================================"
fi

echo ""
echo "Done."
