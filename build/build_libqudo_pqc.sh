#!/usr/bin/env bash
#
# Stage 1 of the QudoSSL build: compiles qudo-pqc-lib as a static, math-only
# archive (libqudo-pqc.a). OpenSSL provides the self-tests, integrity check,
# state machine and DRBG; qudo-pqc-lib provides only the PQC math.
#
#   -DQUDO_PQC_MATH_ONLY=ON   excludes qudo-pqc's POST, PCT, integrity check,
#                             CTR-DRBG, AES and HMAC from the archive.
#   -DBUILD_SHARED_LIBS=OFF   static linkage, so the FIPS module's integrity
#                             check covers the PQC math.
#
# The delegation layer in openssl/crypto/ml_kem and crypto/ml_dsa calls only
# the seeded entry points, with randomness from the OpenSSL DRBG:
#   QUDO_KEM_keypair_from_seed, QUDO_KEM_encaps_derand, QUDO_KEM_decaps,
#   QUDO_MLDSA_keypair_internal, QUDO_MLDSA_sign_internal,
#   QUDO_MLDSA_verify_internal.
# QUDO_KEM_keypair_derand is not seeded: its seed argument is an output.
# SLH-DSA is not delegated.
#
# Usage: build/build_libqudo_pqc.sh [extra cmake args]
#   Environment: QUDO_PQC_BUILD_DIR, QUDO_PQC_BUILD_TYPE, QUDO_PQC_BUILD_TESTS, JOBS
#
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SRC_DIR="${REPO_ROOT}/qudo-pqc-lib"
BUILD_DIR="${QUDO_PQC_BUILD_DIR:-${SRC_DIR}/build}"
BUILD_TYPE="${QUDO_PQC_BUILD_TYPE:-Release}"
JOBS="${JOBS:-$( (command -v nproc >/dev/null && nproc) || sysctl -n hw.ncpu || echo 4 )}"

if [ ! -f "${SRC_DIR}/CMakeLists.txt" ]; then
    echo "error: ${SRC_DIR} is not populated." >&2
    echo "       The qudo-pqc-lib directory is missing from this checkout." >&2
    exit 1
fi

# CMake ignores unknown -D options, so check that QUDO_PQC_MATH_ONLY exists.
if ! grep -q 'QUDO_PQC_MATH_ONLY' "${SRC_DIR}/CMakeLists.txt"; then
    cat >&2 <<'MSG'
error: this qudo-pqc-lib does not support QUDO_PQC_MATH_ONLY.

QudoSSL requires the math-only build mode, which excludes qudo-pqc's own
POST, PCT, integrity check, CTR-DRBG, AES and HMAC from the archive.

Use a qudo-pqc-lib release that supports it (see docs/vendored-versions.md).
MSG
    exit 1
fi

echo "==> Stage 1: qudo-pqc-lib -> libqudo-pqc.a"
echo "    source : ${SRC_DIR}"
echo "    build  : ${BUILD_DIR}"

cmake -S "${SRC_DIR}" -B "${BUILD_DIR}" \
    -DCMAKE_BUILD_TYPE="${BUILD_TYPE}" \
    -DBUILD_SHARED_LIBS=OFF \
    -DQUDO_PQC_MATH_ONLY=ON \
    -DQUDO_PQC_BUILD_TESTS="${QUDO_PQC_BUILD_TESTS:-OFF}" \
    "$@"

# Only the qudo-pqc target is built; QudoSSL does not use the standalone
# sub-libraries.
cmake --build "${BUILD_DIR}" --parallel "${JOBS}" --target qudo-pqc

ARCHIVE="${BUILD_DIR}/lib/libqudo-pqc.a"
if [ ! -f "${ARCHIVE}" ]; then
    echo "error: expected archive not produced: ${ARCHIVE}" >&2
    find "${BUILD_DIR}" -name 'libqudo-pqc*' -print >&2 || true
    exit 1
fi

echo "==> Stage 1 complete: ${ARCHIVE}"
