#!/bin/sh
# Checks that the OpenSSL build was configured with QUDO_PQC_DELEGATE and that
# the qudo-pqc-lib ML-KEM/ML-DSA math is linked into libcrypto or the FIPS
# module. Without --with-qudo-pqc-archive, Configure builds upstream ML-KEM/ML-DSA.
#
# Usage: ci/check-delegation-linked.sh [openssl-build-dir]
set -eu

OSSL_DIR="${1:-openssl}"
fail=0

note() { printf '  %s\n' "$1"; }
bad()  { printf '  FAIL: %s\n' "$1" >&2; fail=1; }

echo "==> checking crypto-layer delegation in ${OSSL_DIR}"

# 1. Configure must have defined the macro.
if [ -f "${OSSL_DIR}/configdata.pm" ]; then
    if grep -q 'QUDO_PQC_DELEGATE' "${OSSL_DIR}/configdata.pm"; then
        note "configdata.pm defines QUDO_PQC_DELEGATE"
    else
        bad "configdata.pm does not define QUDO_PQC_DELEGATE -- Configure was"
        bad "run without --with-qudo-pqc-archive/--with-qudo-pqc-include, so"
        bad "this build is upstream OpenSSL, not QudoSSL."
    fi
else
    bad "no configdata.pm under ${OSSL_DIR} -- tree not configured"
fi

# 2. qudo math entry points must be linked into at least one built artifact.
#    Plain `nm`, not `nm -g`: on Linux the version script localizes non-public
#    symbols in libcrypto.so and fips.so.
found_any=0
total=0
for lib in \
    "${OSSL_DIR}/libcrypto.so" "${OSSL_DIR}/libcrypto.dylib" \
    "${OSSL_DIR}/libcrypto.a" \
    "${OSSL_DIR}/providers/fips.so" "${OSSL_DIR}/providers/fips.dylib"
do
    [ -f "${lib}" ] || continue
    found_any=1
    n=$(nm "${lib}" 2>/dev/null | awk '{print $NF}' | sed 's/^_//' \
        | grep -cE '^QUDO_(KEM|MLDSA)_' || true)
    note "$(basename "${lib}"): ${n} qudo math symbols"
    total=$((total + n))
done

if [ "${found_any}" -eq 0 ]; then
    bad "no libcrypto/fips artifact found under ${OSSL_DIR} -- nothing verified."
elif [ "${total}" -eq 0 ]; then
    bad "no QUDO_KEM_/QUDO_MLDSA_ symbols in any built artifact -- the delegated"
    bad "  math is absent; this build is upstream OpenSSL, not QudoSSL."
fi

echo
if [ "${fail}" -eq 0 ]; then
    echo "DELEGATION CHECK PASSED -- artifacts contain the delegated PQC math."
    exit 0
fi

cat >&2 <<'EOF'

DELEGATION CHECK FAILED.

The built OpenSSL binaries do not use qudo-pqc-lib for ML-KEM/ML-DSA.

Confirm the Configure line passes:
    --with-qudo-pqc-archive=<path to libqudo-pqc.a / qudo-pqc.lib>
    --with-qudo-pqc-include=<qudo-pqc-lib>/include
    --with-qudo-pqc-include=<qudo-pqc-lib>/qudo-mlkem/include
    --with-qudo-pqc-include=<qudo-pqc-lib>/qudo-mldsa/include

See build/Makefile (Unix) and build/build.ps1 (Windows).
EOF
exit 1
