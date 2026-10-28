#!/usr/bin/env bash
#
# ML-KEM constructibility gate.
#
# Checks that QUDO_KEM_init() and QUDO_KEM_new() succeed without a prior call
# to qudo_pqc_init(), which is how QudoSSL uses qudo-pqc-lib.
#
# Usage: ci/check-mlkem-constructible.sh   (after 'make -C build qudo-pqc')
#
set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ARCHIVE="${REPO_ROOT}/qudo-pqc-lib/build/lib/libqudo-pqc.a"
WORK="$(mktemp -d)"
trap 'rm -rf "${WORK}"' EXIT

if [ ! -f "${ARCHIVE}" ]; then
    echo "error: ${ARCHIVE} not built. Run 'make -C build qudo-pqc' first." >&2
    exit 2
fi

cat > "${WORK}/probe.c" <<'EOF'
/* No qudo_pqc_init(), as in QudoSSL. */
#include <stdio.h>
#include "mlkem_wrapper.h"

int main(void)
{
    int rc = QUDO_KEM_init();
    const QUDO_KEM *k = QUDO_KEM_new("ML-KEM-768");

    printf("  QUDO_KEM_init()            = %d\n", rc);
    printf("  QUDO_KEM_new(ML-KEM-768)   = %s\n", k ? "OK" : "NULL");

    return (rc == 0 && k != NULL) ? 0 : 1;
}
EOF

cc -I "${REPO_ROOT}/qudo-pqc-lib/include" \
   -I "${REPO_ROOT}/qudo-pqc-lib/qudo-mlkem/include" \
   -o "${WORK}/probe" "${WORK}/probe.c" "${ARCHIVE}" 2>"${WORK}/cc.log" || {
    echo "error: probe failed to link" >&2; sed 's/^/    /' "${WORK}/cc.log" >&2; exit 2; }

echo "==> constructing ML-KEM without qudo_pqc_init()"
if "${WORK}/probe"; then
    echo "ML-KEM CONSTRUCTIBILITY GATE PASSED"
    exit 0
fi

cat >&2 <<EOF

ML-KEM CONSTRUCTIBILITY GATE FAILED.

QUDO_KEM_init() or QUDO_KEM_new() failed without qudo_pqc_init(). In this
state ML-KEM key generation, encapsulation and decapsulation fail in both
providers, and the FIPS provider fails its ML-KEM self-test.

Check that qudo-pqc-lib was built with QUDO_PQC_MATH_ONLY.
EOF
exit 1
