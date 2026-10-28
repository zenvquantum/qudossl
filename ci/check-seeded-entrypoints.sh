#!/usr/bin/env bash
#
# Seeded-entry-point gate.
#
# Scans openssl/crypto/ml_kem and openssl/crypto/ml_dsa for calls to qudo
# entry points that generate their own randomness. All randomness must come from
# the OpenSSL DRBG and be passed in by the caller.
#
# QUDO_KEM_keypair_derand is non-seeded: its seed argument is an output. The
# seeded equivalent is QUDO_KEM_keypair_from_seed.
#
# Usage: ci/check-seeded-entrypoints.sh
#
set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# SLH-DSA is not delegated, so it is not scanned.
SRC="${REPO_ROOT}/openssl/crypto/ml_kem ${REPO_ROOT}/openssl/crypto/ml_dsa"

# Non-seeded entry points: these obtain randomness themselves.
FORBIDDEN='QUDO_KEM_keypair|QUDO_KEM_keypair_derand|QUDO_KEM_encaps|QUDO_MLDSA_keypair|QUDO_MLDSA_sign'
# Seeded/deterministic forms, which are permitted.
ALLOWED='QUDO_KEM_keypair_from_seed|QUDO_KEM_encaps_derand|QUDO_KEM_decaps|QUDO_MLDSA_keypair_internal|QUDO_MLDSA_sign_internal|QUDO_MLDSA_verify_internal'

echo "==> scanning the delegation layer for non-seeded qudo entry points"

hits=0
for f in $(grep -rl 'QUDO_' ${SRC} --include='*.c' 2>/dev/null); do
    while IFS= read -r line; do
        # Strip anything matching an allowed name, then see if a forbidden
        # name still remains on the line.
        stripped=$(printf '%s' "${line}" | sed -E "s/(${ALLOWED})//g")
        # Match any suffix too (e.g. QUDO_MLDSA_sign_extmu, _with_context).
        if printf '%s' "${stripped}" | grep -qE "(${FORBIDDEN})[A-Za-z0-9_]*[[:space:]]*\("; then
            printf '  FAIL %s: %s\n' "${f#${REPO_ROOT}/}" "$(printf '%s' "${line}" | sed 's/^ *//')"
            hits=$((hits + 1))
        fi
    done < <(grep -nE "(${FORBIDDEN})[A-Za-z0-9_]*[[:space:]]*\(" "${f}" 2>/dev/null)
done

echo
if [ "${hits}" -eq 0 ]; then
    echo "SEEDED-ENTRYPOINT GATE PASSED — all delegated calls take caller-supplied randomness."
    exit 0
fi

cat >&2 <<EOF
SEEDED-ENTRYPOINT GATE FAILED — ${hits} non-seeded call site(s).

Non-seeded qudo entry points draw randomness from qudo-pqc's platform
entropy instead of the OpenSSL DRBG.

Use instead:
  QUDO_KEM_keypair_from_seed / QUDO_KEM_encaps_derand / QUDO_KEM_decaps
  QUDO_MLDSA_keypair_internal / QUDO_MLDSA_sign_internal / QUDO_MLDSA_verify_internal

See build/build_libqudo_pqc.sh.
EOF
exit 1
