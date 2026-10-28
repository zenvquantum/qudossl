#!/usr/bin/env bash
#
# Boundary gate: checks that no qudo-pqc-lib FIPS-infrastructure symbol (DRBG,
# HMAC, integrity, POST/PCT, state machine, security-level controls) is linked
# alongside the ML-KEM math, and, when fips.so/fips.dylib is built, that none is
# present in the module and that it has no OS entropy references.
#
# The forbidden set is derived from the archive's symbol names. A probe linking
# only caller-deterministic entry points must not pull any of them in.
#
# Usage: ci/check-boundary-symbols.sh   (after 'make -C build qudo-pqc')
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

# Matched by symbol name, not object filename: under QUDO_PQC_MATH_ONLY the FIPS
# sources are not compiled into separately-named objects.
FIPS_SYM_RE='^qudo_(fips_|pqc_(post|pct|integrity|indicator|embedded|init|audit|state|ctrdrbg|rand|hmac|get_module_boundary|get_integrity|get_security_level|get_min_security_level|set_min_security_level|check_security_level))'

echo "==> deriving forbidden symbol set from ${ARCHIVE##*/}"
mkdir -p "${WORK}/ar" && (cd "${WORK}/ar" && ar x "${ARCHIVE}")

obj_total=$(ls "${WORK}/ar" | wc -l | tr -d ' ')
echo "  objects in archive: ${obj_total}"

: > "${WORK}/allsyms.txt"
for o in "${WORK}/ar"/*.o; do
    [ -e "${o}" ] || continue
    nm -gU "${o}" 2>/dev/null | awk '{print $NF}' | sed 's/^_//' >> "${WORK}/allsyms.txt"
done
sort -u -o "${WORK}/allsyms.txt" "${WORK}/allsyms.txt"
sym_total=$(wc -l < "${WORK}/allsyms.txt" | tr -d ' ')
echo "  defined symbols: ${sym_total}"

# Objects present but no symbols extracted indicates an nm/parse failure.
if [ "${obj_total}" -gt 0 ] && [ "${sym_total}" -eq 0 ]; then
    echo "error: ${obj_total} objects but 0 symbols extracted — nm/parse failure." >&2
    exit 2
fi

grep -E "${FIPS_SYM_RE}" "${WORK}/allsyms.txt" > "${WORK}/forbidden.txt" || true
forbid_count=$(wc -l < "${WORK}/forbidden.txt" | tr -d ' ')
echo "  forbidden symbols: ${forbid_count}"

# The archive contains these symbols even under MATH_ONLY, so an empty set
# means FIPS_SYM_RE is out of date.
if [ "${forbid_count}" -eq 0 ]; then
    echo "error: forbidden set is empty — FIPS_SYM_RE matches no symbol in the" >&2
    echo "       archive. Update the regex." >&2
    exit 2
fi

# Probe referencing only caller-deterministic entry points. QUDO_KEM_keypair_derand
# is excluded: its seed argument is an output, so it draws randomness internally.
cat > "${WORK}/probe.c" <<'EOF'
#include "mlkem_wrapper.h"
void *refs[] = {
    (void *)QUDO_KEM_keypair_from_seed,   /* const seed[]      IN */
    (void *)QUDO_KEM_encaps_derand,       /* const rand[32]    IN */
    (void *)QUDO_KEM_decaps,              /* deterministic        */
};
int main(void) { return refs[0] == 0; }
EOF

echo "==> linking probe against deterministic math entry points only"
if ! cc -I "${REPO_ROOT}/qudo-pqc-lib/include" \
        -I "${REPO_ROOT}/qudo-pqc-lib/qudo-mlkem/include" \
        -o "${WORK}/probe" "${WORK}/probe.c" "${ARCHIVE}" 2>"${WORK}/cc.log"; then
    echo "error: probe failed to link" >&2
    sed 's/^/    /' "${WORK}/cc.log" >&2
    exit 2
fi

nm "${WORK}/probe" 2>/dev/null | awk '{print $NF}' | sed 's/^_//' | sort -u > "${WORK}/linked.txt"
comm -12 "${WORK}/forbidden.txt" "${WORK}/linked.txt" > "${WORK}/violations.txt"
count=$(wc -l < "${WORK}/violations.txt" | tr -d ' ')

# If the FIPS module is built, scan it directly as well; it links more of the
# archive than the probe does.
for m in "${REPO_ROOT}/openssl/providers/fips.dylib" \
         "${REPO_ROOT}/openssl/providers/fips.so"; do
    [ -f "${m}" ] || continue
    echo "==> scanning shipped module ${m##*/}"
    # Plain nm, not -g: the version script localizes non-exported symbols.
    nm "${m}" 2>/dev/null | awk '{print $NF}' | sed 's/^_//' | sort -u > "${WORK}/mod.txt"
    comm -12 "${WORK}/forbidden.txt" "${WORK}/mod.txt" > "${WORK}/mod_violations.txt"
    mod_count=$(wc -l < "${WORK}/mod_violations.txt" | tr -d ' ')
    echo "  qudo symbols linked in:  $(grep -cE '^(qudo_|QUDO_)' "${WORK}/mod.txt" || true)"
    echo "  FIPS-infra violations:   ${mod_count}"
    if [ "${mod_count}" -gt 0 ]; then
        cat "${WORK}/mod_violations.txt" >> "${WORK}/violations.txt"
        count=$((count + mod_count))
    fi
    # qudo's platform RNG sources must not be referenced from the module.
    ent=$(nm -u "${m}" 2>/dev/null | grep -acE '\b(getentropy|BCryptGenRandom|arc4random)\b')
    echo "  OS entropy refs:         ${ent}"
    if [ "${ent}" -gt 0 ]; then
        echo "os-entropy-in-boundary" >> "${WORK}/violations.txt"
        count=$((count + ent))
    fi
done

echo
if [ "${count}" -eq 0 ]; then
    echo "BOUNDARY GATE PASSED — no qudo FIPS infrastructure reachable from the math."
    exit 0
fi

echo "  qudo FIPS-infra symbols linked in (${count}):"
sed 's/^/    /' "${WORK}/violations.txt"
cat >&2 <<EOF

BOUNDARY GATE FAILED — ${count} qudo FIPS-infrastructure symbol(s) reached the link.

QudoSSL uses OpenSSL's FIPS infrastructure only; qudo-pqc-lib supplies the
PQC math. POST, CAST, PCT, integrity, the DRBG, AES, SHA, HMAC, the state
machine and the approval indicator come from OpenSSL.

A common cause is a deterministic entry point sharing an object file with code
that references the RNG chain. Check that qudo-pqc-lib was built with
QUDO_PQC_MATH_ONLY, or build it with -ffunction-sections/-fdata-sections and
link with --gc-sections.
EOF
exit 1
