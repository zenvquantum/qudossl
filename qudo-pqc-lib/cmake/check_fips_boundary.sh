#!/bin/sh
# SPDX-License-Identifier: Apache-2.0 AND MIT
#
# check_fips_boundary.sh — post-link boundary-coverage check for
# libqudo-pqc.so.
#
# Verifies that the integrity region bracketed by qudo_fips_module_start /
# qudo_fips_module_end contains every module symbol. Runs as a CMake
# POST_BUILD step.
#
# Arguments:
#   $1  path to libqudo-pqc.so (mandatory)
#
# Exit codes:
#   0  all FIPS-core symbols inside the integrity region
#   1  a FIPS-core symbol is outside the region
#   2  required tooling (nm / readelf) is unavailable

set -u

SO="${1:-}"
if [ -z "$SO" ] || [ ! -f "$SO" ]; then
    printf 'check_fips_boundary: missing or nonexistent .so path: "%s"\n' "$SO" >&2
    exit 2
fi

command -v nm      >/dev/null 2>&1 || { echo "check_fips_boundary: nm not found"      >&2; exit 2; }
command -v readelf >/dev/null 2>&1 || { echo "check_fips_boundary: readelf not found" >&2; exit 2; }

# Resolve boundary anchors.
START_HEX=$(nm --defined-only "$SO" 2>/dev/null \
            | awk '$3 == "qudo_fips_module_start" { print $1; exit }')
END_HEX=$(nm --defined-only "$SO" 2>/dev/null \
          | awk '$3 == "qudo_fips_module_end"   { print $1; exit }')

if [ -z "$START_HEX" ] || [ -z "$END_HEX" ]; then
    echo "check_fips_boundary: boundary anchors not found in $SO" >&2
    echo "  qudo_fips_module_start=$START_HEX" >&2
    echo "  qudo_fips_module_end=$END_HEX"     >&2
    exit 1
fi

START_DEC=$(printf '%d' "0x$START_HEX")
END_DEC=$(printf   '%d' "0x$END_HEX")

if [ "$START_DEC" -ge "$END_DEC" ]; then
    echo "check_fips_boundary: start >= end (0x$START_HEX >= 0x$END_HEX)" >&2
    exit 1
fi

# Symbol prefixes that must lie inside the integrity region.
PATTERN='^(qudo_fips_|qudo_pqc_post|qudo_pqc_integrity|qudo_pqc_pct|qudo_pqc_embedded_hmac|qudo_pqc_init|qudo_pqc_platform|mlkem_|mldsa_|slhdsa_)'

# nm columns: <hex-addr> <type> <name>; only defined text symbols (t/T).
violations=0
while IFS= read -r line; do
    addr=$(echo "$line" | awk '{print $1}')
    type=$(echo "$line" | awk '{print $2}')
    name=$(echo "$line" | awk '{print $3}')
    [ -z "$addr" ] && continue
    case "$type" in
        t|T) : ;;
        *)   continue ;;
    esac
    echo "$name" | grep -Eq "$PATTERN" || continue

    # The sentinels delimit the region; qudo_fips_module_end sits at END.
    case "$name" in
        qudo_fips_module_start|qudo_fips_module_end)
            continue
            ;;
    esac

    addr_dec=$(printf '%d' "0x$addr")
    if [ "$addr_dec" -lt "$START_DEC" ] || [ "$addr_dec" -ge "$END_DEC" ]; then
        printf 'check_fips_boundary: symbol OUT OF REGION: %s @ 0x%s\n' \
               "$name" "$addr" >&2
        violations=$((violations + 1))
    fi
done <<EOF
$(nm --defined-only "$SO" 2>/dev/null)
EOF

if [ "$violations" -ne 0 ]; then
    printf 'check_fips_boundary: %d FIPS symbol(s) fell outside the integrity region [0x%s, 0x%s)\n' \
           "$violations" "$START_HEX" "$END_HEX" >&2
    exit 1
fi

# The anchor sections flank .text, so the integrity region must span .text:
#   .qudo_fipsanchor_start  <--  .text  -->  .qudo_fipsanchor_end
TEXT_LINE=$(readelf -WS "$SO" 2>/dev/null | awk '
    $3 == ".text" && $4 == "PROGBITS" { print $5, $7; exit }')
if [ -n "$TEXT_LINE" ]; then
    TEXT_ADDR_HEX=$(echo "$TEXT_LINE" | awk '{print $1}')
    TEXT_SIZE_HEX=$(echo "$TEXT_LINE" | awk '{print $2}')
    TEXT_ADDR=$(printf '%d' "0x$TEXT_ADDR_HEX")
    TEXT_SIZE=$(printf '%d' "0x$TEXT_SIZE_HEX")
    TEXT_END=$((TEXT_ADDR + TEXT_SIZE))
    # Require start <= TEXT_ADDR and end >= TEXT_END.
    if [ "$START_DEC" -gt "$TEXT_ADDR" ] || [ "$END_DEC" -lt "$TEXT_END" ]; then
        printf 'check_fips_boundary: integrity region [0x%s, 0x%s) does not span .text [0x%x, 0x%x)\n' \
               "$START_HEX" "$END_HEX" "$TEXT_ADDR" "$TEXT_END" >&2
        exit 1
    fi
fi

printf 'check_fips_boundary: OK — integrity region [0x%s, 0x%s) bounds all FIPS-core symbols\n' \
       "$START_HEX" "$END_HEX"
exit 0
