#!/usr/bin/env bash
# Builds OpenSSL perftools against each OpenSSL tree and generates the
# certificates and configs the benchmarks use.
#
# Usage: STOCK_DIR=/path/to/openssl-3.5.7 ./scripts/build.sh
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib.sh"
set -e
bench_banner
bench_verify || exit 1

command -v cmake >/dev/null || { echo "FATAL: cmake not installed" >&2; exit 1; }
[ -f "$BENCH/perftools/source/CMakeLists.txt" ] || {
  echo "FATAL: perftools source missing at $BENCH/perftools" >&2
  echo "       git clone https://github.com/openssl/perftools $BENCH/perftools" >&2
  exit 1; }

for t in qudo stock; do
  d=$(tree_dir $t)
  echo "building perftools against $t ($d)" >&2
  cmake -S "$BENCH/perftools/source" -B "$BENCH/build-$t" \
        -DOPENSSL_ROOT_DIR="$d" > "$BENCH/build-$t.log" 2>&1
  cmake --build "$BENCH/build-$t" --config Release >> "$BENCH/build-$t.log" 2>&1
  # Each binary must resolve the libcrypto of the tree it was built against.
  lib=$(lib_of "$BENCH/build-$t/handshake")
  case "$lib" in
    "$d"/*) echo "  ok: handshake -> $lib" >&2 ;;
    *) echo "FATAL: $t handshake linked $lib, expected one under $d" >&2; exit 1 ;;
  esac
done

# handshake reads servercert.pem and serverkey.pem from one directory. ML-DSA-44
# makes the signature side of the handshake use the delegated code.
if [ ! -s "$CERTS/servercert.pem" ]; then
  echo "generating ML-DSA-44 certificate" >&2
  ( cd "$CERTS"
    with_tree qudo "$Q/apps/openssl.cnf" "$Q/apps/openssl" req -x509 -new \
      -newkey ML-DSA-44 -noenc -keyout serverkey.pem -out servercert.pem \
      -days 3650 -subj "/CN=qudossl-benchmark" 2>/dev/null )
  [ -s "$CERTS/servercert.pem" ] || { echo "FATAL: certificate generation failed" >&2; exit 1; }
fi

# ECDSA certificate for the negative control, so that cell uses no delegated
# code for either key exchange or signature.
if [ ! -s "$CERTS_EC/servercert.pem" ]; then
  echo "generating ECDSA P-256 certificate (negative control)" >&2
  mkdir -p "$CERTS_EC"
  ( cd "$CERTS_EC"
    with_tree qudo "$Q/apps/openssl.cnf" "$Q/apps/openssl" ecparam \
      -name prime256v1 -genkey -noout -out serverkey.pem 2>/dev/null
    with_tree qudo "$Q/apps/openssl.cnf" "$Q/apps/openssl" req -x509 -new \
      -key serverkey.pem -out servercert.pem -days 3650 \
      -subj "/CN=qudossl-benchmark-control" 2>/dev/null )
  [ -s "$CERTS_EC/servercert.pem" ] || { echo "FATAL: control certificate failed" >&2; exit 1; }
fi

# One config per key-exchange group; handshake.c does not select a group itself.
# verify.sh checks that the selection takes effect.
mkcnf() {
  printf 'openssl_conf = init\n[init]\nssl_conf = s\n[s]\nsystem_default = d\n[d]\nGroups = %s\n' \
    "$1" > "$CONF/$2.cnf"
}
mkcnf X25519             classical
mkcnf X25519MLKEM768     hybrid
mkcnf SecP256r1MLKEM768  hybrid_p256

# FIPS variants include the module config and set fips=yes as the default.
for t in qudo stock; do
  d=$(tree_dir $t)
  if [ -f "$d/providers/fipsmodule.cnf" ]; then
    printf 'openssl_conf = init\n.include %s/providers/fipsmodule.cnf\n[init]\nproviders = prov\nalg_section = algs\nssl_conf = s\n[prov]\nfips = fips_sect\nbase = base_sect\n[base_sect]\nactivate = 1\n[algs]\ndefault_properties = fips=yes\n[s]\nsystem_default = d\n[d]\nGroups = X25519MLKEM768\n' \
      "$d" > "$CONF/fips_$t.cnf"
  else
    echo "WARNING: $d has no providers/fipsmodule.cnf; FIPS cells will be skipped" >&2
    echo "         build that tree with enable-fips and run fipsinstall" >&2
  fi
done

echo >&2
echo "BUILD OK" >&2
echo "  binaries : $BENCH/build-{qudo,stock}/handshake" >&2
echo "  certs    : $CERTS" >&2
echo "  configs  : $CONF" >&2
echo >&2
echo "next: ./scripts/verify.sh     # check the setup" >&2
echo "      ./scripts/run.sh        # wall-clock, ~15 min" >&2
echo "      ./scripts/run-instr.sh  # instruction counts, ~25 min" >&2
echo "      ./scripts/report.sh     # analysis" >&2
