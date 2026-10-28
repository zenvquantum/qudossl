#!/usr/bin/env bash
# Checks the benchmark setup: tree identity, binary linkage, certificates,
# configs, key-exchange group selection, required tools and FIPS modules.
#
# Usage: STOCK_DIR=/path/to/openssl-3.5.7 ./scripts/verify.sh
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib.sh"
bench_banner
ok=0; bad=0
pass() { printf '  \033[32mOK\033[0m   %-34s %s\n' "$1" "$2"; ok=$((ok+1)); }
fail() { printf '  \033[31mFAIL\033[0m %-34s %s\n' "$1" "$2"; bad=$((bad+1)); }

echo
echo "Trees"
bench_verify && pass "tree identity" "merged and pristine, and distinct" \
              || fail "tree identity" "see above"

echo
echo "Binaries"
for t in qudo stock; do
  b=$BENCH/build-$t/handshake
  if [ ! -x "$b" ]; then fail "$t handshake" "missing - run ./scripts/build.sh"; continue; fi
  lib=$(lib_of "$b")
  case "$lib" in
    "$(tree_dir $t)"/*) pass "$t handshake" "-> $lib" ;;
    *) fail "$t handshake" "linked $lib - wrong tree" ;;
  esac
done

echo
echo "Inputs"
[ -s "$CERTS/servercert.pem" ] && [ -s "$CERTS/serverkey.pem" ] \
  && pass "certificate" "$(with_tree qudo "$Q/apps/openssl.cnf" "$Q/apps/openssl" x509 \
        -in "$CERTS/servercert.pem" -noout -text 2>/dev/null | awk '/Public Key Algorithm/{print $NF; exit}')" \
  || fail "certificate" "missing - run ./scripts/build.sh"
for c in classical hybrid; do
  [ -s "$CONF/$c.cnf" ] && pass "config $c" "$(awk -F'= *' '/^Groups/{print $2}' "$CONF/$c.cnf")" \
                        || fail "config $c" "missing"
done

# handshake.c does not set a group, so OPENSSL_CONF is the only group selector.
echo
echo "Does OPENSSL_CONF actually select the group?"
if [ -x "$BENCH/build-qudo/handshake" ]; then
  cl=$(with_tree qudo "$CONF/classical.cnf" "$BENCH/build-qudo/handshake" -t "$CERTS" 1 2>/dev/null | head -1)
  hy=$(with_tree qudo "$CONF/hybrid.cnf"    "$BENCH/build-qudo/handshake" -t "$CERTS" 1 2>/dev/null | head -1)
  if [ -z "$cl" ] || [ -z "$hy" ]; then
    fail "group selection" "handshake produced no output"
  else
    d=$(awk "BEGIN{printf \"%.1f\", 100*($hy-$cl)/$cl}")
    # Hybrid adds ML-KEM to X25519; near-identical timings mean the config was ignored.
    if awk "BEGIN{exit !($hy > $cl*1.05)}"; then
      pass "group selection" "classical ${cl}us vs hybrid ${hy}us (+${d}%)"
    else
      fail "group selection" "classical ${cl}us vs hybrid ${hy}us - config appears ignored"
    fi
  fi
fi

echo
echo "Tools"
for t in cmake valgrind python3; do
  p=$(command -v $t 2>/dev/null) && pass "$t" "$p" \
    || { [ $t = valgrind ] && printf '  \033[33mWARN\033[0m %-34s %s\n' "$t" "absent - instruction counts unavailable" \
                          || fail "$t" "not on PATH"; }
done

echo
echo "FIPS"
for t in qudo stock; do
  d=$(tree_dir $t)
  if [ -n "$(fips_module "$d")" ] && [ -f "$d/providers/fipsmodule.cnf" ]; then
    pass "$t FIPS" "$(basename "$(fips_module "$d")") + fipsmodule.cnf present"
  else
    printf '  \033[33mWARN\033[0m %-34s %s\n' "$t FIPS" "absent - FIPS cells will be skipped"
  fi
done

echo
echo "=================================================================="
if [ $bad -eq 0 ]; then
  echo "  READY - $ok checks passed. Next: ./scripts/run.sh"
else
  echo "  NOT READY - $bad check(s) failed above."
fi
echo
exit $([ $bad -eq 0 ] && echo 0 || echo 1)
