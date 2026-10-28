#!/usr/bin/env bash
# Instruction counts under callgrind for the TLS handshake and the primitives.
#
# Both tools run for a fixed time, so the instruction total is divided by the
# number of operations each reports completing.
#
# Usage: STOCK_DIR=/path/to/openssl-3.5.7 [ALGS=...] [KEX=...] ./scripts/run-instr.sh
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib.sh"
bench_banner
bench_verify || exit 1
bench_environment
command -v valgrind >/dev/null || {
  echo "FATAL: valgrind not installed - instruction counts unavailable." >&2
  if [ "$BENCH_OS" = macos ]; then
    echo "       Upstream valgrind does not support recent macOS. The community" >&2
    echo "       fork (LouisBrunner/valgrind-macos) is in Homebrew for Intel; on" >&2
    echo "       Apple Silicon its arm64 support is experimental and opt-in." >&2
    echo "       Run this phase on Linux; see README section 7." >&2
  fi
  exit 1; }

# Both overridable to run a subset.
ALGS=${ALGS:-"ML-KEM-512 ML-KEM-768 ML-KEM-1024 ML-DSA-44 ML-DSA-65 ML-DSA-87"}
# Not named GROUPS: that is a bash special variable and assignments are ignored.
# Each entry is <label>:<config>:<certdir>, where certdir is ec or pq.
# X25519+ECDSA is the negative control; no delegated code runs in it.
KEX=${KEX:-"X25519+ECDSA:classical:ec \
           X25519+ML-DSA-44:classical:pq \
           X25519MLKEM768+ML-DSA-44:hybrid:pq \
           SecP256r1MLKEM768+ML-DSA-44:hybrid_p256:pq"}

OUT=$DATA/instructions.csv
LOGS=$DATA/callgrind-logs
mkdir -p "$LOGS"
echo "build,target,detail,instructions,operations,instr_per_op" > "$OUT"

# Callgrind prints its total to stderr as e.g. "==25== I   refs: 2,216,255,085".
irefs() { sed -n 's/.*I *refs: *\([0-9,]*\).*/\1/p' "$1" 2>/dev/null | tail -1 | tr -d ','; }

emit() { # $1=build $2=target $3=detail $4=instructions $5=operations
  local per=""
  [ -n "$4" ] && [ -n "$5" ] && [ "$5" != 0 ] && per=$(awk "BEGIN{printf \"%.0f\", $4/$5}")
  echo "$1,$2,$3,${4:-},${5:-},${per:-}" >> "$OUT"
  if [ -n "$per" ]; then
    echo "  $1 $3: $per instructions per operation" >&2
  else
    echo "  $1 $3: FAILED - see $LOGS" >&2
  fi
}

echo "== TLS handshake (perftools) ==" >&2
for t in qudo stock; do
  for spec in $KEX; do
    g=${spec%%:*}; rest=${spec#*:}; cfname=${rest%%:*}; ct=${rest##*:}
    cf=$CONF/$cfname.cnf
    [ -f "$cf" ] || { echo "  skip $t/$g: no $cf" >&2; continue; }
    [ "$ct" = ec ] && cdir=$CERTS_EC || cdir=$CERTS
    [ -s "$cdir/servercert.pem" ] || { echo "  skip $t/$g: no cert in $cdir" >&2; continue; }
    log=$LOGS/hs_${t}_$g
    with_tree "$t" "$cf" valgrind --tool=callgrind --callgrind-out-file=/dev/null \
      "$BENCH/build-$t/handshake" "$cdir" 1 > "$log.out" 2> "$log.err"
    ins=$(irefs "$log.err")
    # handshake runs for a fixed 5 seconds and reports its rate.
    hps=$(awk '/Handshakes per second/{print $NF}' "$log.out" 2>/dev/null)
    ops=$(awk "BEGIN{printf \"%.0f\", ${hps:-0}*5}")
    emit "$(bname "$t")" handshake "$g" "$ins" "$ops"
  done
done

echo "== primitives (openssl speed) ==" >&2
for t in qudo stock; do
  d=$(tree_dir "$t")
  for a in $ALGS; do
    case $a in *KEM*) flag=-kem-algorithms ;; *) flag=-signature-algorithms ;; esac
    log=$LOGS/sp_${t}_$a
    with_tree "$t" "$d/apps/openssl.cnf" valgrind --tool=callgrind \
      --callgrind-out-file=/dev/null "$d/apps/openssl" speed -seconds 1 "$flag" "$a" \
      > "$log.out" 2> "$log.err"
    ins=$(irefs "$log.err")
    # speed prints one row per algorithm ending in the three per-second rates;
    # their sum over the 1-second window is the operation count.
    ops=$(grep "^ *$a " "$log.out" 2>/dev/null | awk '{printf "%.0f", $(NF-2)+$(NF-1)+$NF}')
    emit "$(bname "$t")" primitive "$a" "$ins" "$ops"
  done
done

echo >&2
echo "INSTRUCTIONS DONE - $OUT" >&2
echo "  callgrind logs kept in $LOGS for any cell that failed" >&2
