#!/usr/bin/env bash
# Wall-clock measurements: primitives, TLS handshake, resumption, memory.
# Build order is reversed on alternate repetitions.
#
# Usage: STOCK_DIR=/path/to/openssl-3.5.7 [REPS=6] ./scripts/run.sh
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib.sh"
bench_banner
bench_verify || exit 1
bench_environment

REPS=${REPS:-6}
KEMS="ML-KEM-512 ML-KEM-768 ML-KEM-1024 X25519MLKEM768 SecP256r1MLKEM768 SecP384r1MLKEM1024"
SIGS="ML-DSA-44 ML-DSA-65 ML-DSA-87"
SUITE=TLS_AES_256_GCM_SHA384

for b in build-qudo/handshake build-stock/handshake; do
  [ -x "$BENCH/$b" ] || { echo "FATAL: $BENCH/$b missing - run ./scripts/build.sh" >&2; exit 1; }
done

# ---------------------------------------------------------------- primitives --
echo "rep,build,mode,family,alg,op1,op2,op3" > "$DATA/primitives.csv"
for R in $(seq 1 $REPS); do
  for M in default fips; do
    # Reversed on even reps so run position does not favour either build.
    [ $((R%2)) -eq 0 ] && ORDER="stock qudo" || ORDER="qudo stock"
    for t in $ORDER; do
      d=$(tree_dir $t)
      if [ "$M" = fips ]; then
        cf=$CONF/fips_$t.cnf; [ -f "$cf" ] || continue
      else
        cf=$d/apps/openssl.cnf
      fi
      for A in $KEMS; do
        v=$(with_tree $t "$cf" "$d/apps/openssl" speed -seconds 2 -kem-algorithms "$A" 2>/dev/null \
            | grep "^ *$A " | awk '{print $(NF-2)","$(NF-1)","$NF}')
        echo "$R,$(bname $t),$M,KEM,$A,$v" >> "$DATA/primitives.csv"
      done
      for A in $SIGS; do
        v=$(with_tree $t "$cf" "$d/apps/openssl" speed -seconds 2 -signature-algorithms "$A" 2>/dev/null \
            | grep "^ *$A " | awk '{print $(NF-2)","$(NF-1)","$NF}')
        echo "$R,$(bname $t),$M,SIG,$A,$v" >> "$DATA/primitives.csv"
      done
    done
  done
  echo "primitives rep $R" >&2
done
echo "PRIMITIVES_DONE" >&2

# ----------------------------------------------------------------- handshake --
# perftools handshake: combined in-memory client and server. The group comes
# from OPENSSL_CONF.
echo "rep,build,mode,group,us_per_handshake" > "$DATA/handshake.csv"
for R in $(seq 1 $REPS); do
  [ $((R%2)) -eq 0 ] && ORDER="stock qudo" || ORDER="qudo stock"
  for t in $ORDER; do
    # Negative control: classical key exchange and certificate, no delegated code.
    if [ -s "$CERTS_EC/servercert.pem" ]; then
      v=$(with_tree $t "$CONF/classical.cnf" "$BENCH/build-$t/handshake" -t "$CERTS_EC" 1 2>/dev/null | head -1)
      echo "$R,$(bname $t),default,X25519+ECDSA,${v:-}" >> "$DATA/handshake.csv"
    fi
    # ML-DSA certificate; these rows differ only in the key exchange.
    for spec in classical:X25519 hybrid:X25519MLKEM768 hybrid_p256:SecP256r1MLKEM768; do
      g=${spec%%:*}; kex=${spec##*:}
      cf=$CONF/$g.cnf; [ -f "$cf" ] || continue
      v=$(with_tree $t "$cf" "$BENCH/build-$t/handshake" -t "$CERTS" 1 2>/dev/null | head -1)
      echo "$R,$(bname $t),default,$kex+ML-DSA-44,${v:-}" >> "$DATA/handshake.csv"
    done
    cf=$CONF/fips_$t.cnf
    if [ -f "$cf" ]; then
      v=$(with_tree $t "$cf" "$BENCH/build-$t/handshake" -t "$CERTS" 1 2>/dev/null | head -1)
      echo "$R,$(bname $t),fips,X25519MLKEM768+ML-DSA-44,${v:-}" >> "$DATA/handshake.csv"
    fi
  done
  echo "handshake rep $R" >&2
done
echo "HANDSHAKE_DONE" >&2

# ------------------------------------------------- resumption and memory -----
# ctz/openssl-bench: full handshake, session resumption and memory per
# connection. Its group list includes X25519MLKEM768.
if [ -x "$BENCH/bench-qudo" ] && [ -x "$BENCH/bench-stock" ]; then
  echo "rep,build,test,side,handshakes_per_s" > "$DATA/resumption.csv"
  for R in $(seq 1 $REPS); do
    [ $((R%2)) -eq 0 ] && ORDER="stock qudo" || ORDER="qudo stock"
    for t in $ORDER; do
      for m in handshake handshake-resume handshake-ticket; do
        # Certificate paths are relative to openssl-bench/. Rates are matched on
        # the trailing "handshakes/s" field because resumption modes add extra
        # lines. --ecdsa avoids the RSA-2048 default, whose signing cost would
        # dominate the key exchange.
        out=$(cd "$BENCH/openssl-bench" && "$BENCH/bench-$t" --ecdsa $m $SUITE 2>/dev/null)
        for side in server client; do
          v=$(printf '%s\n' "$out" | awk -v s=$side '$NF=="handshakes/s" && $2==s {print $(NF-1); exit}')
          echo "$R,$(bname $t),$m,$side,${v:-}" >> "$DATA/resumption.csv"
        done
      done
    done
    echo "resumption rep $R" >&2
  done
  echo "RESUMPTION_DONE" >&2

  echo "build,connections,peak_rss_kb" > "$DATA/memory.csv"
  for t in qudo stock; do
    for n in 100 1000 5000; do
      kb=$(cd "$BENCH/openssl-bench" && peak_rss_kb "$BENCH/bench-$t" memory $SUITE $n)
      echo "$(bname $t),$n,${kb:-}" >> "$DATA/memory.csv"
    done
  done
  echo "MEMORY_DONE" >&2
else
  echo "WARNING: bench-qudo/bench-stock missing; resumption and memory skipped" >&2
fi

echo >&2
echo "RUN COMPLETE - data in $DATA" >&2
echo "next: ./scripts/run-instr.sh   # deterministic instruction counts" >&2
echo "      ./scripts/report.sh" >&2
