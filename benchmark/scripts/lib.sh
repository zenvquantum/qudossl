# Shared setup for the qudossl crypto benchmarks. Sourced by the other scripts.

case "$(uname -s)" in
  Linux)  BENCH_OS=linux ;;
  Darwin) BENCH_OS=macos ;;
  *) echo "FATAL: unsupported OS $(uname -s) - Linux and macOS only." >&2
     echo "       On Windows use WSL2, which runs the full suite." >&2
     exit 1 ;;
esac

_lib=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
BENCH=$(cd "$_lib/.." && pwd)          # <repo>/benchmark
DATA=$BENCH/data
CERTS=$BENCH/certs
CERTS_EC=$BENCH/certs-ecdsa
CONF=$BENCH/conf
mkdir -p "$DATA" "$CERTS" "$CERTS_EC" "$CONF"

# QUDOSSL_DIR defaults to this repository's openssl/; STOCK_DIR has no default.
Q=${QUDOSSL_DIR:-$(cd "$BENCH/../openssl" 2>/dev/null && pwd)}
S=${STOCK_DIR:-}

# Number of qudo strings in a tree's libcrypto; -1 if no libcrypto is found.
qudo_symbols() {
  local lib
  for lib in "$1/libcrypto.so.3" "$1/libcrypto.dylib" "$1/libcrypto.3.dylib"; do
    [ -f "$lib" ] && { strings -a "$lib" 2>/dev/null | grep -ci 'QUDO_\|qudo_pqc'; return; }
  done
  echo -1
}

bench_verify() {
  local nq ns rc=0
  [ -n "$S" ] || {
    echo "FATAL: STOCK_DIR is not set. Point it at a built upstream OpenSSL tree:" >&2
    echo "         export STOCK_DIR=/path/to/openssl-3.5.7" >&2
    return 1; }
  for d in "$Q" "$S"; do
    [ -x "$d/apps/openssl" ] || {
      echo "FATAL: no openssl at ${d:-<unset>}/apps/openssl" >&2
      echo "       Point at the two trees directly:" >&2
      echo "         export QUDOSSL_DIR=/path/to/qudossl/openssl" >&2
      echo "         export STOCK_DIR=/path/to/openssl-3.5.7" >&2
      rc=1; }
  done
  [ $rc -eq 0 ] || return 1
  nq=$(qudo_symbols "$Q"); ns=$(qudo_symbols "$S")
  [ "$(cd "$Q" && pwd)" = "$(cd "$S" && pwd)" ] && {
    echo "FATAL: both trees are the same directory - nothing to compare" >&2; rc=1; }
  [ "$nq" = 0 ] && { echo "FATAL: $Q has no qudo symbols; not a merged build" >&2; rc=1; }
  [ "$ns" != 0 ] && [ "$ns" != -1 ] && {
    echo "FATAL: $S has $ns qudo symbols; not a pristine tree" >&2; rc=1; }
  return $rc
}

# Runs a command against one tree with that tree's libraries and config.
with_tree() { # $1=qudo|stock  $2=config file  $3...=command
  local which=$1 cf=$2; shift 2
  local d; [ "$which" = qudo ] && d=$Q || d=$S
  LD_LIBRARY_PATH=$d OPENSSL_MODULES=$d/providers OPENSSL_CONF=$cf "$@"
}

# Shared-library path a binary resolves, per OS.
lib_of() { # $1=binary  -> path of the libcrypto it will load
  case $BENCH_OS in
    linux) ldd "$1" 2>/dev/null | awk '/libcrypto/{print $3; exit}' ;;
    macos) otool -L "$1" 2>/dev/null | awk '/libcrypto/{print $1; exit}' ;;
  esac
}

# Peak resident set of a command, in KiB. GNU time -f %M reports KiB; BSD time -l
# reports bytes on a labelled line.
peak_rss_kb() { # $1... = command
  case $BENCH_OS in
    linux) /usr/bin/time -f %M "$@" 2>&1 >/dev/null | tail -1 ;;
    macos) /usr/bin/time -l "$@" 2>&1 >/dev/null \
             | awk '/maximum resident set size/{printf "%d", $1/1024; exit}' ;;
  esac
}

# FIPS module path; the file extension differs per platform.
fips_module() { # $1=tree -> path if present, empty otherwise
  local f
  for f in "$1/providers/fips.so" "$1/providers/fips.dylib"; do
    [ -f "$f" ] && { printf '%s' "$f"; return; }
  done
}

# Build label written to every CSV; must match QUDO/STOCK in analyze.py.
bname() { [ "$1" = qudo ] && printf 'QUDOSSL' || printf 'OPENSSL'; }

tree_dir() { [ "$1" = qudo ] && printf '%s' "$Q" || printf '%s' "$S"; }

# Records the host, CPU features and tree versions in data/environment.csv, so
# the report describes the machine the data came from.
bench_environment() {
  local arch cpu simd
  arch=$(uname -m)
  case $BENCH_OS in
    linux)
      cpu=$(awk -F': *' '/model name/{print $2; exit}' /proc/cpuinfo 2>/dev/null)
      [ -z "$cpu" ] && cpu=$(awk -F': *' '/^CPU part|^Model/{print $2; exit}' /proc/cpuinfo 2>/dev/null)
      for f in avx512f avx2 sha_ni asimd sve; do
        grep -qm1 " $f" /proc/cpuinfo 2>/dev/null && simd="$simd${simd:+ }$f"
      done ;;
    macos)
      cpu=$(sysctl -n machdep.cpu.brand_string 2>/dev/null)
      [ "$(sysctl -n hw.optional.avx2_0 2>/dev/null)" = 1 ] && simd="$simd${simd:+ }avx2"
      [ "$(sysctl -n hw.optional.avx512f 2>/dev/null)" = 1 ] && simd="$simd${simd:+ }avx512f"
      [ "$(sysctl -n hw.optional.neon 2>/dev/null)" = 1 ] && simd="$simd${simd:+ }neon" ;;
  esac
  {
    echo "key,value"
    echo "os,$BENCH_OS"
    echo "kernel,$(uname -sr | tr ',' ' ')"
    echo "arch,$arch"
    echo "cpu,$(printf '%s' "$cpu" | tr ',' ' ')"
    echo "simd,${simd:-none detected}"
    echo "cores,$(getconf _NPROCESSORS_ONLN 2>/dev/null || echo unknown)"
    # The qudossl version carries a +qudo suffix; the qudo symbol count also
    # distinguishes the trees.
    echo "qudossl_version,$(with_tree qudo "$Q/apps/openssl.cnf" "$Q/apps/openssl" version 2>/dev/null | tr ',' ' ')"
    echo "openssl_version,$(with_tree stock "$S/apps/openssl.cnf" "$S/apps/openssl" version 2>/dev/null | tr ',' ' ')"
    echo "qudossl_path,$Q"
    echo "openssl_path,$S"
    echo "qudossl_qudo_symbols,$(qudo_symbols "$Q")"
    echo "openssl_qudo_symbols,$(qudo_symbols "$S")"
    echo "date_utc,$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
  } > "$DATA/environment.csv"
}

bench_banner() {
  [ -n "$BENCH_BANNER_SHOWN" ] && return 0
  export BENCH_BANNER_SHOWN=1
  {
    echo "=== qudossl crypto benchmark ==="
    echo "  benchmark dir : $BENCH"
    echo "  qudossl       : $Q  ($(qudo_symbols "$Q") qudo symbols)"
    echo "  stock         : $S  ($(qudo_symbols "$S") qudo symbols)"
    echo "  os/cores      : $BENCH_OS / $(getconf _NPROCESSORS_ONLN 2>/dev/null || echo ?)"
  } >&2
}
