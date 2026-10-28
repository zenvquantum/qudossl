#!/bin/bash
# Cross-implementation PQC TLS interop matrix.
#
# Drives one handshake between a chosen server and client for one group, and
# reports PASS/FAIL with the negotiated group.
#
#   Usage: ci/interop/matrix.sh <server> <client> <group> <port>
#          server/client in: qudo | brew | go
#
#   Example (the full matrix):
#     for g in X25519MLKEM768 SecP256r1MLKEM768 SecP384r1MLKEM1024; do
#       ci/interop/matrix.sh qudo brew "$g" 24101
#       ci/interop/matrix.sh brew qudo "$g" 24102
#       ci/interop/matrix.sh qudo go   "$g" 24103
#       ci/interop/matrix.sh go   qudo "$g" 24104
#     done
#
# OpenSSL peers run with OPENSSL_CONF=/dev/null so no third-party provider from
# the system OpenSSL config is loaded.
set -u

HERE=$(cd "$(dirname "$0")" && pwd)
REPO_ROOT=$(cd "${HERE}/../.." && pwd)

QUDOSSL_DIR="${QUDOSSL_DIR:-${REPO_ROOT}/openssl}"
QUDO="${QUDOSSL_DIR}/apps/openssl"
BREW="${BREW_OPENSSL:-/opt/homebrew/opt/openssl@3/bin/openssl}"
WORK="${INTEROP_WORK:-${TMPDIR:-/tmp}/qudossl-interop}"

CERT="${WORK}/c.pem"
KEY="${WORK}/k.pem"
mkdir -p "${WORK}/logs"

# Loader path so the built apps/openssl uses the built libcrypto.
case "$(uname -s)" in
    Darwin) LOADER_VAR=DYLD_LIBRARY_PATH ;;
    *)      LOADER_VAR=LD_LIBRARY_PATH ;;
esac

qudo()    { env "${LOADER_VAR}=${QUDOSSL_DIR}" OPENSSL_CONF=/dev/null "$QUDO" "$@"; }
brewssl() { OPENSSL_CONF=/dev/null "$BREW" "$@"; }

# Go's TLS stack requires a SAN; a CN-only certificate is rejected.
if [ ! -f "${CERT}" ] || [ ! -f "${KEY}" ]; then
    echo "==> generating test certificate in ${WORK}"
    qudo req -x509 -new -newkey ec -pkeyopt group:P-256 \
        -keyout "${KEY}" -out "${CERT}" -days 30 -nodes \
        -subj "/CN=localhost" \
        -addext "subjectAltName=DNS:localhost,IP:127.0.0.1" >/dev/null 2>&1 \
        || { echo "error: certificate generation failed" >&2; exit 2; }
fi

kill_port() {
    local pids
    pids=$(lsof -ti tcp:"$1" 2>/dev/null)
    [ -n "${pids}" ] && kill -9 ${pids} 2>/dev/null
    return 0
}

# Wait for a readiness marker in the server log. A connection probe is not used
# because the servers run with -naccept 1.
wait_ready() {
    local log=$1 pat=$2 i=0
    while [ ${i} -lt 200 ]; do
        grep -q "${pat}" "${log}" 2>/dev/null && return 0
        sleep 0.05
        i=$((i + 1))
    done
    return 1
}

S=$1; C=$2; G=$3; P=$4
tag="$S s_server  <-  $C client   [$G]"

# The optional Go peer is built only when this case uses it; without a Go
# toolchain the case is reported as SKIP and exits 0.
if [ "${S}" = "go" ] || [ "${C}" = "go" ]; then
    if ! command -v go >/dev/null; then
        echo "=== ${tag}  ==>  SKIP (go not installed; Go 1.26+ needed for ML-KEM)"
        exit 0
    fi
    if [ ! -x "${WORK}/goserver" ] || [ ! -x "${WORK}/goclient" ]; then
        echo "==> building Go peers ($(go version | awk '{print $3}'))"
        if ! (cd "${HERE}" && go build -o "${WORK}/goserver" ./server \
                           && go build -o "${WORK}/goclient" ./client); then
            echo "=== ${tag}  ==>  SKIP (go build failed)"
            exit 0
        fi
    fi
fi

slog="${WORK}/logs/${S}-${C}-${G}.server.log"
clog="${WORK}/logs/${S}-${C}-${G}.client.log"
rm -f "${slog}" "${clog}"; kill_port "${P}"

case ${S} in
    qudo) qudo    s_server -accept "${P}" -cert "${CERT}" -key "${KEY}" -groups "${G}" -tls1_3 -www -naccept 1 >"${slog}" 2>&1 & ;;
    brew) brewssl s_server -accept "${P}" -cert "${CERT}" -key "${KEY}" -groups "${G}" -tls1_3 -www -naccept 1 >"${slog}" 2>&1 & ;;
    go)   "${WORK}/goserver" "127.0.0.1:${P}" "${G}" "${CERT}" "${KEY}" >"${slog}" 2>&1 & ;;
    *)    echo "error: unknown server '${S}' (want qudo|brew|go)" >&2; exit 2 ;;
esac
spid=$!

if [ "${S}" = "go" ]; then RDY="SERVER_READY"; else RDY="ACCEPT"; fi
if ! wait_ready "${slog}" "${RDY}"; then
    echo "=== ${tag}  ==>  FAIL (server never became ready)"
    sed 's/^/    SRV| /' "${slog}" | head -6
    kill -9 ${spid} 2>/dev/null; kill_port "${P}"; exit 1
fi

case ${C} in
    qudo) echo Q | qudo    s_client -connect "127.0.0.1:${P}" -groups "${G}" -tls1_3 -CAfile "${CERT}" -verify_return_error -servername localhost >"${clog}" 2>&1 ;;
    brew) echo Q | brewssl s_client -connect "127.0.0.1:${P}" -groups "${G}" -tls1_3 -CAfile "${CERT}" -verify_return_error -servername localhost >"${clog}" 2>&1 ;;
    go)   "${WORK}/goclient" "127.0.0.1:${P}" "${G}" "${CERT}" >"${clog}" 2>&1 ;;
    *)    echo "error: unknown client '${C}' (want qudo|brew|go)" >&2; kill -9 ${spid} 2>/dev/null; exit 2 ;;
esac
crc=$?

sleep 0.3
kill -9 ${spid} 2>/dev/null; kill_port "${P}"; wait ${spid} 2>/dev/null

ok=1
if [ "${C}" = "go" ]; then
    grep -q '^RESULT=PASS' "${clog}" && ok=0
else
    neg=$(grep -E 'Negotiated TLS1.3 group' "${clog}" | head -1)
    [ ${crc} -eq 0 ] && [ -n "${neg}" ] && ok=0
fi

if [ ${ok} -eq 0 ]; then
    echo "=== ${tag}  ==>  PASS"
else
    echo "=== ${tag}  ==>  FAIL (client rc=${crc})"
fi
grep -h -E 'Negotiated TLS1.3 group|RESULT=|APPDATA_RX' "${clog}" 2>/dev/null | sed 's/^/    CLI| /' | head -3
grep -h -E 'Negotiated TLS1.3 group|SERVER_OK|SERVER_RX' "${slog}" 2>/dev/null | sed 's/^/    SRV| /' | head -3
if [ ${ok} -ne 0 ]; then
    grep -h -E 'alert|error|failure|no.*group|SERVER_HANDSHAKE_FAIL|SERVER_FATAL|err=' \
        "${clog}" "${slog}" 2>/dev/null | sed 's/^/    ERR| /' | head -5
fi
exit ${ok}
