#!/usr/bin/env bash
# Verify the nginx demo (STANDARD build): the default provider is active and
# no FIPS module is installed, a post-quantum handshake succeeds, and a
# classical-only client is still served. Run after `docker compose ... up -d`.
set -euo pipefail

cd "$(dirname "$0")"
dc() { docker compose -f compose.yaml "$@"; }
in_container() { dc exec -T nginx "$@"; }

# Wait for nginx to accept connections.
for _ in $(seq 1 30); do
    if in_container openssl s_client -connect 127.0.0.1:8443 -brief </dev/null >/dev/null 2>&1; then
        break
    fi
    sleep 1
done

fail=0
check() {  # check <description> <expected text> <output>
    if grep -q -- "$2" <<<"$3"; then
        echo "PASS  $1"
    else
        echo "FAIL  $1 (expected: $2)"
        fail=1
    fi
}

providers=$(in_container openssl list -providers)
check "standard build: QudoSSL default provider active" "QudoSSL Default Provider" "$providers"
modules=$(in_container ls /opt/qudossl/lib/ossl-modules 2>/dev/null || true)
if grep -q fips <<<"$providers$modules"; then
    echo "FAIL  standard build: no FIPS module (found one)"; fail=1
else
    echo "PASS  standard build: no FIPS module installed or loaded"
fi

pq=$(in_container openssl s_client -connect 127.0.0.1:8443 \
        -groups X25519MLKEM768 -tls1_3 -brief </dev/null 2>&1)
check "post-quantum handshake (X25519MLKEM768)" \
      "Negotiated TLS1.3 group: X25519MLKEM768" "$pq"

classic=$(in_container openssl s_client -connect 127.0.0.1:8443 \
        -groups secp256r1 -brief </dev/null 2>&1)
# s_client reports a classical group as "Peer Temp Key", not "Negotiated group".
check "classical client still served (secp256r1)" \
      "Peer Temp Key: ECDH, prime256v1" "$classic"

body=$(in_container openssl s_client -connect 127.0.0.1:8443 -quiet \
        -groups X25519MLKEM768 2>/dev/null <<<$'GET / HTTP/1.0\r\nHost: localhost\r\n\r\n' || true)
check "nginx answered over the post-quantum session" "Hello from nginx on QudoSSL" "$body"

exit "$fail"
