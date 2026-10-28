#!/usr/bin/env bash
# Verify the HAProxy demo (STANDARD build): HAProxy is linked against QudoSSL,
# the default provider is active and no FIPS module is installed, every ML-KEM
# hybrid group negotiates, and a classical-only client is still served.
# Run after `docker compose ... up -d`.
set -euo pipefail

cd "$(dirname "$0")"
dc() { docker compose -f compose.yaml "$@"; }
in_container() { dc exec -T haproxy "$@"; }

# Wait for HAProxy to accept connections.
for _ in $(seq 1 30); do
    if in_container openssl s_client -connect 127.0.0.1:9443 -brief </dev/null >/dev/null 2>&1; then
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

build_info=$(in_container haproxy -vv)
check "HAProxy built with QudoSSL" "Built with OpenSSL version : OpenSSL 3.5.7+qudo" "$build_info"
check "HAProxy running on QudoSSL" "Running on OpenSSL version : OpenSSL 3.5.7+qudo" "$build_info"

providers=$(in_container openssl list -providers)
check "standard build: QudoSSL default provider active" "QudoSSL Default Provider" "$providers"
modules=$(in_container ls /opt/qudossl/lib/ossl-modules 2>/dev/null || true)
if grep -q fips <<<"$providers$modules"; then
    echo "FAIL  standard build: no FIPS module (found one)"; fail=1
else
    echo "PASS  standard build: no FIPS module installed or loaded"
fi

for group in X25519MLKEM768 SecP256r1MLKEM768 SecP384r1MLKEM1024; do
    out=$(in_container openssl s_client -connect 127.0.0.1:9443 \
            -groups "$group" -tls1_3 -brief </dev/null 2>&1)
    check "post-quantum handshake ($group)" \
          "Negotiated TLS1.3 group: $group" "$out"
done

classic=$(in_container openssl s_client -connect 127.0.0.1:9443 \
        -groups secp256r1 -brief </dev/null 2>&1)
# s_client reports a classical group as "Peer Temp Key", not "Negotiated group".
check "classical client still served (secp256r1)" \
      "Peer Temp Key: ECDH, prime256v1" "$classic"

body=$(in_container openssl s_client -connect 127.0.0.1:9443 -quiet \
        -groups X25519MLKEM768 2>/dev/null <<<$'GET / HTTP/1.0\r\nHost: localhost\r\n\r\n' || true)
check "HAProxy answered over the post-quantum session" "Hello from HAProxy on QudoSSL" "$body"

exit "$fail"
