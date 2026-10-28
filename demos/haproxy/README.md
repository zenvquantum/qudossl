# HAProxy on QudoSSL — post-quantum TLS in one command

This demo uses the **standard build** of QudoSSL Community: it builds QudoSSL
from this repository with `FIPS=no` (no FIPS module; ML-KEM and ML-DSA run in
the default provider), builds HAProxy 3.0 LTS against it, and terminates HTTPS
with **hybrid post-quantum key exchange**. All three ML-KEM hybrids are offered
(X25519MLKEM768, SecP256r1MLKEM768, SecP384r1MLKEM1024), and clients without
ML-KEM still connect over classical ECDHE.

## Run it

From the repository root (needs Docker with Compose):

```sh
docker compose -f demos/haproxy/compose.yaml up --build -d
demos/haproxy/verify.sh
```

The first build compiles OpenSSL, `qudo-pqc-lib` and HAProxy, and takes roughly
10–20 minutes; later runs start immediately. Expected output:

```
PASS  HAProxy built with QudoSSL
PASS  HAProxy running on QudoSSL
PASS  standard build: QudoSSL default provider active
PASS  standard build: no FIPS module installed or loaded
PASS  post-quantum handshake (X25519MLKEM768)
PASS  post-quantum handshake (SecP256r1MLKEM768)
PASS  post-quantum handshake (SecP384r1MLKEM1024)
PASS  classical client still served (secp256r1)
PASS  HAProxy answered over the post-quantum session
```

Then try it yourself:

```sh
curl -k https://localhost:9443/
```

```
Hello from HAProxy on QudoSSL
protocol: TLSv1.3
cipher:   TLS_CHACHA20_POLY1305_SHA256
```

HAProxy has no sample fetch for the negotiated key-exchange group, so the page
shows protocol and cipher only. To see the group, use the QudoSSL CLI inside the
container:

```sh
docker compose -f demos/haproxy/compose.yaml exec haproxy \
  openssl s_client -connect 127.0.0.1:9443 -groups X25519MLKEM768 -brief </dev/null
```

```
Negotiated TLS1.3 group: X25519MLKEM768
```

The demo listens on port 9443, so it can run alongside the
[nginx demo](../nginx/) on 8443. Stop it with
`docker compose -f demos/haproxy/compose.yaml down`.

## What makes it post-quantum

Two things, both in this directory:

1. **HAProxy is built against QudoSSL** ([`Dockerfile`](Dockerfile)):

   ```sh
   make TARGET=linux-glibc USE_OPENSSL=1 \
        SSL_INC=/opt/qudossl/include SSL_LIB=/opt/qudossl/lib \
        LDFLAGS="-Wl,-rpath,/opt/qudossl/lib"
   ```

2. **One line in [`haproxy.cfg`](haproxy.cfg)** puts the ML-KEM hybrids first:

   ```
   ssl-default-bind-curves X25519MLKEM768:SecP256r1MLKEM768:SecP384r1MLKEM1024:secp256r1:secp384r1
   ```

   HAProxy refuses to start if any name in this list is unknown, so a typo
   fails loudly rather than silently falling back to classical groups.

The certificate is an ordinary RSA certificate; nothing is reissued. HAProxy
reads the certificate and key from a single PEM file. No extra OpenSSL
configuration is needed: QudoSSL uses the stock `openssl.cnf` that the install
puts in `/opt/qudossl/ssl`, the default provider loads on its own, and the group
list lives in `haproxy.cfg`.

## Using it as a template

The certificate is self-signed and generated at build time, and the frontend
returns a status page instead of forwarding to a backend. To put it in front of
a real service, keep the build flags and the `ssl-default-bind-curves` line,
bring your own certificate, and replace the `http-request return` line with a
`default_backend` pointing at your servers.
