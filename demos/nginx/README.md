# nginx on QudoSSL — post-quantum TLS in one command

This demo uses the **standard build** of QudoSSL Community: it builds QudoSSL
from this repository with `FIPS=no` (no FIPS module; ML-KEM and ML-DSA run in
the default provider), builds nginx 1.28 against it, and serves HTTPS with
**hybrid post-quantum key exchange** (X25519MLKEM768). Clients without ML-KEM
still connect over classical ECDHE.

## Run it

From the repository root (needs Docker with Compose):

```sh
docker compose -f demos/nginx/compose.yaml up --build -d
demos/nginx/verify.sh
```

The first build compiles OpenSSL, `qudo-pqc-lib` and nginx, and takes roughly
10–20 minutes; later runs start immediately. Expected output:

```
PASS  standard build: QudoSSL default provider active
PASS  standard build: no FIPS module installed or loaded
PASS  post-quantum handshake (X25519MLKEM768)
PASS  classical client still served (secp256r1)
PASS  nginx answered over the post-quantum session
```

Then try it yourself:

```sh
curl -k https://localhost:8443/
```

```
Hello from nginx on QudoSSL
protocol: TLSv1.3
cipher:   TLS_CHACHA20_POLY1305_SHA256
group:    prime256v1
```

Your system `curl` most likely has no ML-KEM, so it negotiates classical
`prime256v1` — the fallback working as intended. A client with ML-KEM
(QudoSSL, OpenSSL ≥ 3.5, current Chrome or Firefox) gets the hybrid, and the
page then shows `group: X25519MLKEM768`. To see one from the host, use the
QudoSSL CLI inside the container:

```sh
docker compose -f demos/nginx/compose.yaml exec nginx \
  openssl s_client -connect 127.0.0.1:8443 -groups X25519MLKEM768 -brief </dev/null
```

```
Negotiated TLS1.3 group: X25519MLKEM768
```

Stop it with `docker compose -f demos/nginx/compose.yaml down`.

## What makes it post-quantum

Two things, both in this directory:

1. **nginx is built against QudoSSL** ([`Dockerfile`](Dockerfile)):

   ```sh
   ./configure --with-http_ssl_module \
       --with-cc-opt="-I/opt/qudossl/include" \
       --with-ld-opt="-L/opt/qudossl/lib -Wl,-rpath,/opt/qudossl/lib"
   ```

2. **One line in [`nginx.conf`](nginx.conf)** puts the ML-KEM hybrids first:

   ```nginx
   ssl_conf_command Groups X25519MLKEM768:SecP256r1MLKEM768:SecP384r1MLKEM1024:secp256r1:secp384r1;
   ```

The certificate is an ordinary RSA certificate; nothing is reissued. No extra
OpenSSL configuration is needed: QudoSSL uses the stock `openssl.cnf` that the
install puts in `/opt/qudossl/ssl`, the default provider loads on its own, and
the group list lives in `nginx.conf`.

## Not for production as-is

The certificate is self-signed and generated at build time, and the server only
returns a status page. Use it as a template: keep the build flags and the
`Groups` line, and bring your own certificate and server blocks.
