# Cross-implementation PQC TLS interop harness

Drives TLS 1.3 handshakes between QudoSSL and other implementations for each
post-quantum hybrid group, and reports the negotiated group.

The Go peer uses Go's `crypto/tls` with standard-library ML-KEM (Go 1.26+). Its
two source files import only the standard library (`go.mod` has no `require`
block). The Go peer is test-only and optional:

- It is not used by any `.github/workflows/` job or by the product build.
- `matrix.sh` builds it only for cases that use it. The OpenSSL-only cases
  (`qudo`/`brew`) do not need a Go toolchain.
- A `go` case on a machine without Go prints `SKIP` and exits 0.

## Peers

| Tag | Implementation | Independent of QudoSSL | Dependency |
|-----|----------------|--------------------|------------|
| `qudo` | QudoSSL (`openssl/apps/openssl`) | system under test | built in-tree |
| `brew` | stock OpenSSL 3.x | shares OpenSSL lineage | system OpenSSL |
| `go`   | Go `crypto/tls` (stdlib ML-KEM) | yes | Go 1.26+ (optional) |

The harness runs `brew` with `OPENSSL_CONF=/dev/null`, so no third-party
provider from the system OpenSSL config is loaded.

## Usage

```sh
# one case: <server> <client> <group> <port>   (server/client in: qudo|brew|go)
ci/interop/matrix.sh qudo brew X25519MLKEM768 24101

# full matrix, both directions, all hybrids
for g in X25519MLKEM768 SecP256r1MLKEM768 SecP384r1MLKEM1024; do
  ci/interop/matrix.sh qudo brew "$g" 24101
  ci/interop/matrix.sh brew qudo "$g" 24102
  ci/interop/matrix.sh qudo go   "$g" 24103
  ci/interop/matrix.sh go   qudo "$g" 24104
done
```

Environment overrides: `QUDOSSL_DIR` (built OpenSSL tree, default `../../openssl`),
`BREW_OPENSSL` (path to the stock `openssl` binary; the default,
`/opt/homebrew/opt/openssl@3/bin/openssl`, is the macOS Homebrew path, so on
Linux set it to your distribution's `openssl`), `INTEROP_WORK` (scratch dir
for the generated cert, built Go peers, and per-case logs).

## Files

- `matrix.sh` — the driver
- `server/main.go`, `client/main.go` — the Go peer (one group per case, pinned
  on both sides, so a PASS means that group was negotiated)
- `go.mod` — stdlib only, no dependencies

## Adding peers

Additional peers, such as BoringSSL (`bssl`) or AWS-LC (`awslc`), are added as
cases in the `case ${S}`/`case ${C}` blocks in `matrix.sh`, following the
existing OpenSSL invocations.
