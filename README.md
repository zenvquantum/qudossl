# QudoSSL

**Quantum-Safe TLS**

[![CI](https://github.com/zenvquantum/qudossl/actions/workflows/ci.yml/badge.svg)](https://github.com/zenvquantum/qudossl/actions/workflows/ci.yml)
[![License: Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-blue)](LICENSE)
[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/zenvquantum/qudossl/badge)](https://scorecard.dev/viewer/?uri=github.com/zenvquantum/qudossl)

QudoSSL is built on OpenSSL 3.5 LTS (3.5.7), with its ML-KEM and ML-DSA math
delegated to ZenV Quantum's `qudo-pqc-lib`. It has the same API, ABI and CLI as
OpenSSL 3.5.7, so existing applications relink against it unchanged, and TLS
1.3 negotiates the post-quantum hybrid **X25519MLKEM768** out of the box with
ordinary RSA/ECDSA certificates.

This README covers the **standard build** on **Linux** and **macOS**.

- [Install on Linux](#install-on-linux)
- [Install on macOS](#install-on-macos)
- [Verify the install](#verify-the-install)
- [Test](#test)
- [Troubleshooting](#troubleshooting)
- [Demos: nginx and HAProxy](#demos-nginx-and-haproxy)

## Install on Linux

**1. Install the build tools**

```sh
sudo apt-get update
sudo apt-get install -y build-essential cmake perl git netcat-openbsd
```

You need GCC ≥ 11 (or Clang ≥ 14), GNU Make, Perl ≥ 5.10 and CMake ≥ 3.15.
No existing OpenSSL is required.

**2. Get the source**

```sh
git clone https://github.com/zenvquantum/qudossl.git
cd qudossl
```

**3. Choose an install prefix**

```sh
export QUDOSSL_PREFIX="$HOME/qudossl"
unset OPENSSL_CONF OPENSSL_MODULES
```

`$HOME/qudossl` needs no `sudo`. For a system-wide install use `/opt/qudossl`
and run the install commands in step 5 with `sudo`. The `unset` stops an
OpenSSL configuration exported elsewhere from being picked up.

**4. Build (standard build)**

```sh
make -C build all FIPS=no PREFIX="$QUDOSSL_PREFIX" \
     OPENSSL_EXTRA_FLAGS="-Wl,-rpath,$QUDOSSL_PREFIX/lib"
```

`FIPS=no` selects the standard build. The build has two stages: CMake builds
`qudo-pqc-lib/` into a static archive, then OpenSSL is configured against it and
compiled. Add `JOBS=N` to set the parallelism.

Keep the `-Wl,-rpath` flag. Linux distributions ship their own `libssl.so.3`
with the same name; without the RPATH the loader picks that one instead of
QudoSSL's.

**5. Install**

```sh
make -C build install_sw PREFIX="$QUDOSSL_PREFIX"
make -C openssl install_ssldirs
```

This installs the libraries, headers, the `openssl` binary, the `qudossl`
wrapper, and the configuration directory with the stock `openssl.cnf`.

**6. Add QudoSSL to your `PATH`**

```sh
export PATH="$QUDOSSL_PREFIX/bin:$PATH"
```

To make it permanent, add the line to `~/.bashrc` with your prefix written out:

```sh
echo 'export PATH="$HOME/qudossl/bin:$PATH"' >> ~/.bashrc
```

Now [verify the install](#verify-the-install).

## Install on macOS

Tested on macOS (Apple Silicon).

**1. Install the build tools**

```sh
xcode-select --install
brew install cmake
```

`xcode-select --install` installs the Xcode Command Line Tools (Apple Clang ≥ 14
and `make`); if they are already installed it says so, and you can move on.
`brew` needs [Homebrew](https://brew.sh). You need CMake ≥ 3.15; Perl and `nc`
come with macOS. No existing OpenSSL is required.

**2. Get the source**

```sh
git clone https://github.com/zenvquantum/qudossl.git
cd qudossl
```

**3. Choose an install prefix**

```sh
export QUDOSSL_PREFIX="$HOME/qudossl"
unset OPENSSL_CONF OPENSSL_MODULES
```

`$HOME/qudossl` needs no `sudo`. For a system-wide install use `/opt/qudossl`
and run the install commands in step 5 with `sudo`.

**4. Build (standard build)**

```sh
make -C build all FIPS=no PREFIX="$QUDOSSL_PREFIX" \
     OPENSSL_EXTRA_FLAGS="-Wl,-rpath,$QUDOSSL_PREFIX/lib"
```

`FIPS=no` selects the standard build. Add `JOBS=N` to set the parallelism.

**5. Install**

```sh
make -C build install_sw PREFIX="$QUDOSSL_PREFIX"
make -C openssl install_ssldirs
```

**6. Add QudoSSL to your `PATH`**

```sh
export PATH="$QUDOSSL_PREFIX/bin:$PATH"
```

To make it permanent, add the line to `~/.zshrc` with your prefix written out:

```sh
echo 'export PATH="$HOME/qudossl/bin:$PATH"' >> ~/.zshrc
```

Homebrew's `eval "$(brew shellenv)"` line is in `~/.zprofile`, which zsh reads
before `~/.zshrc`, so this line takes precedence over Homebrew's `openssl`. Open
a new terminal, or run `source ~/.zshrc`, for it to apply.

## Verify the install

The same on Linux and macOS. Run these from the `qudossl` directory.

**1. The QudoSSL `openssl` comes first on your `PATH`**

```sh
which -a openssl
```

The first line must be `$QUDOSSL_PREFIX/bin/openssl`, for example
`/home/you/qudossl/bin/openssl` or `/Users/you/qudossl/bin/openssl`.

**2. Version**

```sh
qudossl version
openssl version
```
```
QudoSSL 1.0.0
OpenSSL 3.5.7+qudo-1.0.0 9 Jun 2026 (Library: OpenSSL 3.5.7+qudo-1.0.0 9 Jun 2026)
```

**3. Provider**

```sh
qudossl list -providers
```
```
Providers:
  default
    name: QudoSSL Default Provider
    version: 1.0.0
    status: active
```

**4. Post-quantum groups**

```sh
qudossl list -tls-groups | tr ':' '\n' | grep -i mlkem
```
```
MLKEM512
MLKEM768
MLKEM1024
SecP256r1MLKEM768
X25519MLKEM768
SecP384r1MLKEM1024
```

**5. The ML-KEM / ML-DSA math is delegated to `qudo-pqc-lib`**

```sh
ci/check-delegation-linked.sh openssl
```

On Linux:

```
==> checking crypto-layer delegation in openssl
  configdata.pm defines QUDO_PQC_DELEGATE
  libcrypto.so: 123 qudo math symbols
  libcrypto.a: 12 qudo math symbols
DELEGATION CHECK PASSED -- artifacts contain the delegated PQC math.
```

## Test

**1. A live post-quantum TLS 1.3 handshake**

```sh
cd "$(mktemp -d)"
qudossl req -x509 -new -noenc -newkey rsa:3072 \
    -keyout s.key -out s.crt -days 2 -subj "/CN=localhost" 2>/dev/null
qudossl s_server -cert s.crt -key s.key -accept 4433 -www -quiet & SRV=$!
until nc -z 127.0.0.1 4433 2>/dev/null; do sleep 0.2; done
qudossl s_client -connect 127.0.0.1:4433 -brief </dev/null
kill $SRV
cd -
```

The output includes:

```
Protocol version: TLSv1.3
Signature type: rsa_pss_rsae_sha256          <- ordinary RSA certificate
Negotiated TLS1.3 group: X25519MLKEM768      <- post-quantum key exchange
```

**2. The full OpenSSL test suite** (from the `qudossl` directory)

```sh
env -u OPENSSL_CONF -u OPENSSL_MODULES make -C build test FIPS=no \
    PREFIX="$QUDOSSL_PREFIX" OPENSSL_EXTRA_FLAGS="-Wl,-rpath,$QUDOSSL_PREFIX/lib"
```

Pass the same `FIPS`, `PREFIX` and `OPENSSL_EXTRA_FLAGS` as in the build step;
otherwise `make` reconfigures and rebuilds a different variant before testing.

This takes a few minutes. A short pre-check prints its own result first; the
main suite then ends with `All tests successful.` and `Result: PASS`. The suite
writes temporary files, so leave a few GB of free disk space.

## Troubleshooting

| Symptom | Fix |
|---|---|
| `qudossl: command not found` | Run the `export PATH=…` line from step 6 in this shell, or open a new terminal after adding it to `~/.bashrc` / `~/.zshrc`. |
| `which -a openssl` lists another `openssl` first | Your `PATH` line runs too early. On macOS it must come after Homebrew's `eval "$(brew shellenv)"`. |
| ``version `OPENSSL_3.5.0' not found`` (Linux) | Rebuild with the `-Wl,-rpath` flag from step 4. |
| `list -providers` shows something other than `QudoSSL Default Provider` | An inherited `OPENSSL_CONF` or `OPENSSL_MODULES` points at another install. Run `unset OPENSSL_CONF OPENSSL_MODULES`. |
| `make test` fails in `pkcs12` / `store` / `uitest` | Run it with the `env -u OPENSSL_CONF -u OPENSSL_MODULES` prefix shown above. |
| Handshake falls back to a classical group | The client does not support ML-KEM (most system `curl` builds), or the server's group list leaves the hybrids out. Both sides need TLS 1.3. |
| SecP256r1MLKEM768 or SecP384r1MLKEM1024 fails with `handshake failure` | Only X25519MLKEM768 is in OpenSSL's default group list. Add the others to the server's groups, as shown below. |

## Using QudoSSL in a server

Build the server against `$QUDOSSL_PREFIX`, then list the post-quantum groups
in its TLS settings to offer all three hybrids.

nginx:

```sh
./configure --with-http_ssl_module \
    --with-cc-opt="-I$QUDOSSL_PREFIX/include" \
    --with-ld-opt="-L$QUDOSSL_PREFIX/lib -lssl -lcrypto -Wl,-rpath,$QUDOSSL_PREFIX/lib"
```
```nginx
ssl_conf_command Groups X25519MLKEM768:SecP256r1MLKEM768:SecP384r1MLKEM1024:secp256r1:secp384r1;
```

HAProxy (Linux):

```sh
make TARGET=linux-glibc USE_OPENSSL=1 \
     SSL_INC="$QUDOSSL_PREFIX/include" SSL_LIB="$QUDOSSL_PREFIX/lib" \
     LDFLAGS="-Wl,-rpath,$QUDOSSL_PREFIX/lib"
```
```
ssl-default-bind-curves X25519MLKEM768:SecP256r1MLKEM768:SecP384r1MLKEM1024:secp256r1:secp384r1
```

## Demos: nginx and HAProxy

Two complete, Docker-based examples. Each builds QudoSSL (standard build) from
this repository, builds the server against it, and includes a script that
checks the result. The first build takes 10–20 minutes.

- [demos/nginx/](demos/nginx/) — nginx 1.28 on port 8443

  ```sh
  docker compose -f demos/nginx/compose.yaml up --build -d
  demos/nginx/verify.sh
  ```

- [demos/haproxy/](demos/haproxy/) — HAProxy 3.0 LTS on port 9443, testing all
  three ML-KEM hybrids

  ```sh
  docker compose -f demos/haproxy/compose.yaml up --build -d
  demos/haproxy/verify.sh
  ```

## Support

Community support is through GitHub issues. Commercial support (SLA, deployment
help, indemnity): **[zenv.ai/qudo](https://zenv.ai/qudo)**.

## More

[CONTRIBUTING.md](CONTRIBUTING.md) · [SECURITY.md](SECURITY.md) ·
[CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md) · [CHANGELOG.md](CHANGELOG.md) ·
[docs/](docs/)

## Licence

Apache-2.0 — see [LICENSE](LICENSE) and [NOTICE](NOTICE). QudoSSL derives from
the OpenSSL project; upstream attribution in `openssl/LICENSE.txt` is retained.
