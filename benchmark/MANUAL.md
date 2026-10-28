# Running the benchmarks by hand

This page shows how to run each benchmark tool directly, with sample output.
The `scripts/` wrappers run the same commands, alternate the build order, and
compute the statistics.

Run everything from `benchmark/`:

```bash
cd benchmark
```

Set the two trees once per shell. `Q` is this repository's merged build; `S` is
a separately built upstream OpenSSL 3.5.7 tree named by `STOCK_DIR`:

```bash
export STOCK_DIR=/path/to/openssl-3.5.7
Q=$(cd ../openssl && pwd)
S=$(cd "$STOCK_DIR" && pwd)
```

Run `./scripts/build.sh` once first to produce the perftools binaries,
certificates and configs; `bench-qudo` / `bench-stock` (section 3) are built
separately from `openssl-bench/`. None of the commands below use the network, start a server, or open a
port.

---

## 1. TLS handshake — OpenSSL's own `perftools`

A combined in-memory client and server. `certs` holds the ML-DSA-44 certificate;
`1` is the thread count.

```bash
LD_LIBRARY_PATH=$Q OPENSSL_CONF=conf/hybrid.cnf ./build-qudo/handshake  certs 1
LD_LIBRARY_PATH=$S OPENSSL_CONF=conf/hybrid.cnf ./build-stock/handshake certs 1
```

```
qudossl   Average time per handshake: <t>us    Handshakes per second: <n>
stock     Average time per handshake: <t>us    Handshakes per second: <n>
```

`handshake.c` does not set a key-exchange group, so it is selected through
`OPENSSL_CONF`:

| config | key exchange | certificate | purpose |
|---|---|---|---|
| `conf/classical.cnf` | X25519 | ML-DSA-44 | classical KEX, PQC signature |
| `conf/hybrid.cnf` | X25519MLKEM768 | ML-DSA-44 | the deployment case |
| `conf/hybrid_p256.cnf` | SecP256r1MLKEM768 | ML-DSA-44 | second hybrid group |
| `conf/fips_qudo.cnf`, `conf/fips_stock.cnf` | X25519MLKEM768 | ML-DSA-44 | FIPS provider |

**Negative control**: classical key exchange and a classical certificate, so no
delegated code runs on either side. The two builds are expected to match:

```bash
LD_LIBRARY_PATH=$Q OPENSSL_CONF=conf/classical.cnf ./build-qudo/handshake  certs-ecdsa 1
LD_LIBRARY_PATH=$S OPENSSL_CONF=conf/classical.cnf ./build-stock/handshake certs-ecdsa 1
```

`-t` gives terse output (microseconds only); the scripts use this form.

---

## 2. Primitives — `openssl speed`

```bash
LD_LIBRARY_PATH=$Q $Q/apps/openssl speed -seconds 2 -kem-algorithms ML-KEM-768
LD_LIBRARY_PATH=$S $S/apps/openssl speed -seconds 2 -kem-algorithms ML-KEM-768
```

```
                       keygen    encaps    decaps keygens/s  encaps/s  decaps/s
     ML-KEM-768     0.000017s 0.000013s 0.000019s   59532.8   79907.0   53791.0
```

Signatures use a different flag:

```bash
LD_LIBRARY_PATH=$Q $Q/apps/openssl speed -seconds 2 -signature-algorithms ML-DSA-65
```

Algorithms available: `ML-KEM-512/768/1024`, `X25519MLKEM768`,
`SecP256r1MLKEM768`, `SecP384r1MLKEM1024`, `ML-DSA-44/65/87`.

For FIPS, add the provider config:

```bash
LD_LIBRARY_PATH=$Q OPENSSL_MODULES=$Q/providers OPENSSL_CONF=conf/fips_qudo.cnf \
  $Q/apps/openssl speed -seconds 2 -kem-algorithms ML-KEM-768
```

---

## 3. Resumption and memory — `ctz/openssl-bench`

Build these binaries with an `-rpath` to their tree so `LD_LIBRARY_PATH` is
not needed. They resolve certificate paths relative to the working
directory, so run them from `openssl-bench/`:

```bash
cd openssl-bench
../bench-qudo  handshake        TLS_AES_256_GCM_SHA384
../bench-qudo  handshake-resume TLS_AES_256_GCM_SHA384
../bench-qudo  handshake-ticket TLS_AES_256_GCM_SHA384
```

```
handshake         <rate> hs/s (server)
handshake-resume  <rate> hs/s (server)
handshake-ticket  <rate> hs/s (server)
```

Each mode prints two rate lines, one for the server side and one for the
client. `run.sh` records both and passes `--ecdsa` to use an ECDSA certificate
instead of the default RSA-2048 one.

Memory per connection:

```bash
/usr/bin/time -f %M ../bench-qudo memory TLS_AES_256_GCM_SHA384 1000
```

```
82560          # peak RSS in KB for 1000 concurrent connections
```

Swap `bench-qudo` for `bench-stock` to compare. On macOS use
`/usr/bin/time -l` instead, which reports bytes.

---

## 4. Instruction counts — callgrind

Callgrind counts executed instructions, which do not depend on CPU frequency or
scheduling. Execution is roughly 50x slower, so each run takes a few minutes.

```bash
LD_LIBRARY_PATH=$Q OPENSSL_CONF=conf/hybrid.cnf \
  valgrind --tool=callgrind --callgrind-out-file=/dev/null \
  ./build-qudo/handshake certs 1
```

```
Handshakes per second: 24.800000
==36== I   refs:      1,465,221,057
```

Both numbers are needed. `handshake` runs for a fixed 5 seconds, so:

```
handshakes      = 24.8 x 5              = 124
per handshake   = 1,465,221,057 / 124   = 11,816,299 instructions
```

Repeat for `build-stock` and divide:

| | instructions per handshake |
|---|---|
| qudossl | *q* |
| stock | *s* |
| **ratio** | ***s* / *q*** |

The same approach applies to a primitive: `speed` prints three per-second
rates, and their sum over the one-second window is the operation count:

```bash
LD_LIBRARY_PATH=$Q valgrind --tool=callgrind --callgrind-out-file=/dev/null \
  $Q/apps/openssl speed -seconds 1 -kem-algorithms ML-KEM-768
```

| | instructions per ML-KEM-768 operation |
|---|---|
| qudossl | *q* |
| stock | *s* |
| **ratio** | ***s* / *q*** |

Instruction counts are supported on Linux; see README section 7 for macOS.

---

## 5. Setup checks

These checks detect misconfigurations that would otherwise produce plausible
but meaningless numbers.

**Each binary loads its own libcrypto:**

```bash
ldd ./build-qudo/handshake  | grep libcrypto     # otool -L on macOS
ldd ./build-stock/handshake | grep libcrypto
ldd ./bench-qudo            | grep libcrypto
ldd ./bench-stock           | grep libcrypto
```

Each must point inside its own tree, not a system directory such as
`/lib/x86_64-linux-gnu/`.

**The trees differ.** The merged build contains qudo symbols; the pristine one
contains none:

```bash
strings -a $Q/libcrypto.so.3 | grep -ci qudo     # expect ~154
strings -a $S/libcrypto.so.3 | grep -ci qudo     # expect 0
```

**`OPENSSL_CONF` takes effect.** If it were ignored, every hybrid handshake
would run as classical X25519. The hybrid config is expected to be measurably
slower:

```bash
LD_LIBRARY_PATH=$Q OPENSSL_CONF=conf/classical.cnf ./build-qudo/handshake -t certs 1
LD_LIBRARY_PATH=$Q OPENSSL_CONF=conf/hybrid.cnf    ./build-qudo/handshake -t certs 1
```

```
553.771182     # classical
619.501920     # hybrid, +11.9%
```

`./scripts/verify.sh` runs all three checks; the `libcrypto` check covers the
`handshake` binaries only.

---

## 6. Repetition

Wall-clock numbers vary between runs, so a single measurement is not a reliable
comparison. Either:

- repeat with the build order alternating, as `run.sh` does (6 repetitions by
  default), and apply the rules in `README.md` section 5; or
- use the instruction counts, which vary by about 2% between runs.
