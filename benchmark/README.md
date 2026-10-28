# qudossl crypto benchmark

Measures **qudossl** (OpenSSL 3.5.7 with ML-KEM and ML-DSA delegated to qudo-pqc)
against **pristine OpenSSL 3.5.7**.

All measurements run in-process. No sockets are opened, no server is started,
and no network access is required.

---

## 1. Tools

The suite uses benchmark programs published by the OpenSSL and rustls projects,
vendored here. `scripts/build.sh` builds perftools against each tree;
`openssl-bench` is built by hand into `bench-qudo` and `bench-stock`, otherwise
resumption and memory are skipped.

| tool | origin | licence | measures |
|---|---|---|---|
| `openssl speed` | OpenSSL, already in the tree | Apache-2.0 | ML-KEM and ML-DSA primitives |
| `perftools/` | [openssl/perftools](https://github.com/openssl/perftools) | Apache-2.0 | full TLS 1.3 handshake, in memory |
| `openssl-bench/` | [ctz/openssl-bench](https://github.com/ctz/openssl-bench) | Apache-2.0 | resumption (full / session-id / ticket), memory per connection |
| `valgrind --tool=callgrind` | system package | GPL-2.0 | instruction counts |

The perftools README describes this usage: *"we would expect the apps to be
built multiple times (once for each target OpenSSL version to be tested)"*.

General-purpose HTTP load tools (wrk, k6, vegeta, ab, siege) are not used: they
ship their own TLS stacks and cannot negotiate `X25519MLKEM768`.

### Instruction counts and timings

Callgrind counts executed instructions rather than elapsed time, so the result
does not depend on CPU frequency, core type or scheduling. Both instruction
counts and wall-clock timings are collected; the instruction counts are the
more stable of the two.

---

## 2. Requirements

Two built trees with `fipsinstall` run. Build the QudoSSL tree with
`make -C build all` from the repository root (FIPS is on by default), and the
upstream tree with:

```bash
perl Configure linux-x86_64 enable-fips && make -j$(nproc)
```

Then, in each tree:

```bash
./apps/openssl fipsinstall -module providers/fips.so -out providers/fipsmodule.cnf
```

Tools:

```bash
sudo apt-get install -y cmake g++ valgrind python3 pandoc
```

`pandoc` is only needed for the PDF; the Markdown report is produced without it.

`STOCK_DIR` must point at the upstream tree. `QUDOSSL_DIR` defaults to this
repository's `openssl/` and can be overridden:

```bash
export STOCK_DIR=/path/to/openssl-3.5.7
export QUDOSSL_DIR=/path/to/qudossl/openssl   # optional
```

---

## 3. Running

[MANUAL.md](MANUAL.md) shows how to run each tool directly, with its arguments
and sample output. The scripts below run the same commands, alternate the build
order, and compute the statistics.

```bash
./scripts/build.sh        # build both, generate certs and configs   ~2 min
./scripts/verify.sh       # check the setup                          ~10 s
./scripts/run.sh          # wall-clock: primitives, handshake, ...   ~15 min
./scripts/run-instr.sh    # instruction counts under callgrind       ~25 min
./scripts/report.sh       # REPORT.md and REPORT.pdf                 ~5 s
```

`run.sh` and `run-instr.sh` are independent; either can be run alone, and
`report.sh` uses whatever data exists.

Repetitions default to 6 and can be changed:

```bash
REPS=12 ./scripts/run.sh
```

### verify.sh

Run `verify.sh` before measuring. It checks for misconfigurations that would
otherwise produce plausible but meaningless numbers:

- each perftools `handshake` binary resolves its own tree's `libcrypto`, not the system one or the
  other tree's
- the merged tree contains qudo symbols and the pristine tree does not, checked
  by inspecting `libcrypto`
- the two trees are different directories
- `OPENSSL_CONF` selects the key-exchange group. `handshake.c` does not set a
  group itself, so the check measures a classical and a hybrid group and fails
  unless the hybrid handshake is more than 5% slower.

---

## 4. Output

| file | contents |
|---|---|
| `data/primitives.csv` | `openssl speed` per algorithm, operation, provider, build, repetition |
| `data/handshake.csv` | microseconds per in-memory TLS 1.3 handshake |
| `data/resumption.csv` | handshakes/s for full, session-id and ticket resumption |
| `data/memory.csv` | peak RSS at 100 / 1000 / 5000 connections |
| `data/instructions.csv` | instructions per operation, from callgrind |
| `data/environment.csv` | host, CPU features and tree versions for the run |
| `REPORT.md`, `REPORT.pdf` | generated analysis |

---

## 5. Decision rules

A wall-clock cell is counted as a consistent difference only if all three hold.
The thresholds are defined at the top of `scripts/analyze.py`.

1. **Exact sign test**: every repetition favours the same build. At n=6 the
   two-sided p is 0.031; no other outcome reaches p<0.05 at that sample size.
2. **z >= 2** on the paired per-repetition ratio.
3. **Effect of at least 10%**: smaller wall-clock differences are reported as
   parity. The instruction counts resolve smaller differences and are reported
   separately.

Build order is reversed on alternate repetitions so that run position does not
favour either build.

The `X25519+ECDSA` handshake row is the **negative control**: X25519 key
exchange with an ECDSA certificate, so no delegated code runs on either side. It
is expected to read parity; a difference there indicates that something other
than the delegated math is being measured.

The `*+ML-DSA-44` rows all use an ML-DSA-44 certificate, so each includes an
ML-DSA signature in addition to its key exchange. `X25519+ML-DSA-44` therefore
isolates the signature and is not a control.

---

## 6. Scope

- **Deployment behaviour under real traffic** is not measured. There is no
  server, network or HTTP layer. Handshakes-per-second figures are upper bounds
  with the kernel, scheduler and network removed.
- **Maximum concurrent connections, sustained load and HTTP throughput** are not
  measured; those are dominated by the web server and the kernel rather than by
  the delegated crypto.
- **Architecture**: results apply to the CPU they were measured on. qudo-pqc
  selects its backend at runtime (for example AVX2 on x86-64, NEON on aarch64),
  so ratios from one architecture do not transfer to another. The CPU and SIMD
  features of each run are recorded in `data/environment.csv`.

---

## 7. Portability

The scripts run from any directory. Paths are derived from the script location,
both OpenSSL trees can be set through environment variables, and per-OS
differences are handled by a small set of helpers in `scripts/lib.sh`.

| what differs | Linux | macOS | handled by |
|---|---|---|---|
| resolved library of a binary | `ldd` | `otool -L` | `lib_of()` |
| peak resident set | `time -f %M` (KiB) | `time -l` (bytes) | `peak_rss_kb()` |
| FIPS module | `fips.so` | `fips.dylib` | `fips_module()` |
| libcrypto | `libcrypto.so.3` | `libcrypto*.dylib` | `qudo_symbols()` |

### Platform support

| | Linux | macOS | Windows |
|---|---|---|---|
| `openssl speed` - primitives | yes | yes | yes |
| `perftools` - TLS handshake | yes | yes | yes |
| `openssl-bench` - resumption, memory | yes | yes | no |
| callgrind - instruction counts | yes | Intel only | no |
| **these scripts** | **yes** | untested | no |

**Linux** is the supported platform.

**macOS** support in the scripts is untested. Run `./scripts/verify.sh` to check
a given setup.

Instruction counts on macOS require valgrind, which upstream does not support on
recent macOS releases. The community fork
[LouisBrunner/valgrind-macos](https://github.com/LouisBrunner/valgrind-macos)
is available in Homebrew for Intel Macs. Its arm64 support is experimental and
requires `I_ACKNOWLEDGE_THIS_MIGHT_CRASH_OR_DAMAGE_MY_COMPUTER=yes`, so
instruction counts are treated as unavailable on Apple Silicon.

**Windows** is not supported natively: `openssl-bench` requires `<sys/time.h>`
and GNU `time`, valgrind is not available, and the scripts are POSIX shell that
read `/proc` and run `ldd`. Use WSL2, which runs the full suite.

### Running from another location

`QUDOSSL_DIR` defaults to `../openssl` relative to this directory. If the
benchmark directory is copied elsewhere, set both trees explicitly:

```bash
export QUDOSSL_DIR=/path/to/qudossl/openssl
export STOCK_DIR=/path/to/openssl-3.5.7
./scripts/verify.sh
```

Data, certificates, configs and binaries are all written inside this directory.

---

## 8. Troubleshooting

| symptom | cause |
|---|---|
| `STOCK_DIR is not set` | export `STOCK_DIR` pointing at a built upstream tree |
| `no qudo symbols; not a merged build` | `QUDOSSL_DIR` points at a pristine tree |
| `both trees are the same directory` | `QUDOSSL_DIR` and `STOCK_DIR` are identical |
| `handshake linked ... wrong tree` | rebuild; `build.sh` performs the same check and stops on failure |
| `group selection ... config appears ignored` | the OpenSSL build lacks the hybrid group, or `OPENSSL_CONF` is being overridden |
| `perftools source missing` | `git clone https://github.com/openssl/perftools perftools` |
| FIPS cells absent from the report | that tree has no `providers/fipsmodule.cnf`; run `fipsinstall` |
| PDF missing, Markdown present | `pandoc`, `weasyprint` or `wkhtmltopdf` absent; the Markdown report is complete |
