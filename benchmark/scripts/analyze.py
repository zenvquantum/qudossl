#!/usr/bin/env python3
"""Analysis for the qudossl crypto benchmarks. Writes Markdown to stdout.

    python3 analyze.py <data-dir>

The decision thresholds are defined at the top of this file.
"""

import csv
import math
import os
import statistics as st
import sys
from collections import defaultdict

# ---------------------------------------------------------------- thresholds --
FLOOR = 0.10      # wall-clock effects below this are reported as parity
Z_MIN = 2.0
QUDO, STOCK = "QUDOSSL", "OPENSSL"
KEM_OPS = ("keygen", "encaps", "decaps")
SIG_OPS = ("keygen", "sign", "verify")


def die(m):
    print(f"FATAL: {m}", file=sys.stderr)
    sys.exit(1)


def read(path, required):
    if not os.path.isfile(path):
        return None
    with open(path, newline="") as fh:
        r = csv.DictReader(fh)
        missing = [c for c in required if c not in (r.fieldnames or [])]
        if missing:
            die(f"{os.path.basename(path)} missing column(s) {missing}")
        return list(r)


# --------------------------------------------------------------- statistics --
def zstat(rs):
    if len(rs) < 2:
        return float("nan")
    sd = st.stdev(rs)
    return float("inf") if sd == 0 else abs(st.mean(rs) - 1) / (sd / math.sqrt(len(rs)))


def signs(rs):
    return sum(1 for r in rs if r > 1)


def wilcoxon_all_same(rs):
    """Two-sided exact Wilcoxon signed-rank p for the all-agree outcome; NaN
    otherwise."""
    n = len(rs)
    return 2.0 / (2 ** n) if n and signs(rs) in (0, n) else float("nan")


def glass_delta(q, s):
    """Glass's delta: mean difference over the baseline's standard deviation."""
    if len(s) < 2:
        return float("nan")
    sd = st.stdev(s)
    return float("inf") if sd == 0 else (st.mean(q) - st.mean(s)) / sd


def verdict(rs):
    n = len(rs)
    if n < 2:
        return "n<2", "insufficient reps"
    mu = st.mean(rs)
    if abs(mu - 1) < FLOOR:
        return "parity", f"under {FLOOR:.0%} floor"
    if signs(rs) not in (0, n):
        return "no", f"sign {signs(rs)}/{n}"
    z = zstat(rs)
    if z < Z_MIN:
        return "no", f"z={z:.2f} < {Z_MIN}"
    if n < 6:
        return "no", f"n={n} cannot reach p<0.05"
    return "SEPARATED", f"p={wilcoxon_all_same(rs):.3f}, z={z:.2f}"


def paired(a, b):
    ks = sorted(set(a) & set(b))
    return [a[k] / b[k] for k in ks]


# ------------------------------------------------------------------ sections --
def sec_instructions(ds):
    rows = read(os.path.join(ds, "instructions.csv"),
                ["build", "target", "detail", "instr_per_op"])
    print("## Instruction counts\n")
    if not rows:
        print("`instructions.csv` absent - run `./scripts/run-instr.sh`.\n")
        return
    print("Counted under callgrind: every CPU instruction executed, rather than "
          "elapsed time.\n")
    print("Instruction counts are more stable than wall-clock timings but not "
          "exact. Each benchmark runs for a fixed wall-clock window, so the "
          "number of completed operations varies and process and library "
          "startup is amortised over that count. Repeated measurements of the "
          "same cell vary by about 2%. The `ops` column gives the operation "
          "count each figure was divided by.\n")
    print("Differences between rows carry the uncertainty of both rows, so "
          "subtracting one row from another is not a reliable way to isolate a "
          "component.\n")
    by, ops = defaultdict(dict), {}
    for r in rows:
        if r["instr_per_op"]:
            by[(r["target"], r["detail"])][r["build"]] = int(r["instr_per_op"])
            ops[(r["target"], r["detail"], r["build"])] = r.get("operations", "?")
    print("| target | detail | qudossl | qudossl ops | openssl | openssl ops | ratio |")
    print("|---|---|---|---|---|---|---|")
    for k in sorted(by):
        q, s = by[k].get(QUDO), by[k].get(STOCK)
        if not q or not s:
            continue
        print(f"| {k[0]} | {k[1]} | {q:,} | {ops.get((k[0], k[1], QUDO), '?')} | "
              f"{s:,} | {ops.get((k[0], k[1], STOCK), '?')} | **{s/q:.3f}x** |")
    print()


def sec_primitives(ds):
    rows = read(os.path.join(ds, "primitives.csv"),
                ["rep", "build", "mode", "alg", "op1", "op2", "op3"])
    print("## Primitives\n")
    if not rows:
        print("`primitives.csv` absent.\n")
        return
    print("Measured with `openssl speed`. No classical algorithm is involved, so "
          "these cells measure the delegated ML-KEM and ML-DSA code only.\n")
    cells = defaultdict(dict)
    for r in rows:
        if not r["op1"]:
            continue
        for i in (1, 2, 3):
            cells[(r["mode"], r["alg"], i, r["build"])][int(r["rep"])] = float(r[f"op{i}"])
    modes = sorted({k[0] for k in cells})
    algs = sorted({k[1] for k in cells}, key=lambda a: ("DSA" in a, a))
    # Per-row statistics are not printed; they determine the summary line.
    print("| mode | algorithm | operation | qudossl op/s | openssl op/s | ratio |")
    print("|---|---|---|---|---|---|")
    stats, sep = [], []
    for m in modes:
        for a in algs:
            ops = SIG_OPS if "DSA" in a else KEM_OPS
            for i, op in enumerate(ops, 1):
                q, s = cells.get((m, a, i, QUDO)), cells.get((m, a, i, STOCK))
                if not q or not s:
                    continue
                rs = paired(q, s)
                if not rs:
                    continue
                v, why = verdict(rs)
                if v == "SEPARATED":
                    sep.append(st.mean(rs))
                stats.append(1)
                print(f"| {m} | {a} | {op} | {st.mean(q.values()):,.0f} | "
                      f"{st.mean(s.values()):,.0f} | {st.mean(rs):.3f}x |")
    if sep:
        print(f"\n**{len(stats)} cells measured. {len(sep)} showed a consistent "
              f"difference in every repetition, spanning {min(sep):.2f}x to "
              f"{max(sep):.2f}x.**\n")
    else:
        print()

def sec_handshake(ds):
    rows = read(os.path.join(ds, "handshake.csv"),
                ["rep", "build", "mode", "group", "us_per_handshake"])
    print("## TLS handshake\n")
    if not rows:
        print("`handshake.csv` absent.\n")
        return
    print("Measured with OpenSSL `perftools/handshake`, a combined in-memory "
          "client and server. The ratio is openssl us / qudossl us, so above "
          "1.00 favours qudossl, as in the other tables.\n")
    c = defaultdict(dict)
    for r in rows:
        if r["us_per_handshake"]:
            c[(r["mode"], r["group"], r["build"])][int(r["rep"])] = float(r["us_per_handshake"])
    print("| mode | group | qudossl us | openssl us | ratio |")
    print("|---|---|---|---|---|")
    for (m, g) in sorted({(k[0], k[1]) for k in c}):
        q, s = c.get((m, g, QUDO)), c.get((m, g, STOCK))
        if not q or not s:
            continue
        ks = sorted(set(q) & set(s))
        rs = [s[k] / q[k] for k in ks]          # inverted: us, lower is better
        print(f"| {m} | {g} | {st.mean(q.values()):,.1f} | {st.mean(s.values()):,.1f} "
              f"| {st.mean(rs):.3f}x |")
    print("\nCells are named `<key exchange>+<signature>`.\n")
    print("- **`X25519+ECDSA`**: negative control. No delegated code runs on "
          "either side; the expected ratio is 1.00.")
    print("- **`X25519MLKEM768+ML-DSA-44`**: both the key exchange and the "
          "signature use delegated code.")
    print("- `X25519+ML-DSA-44`: classical key exchange with an ML-DSA "
          "certificate, so only the signature uses delegated code.\n")


def sec_resumption(ds):
    rows = read(os.path.join(ds, "resumption.csv"),
                ["rep", "build", "test", "side", "handshakes_per_s"])
    print("## Session resumption\n")
    if not rows:
        print("`resumption.csv` absent.\n")
        return
    print("Measured with `ctz/openssl-bench`, which reports server-side and "
          "client-side handshake rates for full handshakes and session "
          "resumption.\n")
    c = defaultdict(dict)
    for r in rows:
        if r["handshakes_per_s"]:
            c[(r["test"], r["side"], r["build"])][int(r["rep"])] = float(r["handshakes_per_s"])
    print("| test | side | qudossl hs/s | openssl hs/s | ratio |")
    print("|---|---|---|---|---|")
    for (t, side) in sorted({(k[0], k[1]) for k in c}):
        q, s = c.get((t, side, QUDO)), c.get((t, side, STOCK))
        if not q or not s:
            continue
        rs = paired(q, s)
        print(f"| {t} | {side} | {st.mean(q.values()):,.0f} | {st.mean(s.values()):,.0f} | "
              f"{st.mean(rs):.3f}x |")
    print("\nAn ECDSA P-256 certificate is used instead of the tool's RSA-2048 "
          "default, whose signing cost would dominate the key exchange.\n")
    print("`handshake` is a full exchange that includes ML-KEM; the key exchange "
          "is only part of its cost. `handshake-resume` and `handshake-ticket` "
          "skip the key exchange and the signature, so no delegated code runs in "
          "them; they act as a second negative control with an expected ratio "
          "of 1.00.\n")


def sec_memory(ds):
    rows = read(os.path.join(ds, "memory.csv"), ["build", "connections", "peak_rss_kb"])
    print("## Memory\n")
    if not rows:
        print("`memory.csv` absent.\n")
        return
    print("Peak RSS for a given number of concurrent connections. ML-KEM and "
          "ML-DSA keys are a few kilobytes each, so little difference is "
          "expected.\n")
    print("The ratio is openssl KB / qudossl KB: above 1.00 means qudossl used "
          "less memory. Every ratio in this report reads the same way.\n")
    by = defaultdict(dict)
    for r in rows:
        if r["peak_rss_kb"]:
            by[int(r["connections"])][r["build"]] = int(r["peak_rss_kb"])
    print("| connections | qudossl KB | openssl KB | delta KB | ratio |")
    print("|---|---|---|---|---|")
    for n in sorted(by):
        q, s = by[n].get(QUDO), by[n].get(STOCK)
        if not q or not s:
            continue
        print(f"| {n:,} | {q:,} | {s:,} | {q-s:+,} | {s/q:.3f}x |")
    print()


def load_env(ds):
    rows = read(os.path.join(ds, "environment.csv"), ["key", "value"])
    return {r["key"]: r["value"] for r in rows} if rows else {}


def sec_limits(env):
    print("## Limitations\n")
    if env:
        print("| | measured on |")
        print("|---|---|")
        for k, label in (("cpu", "CPU"), ("arch", "architecture"),
                         ("simd", "SIMD available"), ("cores", "cores"),
                         ("os", "OS"), ("kernel", "kernel"),
                         ("date_utc", "measured")):
            if env.get(k):
                print(f"| {label} | {env[k]} |")
        print()
        if env.get("qudossl_version"):
            print("### The two builds\n")
            print("qudossl is OpenSSL 3.5.7 with ML-KEM and ML-DSA delegated "
                  "to qudo-pqc; its version string carries a +qudo suffix. "
                  "They are separate trees, built and linked independently.\n")
            print("| | qudossl | openssl |")
            print("|---|---|---|")
            print(f"| version | {env.get('qudossl_version','?')} | {env.get('openssl_version','?')} |")
            print()
    print("- **Wall-clock figures are host-dependent.** CPU frequency, core type "
          "and thread placement affect them and are not controlled. Instruction "
          "counts vary by about 2% (see that section).")
    print("- **No network is involved.** Every figure is an in-process "
          "measurement; deployment behaviour under real traffic is not "
          "measured.")
    print("- **`openssl speed -seconds 2`** is used, with more repetitions in "
          "place of the 10 s default.")
    # Recorded from the host: qudo-pqc selects its backend at runtime.
    arch = env.get("arch", "the measured architecture")
    simd = env.get("simd", "unknown")
    print(f"- **{arch}, SIMD available: {simd}.** qudo-pqc selects its backend at "
          f"runtime, so only the path this CPU offers was exercised. Other "
          f"architectures, and any SIMD level absent above, are not covered by "
          f"these ratios.\n")


def main():
    if len(sys.argv) < 2:
        die("usage: analyze.py <data-dir>")
    ds = sys.argv[1]
    os.path.isdir(ds) or die(f"{ds} is not a directory")
    print("# qudossl crypto benchmark\n")
    print("qudossl (OpenSSL 3.5.7 with ML-KEM and ML-DSA delegated to qudo-pqc) "
          "compared with pristine OpenSSL 3.5.7, using benchmark tools from "
          "OpenSSL and ctz/openssl-bench, each built against each tree.\n")
    sec_instructions(ds)
    sec_primitives(ds)
    sec_handshake(ds)
    sec_resumption(ds)
    sec_memory(ds)
    print("---\n")
    sec_limits(load_env(ds))


if __name__ == "__main__":
    main()
