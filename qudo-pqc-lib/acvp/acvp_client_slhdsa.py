#!/usr/bin/env python3
"""
ACVP Client for SLH-DSA (FIPS 205)

Downloads NIST ACVP test vectors from usnistgov/ACVP-Server,
invokes qudo_acvp_slhdsa binary, and validates results.

See: https://pages.nist.gov/ACVP/draft-celi-acvp-slh-dsa.html

Usage:
    python3 acvp_client_slhdsa.py [--binary PATH] [--version VER]
    python3 acvp_client_slhdsa.py -p prompt.json -e expected.json

Note: SLH-DSA is slow. Use --workers N for parallel execution.
"""

import argparse
import atexit
import json
import os
import subprocess
import sys
import threading
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

EXEC_WRAPPER = os.environ.get("EXEC_WRAPPER", "").split() if os.environ.get("EXEC_WRAPPER") else []

DEFAULT_VERSION = "v1.1.0.41"
ACVP_BASE_URL = "https://raw.githubusercontent.com/usnistgov/ACVP-Server/{version}/gen-val/json-files"

VECTOR_FILES = {
    "keyGen": {
        "prompt": "SLH-DSA-keyGen-FIPS205/prompt.json",
        "expected": "SLH-DSA-keyGen-FIPS205/expectedResults.json",
    },
    "sigGen": {
        "prompt": "SLH-DSA-sigGen-FIPS205/prompt.json",
        "expected": "SLH-DSA-sigGen-FIPS205/expectedResults.json",
    },
    "sigVer": {
        "prompt": "SLH-DSA-sigVer-FIPS205/prompt.json",
        "expected": "SLH-DSA-sigVer-FIPS205/expectedResults.json",
    },
}


def download_vectors(version, cache_dir):
    """Download ACVP vectors if not already cached."""
    base_url = ACVP_BASE_URL.format(version=version)
    cache_dir.mkdir(parents=True, exist_ok=True)

    for mode, files in VECTOR_FILES.items():
        for kind, rel_path in files.items():
            local = cache_dir / rel_path
            local.parent.mkdir(parents=True, exist_ok=True)
            if not local.exists():
                url = f"{base_url}/{rel_path}"
                print(f"Downloading {rel_path}...", file=sys.stderr)
                try:
                    urllib.request.urlretrieve(url, local)
                    with open(local) as f:
                        json.load(f)
                except Exception as e:
                    print(f"Error downloading {rel_path}: {e}", file=sys.stderr)
                    local.unlink(missing_ok=True)
                    return False
    return True


def load_json(path):
    """Load JSON, handling ACVTS array format."""
    with open(path) as f:
        data = json.load(f)
    if isinstance(data, list) and len(data) == 2:
        return data[1]
    return data


_tls = threading.local()
_all_procs = []
_all_procs_lock = threading.Lock()


def _get_batch_proc(binary):
    """Lazily start one long-lived --batch process per worker thread.

    The binary runs qudo_pqc_init once and then serves every test case over a
    pipe. The process is thread-local so each --workers thread owns its own
    pipe."""
    proc = getattr(_tls, "proc", None)
    if proc is None or proc.poll() is not None:
        proc = subprocess.Popen(
            EXEC_WRAPPER + [binary, "--batch"],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            text=True,
            bufsize=1,
        )
        _tls.proc = proc
        with _all_procs_lock:
            _all_procs.append(proc)
    return proc


def _shutdown_batch_procs():
    with _all_procs_lock:
        for proc in _all_procs:
            try:
                proc.stdin.close()
            except Exception:
                pass
            try:
                proc.wait(timeout=10)
            except Exception:
                proc.kill()
        _all_procs.clear()


atexit.register(_shutdown_batch_procs)


def run_binary(binary, args, timeout=300):
    """Send one op to this thread's --batch co-process; parse key=value reply.

    timeout is accepted but not applied per op."""
    proc = _get_batch_proc(binary)
    try:
        proc.stdin.write(" ".join(args) + "\n")
        proc.stdin.flush()
    except (BrokenPipeError, ValueError):
        print("ERROR: ACVP batch process is not running", file=sys.stderr)
        return None

    output = {}
    for line in proc.stdout:
        line = line.rstrip("\n")
        if line == "=END=":
            return output
        if "=" in line:
            k, v = line.split("=", 1)
            output[k.strip()] = v.strip()

    print("ERROR: ACVP batch process ended unexpectedly", file=sys.stderr)
    return None


def test_keygen(binary, prompt, expected):
    """Process keyGen test vectors."""
    passed = failed = skipped = 0

    prompt_groups = {g["tgId"]: g for g in prompt["testGroups"]}
    expected_groups = {g["tgId"]: g for g in expected["testGroups"]}

    for tg_id, pg in prompt_groups.items():
        eg = expected_groups.get(tg_id)
        if eg is None:
            skipped += 1
            continue

        param_set = pg["parameterSet"]
        prompt_tests = {t["tcId"]: t for t in pg["tests"]}
        expected_tests = {t["tcId"]: t for t in eg["tests"]}

        for tc_id, pt in prompt_tests.items():
            et = expected_tests.get(tc_id)
            if et is None:
                skipped += 1
                continue

            args = [
                "-parameterSet", param_set,
                "-skSeed", pt["skSeed"],
                "-skPrf", pt["skPrf"],
                "-pkSeed", pt["pkSeed"],
                "keyGen",
            ]
            output = run_binary(binary, args)
            if output is None:
                failed += 1
                continue

            pk_match = output.get("pk", "").upper() == et["pk"].upper()
            sk_match = output.get("sk", "").upper() == et["sk"].upper()
            if pk_match and sk_match:
                passed += 1
            else:
                failed += 1
                print(f"FAIL keyGen tc={tc_id} {param_set}", file=sys.stderr)

    return passed, failed, skipped


def run_siggen_test(binary, param_set, tc_id, pt, et, tg):
    """Run a single sigGen test case. Returns (pass, fail, skip)."""
    deterministic = tg.get("deterministic", False)
    pre_hash = tg.get("preHash", "pure")

    args = ["-parameterSet", param_set]
    args += ["-message", pt["message"]]
    args += ["-sk", pt["sk"]]

    ctx = pt.get("context", "")
    if ctx:
        args += ["-context", ctx]

    # Pre-hash: pass hash algorithm from test case or group
    if pre_hash == "preHash":
        hash_alg = pt.get("hashAlg", tg.get("hashAlg", ""))
        if hash_alg:
            args += ["-hashAlg", hash_alg]

    # Internal interface: pass flag so binary uses Algorithm 19 (no context)
    sig_iface = tg.get("signatureInterface", "external")
    if sig_iface == "internal":
        args += ["-signatureInterface", "internal"]

    if deterministic:
        args += ["-deterministic", "1"]
    else:
        addrnd = pt.get("additionalRandomness", "")
        if addrnd:
            args += ["-additionalRandomness", addrnd]

    args.append("sigGen")

    output = run_binary(binary, args, timeout=600)
    if output is None:
        return (0, 1, 0)

    sig_match = output.get("signature", "").upper() == et["signature"].upper()
    if sig_match:
        return (1, 0, 0)
    else:
        print(f"FAIL sigGen tc={tc_id} {param_set}", file=sys.stderr)
        return (0, 1, 0)


def test_siggen(binary, prompt, expected, workers=1):
    """Process sigGen test vectors."""
    passed = failed = skipped = 0

    prompt_groups = {g["tgId"]: g for g in prompt["testGroups"]}
    expected_groups = {g["tgId"]: g for g in expected["testGroups"]}

    tasks = []
    for tg_id, pg in prompt_groups.items():
        eg = expected_groups.get(tg_id)
        if eg is None:
            skipped += 1
            continue

        param_set = pg["parameterSet"]
        prompt_tests = {t["tcId"]: t for t in pg["tests"]}
        expected_tests = {t["tcId"]: t for t in eg["tests"]}

        for tc_id, pt in prompt_tests.items():
            et = expected_tests.get(tc_id)
            if et is None:
                skipped += 1
                continue
            tasks.append((param_set, tc_id, pt, et, pg))

    if workers > 1:
        with ThreadPoolExecutor(max_workers=workers) as pool:
            futures = [
                pool.submit(run_siggen_test, binary, *task) for task in tasks
            ]
            for future in as_completed(futures):
                p, f, s = future.result()
                passed += p
                failed += f
                skipped += s
    else:
        for task in tasks:
            p, f, s = run_siggen_test(binary, *task)
            passed += p
            failed += f
            skipped += s

    return passed, failed, skipped


def test_sigver(binary, prompt, expected):
    """Process sigVer test vectors."""
    passed = failed = skipped = 0

    prompt_groups = {g["tgId"]: g for g in prompt["testGroups"]}
    expected_groups = {g["tgId"]: g for g in expected["testGroups"]}

    for tg_id, pg in prompt_groups.items():
        eg = expected_groups.get(tg_id)
        if eg is None:
            skipped += 1
            continue

        param_set = pg["parameterSet"]
        prompt_tests = {t["tcId"]: t for t in pg["tests"]}
        expected_tests = {t["tcId"]: t for t in eg["tests"]}

        for tc_id, pt in prompt_tests.items():
            et = expected_tests.get(tc_id)
            if et is None:
                skipped += 1
                continue

            args = [
                "-parameterSet", param_set,
                "-message", pt["message"],
                "-signature", pt["signature"],
                "-pk", pt["pk"],
            ]
            ctx = pt.get("context", "")
            if ctx:
                args += ["-context", ctx]

            # Pre-hash: pass hash algorithm from test case or group
            pre_hash = pg.get("preHash", "pure")
            if pre_hash == "preHash":
                hash_alg = pt.get("hashAlg", pg.get("hashAlg", ""))
                if hash_alg:
                    args += ["-hashAlg", hash_alg]

            # Internal interface: pass flag so binary uses Algorithm 20 (no context)
            sig_iface = pg.get("signatureInterface", "external")
            if sig_iface == "internal":
                args += ["-signatureInterface", "internal"]

            args.append("sigVer")

            output = run_binary(binary, args, timeout=120)
            if output is None:
                failed += 1
                continue

            expected_pass = et.get("testPassed", True)
            actual_pass = output.get("testPassed", "0") == "1"

            if actual_pass == expected_pass:
                passed += 1
            else:
                failed += 1
                print(f"FAIL sigVer tc={tc_id} {param_set} "
                      f"(expected={expected_pass}, got={actual_pass})", file=sys.stderr)

    return passed, failed, skipped


def main():
    parser = argparse.ArgumentParser(description="ACVP SLH-DSA Test Client")
    parser.add_argument("--binary", default=None)
    parser.add_argument("--version", default=DEFAULT_VERSION)
    parser.add_argument("-p", "--prompt", default=None)
    parser.add_argument("-e", "--expected", default=None)
    parser.add_argument("-o", "--output", default=None)
    parser.add_argument("--workers", type=int, default=1,
                        help="Number of parallel workers for sigGen (SLH-DSA is slow)")
    args = parser.parse_args()

    binary = args.binary
    if binary is None:
        script_dir = Path(__file__).parent
        for build_name in ["build", "build-acvp"]:
            candidate = script_dir.parent / build_name / "acvp" / "qudo_acvp_slhdsa"
            if candidate.exists():
                binary = str(candidate)
                break
    if binary is None or not Path(binary).exists():
        print(f"Binary not found. Build with: ./build.sh --acvp", file=sys.stderr)
        sys.exit(1)

    total_passed = total_failed = total_skipped = 0

    if args.prompt and args.expected:
        prompt = load_json(args.prompt)
        expected = load_json(args.expected)
        mode = prompt.get("mode", "")
        if "keyGen" in mode:
            p, f, s = test_keygen(binary, prompt, expected)
        elif "sigGen" in mode:
            p, f, s = test_siggen(binary, prompt, expected, args.workers)
        else:
            p, f, s = test_sigver(binary, prompt, expected)
        total_passed += p
        total_failed += f
        total_skipped += s
    else:
        cache_dir = Path(__file__).parent / ".acvp-data" / args.version / "files"
        if not download_vectors(args.version, cache_dir):
            sys.exit(1)

        for mode, files in VECTOR_FILES.items():
            prompt_path = cache_dir / files["prompt"]
            expected_path = cache_dir / files["expected"]
            if not prompt_path.exists() or not expected_path.exists():
                print(f"Missing vectors for {mode}", file=sys.stderr)
                continue

            prompt = load_json(str(prompt_path))
            expected = load_json(str(expected_path))

            print(f"\n=== SLH-DSA {mode} ===", file=sys.stderr)
            if mode == "keyGen":
                p, f, s = test_keygen(binary, prompt, expected)
            elif mode == "sigGen":
                p, f, s = test_siggen(binary, prompt, expected, args.workers)
            else:
                p, f, s = test_sigver(binary, prompt, expected)

            print(f"  Passed: {p}  Failed: {f}  Skipped: {s}", file=sys.stderr)
            total_passed += p
            total_failed += f
            total_skipped += s

    print(f"\n=== SLH-DSA ACVP Summary ===", file=sys.stderr)
    print(f"  Total Passed:  {total_passed}", file=sys.stderr)
    print(f"  Total Failed:  {total_failed}", file=sys.stderr)
    print(f"  Total Skipped: {total_skipped}", file=sys.stderr)

    sys.exit(0 if total_failed == 0 else 1)


if __name__ == "__main__":
    main()
