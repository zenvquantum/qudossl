#!/usr/bin/env python3
"""
ACVP Client for ML-DSA (FIPS 204)

Downloads NIST ACVP test vectors from usnistgov/ACVP-Server,
invokes qudo_acvp_mldsa binary, and validates results.

See: https://pages.nist.gov/ACVP/draft-celi-acvp-ml-dsa.html

Usage:
    python3 acvp_client_mldsa.py [--binary PATH] [--version VER]
    python3 acvp_client_mldsa.py -p prompt.json -e expected.json
"""

import argparse
import atexit
import json
import os
import subprocess
import sys
import urllib.request
from pathlib import Path

EXEC_WRAPPER = os.environ.get("EXEC_WRAPPER", "").split() if os.environ.get("EXEC_WRAPPER") else []

DEFAULT_VERSION = "v1.1.0.41"
ACVP_BASE_URL = "https://raw.githubusercontent.com/usnistgov/ACVP-Server/{version}/gen-val/json-files"

VECTOR_FILES = {
    "keyGen": {
        "prompt": "ML-DSA-keyGen-FIPS204/prompt.json",
        "expected": "ML-DSA-keyGen-FIPS204/expectedResults.json",
    },
    "sigGen": {
        "prompt": "ML-DSA-sigGen-FIPS204/prompt.json",
        "expected": "ML-DSA-sigGen-FIPS204/expectedResults.json",
    },
    "sigVer": {
        "prompt": "ML-DSA-sigVer-FIPS204/prompt.json",
        "expected": "ML-DSA-sigVer-FIPS204/expectedResults.json",
    },
}

PARAM_SET_TO_LEVEL = {
    "ML-DSA-44": 44,
    "ML-DSA-65": 65,
    "ML-DSA-87": 87,
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


_BATCH_PROC = None


def _get_batch_proc(binary):
    """Lazily start one long-lived --batch process for the whole run.

    The binary runs qudo_pqc_init once and then serves every test case
    over a pipe."""
    global _BATCH_PROC
    if _BATCH_PROC is None or _BATCH_PROC.poll() is not None:
        _BATCH_PROC = subprocess.Popen(
            EXEC_WRAPPER + [binary, "--batch"],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            text=True,
            bufsize=1,
        )
    return _BATCH_PROC


def _shutdown_batch_proc():
    global _BATCH_PROC
    if _BATCH_PROC is not None:
        try:
            _BATCH_PROC.stdin.close()
        except Exception:
            pass
        try:
            _BATCH_PROC.wait(timeout=10)
        except Exception:
            _BATCH_PROC.kill()
        _BATCH_PROC = None


atexit.register(_shutdown_batch_proc)


def run_binary(binary, args):
    """Send one op to the persistent --batch co-process; parse key=value reply."""
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


def build_siggen_mode(tg, tc=None):
    """Determine the sigGen CLI mode name from test group and test case fields."""
    deterministic = tg.get("deterministic", False)
    sig_interface = tg.get("signatureInterface", "external")
    pre_hash = tg.get("preHash", "pure")
    # hashAlg can be at group level or test-case level
    hash_alg = tg.get("hashAlg", "")
    if not hash_alg and tc:
        hash_alg = tc.get("hashAlg", "")

    parts = ["sigGen"]
    if sig_interface == "internal":
        parts.append("Internal")
    if pre_hash == "preHash":
        if hash_alg == "SHAKE-256":
            parts.append("PreHashShake256")
        else:
            parts.append("PreHash")
    if deterministic:
        parts.append("Deterministic")

    return "".join(parts)


def build_sigver_mode(tg, tc=None):
    """Determine the sigVer CLI mode name from test group and test case fields."""
    sig_interface = tg.get("signatureInterface", "external")
    pre_hash = tg.get("preHash", "pure")
    hash_alg = tg.get("hashAlg", "")
    if not hash_alg and tc:
        hash_alg = tc.get("hashAlg", "")

    parts = ["sigVer"]
    if sig_interface == "internal":
        parts.append("Internal")
    if pre_hash == "preHash":
        if hash_alg == "SHAKE-256":
            parts.append("PreHashShake256")
        else:
            parts.append("PreHash")

    return "".join(parts)


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
        level = PARAM_SET_TO_LEVEL.get(param_set)
        if level is None:
            skipped += len(pg["tests"])
            continue

        prompt_tests = {t["tcId"]: t for t in pg["tests"]}
        expected_tests = {t["tcId"]: t for t in eg["tests"]}

        for tc_id, pt in prompt_tests.items():
            et = expected_tests.get(tc_id)
            if et is None:
                skipped += 1
                continue

            args = ["keyGen", f"level={level}", f"seed={pt['seed']}"]
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


def test_siggen(binary, prompt, expected):
    """Process sigGen test vectors (all variants)."""
    passed = failed = skipped = 0

    prompt_groups = {g["tgId"]: g for g in prompt["testGroups"]}
    expected_groups = {g["tgId"]: g for g in expected["testGroups"]}

    for tg_id, pg in prompt_groups.items():
        eg = expected_groups.get(tg_id)
        if eg is None:
            skipped += 1
            continue

        param_set = pg["parameterSet"]
        level = PARAM_SET_TO_LEVEL.get(param_set)
        if level is None:
            skipped += len(pg["tests"])
            continue

        deterministic = pg.get("deterministic", False)
        sig_interface = pg.get("signatureInterface", "external")
        pre_hash = pg.get("preHash", "pure")

        prompt_tests = {t["tcId"]: t for t in pg["tests"]}
        expected_tests = {t["tcId"]: t for t in eg["tests"]}

        for tc_id, pt in prompt_tests.items():
            et = expected_tests.get(tc_id)
            if et is None:
                skipped += 1
                continue

            mode_name = build_siggen_mode(pg, pt)
            args = [mode_name, f"level={level}"]

            # hashAlg can be at test-case or group level
            tc_hash_alg = pt.get("hashAlg", pg.get("hashAlg", ""))

            if sig_interface == "internal":
                # Internal: uses "mu" (externalMu=1) or "message" (externalMu=0)
                has_mu = "mu" in pt
                if has_mu:
                    args.append(f"message={pt['mu']}")
                    args.append(f"sk={pt['sk']}")
                    args.append("externalMu=1")
                else:
                    args.append(f"message={pt['message']}")
                    args.append(f"sk={pt['sk']}")
                    args.append("externalMu=0")
                if not deterministic:
                    args.append(f"rnd={pt['rnd']}")

            elif pre_hash == "preHash":
                # Pre-hash: ACVP sends raw message, binary hashes internally
                if tc_hash_alg == "SHAKE-256":
                    # PreHashShake256: pass raw message, binary does SHAKE-256
                    args.append(f"message={pt['message']}")
                else:
                    # PreHash: pass raw message as ph, binary hashes with hashAlg
                    args.append(f"ph={pt['message']}")
                    if tc_hash_alg:
                        args.append(f"hashAlg={tc_hash_alg}")
                args.append(f"sk={pt['sk']}")
                ctx = pt.get("context", "")
                args.append(f"context={ctx}")
                if not deterministic:
                    args.append(f"rnd={pt['rnd']}")

            else:
                # External pure
                args.append(f"message={pt['message']}")
                args.append(f"sk={pt['sk']}")
                ctx = pt.get("context", "")
                args.append(f"context={ctx}")
                if not deterministic:
                    args.append(f"rnd={pt['rnd']}")

            output = run_binary(binary, args)
            if output is None:
                failed += 1
                continue

            sig_match = output.get("signature", "").upper() == et["signature"].upper()
            if sig_match:
                passed += 1
            else:
                failed += 1
                print(f"FAIL {mode_name} tc={tc_id} {param_set}", file=sys.stderr)

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
        level = PARAM_SET_TO_LEVEL.get(param_set)
        if level is None:
            skipped += len(pg["tests"])
            continue

        sig_interface = pg.get("signatureInterface", "external")
        pre_hash = pg.get("preHash", "pure")

        prompt_tests = {t["tcId"]: t for t in pg["tests"]}
        expected_tests = {t["tcId"]: t for t in eg["tests"]}

        for tc_id, pt in prompt_tests.items():
            et = expected_tests.get(tc_id)
            if et is None:
                skipped += 1
                continue

            mode_name = build_sigver_mode(pg, pt)
            tc_hash_alg = pt.get("hashAlg", pg.get("hashAlg", ""))
            args = [mode_name, f"level={level}"]

            if sig_interface == "internal":
                has_mu = "mu" in pt
                if has_mu:
                    args.append(f"message={pt['mu']}")
                    args.append("externalMu=1")
                else:
                    args.append(f"message={pt['message']}")
                    args.append("externalMu=0")
                args.append(f"pk={pt['pk']}")
                args.append(f"signature={pt['signature']}")

            elif pre_hash == "preHash":
                # Pre-hash: ACVP sends raw message, binary hashes internally
                if tc_hash_alg == "SHAKE-256":
                    args.append(f"message={pt['message']}")
                else:
                    # Pass raw message as ph, binary hashes with hashAlg
                    args.append(f"ph={pt['message']}")
                    if tc_hash_alg:
                        args.append(f"hashAlg={tc_hash_alg}")
                args.append(f"pk={pt['pk']}")
                args.append(f"signature={pt['signature']}")
                ctx = pt.get("context", "")
                if ctx:
                    args.append(f"context={ctx}")

            else:
                args.append(f"message={pt['message']}")
                args.append(f"pk={pt['pk']}")
                args.append(f"signature={pt['signature']}")
                ctx = pt.get("context", "")
                if ctx:
                    args.append(f"context={ctx}")

            output = run_binary(binary, args)
            if output is None:
                failed += 1
                continue

            expected_pass = et.get("testPassed", True)
            actual_pass = output.get("testPassed", "0") == "1"

            if actual_pass == expected_pass:
                passed += 1
            else:
                failed += 1
                print(f"FAIL {mode_name} tc={tc_id} {param_set} "
                      f"(expected={expected_pass}, got={actual_pass})", file=sys.stderr)

    return passed, failed, skipped


def main():
    parser = argparse.ArgumentParser(description="ACVP ML-DSA Test Client")
    parser.add_argument("--binary", default=None)
    parser.add_argument("--version", default=DEFAULT_VERSION)
    parser.add_argument("-p", "--prompt", default=None)
    parser.add_argument("-e", "--expected", default=None)
    parser.add_argument("-o", "--output", default=None)
    args = parser.parse_args()

    binary = args.binary
    if binary is None:
        script_dir = Path(__file__).parent
        for build_name in ["build", "build-acvp"]:
            candidate = script_dir.parent / build_name / "acvp" / "qudo_acvp_mldsa"
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
            p, f, s = test_siggen(binary, prompt, expected)
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

            print(f"\n=== ML-DSA {mode} ===", file=sys.stderr)
            if mode == "keyGen":
                p, f, s = test_keygen(binary, prompt, expected)
            elif mode == "sigGen":
                p, f, s = test_siggen(binary, prompt, expected)
            else:
                p, f, s = test_sigver(binary, prompt, expected)

            print(f"  Passed: {p}  Failed: {f}  Skipped: {s}", file=sys.stderr)
            total_passed += p
            total_failed += f
            total_skipped += s

    print(f"\n=== ML-DSA ACVP Summary ===", file=sys.stderr)
    print(f"  Total Passed:  {total_passed}", file=sys.stderr)
    print(f"  Total Failed:  {total_failed}", file=sys.stderr)
    print(f"  Total Skipped: {total_skipped}", file=sys.stderr)

    sys.exit(0 if total_failed == 0 else 1)


if __name__ == "__main__":
    main()
