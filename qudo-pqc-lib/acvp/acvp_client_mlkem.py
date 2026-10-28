#!/usr/bin/env python3
"""
ACVP Client for ML-KEM (FIPS 203)

Downloads NIST ACVP test vectors from usnistgov/ACVP-Server,
invokes qudo_acvp_mlkem binary, and validates results.

See: https://pages.nist.gov/ACVP/draft-celi-acvp-ml-kem.html

Usage:
    python3 acvp_client_mlkem.py [--binary PATH] [--version VER]
    python3 acvp_client_mlkem.py -p prompt.json -e expected.json
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
        "prompt": "ML-KEM-keyGen-FIPS203/prompt.json",
        "expected": "ML-KEM-keyGen-FIPS203/expectedResults.json",
    },
    "encapDecap": {
        "prompt": "ML-KEM-encapDecap-FIPS203/prompt.json",
        "expected": "ML-KEM-encapDecap-FIPS203/expectedResults.json",
    },
}

# Map ACVP parameter set names to our level integers
PARAM_SET_TO_LEVEL = {
    "ML-KEM-512": 512,
    "ML-KEM-768": 768,
    "ML-KEM-1024": 1024,
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


def test_keygen(binary, prompt, expected):
    """Process keyGen test vectors."""
    passed = 0
    failed = 0
    skipped = 0

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
            print(f"Unsupported parameter set: {param_set}", file=sys.stderr)
            skipped += len(pg["tests"])
            continue

        prompt_tests = {t["tcId"]: t for t in pg["tests"]}
        expected_tests = {t["tcId"]: t for t in eg["tests"]}

        for tc_id, pt in prompt_tests.items():
            et = expected_tests.get(tc_id)
            if et is None:
                skipped += 1
                continue

            args = [
                "keyGen", "AFT",
                f"level={level}",
                f"d={pt['d']}",
                f"z={pt['z']}",
            ]
            output = run_binary(binary, args)
            if output is None:
                failed += 1
                continue

            ek_match = output.get("ek", "").upper() == et["ek"].upper()
            dk_match = output.get("dk", "").upper() == et["dk"].upper()

            if ek_match and dk_match:
                passed += 1
            else:
                failed += 1
                print(f"FAIL keyGen tc={tc_id} {param_set}", file=sys.stderr)
                if not ek_match:
                    print(f"  ek mismatch", file=sys.stderr)
                if not dk_match:
                    print(f"  dk mismatch", file=sys.stderr)

    return passed, failed, skipped


def test_encap_decap(binary, prompt, expected):
    """Process encapDecap test vectors."""
    passed = 0
    failed = 0
    skipped = 0

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

        test_type = pg["testType"]
        function = pg.get("function", "")

        prompt_tests = {t["tcId"]: t for t in pg["tests"]}
        expected_tests = {t["tcId"]: t for t in eg["tests"]}

        for tc_id, pt in prompt_tests.items():
            et = expected_tests.get(tc_id)
            if et is None:
                skipped += 1
                continue

            if function == "encapsulation":
                args = [
                    "encapDecap", test_type, "encapsulation",
                    f"level={level}",
                    f"ek={pt['ek']}",
                    f"m={pt['m']}",
                ]
                output = run_binary(binary, args)
                if output is None:
                    failed += 1
                    continue

                c_match = output.get("c", "").upper() == et["c"].upper()
                k_match = output.get("k", "").upper() == et["k"].upper()
                if c_match and k_match:
                    passed += 1
                else:
                    failed += 1
                    print(f"FAIL encaps tc={tc_id} {param_set}", file=sys.stderr)

            elif function == "decapsulation":
                args = [
                    "encapDecap", test_type, "decapsulation",
                    f"level={level}",
                    f"dk={pt['dk']}",
                    f"c={pt['c']}",
                ]
                output = run_binary(binary, args)
                if output is None:
                    failed += 1
                    continue

                k_match = output.get("k", "").upper() == et["k"].upper()
                if k_match:
                    passed += 1
                else:
                    failed += 1
                    print(f"FAIL decaps tc={tc_id} {param_set}", file=sys.stderr)

            elif function == "encapsulationKeyCheck":
                args = [
                    "encapDecap", test_type, "encapsulationKeyCheck",
                    f"level={level}",
                    f"ek={pt['ek']}",
                ]
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
                    print(f"FAIL ekCheck tc={tc_id} {param_set} "
                          f"(expected={expected_pass}, got={actual_pass})",
                          file=sys.stderr)

            elif function == "decapsulationKeyCheck":
                args = [
                    "encapDecap", test_type, "decapsulationKeyCheck",
                    f"level={level}",
                    f"dk={pt['dk']}",
                ]
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
                    print(f"FAIL dkCheck tc={tc_id} {param_set} "
                          f"(expected={expected_pass}, got={actual_pass})",
                          file=sys.stderr)

            else:
                skipped += 1

    return passed, failed, skipped


def main():
    parser = argparse.ArgumentParser(description="ACVP ML-KEM Test Client")
    parser.add_argument("--binary", default=None,
                        help="Path to qudo_acvp_mlkem binary")
    parser.add_argument("--version", default=DEFAULT_VERSION,
                        help=f"ACVP Server version (default: {DEFAULT_VERSION})")
    parser.add_argument("-p", "--prompt", default=None,
                        help="Path to prompt JSON (skips download)")
    parser.add_argument("-e", "--expected", default=None,
                        help="Path to expected results JSON")
    parser.add_argument("-o", "--output", default=None,
                        help="Write results JSON to file")
    args = parser.parse_args()

    # Find binary
    binary = args.binary
    if binary is None:
        script_dir = Path(__file__).parent
        build_dir = script_dir.parent / "build" / "acvp"
        binary = str(build_dir / "qudo_acvp_mlkem")
        if not Path(binary).exists():
            build_dir = script_dir.parent / "build-acvp" / "acvp"
            binary = str(build_dir / "qudo_acvp_mlkem")
    if not Path(binary).exists():
        print(f"Binary not found: {binary}", file=sys.stderr)
        print("Build with: ./build.sh --acvp", file=sys.stderr)
        sys.exit(1)

    total_passed = 0
    total_failed = 0
    total_skipped = 0

    if args.prompt and args.expected:
        # Use local files
        prompt = load_json(args.prompt)
        expected = load_json(args.expected)
        mode = prompt.get("mode", prompt.get("algorithm", ""))
        if "keyGen" in mode or "keyGen" in args.prompt:
            p, f, s = test_keygen(binary, prompt, expected)
        else:
            p, f, s = test_encap_decap(binary, prompt, expected)
        total_passed += p
        total_failed += f
        total_skipped += s
    else:
        # Download and run all
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

            print(f"\n=== ML-KEM {mode} ===", file=sys.stderr)
            if mode == "keyGen":
                p, f, s = test_keygen(binary, prompt, expected)
            else:
                p, f, s = test_encap_decap(binary, prompt, expected)

            print(f"  Passed: {p}  Failed: {f}  Skipped: {s}", file=sys.stderr)
            total_passed += p
            total_failed += f
            total_skipped += s

    print(f"\n=== ML-KEM ACVP Summary ===", file=sys.stderr)
    print(f"  Total Passed:  {total_passed}", file=sys.stderr)
    print(f"  Total Failed:  {total_failed}", file=sys.stderr)
    print(f"  Total Skipped: {total_skipped}", file=sys.stderr)

    sys.exit(0 if total_failed == 0 else 1)


if __name__ == "__main__":
    main()
