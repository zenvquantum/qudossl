#!/usr/bin/env bash
#
# Build QudoSSL twice from a clean tree and compare artifact hashes.
#
# Covers libcrypto / libssl / libqudo-pqc.a and, in a FIPS build, the FIPS
# module.
#
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORK="${REPRO_WORKDIR:-$(mktemp -d)}"
KEEP="${REPRO_KEEP:-0}"

ARTIFACTS=(
    "qudo-pqc-lib/build/lib/libqudo-pqc.a"
    "openssl/libcrypto.a"
    "openssl/libssl.a"
)

# The FIPS module's extension is platform-dependent.
case "$(uname -s)" in
    Darwin) ARTIFACTS+=("openssl/providers/fips.dylib") ;;
    Linux)  ARTIFACTS+=("openssl/providers/fips.so") ;;
esac

hash_artifacts() {
    local root="$1" out="$2"
    : > "${out}"
    for rel in "${ARTIFACTS[@]}"; do
        if [ -f "${root}/${rel}" ]; then
            if command -v sha256sum >/dev/null; then
                printf '%s  %s\n' "$(sha256sum "${root}/${rel}" | cut -d' ' -f1)" "${rel}" >> "${out}"
            else
                printf '%s  %s\n' "$(shasum -a 256 "${root}/${rel}" | cut -d' ' -f1)" "${rel}" >> "${out}"
            fi
        else
            # A missing artifact is an error, not a matching entry.
            echo "error: expected artifact not produced: ${root}/${rel}" >&2
            return 1
        fi
    done
}

# Both builds use the same absolute path: the compiler-flag string, including
# -ffile-prefix-map=<checkout path>=., is embedded in libcrypto via buildinf.h.
BUILD_PATH="${WORK}/src"

build_once() {
    local label="$1"
    echo "==> clean checkout -> ${BUILD_PATH} (build ${label})"
    rm -rf "${BUILD_PATH}"
    git -C "${REPO_ROOT}" worktree prune >/dev/null 2>&1 || true
    git -C "${REPO_ROOT}" worktree add --detach "${BUILD_PATH}" HEAD >/dev/null 2>&1 \
        || { mkdir -p "${BUILD_PATH}"; tar -C "${REPO_ROOT}" --exclude=.git -cf - . | tar -C "${BUILD_PATH}" -xf -; }
    make -C "${BUILD_PATH}/build" all
}

echo "workdir: ${WORK}"

build_once A
hash_artifacts "${BUILD_PATH}" "${WORK}/a.sha" || { echo "FAIL: build A did not produce all artifacts" >&2; exit 1; }

build_once B
hash_artifacts "${BUILD_PATH}" "${WORK}/b.sha" || { echo "FAIL: build B did not produce all artifacts" >&2; exit 1; }

echo
echo "=== build A ==="; cat "${WORK}/a.sha"
echo "=== build B ==="; cat "${WORK}/b.sha"
echo

if diff -u "${WORK}/a.sha" "${WORK}/b.sha"; then
    echo "PASS: builds are byte-identical"
    rc=0
else
    echo "FAIL: builds differ -- see the diff above" >&2
    rc=1
fi

if [ "${KEEP}" != "1" ]; then
    git -C "${REPO_ROOT}" worktree remove --force "${BUILD_PATH}" 2>/dev/null || true
    git -C "${REPO_ROOT}" worktree prune >/dev/null 2>&1 || true
    rm -rf "${WORK}"
fi
exit ${rc}
