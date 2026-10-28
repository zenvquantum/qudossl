#!/bin/bash
# Point git at the tracked .githooks/ directory (pre-commit clang-format check).
# Usage: ./scripts/install-hooks.sh

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$REPO_ROOT"

if ! GIT_TOPLEVEL="$(git rev-parse --show-toplevel 2>/dev/null)"; then
    echo "error: $REPO_ROOT is not inside a git work tree" >&2
    exit 1
fi

if [ ! -d .githooks ]; then
    echo "error: .githooks/ directory not found" >&2
    exit 1
fi

HOOKS_PATH="$(git rev-parse --show-prefix).githooks"
git -C "$GIT_TOPLEVEL" config core.hooksPath "$HOOKS_PATH"
echo "Git hooks installed: core.hooksPath=$HOOKS_PATH"
echo "Pre-commit clang-format check is now active."
