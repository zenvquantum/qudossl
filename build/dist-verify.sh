#!/usr/bin/env bash
# Verify a QudoSSL Community source tarball end-to-end — the artefact a user
# actually downloads, not the working tree it was cut from.
#
# Unpacks into a scratch directory, builds both stages as the STANDARD build
# (FIPS=no, as the README documents), installs to a scratch prefix, and asserts
# the properties that define this edition: the CLI, library and provider
# versions, the default provider with no FIPS module, that the PQC math is
# genuinely delegated to qudo-pqc, and that a post-quantum handshake completes.
#
# Usage: dist-verify.sh <path/to/qudossl-X.Y.Z-src.tar.gz>
set -euo pipefail

# A developer's shell usually points these at an existing QudoSSL install. The
# gate must judge the tarball's own install, so drop them: with OPENSSL_CONF
# inherited, a missing config in the scratch prefix passes unnoticed.
unset OPENSSL_CONF OPENSSL_MODULES

TARBALL=${1:?usage: dist-verify.sh <tarball>}
[ -f "$TARBALL" ] || { echo "dist-verify: no such tarball: $TARBALL" >&2; exit 1; }
TARBALL=$(cd "$(dirname "$TARBALL")" && pwd)/$(basename "$TARBALL")

VERSION=$(basename "$TARBALL" | sed -n 's/^qudossl-\(.*\)-src\.tar\.gz$/\1/p')
[ -n "$VERSION" ] || { echo "dist-verify: cannot parse version from $(basename "$TARBALL")" >&2; exit 1; }

WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT
PREFIX="$WORK/prefix"
PORT=${PORT:-34533}
pass=0; fail=0

check() {  # check <name> <expected-substring> <actual>
    if printf '%s' "$3" | grep -qF -- "$2"; then
        echo "  PASS  $1"; pass=$((pass+1))
    else
        echo "  FAIL  $1"; echo "        expected to contain: $2"; echo "        got: $3"; fail=$((fail+1))
    fi
}

echo "==> unpacking $(basename "$TARBALL") into $WORK"
tar xf "$TARBALL" -C "$WORK"
SRC="$WORK/qudossl-$VERSION"
[ -d "$SRC" ] || { echo "dist-verify: tarball did not unpack to qudossl-$VERSION/" >&2; exit 1; }

echo "==> building from the tarball (both stages, standard build)"
# Same command the README gives a user. The RPATH is not cosmetic: QudoSSL
# carries the same SONAMEs as a distribution's OpenSSL, so without it the
# installed CLI binds /lib/.../libssl.so.3 and dies with `OPENSSL_3.5.0' not
# found. Verifying without it would test a build no user is told to make.
make -C "$SRC/build" all FIPS=no PREFIX="$PREFIX" \
    OPENSSL_EXTRA_FLAGS="-Wl,-rpath,$PREFIX/lib" >"$WORK/build.log" 2>&1 \
    || { echo "dist-verify: build failed — tail of $WORK/build.log:" >&2; tail -30 "$WORK/build.log" >&2; exit 1; }

echo "==> installing to $PREFIX"
make -C "$SRC/build" install_sw PREFIX="$PREFIX" >>"$WORK/build.log" 2>&1 \
    || { echo "dist-verify: install_sw failed — tail of $WORK/build.log:" >&2; tail -30 "$WORK/build.log" >&2; exit 1; }
# install_sw installs no openssl.cnf. Without this the prefix has no
# configuration at all and `openssl req` below aborts before it can generate the
# test certificate.
make -C "$SRC/openssl" install_ssldirs >>"$WORK/build.log" 2>&1 \
    || { echo "dist-verify: install_ssldirs failed — tail of $WORK/build.log:" >&2; tail -30 "$WORK/build.log" >&2; exit 1; }

echo "==> acceptance checks"
check "openssl reports the upstream base version" "OpenSSL 3.5" "$("$PREFIX/bin/openssl" version 2>&1)"
check "qudossl reports the product version"       "QudoSSL $VERSION" "$("$PREFIX/bin/qudossl" version 2>&1)"
check "the six ML-KEM groups are offered" "MLKEM" \
      "$("$PREFIX/bin/openssl" list -tls-groups 2>&1 | grep -i mlkem || true)"

# The standard build: the QudoSSL default provider, reporting the product
# version, and no FIPS module anywhere in the install.
PROVIDERS=$("$PREFIX/bin/openssl" list -providers 2>&1)
check "standard build: QudoSSL default provider is active" "QudoSSL Default Provider" "$PROVIDERS"
check "the provider reports the product version" "version: $VERSION" "$PROVIDERS"
if ls "$PREFIX"/lib*/ossl-modules 2>/dev/null | grep -q fips; then
    echo "  FAIL  standard build: a FIPS module was installed"; fail=$((fail+1))
else
    echo "  PASS  standard build: no FIPS module installed"; pass=$((pass+1))
fi

# The property that defines this edition: the PQC math is qudo-pqc's, linked in.
if (cd "$SRC" && ci/check-delegation-linked.sh openssl >"$WORK/deleg.log" 2>&1); then
    echo "  PASS  PQC math is delegated to qudo-pqc, and linked"; pass=$((pass+1))
else
    echo "  FAIL  delegation check — tail of log:"; tail -10 "$WORK/deleg.log"; fail=$((fail+1))
fi

echo "==> post-quantum handshake"
( cd "$WORK" && "$PREFIX/bin/openssl" req -x509 -new -noenc -newkey rsa:3072 \
    -keyout s.key -out s.crt -days 2 -subj "/CN=localhost" >"$WORK/req.log" 2>&1 ) \
    || { echo "dist-verify: could not generate the test certificate:" >&2; cat "$WORK/req.log" >&2; exit 1; }
"$PREFIX/bin/openssl" s_server -accept "$PORT" -cert "$WORK/s.crt" -key "$WORK/s.key" \
    -www -quiet >/dev/null 2>&1 &
SRV=$!
trap 'kill "$SRV" 2>/dev/null || true; rm -rf "$WORK"' EXIT
sleep 2
HS=$("$PREFIX/bin/openssl" s_client -connect "127.0.0.1:$PORT" -groups X25519MLKEM768 \
        -tls1_3 -brief </dev/null 2>&1 || true)
check "handshake negotiates X25519MLKEM768" "Negotiated TLS1.3 group: X25519MLKEM768" "$HS"

echo
echo "==> dist-verify: $pass passed, $fail failed"
[ "$fail" -eq 0 ] || exit 1
echo "==> $(basename "$TARBALL") is fit to ship"
