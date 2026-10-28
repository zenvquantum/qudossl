# Changelog

All notable changes to QudoSSL Community are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow
`<OpenSSL base>+qudo-<QudoSSL version>`.

The vendored PQC math library keeps its own history in
[qudo-pqc-lib/CHANGELOG.md](qudo-pqc-lib/CHANGELOG.md).

## [Unreleased]

### Added
- `demos/nginx/`: a working nginx example with post-quantum TLS 1.3, built
  from this repository with one Docker command.
- `demos/haproxy/`: the same for HAProxy 3.0 LTS, testing all three ML-KEM
  hybrid groups.
- Root `SECURITY.md`, `CONTRIBUTING.md`, `CODE_OF_CONDUCT.md`, and issue and
  pull-request templates.

### Changed
- `qudossl version` prints the product version only (`QudoSSL 1.0.0`);
  `openssl version -a` gives the full OpenSSL build details.
- The QudoSSL default, base, legacy and null providers report the QudoSSL
  version (`1.0.0`) in `openssl list -providers`, taken from the build
  metadata in `openssl/VERSION.dat`.
- Copyright and ownership are consolidated under ZenV Quantum.

### Fixed
- The `upstream-parity` CI check compares `openssl/` against upstream's release
  export of `openssl-3.5.7` (which omits submodules and `export-ignore` paths),
  and permits only the delegation seam, `Configure`, the version string and the
  provider names.

### Removed
- Documentation not relevant to the Community edition, from both the root
  `docs/` and `qudo-pqc-lib/docs/`.
- Legacy benchmark programs and an unused generator script in `qudo-pqc-lib/`.

### Security
- Known CRITICAL issues in the OpenSSL 3.5.7 base (CVE-2026-63073,
  CVE-2026-75803) are listed in `SECURITY.md`; both are fixed upstream in 3.5.8.

## [1.0.0] — 2026-10-08

First public source release: `3.5.7+qudo-1.0.0`.

### Added
- OpenSSL 3.5.7 with ML-KEM and ML-DSA math delegated to `qudo-pqc-lib`
  (math-only build, `QUDO_PQC_MATH_ONLY`), statically linked into the FIPS
  provider. Classical primitives and SLH-DSA remain upstream OpenSSL.
- TLS 1.3 hybrid post-quantum key exchange: X25519MLKEM768, SecP256r1MLKEM768,
  SecP384r1MLKEM1024.
- `qudossl` CLI, installed alongside an `openssl` name for drop-in use.
- Builds and CI on Linux x86-64, Linux aarch64, macOS arm64 and Windows x64.
- Boundary gates (`ci/check-*.sh`), a reproducible-build kit and a
  CycloneDX SBOM.
- Source distribution (`make dist`) with a SHA-256 checksum.

[Unreleased]: https://github.com/zenvquantum/qudossl/compare/qudossl-1.0.0...HEAD
[1.0.0]: https://github.com/zenvquantum/qudossl/releases/tag/qudossl-1.0.0
