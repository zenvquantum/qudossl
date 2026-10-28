# Security Policy

QudoSSL is maintained by ZenV Quantum.

## Reporting a Vulnerability

**Do not report security vulnerabilities through public GitHub issues.**

Send vulnerability reports to: **john@zenv.ai**

Please include the affected component (`openssl/` fork, the delegation seam, or
the vendored `qudo-pqc-lib/`), the QudoSSL version (`qudossl version`), steps to
reproduce, and your assessment of impact.

## Scope

- Defects introduced by QudoSSL: the ML-KEM / ML-DSA delegation seam in
  `openssl/`, the build wrapper, and the vendored `qudo-pqc-lib/` math.
- Upstream OpenSSL defects that are not specific to QudoSSL should also be
  reported to the OpenSSL project (`openssl-security@openssl.org`).

Report timelines and disclosure terms for the PQC math follow
[`qudo-pqc-lib/SECURITY.md`](qudo-pqc-lib/SECURITY.md).

## Known issues

QudoSSL 1.0.0 is based on OpenSSL 3.5.7. These CRITICAL vulnerabilities in that
base are fixed upstream in OpenSSL 3.5.8, and will be resolved when QudoSSL
moves its base to that release:

| CVE | Component | Fixed upstream in |
|---|---|---|
| CVE-2026-63073 | OpenSSL 3.5.7 | OpenSSL 3.5.8 |
| CVE-2026-75803 | OpenSSL 3.5.7 | OpenSSL 3.5.8 |

The `security-scan` workflow still reports both on every run. Any other
CRITICAL finding fails the build.
