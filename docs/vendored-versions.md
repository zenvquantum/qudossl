# Vendored versions

QudoSSL includes two source trees, at the following versions.

| Directory | Upstream | Version | Commit |
|---|---|---|---|
| `openssl/` | github.com/openssl/openssl | tag `openssl-3.5.7` | `8cf17aaeb4599f8af87fefd810b5b5fee90fe69e` |
| `qudo-pqc-lib/` | ZenV Quantum | `v1.0.0` | — |

`qudo-pqc-lib/` in turn vendors:

| Directory | Upstream | Commit |
|---|---|---|
| `qudo-pqc-lib/qudo-mlkem/mlkem-native/` | github.com/pq-code-package/mlkem-native | `183f2809` (main) |
| `qudo-pqc-lib/qudo-mldsa/mldsa-native/` | github.com/pq-code-package/mldsa-native | `93a4fc74` (main) |
| `qudo-pqc-lib/qudo-slhdsa/slhdsa-native/` | slhdsa-c | — |

Their licences are listed in `qudo-pqc-lib/THIRD_PARTY_NOTICES.md`.

`openssl/` is upstream `openssl-3.5.7` plus the QudoSSL changes to
`crypto/ml_kem/`, `crypto/ml_dsa/`, `include/crypto/ml_dsa.h`, `Configure`,
`VERSION.dat` and the provider name strings in `providers/{base,deflt,legacy,null}prov.c`. Everything else is byte-identical to the upstream tag; CI checks
this.

## Requirements

**`openssl-3.5.7`** is a released tag of the OpenSSL 3.5 LTS line.

**qudo-pqc-lib `v1.0.0`** or later is required. It provides:

- **`QUDO_PQC_MATH_ONLY`** — excludes qudo-pqc-lib's own self-tests, integrity
  check, CTR-DRBG, AES and HMAC from the archive, so OpenSSL provides those
  services. ML-KEM cannot be constructed without it.
- **No platform entropy source** under math-only, so `getentropy` /
  `BCryptGenRandom` / `arc4random` are not linked into the FIPS module.
  `ci/check-boundary-symbols.sh` asserts this.
- The standalone test suite is skipped in math-only builds.
