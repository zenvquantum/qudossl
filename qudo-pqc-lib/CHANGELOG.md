# Changelog

All notable changes to the QUDO PQC Software project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] - 2026-02-17

### Added

- **qudo-mlkem**: ML-KEM key encapsulation library (FIPS 203)
  - Pure KEM: ML-KEM-512, ML-KEM-768, ML-KEM-1024
  - Object API (`QUDO_KEM_new`) and Direct API (`QUDO_KEM_keypair_generate`)
  - DER/PEM serialization (X.509 SubjectPublicKeyInfo, PKCS#8 PrivateKeyInfo)
  - Runtime CPU dispatch (reference C, AVX2, NEON)
  - Known Answer Tests (KAT) and NIST test vectors
  - `QUDO_KEM_keypair_derand()` takes a trailing `size_t seed_out_len`
    parameter giving the capacity of the `seed_out` buffer; writes to
    `seed_out` are bounded by it

- **qudo-mldsa**: ML-DSA digital signature library (FIPS 204)
  - Signature algorithms: ML-DSA-44, ML-DSA-65, ML-DSA-87
  - Object API (`QUDO_MLDSA_new`) and Direct API
  - DER/PEM serialization
  - Runtime CPU dispatch (reference C, AVX2, NEON)
  - Known Answer Tests (KAT) and NIST test vectors
  - Constant-time operation verification
  - `QUDO_MLDSA_sign` / `QUDO_MLDSA_sign_with_context` check
    `*signature_len >= sig->length_signature` before dispatch;
    `QUDO_MLDSA_verify` / `QUDO_MLDSA_verify_with_context` reject
    `signature_len != sig->length_signature` with
    `QUDO_MLDSA_ERROR_INVALID_SIGNATURE`

- **qudo-slhdsa**: SLH-DSA stateless hash-based signature library (FIPS 205)
  - All 12 parameter sets:
    - SLH-DSA-SHA2-128s, SLH-DSA-SHA2-128f
    - SLH-DSA-SHA2-192s, SLH-DSA-SHA2-192f
    - SLH-DSA-SHA2-256s, SLH-DSA-SHA2-256f
    - SLH-DSA-SHAKE-128s, SLH-DSA-SHAKE-128f
    - SLH-DSA-SHAKE-192s, SLH-DSA-SHAKE-192f
    - SLH-DSA-SHAKE-256s, SLH-DSA-SHAKE-256f
  - Object API (`QUDO_SLHDSA_new`) and Direct API
  - Context string support
  - DER/PEM serialization
  - Extended signing API (`QUDO_SLHDSA_sign_ex`) with deterministic/hedged/test-entropy modes (FIPS 205)
  - Size-query pattern on all sign entry points (`QUDO_SLHDSA_sign_ex`,
    `QUDO_SLHDSA_sign_internal`, `QUDO_SLHDSA_sign_pre_hash` and the internal
    variants): `signature == NULL` returns the required capacity; otherwise
    `*signature_len >= expected` is checked before any native dispatch and the
    caller buffer is zero-initialized before signing

- **Vendored upstreams**: `mlkem-native` at upstream `183f2809` and
  `mldsa-native` at upstream `93a4fc74`, including AVX2 assembly for
  compression/Keccak (x86_64 Keccak x4 is AVX2 assembly,
  `fips202/native/x86_64/src/*.S`, built by `qudo-mldsa/CMakeLists.txt`) and
  HOL Light proof coverage (mlkem-native: all x86_64/aarch64 assembly;
  mldsa-native: partial, see upstream
  [SOUNDNESS.md](https://github.com/pq-code-package/mldsa-native/blob/main/SOUNDNESS.md)). ML-DSA `mld_sign` returns
  `smlen = 0` on failure.

- **Internal DRBG**: Standalone builds use the internal AES-256-CTR-DRBG
  (SP 800-90A) by default; math-only builds contain no DRBG, and
  `QUDO_PQC_USE_HOST_DRBG` routes randomness to a host RNG. No external crypto
  dependencies.

- **DRBG enforcement**: Compile-time `#error` guards prevent conflicting RNG
  paths. Runtime `qudo_fips_rand_is_ready()` check before every crypto operation.

- **Audit/Logging Framework**: Structured event logging for all security-relevant
  operations (POST, PCT, DRBG, state transitions). `qudo_pqc_audit.h` with
  `qudo_audit_cb` callback and 32 categorized error codes in `qudo_pqc_err.h`.

- **Per-Operation FIPS Indicator**: `qudo_fips_ind_t` embedded in all algorithm
  contexts. Tracks approved/unapproved status per operation with strict/tolerant
  modes. `qudo_fips_ind_check_operation()` combines module state, algorithm
  approval, and DRBG readiness. `QUDO_FIPS_IND_CHECK` also covers
  `QUDO_KEM_keypair_derand`, `QUDO_KEM_keypair_from_seed`,
  `QUDO_MLDSA_keypair_internal` and `QUDO_SLHDSA_keypair_internal`.

- **Security Level Enforcement**: `qudo_pqc_set_min_security_level()` with
  algorithm-to-NIST-level mapping for all 18 parameter sets.

- **CAST On-Demand**: `qudo_pqc_run_all_casts()` executes keygen + PCT per
  algorithm family.

- **CMake Package Config**: `find_package(qudo-pqc)` support with
  `qudo-pqc-config.cmake` and version compatibility.

- Project governance files (LICENSE, CONTRIBUTING, SECURITY, CODE_OF_CONDUCT)
- GitHub issue and pull request templates
- SPDX license headers on all source files
