# Algorithms

QUDO PQC implements 18 NIST-standardized post-quantum parameter sets across
three algorithm families.

**NIST security categories** are defined by the strength of the search/collision problem an attacker must solve:

- **Cat 1** — comparable to brute-force key search on AES-128
- **Cat 2** — comparable to collision search on SHA-256
- **Cat 3** — comparable to brute-force key search on AES-192
- **Cat 5** — comparable to brute-force key search on AES-256

These are *strength benchmarks*; the PQC algorithms do not use AES or SHA-256 internally for their security. No parameter set here targets Category 4.

## ML-KEM (FIPS 203) — Key Encapsulation

| Parameter Set | NIST Category | Public Key | Secret Key | Ciphertext | Shared Secret |
| ------------- | ------------- | ---------- | ---------- | ---------- | ------------- |
| ML-KEM-512    | 1             | 800 B      | 1,632 B    | 768 B      | 32 B          |
| ML-KEM-768    | 3             | 1,184 B    | 2,400 B    | 1,088 B    | 32 B          |
| ML-KEM-1024   | 5             | 1,568 B    | 3,168 B    | 1,568 B    | 32 B          |

**Use ML-KEM-768** for most applications (Cat 3 — balances security and performance).

## ML-DSA (FIPS 204) — Digital Signatures

| Parameter Set | NIST Category | Public Key | Secret Key | Signature |
| ------------- | ------------- | ---------- | ---------- | --------- |
| ML-DSA-44     | 2             | 1,312 B    | 2,560 B    | 2,420 B   |
| ML-DSA-65     | 3             | 1,952 B    | 4,032 B    | 3,309 B   |
| ML-DSA-87     | 5             | 2,592 B    | 4,896 B    | 4,627 B   |

**Use ML-DSA-65** for most applications (Cat 3).

## SLH-DSA (FIPS 205) — Stateless Hash-Based Signatures

Two hash families (SHA2 and SHAKE) and two speed/size tradeoffs (`s` = small signatures, slow signing; `f` = fast signing, large signatures):

| Parameter Set       | NIST Category | Public Key | Secret Key | Signature | Signing Speed |
| ------------------- | ------------- | ---------- | ---------- | --------- | ------------- |
| SLH-DSA-SHA2-128s   | 1             | 32 B       | 64 B       | 7,856 B   | Slow          |
| SLH-DSA-SHA2-128f   | 1             | 32 B       | 64 B       | 17,088 B  | Fast          |
| SLH-DSA-SHA2-192s   | 3             | 48 B       | 96 B       | 16,224 B  | Slow          |
| SLH-DSA-SHA2-192f   | 3             | 48 B       | 96 B       | 35,664 B  | Fast          |
| SLH-DSA-SHA2-256s   | 5             | 64 B       | 128 B      | 29,792 B  | Slow          |
| SLH-DSA-SHA2-256f   | 5             | 64 B       | 128 B      | 49,856 B  | Fast          |
| SLH-DSA-SHAKE-128s  | 1             | 32 B       | 64 B       | 7,856 B   | Slow          |
| SLH-DSA-SHAKE-128f  | 1             | 32 B       | 64 B       | 17,088 B  | Fast          |
| SLH-DSA-SHAKE-192s  | 3             | 48 B       | 96 B       | 16,224 B  | Slow          |
| SLH-DSA-SHAKE-192f  | 3             | 48 B       | 96 B       | 35,664 B  | Fast          |
| SLH-DSA-SHAKE-256s  | 5             | 64 B       | 128 B      | 29,792 B  | Slow          |
| SLH-DSA-SHAKE-256f  | 5             | 64 B       | 128 B      | 49,856 B  | Fast          |

**Choosing between s and f variants**:
- `s` (small) — smaller signatures, slower signing. Use when bandwidth matters.
- `f` (fast) — larger signatures, faster signing. Use when speed matters.

**Choosing between SHA2 and SHAKE**:
- SHA2 — faster on platforms with SHA-NI instructions (x86_64 with SHA extensions).
- SHAKE — faster on platforms with dedicated Keccak hardware or NEON.

**Use SLH-DSA-SHA2-128f** for general use. Use SLH-DSA when you want a conservative
assumption (hash-based security) as a backup to lattice-based ML-DSA.

## Which Algorithm to Choose

| Use Case | Recommendation |
|----------|---------------|
| Key exchange / TLS | ML-KEM-768 |
| Code signing / certificates | ML-DSA-65 |
| Long-term archive signatures | SLH-DSA-SHA2-128s (conservative) |
| Embedded / IoT | ML-KEM-512 + ML-DSA-44 (smallest keys) |
| Maximum security | ML-KEM-1024 + ML-DSA-87 |

## Standardization Status

NIST-standardized algorithms (FIPS 203/204/205). This library is not FIPS
140-3 validated.

- ML-KEM: FIPS 203
- ML-DSA: FIPS 204 (including the pre-hash variant, HashML-DSA)
- SLH-DSA: FIPS 205

Query at runtime: `qudo_pqc_is_fips_approved("ML-KEM-768")` returns 1. The
name list it checks covers the 18 parameter sets above plus the three
HashML-DSA names (`HashML-DSA-44`, `HashML-DSA-65`, `HashML-DSA-87`); matching
is case-insensitive.
