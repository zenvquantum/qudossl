# qudo-mldsa Examples

## Building

Examples are built automatically when `BUILD_EXAMPLES=ON` (default):

```bash
cd qudo-mldsa && mkdir -p build && cd build
cmake -DCMAKE_BUILD_TYPE=Release ..
cmake --build . -j
```

Binaries are placed in `build/examples/`.

## Examples

| Example | Description |
|---------|-------------|
| `deterministic_keygen` | Deterministic keypair generation from a fixed 32-byte seed using `QUDO_MLDSA_keypair_internal()`. Useful for testing, key derivation, and KAT reproduction. |
| `deterministic_sign` | Deterministic signature generation with fixed randomness using `QUDO_MLDSA_sign_internal()`. Produces reproducible signatures for testing and validation. |
| `prehash_sha256` | HashML-DSA with SHA2-256 pre-hash using `QUDO_MLDSA_sign_pre_hash_internal()`. Demonstrates signing pre-hashed messages for large file or streaming scenarios. |
| `external_mu` | External mu (pre-computed hash) signing and verification. Demonstrates custom hash construction and integration with external hash computation. |
| `concat_format` | Concatenated signature format (`sig\|\|msg`) using `sign_concat()` and `open()`. Single-blob transmission of signed messages. |
| `context_signature` | FIPS 204 context string feature for domain separation. Demonstrates binding signatures to specific application contexts. |
| `speed_mldsa` | Performance benchmark measuring keygen, sign, and verify across all ML-DSA security levels (44, 65, 87). |

## Quick Start

```bash
# Basic sign/verify with context strings
./build/examples/context_signature

# Deterministic operations
./build/examples/deterministic_keygen
./build/examples/deterministic_sign

# Performance benchmarks
./build/examples/speed_mldsa
```
