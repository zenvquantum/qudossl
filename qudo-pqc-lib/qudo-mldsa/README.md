# QUDO ML-DSA Library

Production-grade ML-DSA digital signatures (NIST FIPS 204) with runtime CPU dispatch.
Part of [QUDO PQC](../README.md).

## Security Levels

| Algorithm | NIST Level | Public Key | Secret Key | Signature | Security |
|-----------|-----------|------------|------------|-----------|----------|
| ML-DSA-44 | Level 2 | 1,312 B | 2,560 B | 2,420 B | ~SHA-256 collision |
| ML-DSA-65 | Level 3 | 1,952 B | 4,032 B | 3,309 B | ~AES-192 |
| ML-DSA-87 | Level 5 | 2,592 B | 4,896 B | 4,627 B | ~AES-256 |

ML-DSA-65 is recommended for most applications.

## Standalone Build

```bash
mkdir -p build && cd build
cmake -DCMAKE_BUILD_TYPE=Release ..
cmake --build . -j
```

## API Usage

**Object API:**
```c
QUDO_MLDSA *sig = QUDO_MLDSA_new("ML-DSA-65");
QUDO_MLDSA_keypair(sig, pk, sk);
QUDO_MLDSA_sign(sig, signature, &sig_len, msg, msg_len, sk);
QUDO_MLDSA_verify(sig, signature, sig_len, msg, msg_len, pk);
QUDO_MLDSA_free(sig);
```

**Direct API:**
```c
QUDO_MLDSA_ML_DSA_65_keypair(pk, sk);
QUDO_MLDSA_ML_DSA_65_sign(signature, &sig_len, msg, msg_len, sk);
QUDO_MLDSA_ML_DSA_65_verify(signature, sig_len, msg, msg_len, pk);
```

## Documentation

- [Build and Install](../INSTALL.md) — full build instructions, all platforms
- [C API Reference](../docs/reference/API.md) — complete API documentation
- [Algorithms](../docs/reference/ALGORITHMS.md) — all algorithms and selection guide

## License

Apache License 2.0 and MIT License. See [LICENSE](../LICENSE) for details.
