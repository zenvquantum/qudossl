# QUDO ML-KEM Library

Production-grade ML-KEM key encapsulation (NIST FIPS 203) with runtime CPU dispatch.
Part of [QUDO PQC](../README.md).

## Security Levels

| Algorithm | NIST Level | Public Key | Secret Key | Ciphertext | Shared Secret |
|-----------|-----------|------------|------------|------------|---------------|
| ML-KEM-512 | Level 1 (~AES-128) | 800 B | 1,632 B | 768 B | 32 B |
| ML-KEM-768 | Level 3 (~AES-192) | 1,184 B | 2,400 B | 1,088 B | 32 B |
| ML-KEM-1024 | Level 5 (~AES-256) | 1,568 B | 3,168 B | 1,568 B | 32 B |

## Standalone Build

```bash
mkdir -p build && cd build
cmake -DCMAKE_BUILD_TYPE=Release ..
cmake --build . -j
```

## API Usage

**Object API:**
```c
QUDO_KEM *kem = QUDO_KEM_new("ML-KEM-768");
QUDO_KEM_keypair(kem, pk, sk);
QUDO_KEM_encaps(kem, ct, ss, pk);
QUDO_KEM_decaps(kem, ss, ct, sk);
QUDO_KEM_free(kem);
```

**Direct API:**
```c
QUDO_KEM_keypair_generate(QUDO_KEM_768, pk, sk);
QUDO_KEM_encapsulate(QUDO_KEM_768, ct, ss, pk);
QUDO_KEM_decapsulate(QUDO_KEM_768, ss, ct, sk);
```

## Documentation

- [Build and Install](../INSTALL.md) — full build instructions, all platforms
- [C API Reference](../docs/reference/API.md) — complete API documentation
- [Algorithms](../docs/reference/ALGORITHMS.md) — all algorithms and selection guide
- [Client-Server Examples](examples/README_CLIENT_SERVER.md) — network protocol docs

## License

Apache License 2.0 and MIT License. See [LICENSE](../LICENSE) for details.
