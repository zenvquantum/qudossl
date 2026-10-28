# QUDO SLH-DSA Library

Production-grade SLH-DSA stateless hash-based signatures (NIST FIPS 205).
Part of [QUDO PQC](../README.md).

## Parameter Sets

| Parameter Set | Security Level | Signature | Public Key | Secret Key |
|--------------|---------------|-----------|------------|------------|
| SLH-DSA-SHA2-128s | 1 | 7,856 B | 32 B | 64 B |
| SLH-DSA-SHA2-128f | 1 | 17,088 B | 32 B | 64 B |
| SLH-DSA-SHA2-192s | 3 | 16,224 B | 48 B | 96 B |
| SLH-DSA-SHA2-192f | 3 | 35,664 B | 48 B | 96 B |
| SLH-DSA-SHA2-256s | 5 | 29,792 B | 64 B | 128 B |
| SLH-DSA-SHA2-256f | 5 | 49,856 B | 64 B | 128 B |
| SLH-DSA-SHAKE-128s | 1 | 7,856 B | 32 B | 64 B |
| SLH-DSA-SHAKE-128f | 1 | 17,088 B | 32 B | 64 B |
| SLH-DSA-SHAKE-192s | 3 | 16,224 B | 48 B | 96 B |
| SLH-DSA-SHAKE-192f | 3 | 35,664 B | 48 B | 96 B |
| SLH-DSA-SHAKE-256s | 5 | 29,792 B | 64 B | 128 B |
| SLH-DSA-SHAKE-256f | 5 | 49,856 B | 64 B | 128 B |

"small" (s) = smaller signatures, slower. "fast" (f) = faster, larger signatures.

## Standalone Build

```bash
mkdir -p build && cd build
cmake -DCMAKE_BUILD_TYPE=Release ..
cmake --build . -j
```

## API Usage

**Object API** (runtime parameter-set selection by name):
```c
QUDO_SLHDSA *sig = QUDO_SLHDSA_new("SLH-DSA-SHA2-128f");
uint8_t pk[32], sk[64], signature[17088];
size_t sig_len = sizeof(signature);
const uint8_t msg[] = "message to sign";
size_t msg_len = sizeof(msg) - 1;

QUDO_SLHDSA_keypair(sig, pk, sk);
QUDO_SLHDSA_sign(sig, signature, &sig_len, msg, msg_len, sk);
int valid = (QUDO_SLHDSA_verify(sig, msg, msg_len, signature, sig_len, pk) == 0);

QUDO_SLHDSA_free(sig);
```

**Direct API (SLH-DSA-SHA2-128s):**
```c
uint8_t pk[32], sk[64], signature[7856];
size_t sig_len = sizeof(signature);

QUDO_SLHDSA_SHA2_128s_keypair(pk, sk);
QUDO_SLHDSA_SHA2_128s_sign(signature, &sig_len, msg, msg_len, sk);
int valid = (QUDO_SLHDSA_SHA2_128s_verify(msg, msg_len, signature, sig_len, pk) == 0);
```

Note the argument order: `verify` takes the message first, then the signature.
A runnable version is in [examples/simple_sign.c](examples/simple_sign.c).

## Documentation

- [Build and Install](../INSTALL.md) — full build instructions, all platforms
- [C API Reference](../docs/reference/API.md) — complete API documentation
- [Algorithms](../docs/reference/ALGORITHMS.md) — all algorithms and selection guide

## License

Apache License 2.0 and MIT License. See [LICENSE](../LICENSE) for details.
