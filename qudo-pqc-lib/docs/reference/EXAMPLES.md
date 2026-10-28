# Usage Examples

A task-oriented companion to the [C API Reference](API.md). The repository ships
runnable example programs in each sub-library's `examples/` directory; build them
with `-DBUILD_EXAMPLES=ON` when configuring a sub-library standalone:

```bash
cmake -S qudo-mlkem -B build-mlkem -DBUILD_EXAMPLES=ON && cmake --build build-mlkem -j
./build-mlkem/examples/simple_kem
```

When linking the combined `libqudo-pqc`, call `qudo_pqc_init(NULL)` once at
startup (it seeds the DRBG; in a FIPS build it also verifies integrity and runs
POST). The standalone sub-library examples do not use it.

## ML-KEM (key encapsulation) — `qudo-mlkem/examples/`

| Task | Example | Notes |
|------|---------|-------|
| Basic encaps/decaps | `simple_kem.c` | The canonical KEM round trip with the Object API |
| Client/server handshake (Object API) | `client_object.c`, `server_object.c` | Runtime algorithm selection via handles |
| Client/server handshake (Direct API) | `client_direct.c`, `server_direct.c` | Zero-allocation, compile-time set |
| DER/PEM serialization | `test_der_pem.c` | Export/import keys (DER and PEM; no OpenSSL needed) |
| Heap-allocation pattern | `test_heap_allocation.c` | Managing handle lifetime |
| Benchmark | `speed_mlkem.c` | Throughput |

**Deriving a symmetric key (the common real use):** ML-KEM gives you a 32-byte
shared secret; **do not use it as a key directly** — run it through a KDF:

```c
QUDO_KEM *kem = QUDO_KEM_new("ML-KEM-768");
uint8_t pk[/*…*/], sk[/*…*/], ct[/*…*/], ss[32];
QUDO_KEM_keypair(kem, pk, sk);          /* recipient */
QUDO_KEM_encaps(kem, ct, ss, pk);       /* sender: send ct, derive key from ss */
QUDO_KEM_decaps(kem, ss, ct, sk);       /* recipient: same ss */
/* key = HKDF-SHA256(ss, salt, info) */
QUDO_KEM_free(kem);
```

## ML-DSA (lattice signatures) — `qudo-mldsa/examples/`

| Task | Example |
|------|---------|
| Context-string signing | `context_signature.c` |
| External-μ signing | `external_mu.c` |
| Prehash (HashML-DSA) | `prehash_sha256.c` |
| Concatenated signed-message format | `concat_format.c` |
| Deterministic keygen / signing | `deterministic_keygen.c`, `deterministic_sign.c` |
| Benchmark | `speed_mldsa.c` |

**Hedged vs deterministic:** the top-level `QUDO_MLDSA_sign` is hedged (the
native routine draws its own randomness). For reproducible signatures use the
deterministic path (see `deterministic_sign.c`); for domain separation across
protocols use a context string (`context_signature.c`).

## SLH-DSA (hash-based signatures) — `qudo-slhdsa/examples/`

| Task | Example |
|------|---------|
| Sign / verify | `simple_sign.c` |
| DER/PEM serialization | `der_pem_example.c` |
| Benchmark | `speed_slhdsa.c` |

**Signing a file / large message:** SLH-DSA signatures are large and signing is
slow for the small (`s`) variants — pick an `f` variant for sign-often workloads,
an `s` variant for verify-often. Use the prehash mode to sign a digest of a large
message rather than the whole message.

## Choosing a parameter set

See [Algorithms & Parameter Sets](ALGORITHMS.md) for sizes and NIST categories.
Rules of thumb: **ML-KEM-768** and **ML-DSA-65** are the common category-3
defaults; SLH-DSA when a conservative, hash-based signature is required.

## Related

- [C API Reference](API.md) — full signatures, error codes, serialization.
- [Troubleshooting](../development/TROUBLESHOOTING.md) — when a call returns an error.
