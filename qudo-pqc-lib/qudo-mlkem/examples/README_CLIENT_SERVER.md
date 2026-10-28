# ML-KEM Client/Server Examples

This directory contains client-server examples demonstrating ML-KEM key exchange using the QUDO KEM library.

## Examples Overview

### Two API Styles

1. **Direct API** (Embedded/IoT optimized)
   - `server_direct.c` / `client_direct.c`
   - Functions: `QUDO_KEM_keypair_generate()`, `QUDO_KEM_encapsulate()`, `QUDO_KEM_decapsulate()`
   - Lower overhead, compile-time or runtime security level selection
   - Requires `QUDO_KEM_init()` call

2. **Object API** (Runtime algorithm selection)
   - `server_object.c` / `client_object.c`
   - Functions: `QUDO_KEM_new()`, `QUDO_KEM_keypair()`, `QUDO_KEM_encaps()`, `QUDO_KEM_decaps()`, `QUDO_KEM_free()`
   - Object-oriented approach with `QUDO_KEM` struct
   - Better for applications needing multiple algorithms

### Protocol Flow

```
CLIENT                              SERVER
------                              ------
1. Connect           ------>        Accept connection
2. Send "GET_PUBLIC_KEY"            
                     <------        3. Send public_key
4. Encapsulate:
   - Generate shared_secret
   - Create ciphertext
5. Send ciphertext   ------>        6. Receive ciphertext
                                    7. Decapsulate:
                                       - Recover shared_secret
8. Both sides now have identical shared_secret
9. Encrypted message ------>        10. Decrypt message
                     <------        11. Send encrypted response
```

> **Warning — demonstration only.** Steps 9–11 "encrypt" the messages by XORing
> them with the shared secret. That is **not** secure encryption and must never
> be used in production. Derive keys from the shared secret with a KDF and use an
> AEAD such as AES-256-GCM or ChaCha20-Poly1305.

## Building

```bash
cd qudo-pqc-lib/qudo-mlkem
./scripts/build_unix.sh
# or
rm -rf build && mkdir build && cd build
cmake -G "Unix Makefiles" -DCMAKE_BUILD_TYPE=Release ..
cmake --build . -j
```

## Running

### Testing Examples

#### Direct API

**Terminal 1 (Server):**
```bash
cd build/examples
./server_direct 768    # Options: 512, 768, 1024
```

**Terminal 2 (Client):**
```bash
cd build/examples
./client_direct 768    # Must match server's security level
```

**Note:** `LD_LIBRARY_PATH` is **not required** when running from the build directory because CMake sets RUNPATH automatically. Only needed if you move the binary elsewhere without the library.

#### Object API

**Terminal 1 (Server):**
```bash
cd build/examples
./server_object 1024   # Options: 512, 768, 1024
```

**Terminal 2 (Client):**
```bash
cd build/examples
./client_object 1024   # Must match server's security level
```

## Security Levels

| Level | Algorithm   | NIST Level | Security (bits) | Public Key | Ciphertext |
|-------|-------------|------------|-----------------|------------|------------|
| 512   | ML-KEM-512  | 1          | 128             | 800 bytes  | 768 bytes  |
| 768   | ML-KEM-768  | 3          | 192             | 1184 bytes | 1088 bytes |
| 1024  | ML-KEM-1024 | 5          | 256             | 1568 bytes | 1568 bytes |

## Expected Output

### Direct API Example (ML-KEM-768)

**Server:**
```
==================================================
ML-KEM Server - Direct API
==================================================

[INIT] Initializing QUDO KEM library...
  Library version: 1.0.0
  Platform: Linux (x86_64)
  Algorithm: ML-KEM-768

[1] Generating ML-KEM keypair (Direct API)...
  ✓ Keypair generated (1234.56 μs)
  Public key: 3a7f8e... (1184 bytes total)

[2] Setting up server socket...
  ✓ Server listening on port 8443

[3] Waiting for client connection...
  ✓ Client connected from 127.0.0.1
...
```

**Client:**
```
==================================================
ML-KEM Client - Direct API
==================================================

[INIT] Initializing QUDO KEM library...
  Library version: 1.0.0
  Algorithm: ML-KEM-768
  Connecting to: 127.0.0.1:8443

[1] Creating socket...
  ✓ Socket created

[2] Connecting to server...
  ✓ Connected to server

[3] Requesting public key...
  ✓ Public key received (1184 bytes)
...
```

## Code Comparison

### Direct API
```c
// Initialize once
QUDO_KEM_init();

// Use directly with security level (fixed-size buffers for ML-KEM-768)
uint8_t public_key[QUDO_KEM_768_PUBLIC_KEY_BYTES];
uint8_t secret_key[QUDO_KEM_768_SECRET_KEY_BYTES];

QUDO_KEM_keypair_generate(QUDO_KEM_768, public_key, secret_key);
QUDO_KEM_encapsulate(QUDO_KEM_768, ct, ss, public_key);
QUDO_KEM_decapsulate(QUDO_KEM_768, ss, ct, secret_key);

QUDO_KEM_cleanup();
```

### Object API
```c
// Create object (no init needed)
QUDO_KEM *kem = QUDO_KEM_new(QUDO_KEM_alg_mlkem_768);

// Use object methods (buffers sized from the object at runtime)
uint8_t *public_key = malloc(kem->length_public_key);
uint8_t *secret_key = malloc(kem->length_secret_key);

QUDO_KEM_keypair(kem, public_key, secret_key);
QUDO_KEM_encaps(kem, ct, ss, public_key);
QUDO_KEM_decaps(kem, ss, ct, secret_key);

free(public_key);
free(secret_key);
QUDO_KEM_free(kem);
```

## Network Configuration

- **Port:** 8443 (configurable in `common_network.h`)
- **Address:** 127.0.0.1 (localhost)
- **Protocol:** TCP/IPv4

## Performance Measurement

**For accurate performance numbers, use the benchmark tool:**

```bash
cd build
./examples/speed_mlkem
```

This runs each operation for 3 seconds with statistical analysis and outlier filtering.

**Example results (x86_64 with AVX2):**
- **ML-KEM-512:** ~5 μs keypair, ~5 μs encaps, ~7 μs decaps
- **ML-KEM-768:** ~8 μs keypair, ~8 μs encaps, ~10 μs decaps  
- **ML-KEM-1024:** ~11 μs keypair, ~11 μs encaps, ~14 μs decaps

**Note:** Client/server examples include network overhead and are not suitable for performance measurement.

## Files

- `common_network.h` - Shared network utilities and protocol definitions
- `server_direct.c` / `client_direct.c` - Client/server using Direct API
- `server_object.c` / `client_object.c` - Client/server using Object API
- `speed_mlkem.c` - Performance benchmark tool (accurate crypto timing)

## Notes

1. **Encryption Demo:** Examples use simple XOR "encryption" for demonstration only — it is not secure. In production, derive keys with a KDF and use an AEAD such as AES-256-GCM or ChaCha20-Poly1305.

2. **Error Handling:** Examples include comprehensive error checking. Status codes are defined in `mlkem_types.h`.

3. **Thread Safety:** Both APIs are thread-safe after initialization.

4. **Memory Management:** Caller allocates buffers; use size getters or object fields.

## Troubleshooting

### "Connection refused"
- Ensure server is started before client
- Check firewall settings
- Verify port 8443 is available

### "Library initialization failed"
- Verify library path is set correctly
- Check that a platform entropy source is available

### "Shared library not found"
When running from the build directory RUNPATH is set, so the library is found
automatically. Otherwise:
- Check: `ldd examples/server_direct` to see library dependencies
- Check: `readelf -d examples/server_direct | grep RUNPATH` to verify embedded path
- **Only if RUNPATH is missing:**
  - Preferred: `sudo cp libqudo-mlkem.so* /usr/local/lib && sudo ldconfig`
  - Temporary (development only): `export LD_LIBRARY_PATH=$PWD/../:$LD_LIBRARY_PATH`

> **Note:** Prefer `sudo ldconfig` over `LD_LIBRARY_PATH` for production.
> `LD_LIBRARY_PATH` persists only for the current shell and can mask library
> version conflicts. `ldconfig` updates the system linker cache permanently.

## See Also

- [INSTALL.md](../../INSTALL.md) - Build guide
- [mlkem_wrapper.h](../include/mlkem_wrapper.h) - Complete API reference
- [simple_kem.c](simple_kem.c) - Basic KEM example
- [test_der_pem.c](test_der_pem.c) - Key serialization example
