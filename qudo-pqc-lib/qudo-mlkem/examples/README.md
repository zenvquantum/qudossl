# qudo-mlkem Examples

## Building

Examples are built automatically when `BUILD_EXAMPLES=ON` (default):

```bash
cd qudo-mlkem && mkdir -p build && cd build
cmake -DCMAKE_BUILD_TYPE=Release ..
cmake --build . -j
```

Binaries are placed in `build/examples/`.

## Examples

| Example | Description |
|---------|-------------|
| `simple_kem` | Basic ML-KEM key encapsulation and decapsulation using the Object API across all three security levels (512, 768, 1024). |
| `speed_mlkem` | Performance benchmark with time-based iterations, CPU cycle counting (RDTSC), Welford's mean/stddev, and outlier filtering. Cross-platform (Linux/macOS/Windows). |
| `test_der_pem` | DER/PEM key export and import. Demonstrates saving ML-KEM keys to files and loading them back in standard formats. |
| `test_heap_allocation` | Tests Object API heap allocation and instance independence — verifies that multiple `QUDO_KEM` instances operate without interference. |
| `client_object` | Network client using the Object API for ML-KEM key exchange over TCP sockets. See [README_CLIENT_SERVER.md](README_CLIENT_SERVER.md). |
| `client_direct` | Network client using the Direct (zero-allocation) API for ML-KEM key exchange. See [README_CLIENT_SERVER.md](README_CLIENT_SERVER.md). |
| `server_object` | Network server using the Object API. Pairs with `client_object`. See [README_CLIENT_SERVER.md](README_CLIENT_SERVER.md). |
| `server_direct` | Network server using the Direct API. Pairs with `client_direct`. See [README_CLIENT_SERVER.md](README_CLIENT_SERVER.md). |

## Quick Start

```bash
# Basic KEM operations
./build/examples/simple_kem

# Performance benchmarks
./build/examples/speed_mlkem

# DER/PEM serialization
./build/examples/test_der_pem
```
