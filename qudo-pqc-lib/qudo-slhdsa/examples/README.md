# qudo-slhdsa Examples

## Building

Examples are built automatically when `BUILD_EXAMPLES=ON` (default):

```bash
cd qudo-slhdsa && mkdir -p build && cd build
cmake -DCMAKE_BUILD_TYPE=Release ..
cmake --build . -j
```

Binaries are placed in `build/examples/`.

## Examples

| Example | Description |
|---------|-------------|
| `simple_sign` | Basic SLH-DSA sign and verify using the Object API with SLH-DSA-SHA2-128f. Demonstrates keypair generation, signing, and verification. |
| `speed_slhdsa` | Performance benchmark for keygen, sign, and verify across all 12 SLH-DSA parameter sets (SHA2/SHAKE x 128/192/256 x small/fast). |
| `der_pem_example` | DER/PEM key serialization. Demonstrates exporting and importing SLH-DSA keys in standard DER and PEM formats. |

## Quick Start

```bash
# Basic sign/verify
./build/examples/simple_sign

# Performance benchmarks (all 12 parameter sets)
./build/examples/speed_slhdsa

# Key serialization
./build/examples/der_pem_example
```
