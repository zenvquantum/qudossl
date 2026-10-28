#!/bin/bash
# Build script for Linux/macOS

set -e  # Exit on error

echo "======================================"
echo "ML-DSA Post-Quantum Signature Build"
echo "======================================"

# Colors for output
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Detect platform
if [[ "$OSTYPE" == "linux-gnu"* ]]; then
    PLATFORM="Linux"
elif [[ "$OSTYPE" == "darwin"* ]]; then
    PLATFORM="macOS"
else
    echo "Unsupported platform: $OSTYPE"
    exit 1
fi

echo -e "${GREEN}Platform: $PLATFORM${NC}"

# Check dependencies
echo ""
echo "Checking dependencies..."

if ! command -v cmake &> /dev/null; then
    echo -e "${YELLOW}CMake not found. Please install CMake${NC}"
    exit 1
fi

if ! command -v gcc &> /dev/null && ! command -v clang &> /dev/null; then
    echo -e "${YELLOW}No C compiler found. Please install gcc or clang${NC}"
    exit 1
fi

# Check OpenSSL
if ! pkg-config --exists openssl; then
    echo -e "${YELLOW}OpenSSL not found. Please install libssl-dev${NC}"
    echo "  Ubuntu/Debian: sudo apt install libssl-dev"
    echo "  macOS: brew install openssl"
    exit 1
fi

OPENSSL_VERSION=$(pkg-config --modversion openssl)
echo -e "${GREEN}✓ OpenSSL $OPENSSL_VERSION found${NC}"
echo -e "${GREEN}✓ CMake $(cmake --version | head -n1 | cut -d' ' -f3) found${NC}"

# Build configuration
BUILD_TYPE=${1:-Release}  # Default to Release build
BUILD_DIR="build"

echo ""
echo "Build configuration:"
echo "  Type: $BUILD_TYPE"
echo "  Directory: $BUILD_DIR"

# Detect AVX2 support
AVX2_SUPPORT="OFF"
if [[ "$PLATFORM" == "Linux" ]]; then
    if grep -q avx2 /proc/cpuinfo 2>/dev/null; then
        AVX2_SUPPORT="ON"
        echo -e "  AVX2: ${GREEN}Enabled${NC}"
    else
        echo "  AVX2: Disabled (CPU doesn't support it)"
    fi
elif [[ "$PLATFORM" == "macOS" ]]; then
    if sysctl -a | grep -q "hw.optional.avx2_0: 1" 2>/dev/null; then
        AVX2_SUPPORT="ON"
        echo -e "  AVX2: ${GREEN}Enabled${NC}"
    fi
fi

# Create build directory
echo ""
echo "Creating build directory..."
rm -rf $BUILD_DIR
mkdir -p $BUILD_DIR
cd $BUILD_DIR

# Configure with CMake
echo ""
echo "Configuring with CMake..."
cmake .. \
    -DCMAKE_BUILD_TYPE=$BUILD_TYPE \
    -DBUILD_SHARED_LIBS=ON \
    -DBUILD_EXAMPLES=ON \
    -DBUILD_TESTS=ON

# Build
echo ""
echo "Building..."
cmake --build . --config $BUILD_TYPE -j$(nproc 2>/dev/null || sysctl -n hw.ncpu 2>/dev/null || echo 4)

echo ""
echo -e "${GREEN}======================================"
echo "✓ Build completed successfully!"
echo "=====================================${NC}"
echo ""
echo "To install (requires sudo):"
echo "  cd $BUILD_DIR && sudo cmake --install ."
echo ""
echo "To run tests:"
echo "  cd $BUILD_DIR && ctest --output-on-failure"
echo ""
echo "To run examples:"
echo "  cd $BUILD_DIR/examples"
echo "  ./speed_mldsa"
echo ""
