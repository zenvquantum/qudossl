# CMake toolchain file for ARMv7 hard-float (arm-linux-gnueabihf)
# Target: 32-bit ARMv7 Linux with hardware floating-point (Cortex-A, Raspberry Pi 2/3)
# Host:   x86_64 Linux (cross-compilation)
#
# Usage:
#   cmake -DCMAKE_TOOLCHAIN_FILE=cmake/toolchains/arm-linux-gnueabihf.cmake ..

set(CMAKE_SYSTEM_NAME    Linux)
set(CMAKE_SYSTEM_PROCESSOR arm)

set(CROSS_PREFIX "arm-linux-gnueabihf-")

set(CMAKE_C_COMPILER   "${CROSS_PREFIX}gcc")
set(CMAKE_CXX_COMPILER "${CROSS_PREFIX}g++")
set(CMAKE_ASM_COMPILER "${CROSS_PREFIX}gcc")
set(CMAKE_AR           "${CROSS_PREFIX}ar")
set(CMAKE_RANLIB       "${CROSS_PREFIX}ranlib")
set(CMAKE_STRIP        "${CROSS_PREFIX}strip")

# Cross-compiler already knows its sysroot — don't set CMAKE_SYSROOT
# to avoid double-prefixed library paths.
set(CMAKE_FIND_ROOT_PATH /usr/arm-linux-gnueabihf /usr)

set(CMAKE_FIND_ROOT_PATH_MODE_PROGRAM NEVER)
set(CMAKE_FIND_ROOT_PATH_MODE_LIBRARY ONLY)
set(CMAKE_FIND_ROOT_PATH_MODE_INCLUDE BOTH)
set(CMAKE_FIND_ROOT_PATH_MODE_PACKAGE ONLY)

# ARMv7-A with NEON (covers Cortex-A7/A9/A53 in 32-bit mode)
set(CMAKE_C_FLAGS_INIT   "-march=armv7-a -mfpu=neon-vfpv4 -mfloat-abi=hard")
set(CMAKE_CXX_FLAGS_INIT "-march=armv7-a -mfpu=neon-vfpv4 -mfloat-abi=hard")
