set(CMAKE_SYSTEM_NAME Windows)
set(CMAKE_SYSTEM_PROCESSOR ARM64)

# MSVC cross-compilation for ARM64
# When using Visual Studio generator, use: cmake -G "Visual Studio 17 2022" -A ARM64
# When using Ninja or NMake, this toolchain sets up the correct target architecture

set(CMAKE_C_COMPILER cl)
set(CMAKE_CXX_COMPILER cl)

# ARM64 target flags for MSVC
set(CMAKE_C_FLAGS_INIT "/D_ARM64_")
set(CMAKE_CXX_FLAGS_INIT "/D_ARM64_")

set(CMAKE_FIND_ROOT_PATH_MODE_PROGRAM NEVER)
set(CMAKE_FIND_ROOT_PATH_MODE_LIBRARY ONLY)
set(CMAKE_FIND_ROOT_PATH_MODE_INCLUDE ONLY)
