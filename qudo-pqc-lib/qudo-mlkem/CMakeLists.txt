# SPDX-License-Identifier: Apache-2.0 AND MIT

cmake_minimum_required(VERSION 3.15)

# CMake policies for better compatibility
if(POLICY CMP0077)
    cmake_policy(SET CMP0077 NEW)
endif()
if(POLICY CMP0063)
    cmake_policy(SET CMP0063 NEW)
endif()
if(POLICY CMP0066)
    cmake_policy(SET CMP0066 NEW)
endif()

if(WIN32)
    project(QUDO_KEM VERSION 1.0.0 LANGUAGES C)
else()
    project(QUDO_KEM VERSION 1.0.0 LANGUAGES C ASM)
endif()

# Version information
set(MLKEM_VERSION_MAJOR 1)
set(MLKEM_VERSION_MINOR 0)
set(MLKEM_VERSION_PATCH 0)
set(MLKEM_VERSION_TEXT "${MLKEM_VERSION_MAJOR}.${MLKEM_VERSION_MINOR}.${MLKEM_VERSION_PATCH}")

# Build options
option(BUILD_SHARED_LIBS "Build shared libraries" ON)
option(MLKEM_BUILD_ONLY_LIB "Build only library without tests/examples" OFF)
option(BUILD_EXAMPLES "Build example programs" ON)
option(BUILD_TESTS "Build tests" ON)
option(MLKEM_DIST_BUILD "Build with runtime CPU detection for multiple architectures" ON)
option(MLKEM_STRICT_WARNINGS "Enable strict compiler warnings" OFF)
option(MLKEM_EMBEDDED_BUILD "Build for embedded systems without full stdlib" OFF)
option(MLKEM_USE_OPENSSL "Use OpenSSL for cryptographic primitives and RNG" ON)
option(ENABLE_SANITIZERS "Enable AddressSanitizer and UndefinedBehaviorSanitizer" OFF)
option(ENABLE_COVERAGE "Enable code coverage instrumentation" OFF)
option(BUILD_FUZZ "Build fuzzing harnesses (requires Clang with libFuzzer)" OFF)
option(MLKEM_CT_VALGRIND "Build constant-time validation (MLK_CONFIG_CT_TESTING_ENABLED + Valgrind)" OFF)
set(MLKEM_OPT_TARGET "auto" CACHE STRING "Target microarchitecture for optimization")

# Platform-specific optimizations
option(ENABLE_AVX2 "Enable AVX2 optimizations (x86_64)" ON)
option(ENABLE_NEON "Enable NEON optimizations (ARM64)" ON)
option(ENABLE_RVV "Enable RISC-V Vector optimizations" ON)

# Constant-time validation: poison secret data with Valgrind annotations so any
# secret-dependent branch or memory index is reported. Run the resulting test
# under Valgrind.
if(MLKEM_CT_VALGRIND)
    add_definitions(-DMLK_CONFIG_CT_TESTING_ENABLED)
    message(STATUS "Constant-time validation enabled (MLK_CONFIG_CT_TESTING_ENABLED)")
endif()

# Set C standard
set(CMAKE_C_STANDARD 99)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)
set(CMAKE_C_VISIBILITY_PRESET hidden)

# Platform detection
if(WIN32)
    add_definitions(-D_CRT_SECURE_NO_WARNINGS)
    set(PLATFORM_NAME "Windows")
    set(MLKEM_PLATFORM_WINDOWS ON)
elseif(APPLE)
    set(PLATFORM_NAME "macOS")
    set(MLKEM_PLATFORM_MACOS ON)
elseif(UNIX)
    set(PLATFORM_NAME "Linux")
    set(MLKEM_PLATFORM_LINUX ON)
endif()

# Detect if being built as a subdirectory (combined build)
if(NOT CMAKE_SOURCE_DIR STREQUAL CMAKE_CURRENT_SOURCE_DIR)
    set(MLKEM_QUIET ON)
endif()

# Architecture detection
if(CMAKE_SYSTEM_PROCESSOR MATCHES "x86_64|AMD64|amd64")
    set(MLKEM_ARCH_X86_64 ON)
elseif(CMAKE_SYSTEM_PROCESSOR MATCHES "aarch64|arm64|ARM64")
    set(MLKEM_ARCH_ARM64 ON)
elseif(CMAKE_SYSTEM_PROCESSOR MATCHES "riscv64")
    set(MLKEM_ARCH_RISCV64 ON)
elseif(CMAKE_SYSTEM_PROCESSOR MATCHES "^arm|^armv7|^armhf")
    set(MLKEM_ARCH_ARM32 ON)
elseif(CMAKE_SYSTEM_PROCESSOR MATCHES "i[3456]86|x86")
    set(MLKEM_ARCH_X86_32 ON)
else()
    message(WARNING "Unknown architecture: ${CMAKE_SYSTEM_PROCESSOR}")
endif()

if(NOT MLKEM_QUIET)
    message(STATUS "Building for platform: ${PLATFORM_NAME}")
endif()

# Include standard modules
include(CheckCCompilerFlag)
include(CheckSymbolExists)
include(GNUInstallDirs)
include(CMakePackageConfigHelpers)

# Compiler flags for security hardening and optimization
if(CMAKE_C_COMPILER_ID MATCHES "GNU|Clang")
    add_compile_options(
        -O3
        -fomit-frame-pointer
        -D_FORTIFY_SOURCE=2
        -fno-strict-overflow
    )
    # Stack protector is not enabled for MinGW.
    if(NOT WIN32)
        add_compile_options(-fstack-protector-strong)
    endif()
    if(NOT MLKEM_EMBEDDED_BUILD)
        if(UNIX AND NOT APPLE AND NOT WIN32)
            add_link_options(-Wl,-z,relro -Wl,-z,now -Wl,-z,noexecstack)
        endif()
    endif()
elseif(MSVC)
    add_compile_options(/GS /sdl)
    add_definitions(-D_CRT_SECURE_NO_WARNINGS)
endif()

# Code coverage instrumentation
if(ENABLE_COVERAGE)
    add_compile_options(--coverage -fprofile-arcs -ftest-coverage)
    add_link_options(--coverage)
endif()

# Sanitizer support (ASAN + UBSAN)
if(ENABLE_SANITIZERS)
    if(CMAKE_C_COMPILER_ID MATCHES "GNU|Clang")
        add_compile_options(-fsanitize=address,undefined -fno-omit-frame-pointer -fno-sanitize-recover=all -fPIC)
        add_link_options(-fsanitize=address,undefined)
        message(STATUS "Sanitizers enabled: AddressSanitizer + UndefinedBehaviorSanitizer")
    else()
        message(WARNING "Sanitizers requested but not supported with this compiler")
    endif()
endif()

# Fuzz instrumentation: when BUILD_FUZZ=ON, compile the library with sanitizer
# coverage so libFuzzer can instrument all branches (not just the harness).
if(BUILD_FUZZ AND CMAKE_C_COMPILER_ID MATCHES "Clang")
    add_compile_options(-fsanitize=fuzzer-no-link,address,undefined -fno-omit-frame-pointer)
    add_link_options(-fsanitize=address,undefined)
endif()

# Strict warnings
if(MLKEM_STRICT_WARNINGS)
    if(CMAKE_C_COMPILER_ID MATCHES "GNU|Clang")
        add_compile_options(-Wall -Wextra -Wpedantic -Werror)
    elseif(MSVC)
        add_compile_options(/W4 /WX)
    endif()
else()
    # Suppress warnings from mlkem-native multi-level build
    if(CMAKE_C_COMPILER_ID MATCHES "GNU")
        add_compile_options(
            -Wno-implicit-function-declaration
            -Wno-array-parameter
            -Wno-builtin-declaration-mismatch
        )
    elseif(CMAKE_C_COMPILER_ID MATCHES "Clang")
        add_compile_options(
            -Wno-implicit-function-declaration
            -Wno-array-parameter
            -Wno-unknown-warning-option
        )
    endif()
endif()

# Find OpenSSL (optional)
if(MLKEM_USE_OPENSSL)
    # macOS: Help find_package locate Homebrew OpenSSL installations
    if(NOT DEFINED OPENSSL_ROOT_DIR)
        if(${CMAKE_HOST_SYSTEM_NAME} STREQUAL "Darwin")
            # Check common Homebrew locations (Intel and Apple Silicon)
            if(EXISTS "/usr/local/opt/openssl@3")
                set(OPENSSL_ROOT_DIR "/usr/local/opt/openssl@3")
            elseif(EXISTS "/opt/homebrew/opt/openssl@3")
                set(OPENSSL_ROOT_DIR "/opt/homebrew/opt/openssl@3")
            elseif(EXISTS "/usr/local/opt/openssl@1.1")
                set(OPENSSL_ROOT_DIR "/usr/local/opt/openssl@1.1")
            elseif(EXISTS "/opt/homebrew/opt/openssl@1.1")
                set(OPENSSL_ROOT_DIR "/opt/homebrew/opt/openssl@1.1")
            endif()
        endif()
    endif()
    
    if(MLKEM_QUIET)
        find_package(OpenSSL 1.1.1 QUIET)
    else()
        find_package(OpenSSL 1.1.1)
    endif()

    if(OPENSSL_FOUND)
        if(NOT MLKEM_QUIET)
            message(STATUS "OpenSSL enabled")
            message(STATUS "  Version: ${OPENSSL_VERSION}")
            message(STATUS "  Include: ${OPENSSL_INCLUDE_DIR}")
            message(STATUS "  Libraries: ${OPENSSL_LIBRARIES}")
        endif()
        add_definitions(-DQUDO_KEM_USE_OPENSSL)
    else()
        message(WARNING "OpenSSL requested but not found. Using system RNG fallback. DER/PEM disabled.")
        set(MLKEM_USE_OPENSSL OFF)
    endif()
endif()

# Include directories
include_directories(
    ${CMAKE_CURRENT_SOURCE_DIR}/include
    ${CMAKE_CURRENT_SOURCE_DIR}/mlkem-native
    ${CMAKE_CURRENT_SOURCE_DIR}/mlkem-native/mlkem
    ${CMAKE_CURRENT_SOURCE_DIR}/mlkem-native/qudo_runtime_dispatch
    ${OPENSSL_INCLUDE_DIR}
)

# Internal DRBG headers: provided by the parent in the combined build,
# otherwise taken from ../src.
if(NOT QUDO_COMBINED_BUILD)
    if(EXISTS ${CMAKE_CURRENT_SOURCE_DIR}/../src/fips)
        include_directories(${CMAKE_CURRENT_SOURCE_DIR}/../src)
    endif()
endif()

# Source files for ML-KEM wrapper library (absolute paths for parent scope export)
set(MLKEM_WRAPPER_SOURCES
    ${CMAKE_CURRENT_SOURCE_DIR}/src/mlkem_wrapper.c
    ${CMAKE_CURRENT_SOURCE_DIR}/src/mlkem_config.c
    ${CMAKE_CURRENT_SOURCE_DIR}/src/mlkem_error.c
    ${CMAKE_CURRENT_SOURCE_DIR}/src/mlkem_rand.c
    ${CMAKE_CURRENT_SOURCE_DIR}/src/mlkem_memory.c
    ${CMAKE_CURRENT_SOURCE_DIR}/src/platform_utils.c
    ${CMAKE_CURRENT_SOURCE_DIR}/src/mlkem_interop.c
)

# Runtime CPU dispatch sources (QUDO extension)
if(MLKEM_DIST_BUILD)
    list(APPEND MLKEM_WRAPPER_SOURCES
        ${CMAKE_CURRENT_SOURCE_DIR}/mlkem-native/qudo_runtime_dispatch/cpu_features.c
    )
    add_definitions(-DMLK_CONFIG_RUNTIME_DISPATCH)
    if(NOT MLKEM_QUIET)
        message(STATUS "Runtime CPU dispatch enabled - will include all CPU variants")
    endif()
endif()

# ML-KEM native library sources (generic C implementation)
file(GLOB MLKEM_NATIVE_CORE_SOURCES
    mlkem-native/mlkem/src/*.c
    mlkem-native/mlkem/src/fips202/*.c
)

# Prepare architecture-specific source lists
file(GLOB MLKEM_NATIVE_X86_SOURCES
    mlkem-native/mlkem/src/native/x86_64/src/*.c
    mlkem-native/mlkem/src/native/x86_64/src/*.S
    mlkem-native/mlkem/src/fips202/native/x86_64/src/*.c
    mlkem-native/mlkem/src/fips202/native/x86_64/src/*.S
)

file(GLOB MLKEM_NATIVE_ARM_SOURCES
    mlkem-native/mlkem/src/native/aarch64/src/*.c
    mlkem-native/mlkem/src/native/aarch64/src/*.S
    mlkem-native/mlkem/src/fips202/native/aarch64/src/*.c
    mlkem-native/mlkem/src/fips202/native/aarch64/src/*.S
)

if(MLKEM_DIST_BUILD)
    if(NOT MLKEM_QUIET)
        message(STATUS "DIST_BUILD mode: Building 3 variants (ref + avx2 + neon) with separate namespaces")
    endif()
else()
    # Compile-time selection: Only current architecture
    set(MLKEM_NATIVE_ARCH_SOURCES "")
    if(MLKEM_ARCH_X86_64 AND ENABLE_AVX2 AND NOT WIN32)
        list(APPEND MLKEM_NATIVE_ARCH_SOURCES ${MLKEM_NATIVE_X86_SOURCES})
        message(STATUS "Adding x86_64 AVX2 optimizations (C + Assembly)")
        set(MLKEM_USE_NATIVE_X86 ON)
    elseif(WIN32 AND MLKEM_ARCH_X86_64)
        message(STATUS "Windows detected - using generic C implementation (no AVX2 assembly)")
        set(MLKEM_USE_NATIVE_X86 OFF)
    elseif(MLKEM_ARCH_ARM64 AND ENABLE_NEON)
        list(APPEND MLKEM_NATIVE_ARCH_SOURCES ${MLKEM_NATIVE_ARM_SOURCES})
        message(STATUS "Adding ARM64 NEON optimizations")
    elseif(MLKEM_ARCH_RISCV64 AND ENABLE_RVV)
        file(GLOB MLKEM_NATIVE_RISCV_SOURCES
            mlkem-native/mlkem/src/native/riscv64/src/*.c
        )
        list(APPEND MLKEM_NATIVE_ARCH_SOURCES ${MLKEM_NATIVE_RISCV_SOURCES})
        message(STATUS "Adding RISC-V vector optimizations")
    endif()
endif()

# Combine all sources
if(NOT MLKEM_DIST_BUILD)
    set(MLKEM_NATIVE_SOURCES ${MLKEM_NATIVE_CORE_SOURCES} ${MLKEM_NATIVE_ARCH_SOURCES})
endif()

if(MLKEM_DIST_BUILD)
    # ===== DIST BUILD: Create multiple variants per security level =====
    # Build only what's supported by current compiler:
    #   - ref: Portable C (always built)
    #   - avx2: x86_64 AVX2 optimized (if x86_64 & not Windows)
    #   - neon: ARM64 NEON optimized (if ARM64)
    
    # ML-KEM-512 variants
    add_library(mlkem512_ref_objs OBJECT ${MLKEM_NATIVE_CORE_SOURCES})
    target_compile_definitions(mlkem512_ref_objs PRIVATE 
        MLK_CONFIG_PARAMETER_SET=512
        MLK_CONFIG_MULTILEVEL_WITH_SHARED
        "MLK_CONFIG_NAMESPACE_PREFIX=mlkem_ref"
    )
    target_include_directories(mlkem512_ref_objs PRIVATE mlkem-native/mlkem mlkem-native/mlkem/src)
    
    if(MLKEM_ARCH_X86_64 AND NOT WIN32)
        add_library(mlkem512_avx2_objs OBJECT ${MLKEM_NATIVE_CORE_SOURCES} ${MLKEM_NATIVE_X86_SOURCES})
        target_compile_definitions(mlkem512_avx2_objs PRIVATE 
            MLK_CONFIG_PARAMETER_SET=512
            MLK_CONFIG_MULTILEVEL_WITH_SHARED
            "MLK_CONFIG_NAMESPACE_PREFIX=mlkem_avx2"
            MLK_CONFIG_USE_NATIVE_BACKEND_ARITH
            MLK_CONFIG_USE_NATIVE_BACKEND_FIPS202
        )
        target_compile_options(mlkem512_avx2_objs PRIVATE -mavx2 -mbmi2 -mpopcnt)
        target_include_directories(mlkem512_avx2_objs PRIVATE mlkem-native/mlkem mlkem-native/mlkem/src)
        add_definitions(-DQUDO_HAS_AVX2_VARIANT)
    endif()
    
    if(MLKEM_ARCH_ARM64)
        add_library(mlkem512_neon_objs OBJECT ${MLKEM_NATIVE_CORE_SOURCES} ${MLKEM_NATIVE_ARM_SOURCES})
        target_compile_definitions(mlkem512_neon_objs PRIVATE 
            MLK_CONFIG_PARAMETER_SET=512
            MLK_CONFIG_MULTILEVEL_WITH_SHARED
            "MLK_CONFIG_NAMESPACE_PREFIX=mlkem_neon"
            MLK_CONFIG_USE_NATIVE_BACKEND_ARITH
            MLK_CONFIG_USE_NATIVE_BACKEND_FIPS202
        )
        target_include_directories(mlkem512_neon_objs PRIVATE mlkem-native/mlkem mlkem-native/mlkem/src)
        add_definitions(-DQUDO_HAS_NEON_VARIANT)
    endif()
    
    # ML-KEM-768 variants
    add_library(mlkem768_ref_objs OBJECT ${MLKEM_NATIVE_CORE_SOURCES})
    target_compile_definitions(mlkem768_ref_objs PRIVATE 
        MLK_CONFIG_PARAMETER_SET=768
        MLK_CONFIG_MULTILEVEL_NO_SHARED
        "MLK_CONFIG_NAMESPACE_PREFIX=mlkem_ref"
    )
    target_include_directories(mlkem768_ref_objs PRIVATE mlkem-native/mlkem mlkem-native/mlkem/src)
    
    if(MLKEM_ARCH_X86_64 AND NOT WIN32)
        add_library(mlkem768_avx2_objs OBJECT ${MLKEM_NATIVE_CORE_SOURCES} ${MLKEM_NATIVE_X86_SOURCES})
        target_compile_definitions(mlkem768_avx2_objs PRIVATE 
            MLK_CONFIG_PARAMETER_SET=768
            MLK_CONFIG_MULTILEVEL_NO_SHARED
            "MLK_CONFIG_NAMESPACE_PREFIX=mlkem_avx2"
            MLK_CONFIG_USE_NATIVE_BACKEND_ARITH
            MLK_CONFIG_USE_NATIVE_BACKEND_FIPS202
        )
        target_compile_options(mlkem768_avx2_objs PRIVATE -mavx2 -mbmi2 -mpopcnt)
        target_include_directories(mlkem768_avx2_objs PRIVATE mlkem-native/mlkem mlkem-native/mlkem/src)
    endif()
    
    if(MLKEM_ARCH_ARM64)
        add_library(mlkem768_neon_objs OBJECT ${MLKEM_NATIVE_CORE_SOURCES} ${MLKEM_NATIVE_ARM_SOURCES})
        target_compile_definitions(mlkem768_neon_objs PRIVATE 
            MLK_CONFIG_PARAMETER_SET=768
            MLK_CONFIG_MULTILEVEL_NO_SHARED
            "MLK_CONFIG_NAMESPACE_PREFIX=mlkem_neon"
            MLK_CONFIG_USE_NATIVE_BACKEND_ARITH
            MLK_CONFIG_USE_NATIVE_BACKEND_FIPS202
        )
        target_include_directories(mlkem768_neon_objs PRIVATE mlkem-native/mlkem mlkem-native/mlkem/src)
    endif()
    
    # ML-KEM-1024 variants
    add_library(mlkem1024_ref_objs OBJECT ${MLKEM_NATIVE_CORE_SOURCES})
    target_compile_definitions(mlkem1024_ref_objs PRIVATE 
        MLK_CONFIG_PARAMETER_SET=1024
        MLK_CONFIG_MULTILEVEL_NO_SHARED
        "MLK_CONFIG_NAMESPACE_PREFIX=mlkem_ref"
    )
    target_include_directories(mlkem1024_ref_objs PRIVATE mlkem-native/mlkem mlkem-native/mlkem/src)
    
    if(MLKEM_ARCH_X86_64 AND NOT WIN32)
        add_library(mlkem1024_avx2_objs OBJECT ${MLKEM_NATIVE_CORE_SOURCES} ${MLKEM_NATIVE_X86_SOURCES})
        target_compile_definitions(mlkem1024_avx2_objs PRIVATE 
            MLK_CONFIG_PARAMETER_SET=1024
            MLK_CONFIG_MULTILEVEL_NO_SHARED
            "MLK_CONFIG_NAMESPACE_PREFIX=mlkem_avx2"
            MLK_CONFIG_USE_NATIVE_BACKEND_ARITH
            MLK_CONFIG_USE_NATIVE_BACKEND_FIPS202
        )
        target_compile_options(mlkem1024_avx2_objs PRIVATE -mavx2 -mbmi2 -mpopcnt)
        target_include_directories(mlkem1024_avx2_objs PRIVATE mlkem-native/mlkem mlkem-native/mlkem/src)
    endif()
    
    if(MLKEM_ARCH_ARM64)
        add_library(mlkem1024_neon_objs OBJECT ${MLKEM_NATIVE_CORE_SOURCES} ${MLKEM_NATIVE_ARM_SOURCES})
        target_compile_definitions(mlkem1024_neon_objs PRIVATE 
            MLK_CONFIG_PARAMETER_SET=1024
            MLK_CONFIG_MULTILEVEL_NO_SHARED
            "MLK_CONFIG_NAMESPACE_PREFIX=mlkem_neon"
            MLK_CONFIG_USE_NATIVE_BACKEND_ARITH
            MLK_CONFIG_USE_NATIVE_BACKEND_FIPS202
        )
        target_include_directories(mlkem1024_neon_objs PRIVATE mlkem-native/mlkem mlkem-native/mlkem/src)
    endif()
    
else()
    # ===== COMPILE-TIME BUILD: single variant per level =====
    set(MLKEM_NATIVE_SOURCES ${MLKEM_NATIVE_CORE_SOURCES} ${MLKEM_NATIVE_ARCH_SOURCES})
    
    # Create object libraries for each security level (multi-level build)
    add_library(mlkem512_objs OBJECT ${MLKEM_NATIVE_SOURCES})
target_compile_definitions(mlkem512_objs PRIVATE 
    MLK_CONFIG_PARAMETER_SET=512
    MLK_CONFIG_MULTILEVEL_WITH_SHARED
    "MLK_CONFIG_NAMESPACE_PREFIX=mlkem"
)
# Enable native backends
if(MLKEM_DIST_BUILD OR MLKEM_USE_NATIVE_X86)
    target_compile_definitions(mlkem512_objs PRIVATE
        MLK_CONFIG_USE_NATIVE_BACKEND_ARITH
        MLK_CONFIG_USE_NATIVE_BACKEND_FIPS202
    )
endif()
if(NOT MSVC AND NOT WIN32 AND MLKEM_ARCH_X86_64 AND (MLKEM_DIST_BUILD OR MLKEM_USE_NATIVE_X86))
    target_compile_options(mlkem512_objs PRIVATE -mavx2 -mbmi2 -mpopcnt)
endif()
target_include_directories(mlkem512_objs PRIVATE
    mlkem-native/mlkem
    mlkem-native/mlkem/src
)

add_library(mlkem768_objs OBJECT ${MLKEM_NATIVE_SOURCES})
target_compile_definitions(mlkem768_objs PRIVATE 
    MLK_CONFIG_PARAMETER_SET=768
    MLK_CONFIG_MULTILEVEL_NO_SHARED
    "MLK_CONFIG_NAMESPACE_PREFIX=mlkem"
)
# Enable native backends
if(MLKEM_DIST_BUILD OR MLKEM_USE_NATIVE_X86)
    target_compile_definitions(mlkem768_objs PRIVATE
        MLK_CONFIG_USE_NATIVE_BACKEND_ARITH
        MLK_CONFIG_USE_NATIVE_BACKEND_FIPS202
    )
endif()
if(NOT MSVC AND NOT WIN32 AND MLKEM_ARCH_X86_64 AND (MLKEM_DIST_BUILD OR MLKEM_USE_NATIVE_X86))
    target_compile_options(mlkem768_objs PRIVATE -mavx2 -mbmi2 -mpopcnt)
endif()
target_include_directories(mlkem768_objs PRIVATE
    mlkem-native/mlkem
    mlkem-native/mlkem/src
)

add_library(mlkem1024_objs OBJECT ${MLKEM_NATIVE_SOURCES})
target_compile_definitions(mlkem1024_objs PRIVATE 
    MLK_CONFIG_PARAMETER_SET=1024
    MLK_CONFIG_MULTILEVEL_NO_SHARED
    "MLK_CONFIG_NAMESPACE_PREFIX=mlkem"
)
# Enable native backends
if(MLKEM_DIST_BUILD OR MLKEM_USE_NATIVE_X86)
    target_compile_definitions(mlkem1024_objs PRIVATE
        MLK_CONFIG_USE_NATIVE_BACKEND_ARITH
        MLK_CONFIG_USE_NATIVE_BACKEND_FIPS202
    )
endif()
if(NOT MSVC AND NOT WIN32 AND MLKEM_ARCH_X86_64 AND (MLKEM_DIST_BUILD OR MLKEM_USE_NATIVE_X86))
    target_compile_options(mlkem1024_objs PRIVATE -mavx2 -mbmi2 -mpopcnt)
endif()
target_include_directories(mlkem1024_objs PRIVATE
    mlkem-native/mlkem
    mlkem-native/mlkem/src
)
endif()  # End of MLKEM_DIST_BUILD conditional

# Create QUDO ML-KEM library
if(MLKEM_DIST_BUILD)
    # Link all built variants based on architecture
    set(MLKEM_ALL_OBJS
        ${MLKEM_WRAPPER_SOURCES}
        $<TARGET_OBJECTS:mlkem512_ref_objs>
        $<TARGET_OBJECTS:mlkem768_ref_objs>
        $<TARGET_OBJECTS:mlkem1024_ref_objs>
    )
    
    # Add AVX2 variants if built (x86_64 only)
    if(MLKEM_ARCH_X86_64 AND NOT WIN32)
        list(APPEND MLKEM_ALL_OBJS
            $<TARGET_OBJECTS:mlkem512_avx2_objs>
            $<TARGET_OBJECTS:mlkem768_avx2_objs>
            $<TARGET_OBJECTS:mlkem1024_avx2_objs>
        )
    endif()
    
    # Add NEON variants if built (ARM64 only)
    if(MLKEM_ARCH_ARM64)
        list(APPEND MLKEM_ALL_OBJS
            $<TARGET_OBJECTS:mlkem512_neon_objs>
            $<TARGET_OBJECTS:mlkem768_neon_objs>
            $<TARGET_OBJECTS:mlkem1024_neon_objs>
        )
    endif()
    
    add_library(qudo-mlkem ${MLKEM_ALL_OBJS})
    # Export for combined libqudo-pqc build (parent scope)
    set(QUDO_MLKEM_ALL_OBJS ${MLKEM_ALL_OBJS} PARENT_SCOPE)
else()
    # Compile-time build: single variant
    set(MLKEM_ALL_OBJS
        ${MLKEM_WRAPPER_SOURCES}
        $<TARGET_OBJECTS:mlkem512_objs>
        $<TARGET_OBJECTS:mlkem768_objs>
        $<TARGET_OBJECTS:mlkem1024_objs>
    )
    add_library(qudo-mlkem ${MLKEM_ALL_OBJS})
    # Export for combined libqudo-pqc build (parent scope)
    set(QUDO_MLKEM_ALL_OBJS ${MLKEM_ALL_OBJS} PARENT_SCOPE)
endif()

# Set library properties
set_target_properties(qudo-mlkem PROPERTIES
    OUTPUT_NAME "qudo-mlkem"
    PUBLIC_HEADER "include/mlkem_wrapper.h;include/mlkem_types.h;include/mlkem_config.h"
    VERSION ${PROJECT_VERSION}
    SOVERSION ${PROJECT_VERSION_MAJOR}
)

# Symbol versioning (Linux/ELF only)
if(UNIX AND NOT APPLE)
    set_target_properties(qudo-mlkem PROPERTIES
        LINK_FLAGS "-Wl,--version-script=${CMAKE_CURRENT_SOURCE_DIR}/config/libqudo-mlkem.map"
    )
endif()

# Define DLL export macro when building shared library on Windows
if(WIN32 AND BUILD_SHARED_LIBS)
    target_compile_definitions(qudo-mlkem PRIVATE QUDO_KEM_BUILD_SHARED)
endif()

# Conditionally link OpenSSL
if(MLKEM_USE_OPENSSL AND OPENSSL_FOUND)
    target_link_libraries(qudo-mlkem PUBLIC OpenSSL::SSL OpenSSL::Crypto)
    target_include_directories(qudo-mlkem PRIVATE ${OPENSSL_INCLUDE_DIR})
endif()

# Platform-specific libraries
if(WIN32)
    target_link_libraries(qudo-mlkem PRIVATE ws2_32 bcrypt)
elseif(UNIX AND NOT APPLE)
    target_link_libraries(qudo-mlkem PRIVATE pthread dl)
endif()

# Compiler flags
if(MSVC)
    # Suppress harmless warnings for multilevel build pattern
    target_compile_options(qudo-mlkem PRIVATE /wd4013 /W4)
    if(MLKEM_DIST_BUILD)
        # DIST_BUILD uses ref/avx2/neon suffixed targets
        target_compile_options(mlkem512_ref_objs PRIVATE /wd4013)
        target_compile_options(mlkem768_ref_objs PRIVATE /wd4013)
        target_compile_options(mlkem1024_ref_objs PRIVATE /wd4013)
    elseif(TARGET mlkem512_objs)
        # Compile-time build uses unsuffixed targets
        target_compile_options(mlkem512_objs PRIVATE /wd4013)
        target_compile_options(mlkem768_objs PRIVATE /wd4013)
        target_compile_options(mlkem1024_objs PRIVATE /wd4013)
    endif()
else()
    target_compile_options(qudo-mlkem PRIVATE 
        -Wall -Wextra -Wpedantic
        -Wno-unused-parameter
    )
endif()

# AVX2 compile flag for the wrapper library — only on non-Windows x86_64
# (Windows excludes AVX2 native variants due to assembly incompatibility,
# so the wrapper should not require AVX2 instructions either)
if(ENABLE_AVX2 AND MLKEM_ARCH_X86_64 AND NOT WIN32)
    target_compile_options(qudo-mlkem PRIVATE -mavx2)
    add_definitions(-DMLKEM_USE_AVX2)
endif()

# Skip individual installation when built as part of qudo-pqc.
# The combined libqudo-pqc.so includes all ML-KEM code.
if(NOT QUDO_COMBINED_BUILD)

# Install targets
install(TARGETS qudo-mlkem
    EXPORT qudo-mlkem-targets
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
    ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
    PUBLIC_HEADER DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/qudo-mlkem
)

install(DIRECTORY include/ DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/qudo-mlkem)
install(FILES config/mlkem.conf DESTINATION ${CMAKE_INSTALL_SYSCONFDIR}/qudo-mlkem)

# Export targets
install(EXPORT qudo-mlkem-targets
    FILE qudo-mlkem-targets.cmake
    NAMESPACE qudo::
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/qudo-mlkem
)

# Generate and install package config
configure_package_config_file(
    ${CMAKE_CURRENT_SOURCE_DIR}/config/qudo-mlkem-config.cmake.in
    ${CMAKE_CURRENT_BINARY_DIR}/qudo-mlkem-config.cmake
    INSTALL_DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/qudo-mlkem
)

install(FILES
    ${CMAKE_CURRENT_BINARY_DIR}/qudo-mlkem-config.cmake
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/qudo-mlkem
)

# pkg-config
configure_file(config/qudo-mlkem.pc.in ${CMAKE_BINARY_DIR}/qudo-mlkem.pc @ONLY)
install(FILES ${CMAKE_BINARY_DIR}/qudo-mlkem.pc
        DESTINATION ${CMAKE_INSTALL_LIBDIR}/pkgconfig)

endif() # NOT QUDO_COMBINED_BUILD

# Build examples
if(BUILD_EXAMPLES)
    add_subdirectory(examples)
endif()

# Build tests
if(BUILD_TESTS)
    enable_testing()
    add_subdirectory(tests)
endif()

# Build fuzzing harnesses
if(BUILD_FUZZ)
    add_subdirectory(fuzz)
endif()

# Print build configuration (suppress in combined builds)
if(NOT MLKEM_QUIET)
message(STATUS "")
message(STATUS "=== QUDO KEM Build Configuration ===")
message(STATUS "Build type: ${CMAKE_BUILD_TYPE}")
message(STATUS "Shared libraries: ${BUILD_SHARED_LIBS}")
message(STATUS "Build examples: ${BUILD_EXAMPLES}")
message(STATUS "Build tests: ${BUILD_TESTS}")
if(MLKEM_ARCH_X86_64 AND NOT WIN32 AND ENABLE_AVX2)
    message(STATUS "Native optimizations: AVX2")
elseif(MLKEM_ARCH_ARM64 AND ENABLE_NEON)
    message(STATUS "Native optimizations: NEON")
elseif(WIN32 AND MLKEM_ARCH_X86_64)
    message(STATUS "Native optimizations: OFF (Windows — no assembly support)")
else()
    message(STATUS "Native optimizations: OFF (portable C)")
endif()
message(STATUS "Platform: ${PLATFORM_NAME}")
message(STATUS "====================================================")
message(STATUS "")
endif() # NOT MLKEM_QUIET
