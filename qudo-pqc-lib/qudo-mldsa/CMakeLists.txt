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
    project(QUDO_MLDSA VERSION 1.0.0 LANGUAGES C)
else()
    project(QUDO_MLDSA VERSION 1.0.0 LANGUAGES C ASM)
endif()

# Version information
set(MLDSA_VERSION_MAJOR 1)
set(MLDSA_VERSION_MINOR 0)
set(MLDSA_VERSION_PATCH 0)
set(MLDSA_VERSION_TEXT "${MLDSA_VERSION_MAJOR}.${MLDSA_VERSION_MINOR}.${MLDSA_VERSION_PATCH}")

# Build options
option(BUILD_SHARED_LIBS "Build shared libraries" ON)
option(MLDSA_BUILD_ONLY_LIB "Build only library without tests/examples" OFF)
option(BUILD_EXAMPLES "Build example programs" ON)
option(BUILD_TESTS "Build tests" ON)
option(MLDSA_USE_OPENSSL "Use OpenSSL for DER/PEM serialization" ON)
option(ENABLE_SANITIZERS "Enable AddressSanitizer and UndefinedBehaviorSanitizer" OFF)
option(ENABLE_COVERAGE "Enable code coverage instrumentation" OFF)
option(BUILD_FUZZ "Build fuzzing harnesses (requires Clang with libFuzzer)" OFF)
option(MLDSA_STRICT_WARNINGS "Enable strict compiler warnings" OFF)
option(MLDSA_EMBEDDED_BUILD "Build for embedded systems without full stdlib" OFF)

# Platform-specific optimizations
option(ENABLE_AVX2 "Enable AVX2 optimizations (x86_64)" ON)
option(ENABLE_NEON "Enable NEON optimizations (ARM64)" ON)
option(MLDSA_CT_VALGRIND "Build constant-time validation (MLD_CONFIG_CT_TESTING_ENABLED + Valgrind)" OFF)

# Set C standard
set(CMAKE_C_STANDARD 99)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)
set(CMAKE_C_VISIBILITY_PRESET hidden)

# Platform detection
if(WIN32)
    add_definitions(-D_CRT_SECURE_NO_WARNINGS)
    set(PLATFORM_NAME "Windows")
elseif(APPLE)
    set(PLATFORM_NAME "macOS")
elseif(UNIX)
    set(PLATFORM_NAME "Linux")
endif()

# Detect if being built as a subdirectory (combined build)
if(NOT CMAKE_SOURCE_DIR STREQUAL CMAKE_CURRENT_SOURCE_DIR)
    set(MLDSA_QUIET ON)
endif()

if(NOT MLDSA_QUIET)
    message(STATUS "Building qudo-mldsa for platform: ${PLATFORM_NAME}")
endif()

# Runtime CPU dispatch option (must be before mldsa-native build)
option(MLDSA_DIST_BUILD "Enable runtime CPU dispatch (multi-variant build)" ON)

if(MLDSA_DIST_BUILD)
    add_definitions(-DMLDSA_DIST_BUILD)
    add_definitions(-DMLD_CONFIG_RUNTIME_DISPATCH)
    if(NOT MLDSA_QUIET)
        message(STATUS "Runtime CPU dispatch enabled - will select variant at runtime")
    endif()
else()
    if(NOT MLDSA_QUIET)
        message(STATUS "Single variant build - no runtime dispatch")
    endif()
endif()

# Include standard modules
include(GNUInstallDirs)
include(CMakePackageConfigHelpers)

# OpenSSL detection (for DER/PEM serialization)
if(MLDSA_USE_OPENSSL)
    if(MLDSA_QUIET)
        find_package(OpenSSL 1.1.1 QUIET)
    else()
        find_package(OpenSSL 1.1.1)
    endif()

    if(OPENSSL_FOUND)
        if(NOT MLDSA_QUIET)
            message(STATUS "OpenSSL enabled for DER/PEM serialization")
            message(STATUS "  Version: ${OPENSSL_VERSION}")
            message(STATUS "  Include: ${OPENSSL_INCLUDE_DIR}")
            message(STATUS "  Libraries: ${OPENSSL_LIBRARIES}")
        endif()
        add_definitions(-DQUDO_MLDSA_USE_OPENSSL)
    else()
        message(WARNING "OpenSSL requested but not found. DER/PEM serialization disabled.")
        set(MLDSA_USE_OPENSSL OFF)
    endif()
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
    if(NOT MLDSA_EMBEDDED_BUILD)
        if(UNIX AND NOT APPLE AND NOT WIN32)
            add_link_options(-Wl,-z,relro -Wl,-z,now -Wl,-z,noexecstack)
        endif()
    endif()
elseif(MSVC)
    add_compile_options(/GS /sdl)
    add_definitions(-D_CRT_SECURE_NO_WARNINGS)
endif()

# Strict warnings
if(MLDSA_STRICT_WARNINGS)
    if(CMAKE_C_COMPILER_ID MATCHES "GNU|Clang")
        add_compile_options(-Wall -Wextra -Wpedantic -Werror)
    elseif(MSVC)
        add_compile_options(/W4 /WX)
    endif()
else()
    # Suppress warnings from mldsa-native multi-level build
    if(CMAKE_C_COMPILER_ID MATCHES "GNU")
        add_compile_options(
            -Wno-implicit-function-declaration
            -Wno-array-parameter
            -Wno-builtin-declaration-mismatch
        )
    elseif(CMAKE_C_COMPILER_ID MATCHES "Clang")
        add_compile_options(
            -Wno-implicit-function-declaration
        )
    endif()
endif()

# ========================================================================== #
#                          mldsa-native Integration                          #
# ========================================================================== #

# Build mldsa-native from source
set(MLDSA_NATIVE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/mldsa-native)

# Collect mldsa-native source files
file(GLOB MLDSA_NATIVE_CORE_SOURCES
    ${MLDSA_NATIVE_DIR}/mldsa/src/*.c
    ${MLDSA_NATIVE_DIR}/mldsa/src/fips202/*.c
)

# Architecture-specific sources
set(MLDSA_NATIVE_ARCH_SOURCES "")
if(CMAKE_SYSTEM_PROCESSOR MATCHES "x86_64|AMD64|amd64" AND ENABLE_AVX2 AND NOT WIN32)
    file(GLOB MLDSA_NATIVE_X86_SOURCES
        ${MLDSA_NATIVE_DIR}/mldsa/src/native/x86_64/src/*.c
        ${MLDSA_NATIVE_DIR}/mldsa/src/native/x86_64/src/*.S
        ${MLDSA_NATIVE_DIR}/mldsa/src/fips202/native/x86_64/src/*.c
        ${MLDSA_NATIVE_DIR}/mldsa/src/fips202/native/x86_64/src/*.S
    )
    list(APPEND MLDSA_NATIVE_ARCH_SOURCES ${MLDSA_NATIVE_X86_SOURCES})
    if(NOT MLDSA_QUIET)
        message(STATUS "Adding x86_64 AVX2 optimizations for ML-DSA")
    endif()
elseif(CMAKE_SYSTEM_PROCESSOR MATCHES "aarch64|arm64|ARM64" AND ENABLE_NEON)
    file(GLOB MLDSA_NATIVE_ARM_SOURCES
        ${MLDSA_NATIVE_DIR}/mldsa/src/native/aarch64/src/*.c
        ${MLDSA_NATIVE_DIR}/mldsa/src/native/aarch64/src/*.S
        ${MLDSA_NATIVE_DIR}/mldsa/src/fips202/native/aarch64/src/*.c
        ${MLDSA_NATIVE_DIR}/mldsa/src/fips202/native/aarch64/src/*.S
    )
    list(APPEND MLDSA_NATIVE_ARCH_SOURCES ${MLDSA_NATIVE_ARM_SOURCES})
    message(STATUS "Adding ARM64 NEON optimizations for ML-DSA")
endif()

# Constant-time validation: poison secret data with Valgrind annotations so any
# secret-dependent branch or memory index is reported. Runs against the C
# reference backend, so it requires a non-dist, non-AVX2 build:
#   -DMLDSA_DIST_BUILD=OFF -DENABLE_AVX2=OFF -DMLDSA_CT_VALGRIND=ON
if(MLDSA_CT_VALGRIND)
    add_definitions(-DMLD_CONFIG_CT_TESTING_ENABLED)
    message(STATUS "Constant-time validation enabled (MLD_CONFIG_CT_TESTING_ENABLED)")
endif()

set(MLDSA_NATIVE_SOURCES ${MLDSA_NATIVE_CORE_SOURCES} ${MLDSA_NATIVE_ARCH_SOURCES})

# Object libraries for each ML-DSA variant (multi-level build); with
# DIST_BUILD, separate _ref, _avx2, _neon variants for runtime dispatch.
if(MLDSA_DIST_BUILD)
    if(NOT MLDSA_QUIET)
        message(STATUS "Building ML-DSA with multi-variant support for runtime dispatch")
    endif()
    
    # Detect architecture for variant selection (gated by ENABLE_AVX2/ENABLE_NEON)
    set(MLDSA_ARCH_X86_64 OFF)
    set(MLDSA_ARCH_ARM64 OFF)
    set(MLDSA_ARCH_ARM32 OFF)
    if(CMAKE_SYSTEM_PROCESSOR MATCHES "x86_64|AMD64|amd64" AND ENABLE_AVX2)
        set(MLDSA_ARCH_X86_64 ON)
        if(NOT WIN32)
            add_definitions(-DQUDO_HAS_AVX2_VARIANT)
            if(NOT MLDSA_QUIET)
                message(STATUS "ML-DSA: Architecture x86_64 — AVX2 dispatch enabled")
            endif()
        else()
            if(NOT MLDSA_QUIET)
                message(STATUS "ML-DSA: Architecture x86_64 — ref only (no AVX2 assembly on Windows)")
            endif()
        endif()
    elseif(CMAKE_SYSTEM_PROCESSOR MATCHES "aarch64|arm64|ARM64" AND ENABLE_NEON)
        set(MLDSA_ARCH_ARM64 ON)
        add_definitions(-DQUDO_HAS_NEON_VARIANT)
        if(NOT MLDSA_QUIET)
            message(STATUS "ML-DSA: Architecture ARM64 — NEON dispatch enabled")
        endif()
    elseif(CMAKE_SYSTEM_PROCESSOR MATCHES "^arm|^armv7|^armhf")
        # ARM32 (ARMv7-A hard-float) — no ARM32-specific ASM; uses portable C reference
        set(MLDSA_ARCH_ARM32 ON)
        if(NOT MLDSA_QUIET)
            message(STATUS "ML-DSA: Architecture ARM32 (portable C, no NEON assembly)")
        endif()
    elseif(CMAKE_SYSTEM_PROCESSOR MATCHES "i[3456]86|x86")
        set(MLDSA_ARCH_X86_32 ON)
        if(NOT MLDSA_QUIET)
            message(STATUS "ML-DSA: Architecture x86 32-bit (portable C)")
        endif()
    else()
        message(STATUS "ML-DSA: Architecture ${CMAKE_SYSTEM_PROCESSOR} — using portable C reference")
    endif()
    
    # ML-DSA-44 variants
    add_library(mldsa44_ref_objs OBJECT ${MLDSA_NATIVE_CORE_SOURCES})
    target_compile_definitions(mldsa44_ref_objs PRIVATE 
        MLD_CONFIG_PARAMETER_SET=44
        MLD_CONFIG_MULTILEVEL_WITH_SHARED
        "MLD_CONFIG_NAMESPACE_PREFIX=mldsa_ref"
    )
    target_include_directories(mldsa44_ref_objs PRIVATE
        ${MLDSA_NATIVE_DIR}/mldsa
        ${MLDSA_NATIVE_DIR}/mldsa/src
    )
    
    if(MLDSA_ARCH_X86_64 AND NOT WIN32)
        file(GLOB MLDSA_NATIVE_X86_SOURCES
            ${MLDSA_NATIVE_DIR}/mldsa/src/native/x86_64/src/*.c
            ${MLDSA_NATIVE_DIR}/mldsa/src/native/x86_64/src/*.S
            ${MLDSA_NATIVE_DIR}/mldsa/src/fips202/native/x86_64/src/*.c
            ${MLDSA_NATIVE_DIR}/mldsa/src/fips202/native/x86_64/src/*.S
        )
        add_library(mldsa44_avx2_objs OBJECT ${MLDSA_NATIVE_CORE_SOURCES} ${MLDSA_NATIVE_X86_SOURCES})
        target_compile_definitions(mldsa44_avx2_objs PRIVATE 
            MLD_CONFIG_PARAMETER_SET=44
            MLD_CONFIG_MULTILEVEL_WITH_SHARED
            "MLD_CONFIG_NAMESPACE_PREFIX=mldsa_avx2"
            MLD_CONFIG_USE_NATIVE_BACKEND_ARITH
            MLD_CONFIG_USE_NATIVE_BACKEND_FIPS202
        )
        target_compile_options(mldsa44_avx2_objs PRIVATE -mavx2)
        target_include_directories(mldsa44_avx2_objs PRIVATE
            ${MLDSA_NATIVE_DIR}/mldsa
            ${MLDSA_NATIVE_DIR}/mldsa/src
        )
    endif()
    
    if(MLDSA_ARCH_ARM64)
        file(GLOB MLDSA_NATIVE_ARM_SOURCES
            ${MLDSA_NATIVE_DIR}/mldsa/src/native/aarch64/src/*.c
            ${MLDSA_NATIVE_DIR}/mldsa/src/native/aarch64/src/*.S
            ${MLDSA_NATIVE_DIR}/mldsa/src/fips202/native/aarch64/src/*.c
            ${MLDSA_NATIVE_DIR}/mldsa/src/fips202/native/aarch64/src/*.S
        )
        add_library(mldsa44_neon_objs OBJECT ${MLDSA_NATIVE_CORE_SOURCES} ${MLDSA_NATIVE_ARM_SOURCES})
        target_compile_definitions(mldsa44_neon_objs PRIVATE 
            MLD_CONFIG_PARAMETER_SET=44
            MLD_CONFIG_MULTILEVEL_WITH_SHARED
            "MLD_CONFIG_NAMESPACE_PREFIX=mldsa_neon"
            MLD_CONFIG_USE_NATIVE_BACKEND_ARITH
            MLD_CONFIG_USE_NATIVE_BACKEND_FIPS202
        )
        target_include_directories(mldsa44_neon_objs PRIVATE
            ${MLDSA_NATIVE_DIR}/mldsa
            ${MLDSA_NATIVE_DIR}/mldsa/src
        )
    endif()
    
    # ML-DSA-65 variants
    add_library(mldsa65_ref_objs OBJECT ${MLDSA_NATIVE_CORE_SOURCES})
    target_compile_definitions(mldsa65_ref_objs PRIVATE 
        MLD_CONFIG_PARAMETER_SET=65
        MLD_CONFIG_MULTILEVEL_NO_SHARED
        "MLD_CONFIG_NAMESPACE_PREFIX=mldsa_ref"
    )
    target_include_directories(mldsa65_ref_objs PRIVATE
        ${MLDSA_NATIVE_DIR}/mldsa
        ${MLDSA_NATIVE_DIR}/mldsa/src
    )
    
    if(MLDSA_ARCH_X86_64 AND NOT WIN32)
        add_library(mldsa65_avx2_objs OBJECT ${MLDSA_NATIVE_CORE_SOURCES} ${MLDSA_NATIVE_X86_SOURCES})
        target_compile_definitions(mldsa65_avx2_objs PRIVATE 
            MLD_CONFIG_PARAMETER_SET=65
            MLD_CONFIG_MULTILEVEL_NO_SHARED
            "MLD_CONFIG_NAMESPACE_PREFIX=mldsa_avx2"
            MLD_CONFIG_USE_NATIVE_BACKEND_ARITH
            MLD_CONFIG_USE_NATIVE_BACKEND_FIPS202
        )
        target_compile_options(mldsa65_avx2_objs PRIVATE -mavx2)
        target_include_directories(mldsa65_avx2_objs PRIVATE
            ${MLDSA_NATIVE_DIR}/mldsa
            ${MLDSA_NATIVE_DIR}/mldsa/src
        )
    endif()
    
    if(MLDSA_ARCH_ARM64)
        add_library(mldsa65_neon_objs OBJECT ${MLDSA_NATIVE_CORE_SOURCES} ${MLDSA_NATIVE_ARM_SOURCES})
        target_compile_definitions(mldsa65_neon_objs PRIVATE 
            MLD_CONFIG_PARAMETER_SET=65
            MLD_CONFIG_MULTILEVEL_NO_SHARED
            "MLD_CONFIG_NAMESPACE_PREFIX=mldsa_neon"
            MLD_CONFIG_USE_NATIVE_BACKEND_ARITH
            MLD_CONFIG_USE_NATIVE_BACKEND_FIPS202
        )
        target_include_directories(mldsa65_neon_objs PRIVATE
            ${MLDSA_NATIVE_DIR}/mldsa
            ${MLDSA_NATIVE_DIR}/mldsa/src
        )
    endif()
    
    # ML-DSA-87 variants
    add_library(mldsa87_ref_objs OBJECT ${MLDSA_NATIVE_CORE_SOURCES})
    target_compile_definitions(mldsa87_ref_objs PRIVATE 
        MLD_CONFIG_PARAMETER_SET=87
        MLD_CONFIG_MULTILEVEL_NO_SHARED
        "MLD_CONFIG_NAMESPACE_PREFIX=mldsa_ref"
    )
    target_include_directories(mldsa87_ref_objs PRIVATE
        ${MLDSA_NATIVE_DIR}/mldsa
        ${MLDSA_NATIVE_DIR}/mldsa/src
    )
    
    if(MLDSA_ARCH_X86_64 AND NOT WIN32)
        add_library(mldsa87_avx2_objs OBJECT ${MLDSA_NATIVE_CORE_SOURCES} ${MLDSA_NATIVE_X86_SOURCES})
        target_compile_definitions(mldsa87_avx2_objs PRIVATE 
            MLD_CONFIG_PARAMETER_SET=87
            MLD_CONFIG_MULTILEVEL_NO_SHARED
            "MLD_CONFIG_NAMESPACE_PREFIX=mldsa_avx2"
            MLD_CONFIG_USE_NATIVE_BACKEND_ARITH
            MLD_CONFIG_USE_NATIVE_BACKEND_FIPS202
        )
        target_compile_options(mldsa87_avx2_objs PRIVATE -mavx2)
        target_include_directories(mldsa87_avx2_objs PRIVATE
            ${MLDSA_NATIVE_DIR}/mldsa
            ${MLDSA_NATIVE_DIR}/mldsa/src
        )
    endif()
    
    if(MLDSA_ARCH_ARM64)
        add_library(mldsa87_neon_objs OBJECT ${MLDSA_NATIVE_CORE_SOURCES} ${MLDSA_NATIVE_ARM_SOURCES})
        target_compile_definitions(mldsa87_neon_objs PRIVATE 
            MLD_CONFIG_PARAMETER_SET=87
            MLD_CONFIG_MULTILEVEL_NO_SHARED
            "MLD_CONFIG_NAMESPACE_PREFIX=mldsa_neon"
            MLD_CONFIG_USE_NATIVE_BACKEND_ARITH
            MLD_CONFIG_USE_NATIVE_BACKEND_FIPS202
        )
        target_include_directories(mldsa87_neon_objs PRIVATE
            ${MLDSA_NATIVE_DIR}/mldsa
            ${MLDSA_NATIVE_DIR}/mldsa/src
        )
    endif()
    
else()
    # Single variant build - simple namespace
    add_library(mldsa44_objs OBJECT ${MLDSA_NATIVE_SOURCES})
    target_compile_definitions(mldsa44_objs PRIVATE 
        MLD_CONFIG_PARAMETER_SET=44
        MLD_CONFIG_MULTILEVEL_WITH_SHARED
        "MLD_CONFIG_NAMESPACE_PREFIX=mldsa"
    )
    # Enable native backends
    if(MLDSA_DIST_BUILD OR CMAKE_SYSTEM_PROCESSOR MATCHES "x86_64|AMD64|amd64|aarch64|arm64|ARM64")
        target_compile_definitions(mldsa44_objs PRIVATE
            MLD_CONFIG_USE_NATIVE_BACKEND_ARITH
            MLD_CONFIG_USE_NATIVE_BACKEND_FIPS202
        )
    endif()
    target_include_directories(mldsa44_objs PRIVATE
        ${MLDSA_NATIVE_DIR}/mldsa
        ${MLDSA_NATIVE_DIR}/mldsa/src
    )
    if(CMAKE_SYSTEM_PROCESSOR MATCHES "x86_64|AMD64|amd64" AND NOT WIN32)
        target_compile_options(mldsa44_objs PRIVATE -mavx2)
    endif()

    add_library(mldsa65_objs OBJECT ${MLDSA_NATIVE_SOURCES})
    target_compile_definitions(mldsa65_objs PRIVATE
        MLD_CONFIG_PARAMETER_SET=65
        MLD_CONFIG_MULTILEVEL_WITH_SHARED
        "MLD_CONFIG_NAMESPACE_PREFIX=mldsa"
    )
    # Enable native backends
    if(MLDSA_DIST_BUILD OR CMAKE_SYSTEM_PROCESSOR MATCHES "x86_64|AMD64|amd64|aarch64|arm64|ARM64")
        target_compile_definitions(mldsa65_objs PRIVATE
            MLD_CONFIG_USE_NATIVE_BACKEND_ARITH
            MLD_CONFIG_USE_NATIVE_BACKEND_FIPS202
        )
    endif()
    target_include_directories(mldsa65_objs PRIVATE
        ${MLDSA_NATIVE_DIR}/mldsa
        ${MLDSA_NATIVE_DIR}/mldsa/src
    )
    if(CMAKE_SYSTEM_PROCESSOR MATCHES "x86_64|AMD64|amd64" AND NOT WIN32)
        target_compile_options(mldsa65_objs PRIVATE -mavx2)
    endif()

    add_library(mldsa87_objs OBJECT ${MLDSA_NATIVE_SOURCES})
    target_compile_definitions(mldsa87_objs PRIVATE
        MLD_CONFIG_PARAMETER_SET=87
        MLD_CONFIG_MULTILEVEL_WITH_SHARED
        "MLD_CONFIG_NAMESPACE_PREFIX=mldsa"
    )
    # Enable native backends
    if(MLDSA_DIST_BUILD OR CMAKE_SYSTEM_PROCESSOR MATCHES "x86_64|AMD64|amd64|aarch64|arm64|ARM64")
        target_compile_definitions(mldsa87_objs PRIVATE
            MLD_CONFIG_USE_NATIVE_BACKEND_ARITH
            MLD_CONFIG_USE_NATIVE_BACKEND_FIPS202
        )
    endif()
    target_include_directories(mldsa87_objs PRIVATE
        ${MLDSA_NATIVE_DIR}/mldsa
        ${MLDSA_NATIVE_DIR}/mldsa/src
    )
    if(CMAKE_SYSTEM_PROCESSOR MATCHES "x86_64|AMD64|amd64" AND NOT WIN32)
        target_compile_options(mldsa87_objs PRIVATE -mavx2)
    endif()
    
endif()  # MLDSA_DIST_BUILD

if(NOT MLDSA_QUIET)
    message(STATUS "Building mldsa-native from source (CMake)")
endif()

# ========================================================================== #
#                          qudo-mldsa Library                                 #
# ========================================================================== #

# Library sources (absolute paths for parent scope export)
set(MLDSA_SOURCES
    ${CMAKE_CURRENT_SOURCE_DIR}/src/mldsa_wrapper.c
    ${CMAKE_CURRENT_SOURCE_DIR}/src/mldsa_shake256.c
    ${CMAKE_CURRENT_SOURCE_DIR}/src/mldsa_config.c
    ${CMAKE_CURRENT_SOURCE_DIR}/src/mldsa_error.c
    ${CMAKE_CURRENT_SOURCE_DIR}/src/mldsa_interop.c
    ${CMAKE_CURRENT_SOURCE_DIR}/src/mldsa_rand.c
    ${CMAKE_CURRENT_SOURCE_DIR}/src/mldsa_memory.c
    ${CMAKE_CURRENT_SOURCE_DIR}/src/platform_utils.c
    # SHA3/SHAKE from slhdsa-native for QUDO_MLDSA_shake256_* wrapper
    ${CMAKE_CURRENT_SOURCE_DIR}/../qudo-slhdsa/slhdsa-native/sha3_api.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../qudo-slhdsa/slhdsa-native/sha3_f1600.c
    # SHA-2 from slhdsa-native for HashML-DSA pre-hash mode
    ${CMAKE_CURRENT_SOURCE_DIR}/../qudo-slhdsa/slhdsa-native/sha2_256.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../qudo-slhdsa/slhdsa-native/sha2_512.c
)

# Runtime CPU dispatch sources (if DIST_BUILD enabled)
if(MLDSA_DIST_BUILD)
    list(APPEND MLDSA_SOURCES
        ${MLDSA_NATIVE_DIR}/qudo_runtime_dispatch/cpu_features.c
    )
endif()

# Create library with wrapper sources AND all variant object files
if(MLDSA_DIST_BUILD)
    # Multi-variant build - include all _ref, _avx2, _neon variants
    set(MLDSA_ALL_OBJS ${MLDSA_SOURCES})
    if(MLDSA_ARCH_X86_64 AND NOT WIN32)
        list(APPEND MLDSA_ALL_OBJS
            $<TARGET_OBJECTS:mldsa44_ref_objs>
            $<TARGET_OBJECTS:mldsa44_avx2_objs>
            $<TARGET_OBJECTS:mldsa65_ref_objs>
            $<TARGET_OBJECTS:mldsa65_avx2_objs>
            $<TARGET_OBJECTS:mldsa87_ref_objs>
            $<TARGET_OBJECTS:mldsa87_avx2_objs>
        )
    elseif(MLDSA_ARCH_X86_64 AND WIN32)
        # Windows x86_64: ref only (no AVX2 assembly)
        list(APPEND MLDSA_ALL_OBJS
            $<TARGET_OBJECTS:mldsa44_ref_objs>
            $<TARGET_OBJECTS:mldsa65_ref_objs>
            $<TARGET_OBJECTS:mldsa87_ref_objs>
        )
    elseif(MLDSA_ARCH_ARM64)
        list(APPEND MLDSA_ALL_OBJS
            $<TARGET_OBJECTS:mldsa44_ref_objs>
            $<TARGET_OBJECTS:mldsa44_neon_objs>
            $<TARGET_OBJECTS:mldsa65_ref_objs>
            $<TARGET_OBJECTS:mldsa65_neon_objs>
            $<TARGET_OBJECTS:mldsa87_ref_objs>
            $<TARGET_OBJECTS:mldsa87_neon_objs>
        )
    else()
        list(APPEND MLDSA_ALL_OBJS
            $<TARGET_OBJECTS:mldsa44_ref_objs>
            $<TARGET_OBJECTS:mldsa65_ref_objs>
            $<TARGET_OBJECTS:mldsa87_ref_objs>
        )
    endif()
    add_library(qudo-mldsa ${MLDSA_ALL_OBJS})
else()
    # Single variant build
    set(MLDSA_ALL_OBJS
        ${MLDSA_SOURCES}
        $<TARGET_OBJECTS:mldsa44_objs>
        $<TARGET_OBJECTS:mldsa65_objs>
        $<TARGET_OBJECTS:mldsa87_objs>
    )
    add_library(qudo-mldsa ${MLDSA_ALL_OBJS})
endif()

# Export for combined libqudo-pqc build (parent scope)
set(QUDO_MLDSA_ALL_OBJS ${MLDSA_ALL_OBJS} PARENT_SCOPE)

# Include directories
target_include_directories(qudo-mldsa
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
        $<INSTALL_INTERFACE:include>
    PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/mldsa-native/mldsa
        # mldsa_shake256.c uses sha3_api.h from slhdsa-native
        ${CMAKE_CURRENT_SOURCE_DIR}/../qudo-slhdsa/slhdsa-native
)

# Internal FIPS DRBG headers — provided by parent in combined build,
# or discovered from relative path in standalone build.
if(NOT QUDO_COMBINED_BUILD)
    if(EXISTS ${CMAKE_CURRENT_SOURCE_DIR}/../src/fips)
        target_include_directories(qudo-mldsa PRIVATE
            ${CMAKE_CURRENT_SOURCE_DIR}/../src
        )
    endif()
endif()

# Link system libraries
if(WIN32)
    target_link_libraries(qudo-mldsa PRIVATE bcrypt)
elseif(UNIX)
    target_link_libraries(qudo-mldsa PRIVATE m pthread)
endif()

# The Keccak assembly lives in qudo-slhdsa; use the portable C path in
# sha3_f1600.c for the standalone qudo-mldsa target.
target_compile_definitions(qudo-mldsa PRIVATE SLH_NO_ASM=1)

# Link OpenSSL (if enabled)
if(OPENSSL_FOUND)
    target_link_libraries(qudo-mldsa PRIVATE OpenSSL::SSL OpenSSL::Crypto)
    target_include_directories(qudo-mldsa PRIVATE ${OPENSSL_INCLUDE_DIR})
endif()

# Set library properties
set_target_properties(qudo-mldsa PROPERTIES
    OUTPUT_NAME "qudo-mldsa"
    PUBLIC_HEADER "include/mldsa_wrapper.h;include/mldsa_types.h;include/mldsa_config.h"
    VERSION ${PROJECT_VERSION}
    SOVERSION ${PROJECT_VERSION_MAJOR}
)

# Symbol versioning (Linux/ELF only)
if(UNIX AND NOT APPLE)
    set_target_properties(qudo-mldsa PROPERTIES
        LINK_FLAGS "-Wl,--version-script=${CMAKE_CURRENT_SOURCE_DIR}/config/libqudo-mldsa.map"
    )
endif()

# Compile definitions
target_compile_definitions(qudo-mldsa
    PRIVATE
        QUDO_MLDSA_BUILD_SHARED
    PUBLIC
        MLDSA_VERSION="${MLDSA_VERSION_TEXT}"
)

# ========================================================================== #
#                          Examples                                          #
# ========================================================================== #

if(BUILD_EXAMPLES AND NOT MLDSA_BUILD_ONLY_LIB)
    add_subdirectory(examples)
endif()

# ========================================================================== #
#                          Tests                                             #
# ========================================================================== #

if(BUILD_TESTS AND NOT MLDSA_BUILD_ONLY_LIB)
    enable_testing()
    add_subdirectory(tests)
endif()

# Build fuzzing harnesses
if(BUILD_FUZZ AND NOT MLDSA_BUILD_ONLY_LIB)
    add_subdirectory(fuzz)
endif()

# Skip individual installation when built as part of qudo-pqc.
# The combined libqudo-pqc.so includes all ML-DSA code.
if(NOT QUDO_COMBINED_BUILD)

install(TARGETS qudo-mldsa
    EXPORT qudo-mldsa-targets
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
    ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
    PUBLIC_HEADER DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/qudo-mldsa
)

# Export targets
install(EXPORT qudo-mldsa-targets
    FILE qudo-mldsa-targets.cmake
    NAMESPACE qudo::
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/qudo-mldsa
)

# Generate and install package config
configure_package_config_file(
    ${CMAKE_CURRENT_SOURCE_DIR}/config/qudo-mldsa-config.cmake.in
    ${CMAKE_CURRENT_BINARY_DIR}/qudo-mldsa-config.cmake
    INSTALL_DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/qudo-mldsa
)

install(FILES
    ${CMAKE_CURRENT_BINARY_DIR}/qudo-mldsa-config.cmake
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/qudo-mldsa
)

# pkg-config
configure_file(config/qudo-mldsa.pc.in ${CMAKE_BINARY_DIR}/qudo-mldsa.pc @ONLY)
install(FILES ${CMAKE_BINARY_DIR}/qudo-mldsa.pc
        DESTINATION ${CMAKE_INSTALL_LIBDIR}/pkgconfig)

endif() # NOT QUDO_COMBINED_BUILD

# Print configuration summary (suppress in combined builds)
if(NOT MLDSA_QUIET)
message(STATUS "")
message(STATUS "========================================")
message(STATUS "  qudo-mldsa Configuration Summary")
message(STATUS "========================================")
message(STATUS "  Version: ${MLDSA_VERSION_TEXT}")
message(STATUS "  Platform: ${PLATFORM_NAME}")
message(STATUS "  Build shared libs: ${BUILD_SHARED_LIBS}")
message(STATUS "  Build examples: ${BUILD_EXAMPLES}")
message(STATUS "  Build tests: ${BUILD_TESTS}")
if(MLDSA_ARCH_X86_64 AND NOT WIN32)
    message(STATUS "  Native optimizations: AVX2")
elseif(MLDSA_ARCH_ARM64)
    message(STATUS "  Native optimizations: NEON")
elseif(WIN32 AND MLDSA_ARCH_X86_64)
    message(STATUS "  Native optimizations: OFF (Windows — no assembly support)")
else()
    message(STATUS "  Native optimizations: OFF (portable C)")
endif()
message(STATUS "  mldsa-native: ${MLDSA_NATIVE_DIR}")
message(STATUS "========================================")
message(STATUS "")
endif() # NOT MLDSA_QUIET
