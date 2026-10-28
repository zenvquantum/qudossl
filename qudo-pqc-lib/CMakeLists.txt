# SPDX-License-Identifier: Apache-2.0 AND MIT
cmake_minimum_required(VERSION 3.15)

if(WIN32)
    project(qudo-pqc
        VERSION 1.0.0
        DESCRIPTION "QUDO PQC Crypto Library — ML-KEM, ML-DSA, SLH-DSA (FIPS 203/204/205)"
        LANGUAGES C
    )
else()
    project(qudo-pqc
        VERSION 1.0.0
        DESCRIPTION "QUDO PQC Crypto Library — ML-KEM, ML-DSA, SLH-DSA (FIPS 203/204/205)"
        LANGUAGES C ASM
    )
endif()

# ========================================================================== #
# Build Options                                                               #
# ========================================================================== #

option(QUDO_FIPS_MODULE "Build as FIPS 140-3 module (POST, KATs, integrity, state machine)" OFF)
option(QUDO_PQC_BUILD_TESTS "Build library-level tests" ON)
option(QUDO_FUZZ_REPLAY "Build fuzz corpus replay tests (needs a populated corpus_* dir)" OFF)
option(BUILD_ACVP "Build ACVP runners that replay published NIST ACVP test vectors" OFF)
option(QUDO_BUILD_EMBEDDED_OBJ "Build static archive + qudo_fips_module.o partial-link for embedded/firmware use (QUDO_FIPS_MODULE only)" OFF)
option(ENABLE_SANITIZERS "Enable AddressSanitizer + UndefinedBehaviorSanitizer" OFF)
option(ENABLE_MSAN "Enable MemorySanitizer (Clang only, incompatible with ASan)" OFF)
option(ENABLE_TSAN "Enable ThreadSanitizer (incompatible with ASan)" OFF)
option(ENABLE_COVERAGE "Enable code coverage instrumentation (gcov/lcov)" OFF)
option(QUDO_PQC_USE_HOST_DRBG "Route randomness to a host-provided RNG instead of the embedded CTR-DRBG" OFF)
# Math-only: the host supplies self-tests, DRBG, integrity, state machine and
# indicator; this library provides only the PQC algorithm math.
option(QUDO_PQC_MATH_ONLY "Build PQC algorithm math only; host supplies self-tests, DRBG and integrity. Mutually exclusive with QUDO_FIPS_MODULE." OFF)

option(QUDO_PQC_DISABLE_EMBEDDED_HMAC "Disable the embedded integrity HMAC self-check; the host checks integrity" OFF)

if(QUDO_PQC_MATH_ONLY AND QUDO_FIPS_MODULE)
    message(FATAL_ERROR
        "QUDO_PQC_MATH_ONLY and QUDO_FIPS_MODULE are mutually exclusive.")
endif()
if(QUDO_PQC_MATH_ONLY AND (QUDO_PQC_USE_HOST_DRBG OR QUDO_PQC_DISABLE_EMBEDDED_HMAC))
    message(FATAL_ERROR
        "QUDO_PQC_MATH_ONLY already excludes the embedded DRBG and integrity "
        "HMAC; QUDO_PQC_USE_HOST_DRBG / QUDO_PQC_DISABLE_EMBEDDED_HMAC do not apply.")
endif()

if(QUDO_PQC_USE_HOST_DRBG AND NOT QUDO_FIPS_MODULE)
    message(FATAL_ERROR "QUDO_PQC_USE_HOST_DRBG requires QUDO_FIPS_MODULE=ON")
endif()
if(QUDO_PQC_DISABLE_EMBEDDED_HMAC AND NOT QUDO_FIPS_MODULE)
    message(FATAL_ERROR "QUDO_PQC_DISABLE_EMBEDDED_HMAC requires QUDO_FIPS_MODULE=ON")
endif()

# Generate build config header — exposes QUDO_FIPS_MODULE to consumers
configure_file(
    ${CMAKE_CURRENT_SOURCE_DIR}/include/qudo_pqc_build_config.h.in
    ${CMAKE_CURRENT_BINARY_DIR}/include/qudo_pqc_build_config.h
)

# ========================================================================== #
# Compiler Configuration                                                      #
# ========================================================================== #

set(CMAKE_C_STANDARD 99)
set(CMAKE_C_STANDARD_REQUIRED ON)

if(NOT ENABLE_COVERAGE)
    if(CMAKE_C_COMPILER_ID MATCHES "GNU|Clang")
        add_compile_options(-O3 -fomit-frame-pointer)
    elseif(MSVC)
        add_compile_options(/O2)
    endif()
endif()

if(ENABLE_COVERAGE)
    if(CMAKE_C_COMPILER_ID MATCHES "GNU|Clang")
        add_compile_options(--coverage -fprofile-arcs -ftest-coverage)
        add_link_options(--coverage)
        message(STATUS "Code coverage enabled")
    endif()
endif()

# ========================================================================== #
# Security Hardening                                                          #
# ========================================================================== #

if(CMAKE_C_COMPILER_ID MATCHES "GNU|Clang")
    add_compile_options(-fstack-protector-strong)
    if(NOT CMAKE_BUILD_TYPE STREQUAL "Debug" AND NOT ENABLE_SANITIZERS)
        add_compile_options(-D_FORTIFY_SOURCE=2)
    endif()
    # Strip source paths from the binary (reproducible builds)
    add_compile_options(-ffile-prefix-map=${CMAKE_SOURCE_DIR}=.)
    # Only QUDO_*_API functions are exported.
    add_compile_options(-fvisibility=hidden)
    # Warnings
    add_compile_options(-Wall -Wextra)

    if(QUDO_FIPS_MODULE)
        if(NOT DEFINED ENV{SOURCE_DATE_EPOCH})
            set(ENV{SOURCE_DATE_EPOCH} "1704067200")
        endif()
        message(STATUS "Reproducible build — SOURCE_DATE_EPOCH=$ENV{SOURCE_DATE_EPOCH}")
        # Suppress the per-build GNU ld build-id (ELF only).
        if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
            add_link_options(-Wl,--build-id=none)
        endif()
    endif()
endif()

if(ENABLE_SANITIZERS)
    if(CMAKE_C_COMPILER_ID MATCHES "GNU|Clang")
        add_compile_options(-fsanitize=address,undefined -fno-omit-frame-pointer -fno-sanitize-recover=all -fPIC)
        add_link_options(-fsanitize=address,undefined)
        message(STATUS "Sanitizers enabled: ASan + UBSan")
    endif()
endif()

if(ENABLE_MSAN)
    if(ENABLE_SANITIZERS)
        message(FATAL_ERROR "ENABLE_MSAN is incompatible with ENABLE_SANITIZERS (ASan). Use only one.")
    endif()
    if(ENABLE_TSAN)
        message(FATAL_ERROR "ENABLE_MSAN is incompatible with ENABLE_TSAN. Use only one.")
    endif()
    if(NOT CMAKE_C_COMPILER_ID MATCHES "Clang")
        message(FATAL_ERROR "ENABLE_MSAN requires Clang. GCC does not support MemorySanitizer.")
    endif()
    add_compile_options(-fsanitize=memory -fno-omit-frame-pointer -fPIC)
    add_link_options(-fsanitize=memory)
    message(STATUS "Sanitizers enabled: MSan (MemorySanitizer)")
endif()

if(ENABLE_TSAN)
    if(ENABLE_SANITIZERS)
        message(FATAL_ERROR "ENABLE_TSAN is incompatible with ENABLE_SANITIZERS (ASan). Use only one.")
    endif()
    if(ENABLE_MSAN)
        message(FATAL_ERROR "ENABLE_TSAN is incompatible with ENABLE_MSAN. Use only one.")
    endif()
    if(CMAKE_C_COMPILER_ID MATCHES "GNU|Clang")
        add_compile_options(-fsanitize=thread -fno-omit-frame-pointer -fPIC)
        add_link_options(-fsanitize=thread)
        message(STATUS "Sanitizers enabled: TSan (ThreadSanitizer)")
    endif()
endif()

# ========================================================================== #
# Internal crypto (AES-256-CTR-DRBG, HMAC); no OpenSSL dependency           #
# ========================================================================== #

set(QUDO_PQC_USE_OPENSSL OFF)

# ========================================================================== #
# Algorithm Sub-Libraries                                                     #
# ========================================================================== #

# Sub-libraries build without tests, examples or OpenSSL; only libqudo-pqc is
# installed (QUDO_COMBINED_BUILD).
set(BUILD_TESTS OFF)
set(BUILD_EXAMPLES OFF)
set(MLKEM_USE_OPENSSL OFF)
set(MLDSA_USE_OPENSSL OFF)
set(SLHDSA_USE_OPENSSL OFF)
set(QUDO_COMBINED_BUILD ON)

# Sub-libraries need access to internal DRBG headers (src/fips/)
set(QUDO_PQC_FIPS_INCLUDE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/src/fips
    CACHE INTERNAL "Internal FIPS crypto headers for sub-libraries")
set(QUDO_PQC_INCLUDE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/include
    CACHE INTERNAL "QUDO PQC public headers for sub-libraries")
set(QUDO_PQC_SRC_INCLUDE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/src
    CACHE INTERNAL "QUDO PQC internal headers for sub-libraries")

# Keep all algorithm code in one contiguous .text section for the integrity HMAC.
if(QUDO_FIPS_MODULE AND CMAKE_C_COMPILER_ID MATCHES "GNU|Clang")
    add_compile_options(-fno-function-sections -fno-data-sections)
endif()

add_subdirectory(qudo-mlkem)
add_subdirectory(qudo-mldsa)
add_subdirectory(qudo-slhdsa)

# Parent include paths for sub-library targets. The generated build-config
# directory is omitted: QUDO_FIPS_MODULE applies only to the combined target.
target_include_directories(qudo-mlkem PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/src/fips
    ${CMAKE_CURRENT_SOURCE_DIR}/src
    ${CMAKE_CURRENT_SOURCE_DIR}/include
)
target_include_directories(qudo-mldsa PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/src/fips
    ${CMAKE_CURRENT_SOURCE_DIR}/src
    ${CMAKE_CURRENT_SOURCE_DIR}/include
)
target_include_directories(qudo-slhdsa PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/src/fips
    ${CMAKE_CURRENT_SOURCE_DIR}/src
    ${CMAKE_CURRENT_SOURCE_DIR}/include
)

# ========================================================================== #
# FIPS Infrastructure Sources                                                 #
# ========================================================================== #

# Integrity-region markers, linked first and last; not used in math-only mode.
if(QUDO_PQC_MATH_ONLY)
    set(QUDO_PQC_BOUNDARY_START "")
    set(QUDO_PQC_BOUNDARY_END   "")
else()
    set(QUDO_PQC_BOUNDARY_START src/qudo_fips_boundary_start.c)
    set(QUDO_PQC_BOUNDARY_END   src/qudo_fips_boundary_end.c)
endif()

# Inner sources (everything between the boundaries)

# Symbol-visibility and combined-build definitions for a target:
#
#   QUDO_*_BUILD_SHARED  only for a real shared build (Windows dllexport).
#   QUDO_*_STATIC_LINK   for a static build, so the API macros expand to
#                        nothing instead of __declspec(dllimport), which MSVC
#                        rejects on the library's own definitions (C2491).
#   QUDO_COMBINED_BUILD  routes randomness through the embedded DRBG
#                        (omitted in math-only mode).
function(qudo_apply_linkage_defs tgt)
    if(BUILD_SHARED_LIBS)
        target_compile_definitions(${tgt} PRIVATE
            QUDO_KEM_BUILD_SHARED
            QUDO_MLDSA_BUILD_SHARED
            QUDO_SLHDSA_BUILD_SHARED)
    else()
        target_compile_definitions(${tgt} PRIVATE
            QUDO_KEM_STATIC_LINK
            QUDO_MLDSA_STATIC_LINK
            QUDO_SLHDSA_STATIC_LINK
            QUDO_PQC_STATIC_LINK)
    endif()
    if(QUDO_PQC_MATH_ONLY)
        target_compile_definitions(${tgt} PRIVATE QUDO_PQC_MATH_ONLY)
    else()
        target_compile_definitions(${tgt} PRIVATE QUDO_COMBINED_BUILD)
    endif()
endfunction()

# Always required: platform shims, security helpers, utilities.
set(QUDO_PQC_INNER_SOURCES
    src/qudo_pqc_platform.c
    src/qudo_pqc_security.c
    src/qudo_pqc_utils.c
)

# Self-test, integrity and audit services; omitted in math-only mode.
if(NOT QUDO_PQC_MATH_ONLY)
    list(APPEND QUDO_PQC_INNER_SOURCES
        src/qudo_pqc_audit.c
        src/qudo_pqc_indicator.c
        src/qudo_pqc_init.c
        src/qudo_pqc_post.c
        src/qudo_pqc_pct.c
        src/qudo_pqc_integrity.c
        src/qudo_pqc_embedded_hmac.c
    )
endif()

# Internal AES-256-CTR-DRBG (SP 800-90A) and HMAC-SHA-256; omitted in
# math-only mode. AES dispatches at runtime between AES-NI and a
# constant-time portable implementation.
if(NOT QUDO_PQC_MATH_ONLY)
    list(APPEND QUDO_PQC_INNER_SOURCES
        src/fips/qudo_fips_aes.c
        src/fips/qudo_fips_aes_ct.c
        src/fips/qudo_fips_ctrdrbg.c
        src/fips/qudo_fips_hmac.c
        src/fips/qudo_fips_rand.c
    )
endif()

# AES-NI hardware acceleration — x86/x86-64 only
if(CMAKE_SYSTEM_PROCESSOR MATCHES "(x86_64|amd64|AMD64|i[3-6]86)" AND NOT QUDO_PQC_MATH_ONLY)
    list(APPEND QUDO_PQC_INNER_SOURCES src/fips/qudo_fips_aes_ni.c)
    if(NOT MSVC)
        set_source_files_properties(src/fips/qudo_fips_aes_ni.c PROPERTIES
            COMPILE_FLAGS "-maes -msse4.1")
    endif()
endif()

# Combined source list for shared/static libraries:
# boundary_start FIRST, inner sources, algorithm objects added in add_library,
# boundary_end LAST
set(QUDO_PQC_SOURCES
    ${QUDO_PQC_BOUNDARY_START}
    ${QUDO_PQC_INNER_SOURCES}
)

# ========================================================================== #
# Combined Library: libqudo-pqc                                                #
#                                                                              #
# BUILD_SHARED_LIBS (default ON):                                             #
#   ON  → libqudo-pqc.so (shared library)                                    #
#   OFF → libqudo-pqc.a  (static library)                                    #
# ========================================================================== #

option(BUILD_SHARED_LIBS "Build shared library (ON) or static library (OFF)" ON)

add_library(qudo-pqc
    ${QUDO_PQC_SOURCES}
    ${QUDO_MLKEM_ALL_OBJS}
    ${QUDO_MLDSA_ALL_OBJS}
    ${QUDO_SLHDSA_ALL_OBJS}
    ${QUDO_PQC_BOUNDARY_END}
)

set_target_properties(qudo-pqc PROPERTIES
    OUTPUT_NAME "qudo-pqc"
    LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib
    ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib
    VERSION ${PROJECT_VERSION}
    SOVERSION 1
)
if(WIN32)
    set_target_properties(qudo-pqc PROPERTIES
        RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib
        RUNTIME_OUTPUT_DIRECTORY_RELEASE ${CMAKE_BINARY_DIR}/lib
        RUNTIME_OUTPUT_DIRECTORY_DEBUG ${CMAKE_BINARY_DIR}/lib
    )
endif()

target_include_directories(qudo-pqc PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
    $<BUILD_INTERFACE:${CMAKE_CURRENT_BINARY_DIR}/include>
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/qudo-mlkem/include>
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/qudo-mldsa/include>
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/qudo-slhdsa/include>
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/qudo-mlkem/mlkem-native/mlkem>
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/qudo-mlkem/mlkem-native>
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/qudo-mlkem/mlkem-native/qudo_runtime_dispatch>
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/qudo-mldsa/mldsa-native/mldsa>
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/qudo-slhdsa/slhdsa-native>
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/qudo-slhdsa/src>
    $<INSTALL_INTERFACE:include/qudo-pqc>
)

# Private includes for FIPS infrastructure
target_include_directories(qudo-pqc PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/src
    ${CMAKE_CURRENT_SOURCE_DIR}/src/fips
)

# Compile definitions
target_compile_definitions(qudo-pqc PRIVATE
    QUDO_PQC_BUILDING
    MLKEM_DIST_BUILD
    MLK_CONFIG_RUNTIME_DISPATCH
    MLDSA_DIST_BUILD
)
qudo_apply_linkage_defs(qudo-pqc)

if(QUDO_FIPS_MODULE)
    target_compile_definitions(qudo-pqc PRIVATE QUDO_FIPS_MODULE)
    if(QUDO_PQC_USE_HOST_DRBG)
        target_compile_definitions(qudo-pqc PRIVATE QUDO_PQC_USE_HOST_DRBG)
    endif()
    if(QUDO_PQC_DISABLE_EMBEDDED_HMAC)
        target_compile_definitions(qudo-pqc PRIVATE QUDO_PQC_DISABLE_EMBEDDED_HMAC)
    endif()

    # Keep functions in .text so the integrity region is contiguous.
    if(CMAKE_C_COMPILER_ID MATCHES "GNU|Clang")
        target_compile_options(qudo-pqc PRIVATE -fno-function-sections)
    endif()

    # Linker script placing boundary_start first and boundary_end last in .text
    # (GNU ld/ELF only).
    if(CMAKE_C_COMPILER_ID MATCHES "GNU|Clang" AND UNIX AND NOT APPLE)
        set(QUDO_FIPS_LINKER_SCRIPT
            "${CMAKE_CURRENT_SOURCE_DIR}/cmake/fips_module.ld")
        if(NOT EXISTS "${QUDO_FIPS_LINKER_SCRIPT}")
            message(FATAL_ERROR
                "FIPS: linker script ${QUDO_FIPS_LINKER_SCRIPT} missing — "
                "required for integrity-region coverage.")
        endif()
        target_link_options(qudo-pqc PRIVATE
            "-Wl,-T,${QUDO_FIPS_LINKER_SCRIPT}")
        message(STATUS "FIPS: applied linker script ${QUDO_FIPS_LINKER_SCRIPT}")
    endif()

    # Reject options that break the contiguous integrity region.
    if(CMAKE_C_FLAGS MATCHES "-ffunction-sections")
        message(FATAL_ERROR
            "FIPS: -ffunction-sections in CMAKE_C_FLAGS breaks the "
            "in-memory integrity boundary. Remove it or rely on "
            "-fno-function-sections (added per-target).")
    endif()
    if(CMAKE_INTERPROCEDURAL_OPTIMIZATION)
        message(FATAL_ERROR
            "FIPS: LTO (CMAKE_INTERPROCEDURAL_OPTIMIZATION) reorders "
            "functions across the integrity boundary markers and is not "
            "supported with QUDO_FIPS_MODULE.")
    endif()
    # Post-link check that all module symbols lie inside the integrity region.
    if(CMAKE_C_COMPILER_ID MATCHES "GNU|Clang" AND UNIX AND NOT APPLE)
        add_custom_command(TARGET qudo-pqc POST_BUILD
            COMMAND sh
                "${CMAKE_CURRENT_SOURCE_DIR}/cmake/check_fips_boundary.sh"
                "$<TARGET_FILE:qudo-pqc>"
            COMMENT "FIPS: post-link boundary-coverage check"
            VERBATIM
        )
    endif()

    message(STATUS "FIPS 140-3 module build enabled")
endif()

# CPU variant definitions
if(CMAKE_SYSTEM_PROCESSOR MATCHES "x86_64|AMD64|amd64")
    if(NOT WIN32)
        target_compile_definitions(qudo-pqc PRIVATE QUDO_HAS_AVX2_VARIANT)
    endif()
    if(WIN32)
        target_compile_definitions(qudo-pqc PRIVATE SLH_NO_ASM=1)
    endif()
    if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
        target_compile_definitions(qudo-pqc PRIVATE SLH_HAS_SHA_NI)
    endif()
elseif(CMAKE_SYSTEM_PROCESSOR MATCHES "aarch64|arm64|ARM64")
    target_compile_definitions(qudo-pqc PRIVATE QUDO_HAS_NEON_VARIANT)
endif()

# Platform libraries
if(WIN32)
    target_link_libraries(qudo-pqc PRIVATE bcrypt)
elseif(UNIX)
    target_link_libraries(qudo-pqc PRIVATE pthread dl)
    if(NOT APPLE)
        target_link_libraries(qudo-pqc PRIVATE m)
    endif()
endif()

# ========================================================================== #
# Linker Hardening & Symbol Visibility for libqudo-pqc.so                     #
# ========================================================================== #

if(BUILD_SHARED_LIBS AND UNIX)
    if(NOT APPLE)
        # Full RELRO — makes GOT read-only after symbol resolution
        target_link_options(qudo-pqc PRIVATE -Wl,-z,relro -Wl,-z,now)
        # Non-executable stack
        target_link_options(qudo-pqc PRIVATE -Wl,-z,noexecstack)
        # Version script — restricts exported symbols to public API only
        set(PQC_VERSION_SCRIPT "${CMAKE_CURRENT_SOURCE_DIR}/config/libqudo-pqc.map")
        if(EXISTS "${PQC_VERSION_SCRIPT}")
            target_link_options(qudo-pqc PRIVATE
                "-Wl,--version-script=${PQC_VERSION_SCRIPT}")
        endif()
    elseif(APPLE)
        target_link_options(qudo-pqc PRIVATE -Wl,-dead_strip)
    endif()
endif()


# ========================================================================== #
# Static library used by the qudo_fips_module.o partial link               #
# ========================================================================== #

if(QUDO_FIPS_MODULE AND QUDO_BUILD_EMBEDDED_OBJ)

add_library(qudo-pqc-static STATIC
    ${QUDO_PQC_SOURCES}
    ${QUDO_MLKEM_ALL_OBJS}
    ${QUDO_MLDSA_ALL_OBJS}
    ${QUDO_SLHDSA_ALL_OBJS}
    ${QUDO_PQC_BOUNDARY_END}
)

set_target_properties(qudo-pqc-static PROPERTIES
    ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib
)
if(WIN32)
    set_target_properties(qudo-pqc-static PROPERTIES OUTPUT_NAME "qudo-pqc-static")
else()
    set_target_properties(qudo-pqc-static PROPERTIES OUTPUT_NAME "qudo-pqc")
endif()

target_include_directories(qudo-pqc-static PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
    $<BUILD_INTERFACE:${CMAKE_CURRENT_BINARY_DIR}/include>
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/qudo-mlkem/include>
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/qudo-mldsa/include>
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/qudo-slhdsa/include>
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/qudo-mlkem/mlkem-native/mlkem>
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/qudo-mlkem/mlkem-native>
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/qudo-mlkem/mlkem-native/qudo_runtime_dispatch>
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/qudo-mldsa/mldsa-native/mldsa>
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/qudo-slhdsa/slhdsa-native>
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/qudo-slhdsa/src>
)

target_include_directories(qudo-pqc-static PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/src
    ${CMAKE_CURRENT_SOURCE_DIR}/src/fips
)

target_compile_definitions(qudo-pqc-static PRIVATE
    QUDO_PQC_BUILDING
    MLKEM_DIST_BUILD
    MLK_CONFIG_RUNTIME_DISPATCH
    MLDSA_DIST_BUILD
    QUDO_COMBINED_BUILD
    QUDO_FIPS_MODULE
)
if(CMAKE_C_COMPILER_ID MATCHES "GNU|Clang")
    target_compile_options(qudo-pqc-static PRIVATE -fno-function-sections)
endif()
if(CMAKE_SYSTEM_PROCESSOR MATCHES "x86_64|AMD64|amd64")
    if(NOT WIN32)
        target_compile_definitions(qudo-pqc-static PRIVATE QUDO_HAS_AVX2_VARIANT)
    endif()
    if(WIN32)
        target_compile_definitions(qudo-pqc-static PRIVATE SLH_NO_ASM=1)
    endif()
    if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
        target_compile_definitions(qudo-pqc-static PRIVATE SLH_HAS_SHA_NI)
    endif()
elseif(CMAKE_SYSTEM_PROCESSOR MATCHES "aarch64|arm64|ARM64")
    target_compile_definitions(qudo-pqc-static PRIVATE QUDO_HAS_NEON_VARIANT)
endif()

endif() # QUDO_FIPS_MODULE AND QUDO_BUILD_EMBEDDED_OBJ

# ========================================================================== #
# FIPS Module Object — Partial Link for Embedded/Static Linking               #
# ========================================================================== #

#
# Creates a single qudo_fips_module.o via partial link (ld -r) so object
# order (boundary_start, module code, boundary_end) is preserved when
# statically linked.
#
# Usage (embedded firmware):
#   arm-none-eabi-gcc -o firmware.elf main.o qudo_fips_module.o -lc
#   qudo_fipsinstall -embed -module firmware.elf
#
if(QUDO_FIPS_MODULE AND QUDO_BUILD_EMBEDDED_OBJ AND CMAKE_C_COMPILER_ID MATCHES "GNU|Clang")
    set(QUDO_FIPS_MODULE_OBJ ${CMAKE_BINARY_DIR}/lib/qudo_fips_module.o)

    add_custom_command(
        OUTPUT ${QUDO_FIPS_MODULE_OBJ}
        COMMAND ${CMAKE_COMMAND}
            -DSTATIC_LIB=$<TARGET_FILE:qudo-pqc-static>
            -DOUTPUT_OBJ=${QUDO_FIPS_MODULE_OBJ}
            -DAR=${CMAKE_AR}
            -DCC=${CMAKE_C_COMPILER}
            -DTMPDIR=${CMAKE_BINARY_DIR}/_fips_partial_link
            -P ${CMAKE_CURRENT_SOURCE_DIR}/cmake/fips_partial_link.cmake
        DEPENDS qudo-pqc-static
        COMMENT "Creating qudo_fips_module.o (partial link with boundary ordering)"
        VERBATIM
    )

    add_custom_target(qudo-fips-module DEPENDS ${QUDO_FIPS_MODULE_OBJ})

    message(STATUS "FIPS module object target: qudo-fips-module (make qudo-fips-module)")
endif()

# ========================================================================== #
# FIPS Install Tool                                                           #
# ========================================================================== #

# qudo_fipsinstall: computes the integrity HMAC using the library's HMAC-SHA-256 sources.
add_executable(qudo_fipsinstall
    tools/qudo_fipsinstall.c
    src/fips/qudo_fips_hmac.c
    qudo-slhdsa/slhdsa-native/sha2_256.c
)
target_include_directories(qudo_fipsinstall PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/include
    ${CMAKE_CURRENT_SOURCE_DIR}/src/fips
    ${CMAKE_CURRENT_SOURCE_DIR}/qudo-slhdsa/slhdsa-native
)
# Sources are compiled directly into the tool, so no dllimport/dllexport.
target_compile_definitions(qudo_fipsinstall PRIVATE QUDO_PQC_STATIC_LINK)
set_target_properties(qudo_fipsinstall PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/tools"
)
install(TARGETS qudo_fipsinstall RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})

# qudo_fipsinstall -embed is run manually after all post-processing
# (strip, codesign on macOS):
#   ./tools/qudo_fipsinstall -embed -module ./lib/libqudo-pqc.so

# ========================================================================== #
# Installation                                                                #
# ========================================================================== #

include(GNUInstallDirs)

install(TARGETS qudo-pqc
    EXPORT qudo-pqc-targets
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
    ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
    RUNTIME DESTINATION bin
)

# Install public headers
install(DIRECTORY include/ DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/qudo-pqc
    FILES_MATCHING PATTERN "*.h"
    PATTERN "*.h.in" EXCLUDE
)
install(FILES ${CMAKE_CURRENT_BINARY_DIR}/include/qudo_pqc_build_config.h
    DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/qudo-pqc
)
install(DIRECTORY qudo-mlkem/include/ DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/qudo-pqc
    FILES_MATCHING PATTERN "*.h"
)
install(DIRECTORY qudo-mldsa/include/ DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/qudo-pqc
    FILES_MATCHING PATTERN "*.h"
)
install(DIRECTORY qudo-slhdsa/include/ DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/qudo-pqc
    FILES_MATCHING PATTERN "*.h"
)

# Export targets for find_package(qudo-pqc)
install(EXPORT qudo-pqc-targets
    FILE qudo-pqc-targets.cmake
    NAMESPACE qudo::
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/qudo-pqc
)

export(EXPORT qudo-pqc-targets
    FILE ${CMAKE_CURRENT_BINARY_DIR}/qudo-pqc-targets.cmake
    NAMESPACE qudo::
)

# CMake package config — enables find_package(qudo-pqc)
include(CMakePackageConfigHelpers)

configure_package_config_file(
    ${CMAKE_CURRENT_SOURCE_DIR}/cmake/qudo-pqc-config.cmake.in
    ${CMAKE_CURRENT_BINARY_DIR}/qudo-pqc-config.cmake
    INSTALL_DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/qudo-pqc
)

write_basic_package_version_file(
    ${CMAKE_CURRENT_BINARY_DIR}/qudo-pqc-config-version.cmake
    VERSION ${PROJECT_VERSION}
    COMPATIBILITY SameMajorVersion
)

install(FILES
    ${CMAKE_CURRENT_BINARY_DIR}/qudo-pqc-config.cmake
    ${CMAKE_CURRENT_BINARY_DIR}/qudo-pqc-config-version.cmake
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/qudo-pqc
)

install(FILES
    ${CMAKE_CURRENT_SOURCE_DIR}/LICENSE
    ${CMAKE_CURRENT_SOURCE_DIR}/README.md
    ${CMAKE_CURRENT_SOURCE_DIR}/CHANGELOG.md
    ${CMAKE_CURRENT_SOURCE_DIR}/CONTRIBUTING.md
    ${CMAKE_CURRENT_SOURCE_DIR}/SECURITY.md
    DESTINATION ${CMAKE_INSTALL_DOCDIR}
)

# ========================================================================== #
# Tests                                                                       #
# ========================================================================== #

# The test suite links the DRBG, self-test and integrity services, which
# math-only builds omit.
if(QUDO_PQC_BUILD_TESTS AND QUDO_PQC_MATH_ONLY)
    message(STATUS
        "QUDO_PQC_MATH_ONLY=ON: skipping the standalone test suite "
        "(it links this library's FIPS services, which math-only omits)")
endif()

if(QUDO_PQC_BUILD_TESTS AND NOT QUDO_PQC_MATH_ONLY)
    enable_testing()

    # Common test settings — link against static library for internal access
    set(QUDO_TEST_COMMON_INCLUDES
        ${CMAKE_CURRENT_SOURCE_DIR}/include
        ${CMAKE_CURRENT_SOURCE_DIR}/src
        ${CMAKE_CURRENT_SOURCE_DIR}/src/fips
        ${CMAKE_CURRENT_SOURCE_DIR}/qudo-mlkem/include
        ${CMAKE_CURRENT_SOURCE_DIR}/qudo-mldsa/include
        ${CMAKE_CURRENT_SOURCE_DIR}/qudo-slhdsa/include
        ${CMAKE_CURRENT_SOURCE_DIR}/qudo-mlkem/mlkem-native/mlkem
        ${CMAKE_CURRENT_SOURCE_DIR}/qudo-mlkem/mlkem-native
        ${CMAKE_CURRENT_SOURCE_DIR}/qudo-mlkem/mlkem-native/qudo_runtime_dispatch
        ${CMAKE_CURRENT_SOURCE_DIR}/qudo-mldsa/mldsa-native/mldsa
        ${CMAKE_CURRENT_SOURCE_DIR}/qudo-slhdsa/slhdsa-native
        ${CMAKE_CURRENT_SOURCE_DIR}/qudo-slhdsa/src
    )

    set(QUDO_TEST_COMPILE_DEFS
        QUDO_PQC_BUILDING
        QUDO_KEM_BUILD_SHARED
        QUDO_MLDSA_BUILD_SHARED
        QUDO_SLHDSA_BUILD_SHARED
        MLKEM_DIST_BUILD
        MLK_CONFIG_RUNTIME_DISPATCH
        MLDSA_DIST_BUILD
        QUDO_COMBINED_BUILD
    )
    if(QUDO_FIPS_MODULE)
        list(APPEND QUDO_TEST_COMPILE_DEFS QUDO_FIPS_MODULE)
        if(QUDO_PQC_USE_HOST_DRBG)
            list(APPEND QUDO_TEST_COMPILE_DEFS QUDO_PQC_USE_HOST_DRBG)
        endif()
        if(QUDO_PQC_DISABLE_EMBEDDED_HMAC)
            list(APPEND QUDO_TEST_COMPILE_DEFS QUDO_PQC_DISABLE_EMBEDDED_HMAC)
        endif()
    endif()
    if(CMAKE_SYSTEM_PROCESSOR MATCHES "x86_64|AMD64|amd64")
        if(NOT WIN32)
            list(APPEND QUDO_TEST_COMPILE_DEFS QUDO_HAS_AVX2_VARIANT)
        endif()
        if(WIN32)
            list(APPEND QUDO_TEST_COMPILE_DEFS SLH_NO_ASM=1)
        endif()
        if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
            list(APPEND QUDO_TEST_COMPILE_DEFS SLH_HAS_SHA_NI)
        endif()
    elseif(CMAKE_SYSTEM_PROCESSOR MATCHES "aarch64|arm64|ARM64")
        list(APPEND QUDO_TEST_COMPILE_DEFS QUDO_HAS_NEON_VARIANT)
    endif()

    # Integrity config for tests: Linux/macOS use the embedded HMAC; Windows
    # passes --fips-cnf <path> (handled by tests/test_fips_init.h).
    set(QUDO_TEST_FIPS_ARGS "")
    if(WIN32 AND QUDO_FIPS_MODULE)
        set(QUDO_TEST_FIPS_ARGS --fips-cnf "${CMAKE_BINARY_DIR}/qudofipsmodule.cnf")
    endif()

    # Platform libraries for tests
    set(QUDO_TEST_PLATFORM_LIBS "")
    if(WIN32)
        list(APPEND QUDO_TEST_PLATFORM_LIBS bcrypt)
    elseif(UNIX)
        list(APPEND QUDO_TEST_PLATFORM_LIBS pthread dl)
        if(NOT APPLE)
            list(APPEND QUDO_TEST_PLATFORM_LIBS m)
        endif()
    endif()


    # Tests load libqudo-pqc from the build directory.
    set(QUDO_TEST_ENV "LD_LIBRARY_PATH=${CMAKE_BINARY_DIR}/lib")

    # ==========================================================================
    # FIPS-only tests: only built when QUDO_FIPS_MODULE=ON.
    # POST KATs, integrity HMAC, embedded checksums and indicators.
    # ==========================================================================
    if(QUDO_FIPS_MODULE AND NOT ENABLE_MSAN)

    # --- test_pqc_post: POST and module lifecycle tests ---
    add_executable(test_pqc_post tests/test_pqc_post.c)
    target_include_directories(test_pqc_post PRIVATE ${QUDO_TEST_COMMON_INCLUDES})
    target_compile_definitions(test_pqc_post PRIVATE ${QUDO_TEST_COMPILE_DEFS})
    target_link_libraries(test_pqc_post PRIVATE qudo-pqc ${QUDO_TEST_PLATFORM_LIBS})
    set_target_properties(test_pqc_post PROPERTIES
        RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/tests"
    )
    # CTest: run all sections (working dir = tests/ for relative path access)
    add_test(NAME pqc_post COMMAND test_pqc_post ${QUDO_TEST_FIPS_ARGS})
    set_tests_properties(pqc_post PROPERTIES WORKING_DIRECTORY "${CMAKE_BINARY_DIR}/tests" ENVIRONMENT "${QUDO_TEST_ENV}")
    # CTest: individual sections
    add_test(NAME pqc_post_init COMMAND test_pqc_post --init ${QUDO_TEST_FIPS_ARGS})
    set_tests_properties(pqc_post_init PROPERTIES WORKING_DIRECTORY "${CMAKE_BINARY_DIR}/tests" ENVIRONMENT "${QUDO_TEST_ENV}")
    add_test(NAME pqc_post_kats COMMAND test_pqc_post --kats ${QUDO_TEST_FIPS_ARGS})
    set_tests_properties(pqc_post_kats PROPERTIES WORKING_DIRECTORY "${CMAKE_BINARY_DIR}/tests" ENVIRONMENT "${QUDO_TEST_ENV}")
    add_test(NAME pqc_post_negative COMMAND test_pqc_post --negative ${QUDO_TEST_FIPS_ARGS})
    set_tests_properties(pqc_post_negative PROPERTIES WORKING_DIRECTORY "${CMAKE_BINARY_DIR}/tests" ENVIRONMENT "${QUDO_TEST_ENV}")
    add_test(NAME pqc_post_selftest COMMAND test_pqc_post --selftest ${QUDO_TEST_FIPS_ARGS})
    set_tests_properties(pqc_post_selftest PROPERTIES WORKING_DIRECTORY "${CMAKE_BINARY_DIR}/tests" ENVIRONMENT "${QUDO_TEST_ENV}")
    add_test(NAME pqc_post_statemachine COMMAND test_pqc_post --statemachine ${QUDO_TEST_FIPS_ARGS})
    set_tests_properties(pqc_post_statemachine PROPERTIES WORKING_DIRECTORY "${CMAKE_BINARY_DIR}/tests" ENVIRONMENT "${QUDO_TEST_ENV}")

    endif() # QUDO_FIPS_MODULE (POST)

    # --- FIPS-only: test_pqc_pct ---
    if(QUDO_FIPS_MODULE AND NOT ENABLE_MSAN)

    # --- test_pqc_pct: Pairwise Consistency Tests ---
    add_executable(test_pqc_pct tests/test_pqc_pct.c)
    target_include_directories(test_pqc_pct PRIVATE ${QUDO_TEST_COMMON_INCLUDES})
    target_compile_definitions(test_pqc_pct PRIVATE ${QUDO_TEST_COMPILE_DEFS})
    target_link_libraries(test_pqc_pct PRIVATE qudo-pqc ${QUDO_TEST_PLATFORM_LIBS})
    set_target_properties(test_pqc_pct PROPERTIES
        RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/tests"
    )
    add_test(NAME pqc_pct COMMAND test_pqc_pct ${QUDO_TEST_FIPS_ARGS})
    set_tests_properties(pqc_pct PROPERTIES WORKING_DIRECTORY "${CMAKE_BINARY_DIR}/tests" ENVIRONMENT "${QUDO_TEST_ENV}")
    add_test(NAME pqc_pct_mlkem COMMAND test_pqc_pct --mlkem ${QUDO_TEST_FIPS_ARGS})
    set_tests_properties(pqc_pct_mlkem PROPERTIES WORKING_DIRECTORY "${CMAKE_BINARY_DIR}/tests" ENVIRONMENT "${QUDO_TEST_ENV}")
    add_test(NAME pqc_pct_mldsa COMMAND test_pqc_pct --mldsa ${QUDO_TEST_FIPS_ARGS})
    set_tests_properties(pqc_pct_mldsa PROPERTIES WORKING_DIRECTORY "${CMAKE_BINARY_DIR}/tests" ENVIRONMENT "${QUDO_TEST_ENV}")
    add_test(NAME pqc_pct_slhdsa COMMAND test_pqc_pct --slhdsa ${QUDO_TEST_FIPS_ARGS})
    set_tests_properties(pqc_pct_slhdsa PROPERTIES WORKING_DIRECTORY "${CMAKE_BINARY_DIR}/tests" ENVIRONMENT "${QUDO_TEST_ENV}")
    add_test(NAME pqc_pct_edge COMMAND test_pqc_pct --edge ${QUDO_TEST_FIPS_ARGS})
    set_tests_properties(pqc_pct_edge PROPERTIES WORKING_DIRECTORY "${CMAKE_BINARY_DIR}/tests" ENVIRONMENT "${QUDO_TEST_ENV}")

    endif() # QUDO_FIPS_MODULE (PCT)

    # --- FIPS-only: test_pqc_integrity, test_pqc_indicator ---
    if(QUDO_FIPS_MODULE AND NOT ENABLE_MSAN)

    # --- test_pqc_integrity: Integrity verification tests ---
    add_executable(test_pqc_integrity tests/test_pqc_integrity.c)
    target_include_directories(test_pqc_integrity PRIVATE ${QUDO_TEST_COMMON_INCLUDES})
    target_compile_definitions(test_pqc_integrity PRIVATE ${QUDO_TEST_COMPILE_DEFS})
    target_link_libraries(test_pqc_integrity PRIVATE qudo-pqc ${QUDO_TEST_PLATFORM_LIBS})
    set_target_properties(test_pqc_integrity PROPERTIES
        RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/tests"
    )
    add_test(NAME pqc_integrity COMMAND test_pqc_integrity ${QUDO_TEST_FIPS_ARGS})
    set_tests_properties(pqc_integrity PROPERTIES WORKING_DIRECTORY "${CMAKE_BINARY_DIR}/tests" ENVIRONMENT "${QUDO_TEST_ENV}")
    add_test(NAME pqc_integrity_hmac COMMAND test_pqc_integrity --hmac ${QUDO_TEST_FIPS_ARGS})
    set_tests_properties(pqc_integrity_hmac PROPERTIES WORKING_DIRECTORY "${CMAKE_BINARY_DIR}/tests" ENVIRONMENT "${QUDO_TEST_ENV}")
    add_test(NAME pqc_integrity_synthetic COMMAND test_pqc_integrity --synthetic ${QUDO_TEST_FIPS_ARGS})
    set_tests_properties(pqc_integrity_synthetic PROPERTIES WORKING_DIRECTORY "${CMAKE_BINARY_DIR}/tests" ENVIRONMENT "${QUDO_TEST_ENV}")
    add_test(NAME pqc_integrity_real COMMAND test_pqc_integrity --real ${QUDO_TEST_FIPS_ARGS})
    set_tests_properties(pqc_integrity_real PROPERTIES WORKING_DIRECTORY "${CMAKE_BINARY_DIR}/tests" ENVIRONMENT "${QUDO_TEST_ENV}")
    add_test(NAME pqc_integrity_fipsinstall COMMAND test_pqc_integrity --fipsinstall ${QUDO_TEST_FIPS_ARGS})
    set_tests_properties(pqc_integrity_fipsinstall PROPERTIES WORKING_DIRECTORY "${CMAKE_BINARY_DIR}/tests" ENVIRONMENT "${QUDO_TEST_ENV}")
    add_test(NAME pqc_integrity_init COMMAND test_pqc_integrity --init ${QUDO_TEST_FIPS_ARGS})
    set_tests_properties(pqc_integrity_init PROPERTIES WORKING_DIRECTORY "${CMAKE_BINARY_DIR}/tests" ENVIRONMENT "${QUDO_TEST_ENV}")
    add_test(NAME pqc_integrity_negative COMMAND test_pqc_integrity --negative ${QUDO_TEST_FIPS_ARGS})
    set_tests_properties(pqc_integrity_negative PROPERTIES WORKING_DIRECTORY "${CMAKE_BINARY_DIR}/tests" ENVIRONMENT "${QUDO_TEST_ENV}")

    endif() # QUDO_FIPS_MODULE (integrity, embedded)

    # --- test_pqc_drbg: CTR-DRBG and FIPS RNG tests ---
    add_executable(test_pqc_drbg tests/test_pqc_drbg.c)
    target_include_directories(test_pqc_drbg PRIVATE ${QUDO_TEST_COMMON_INCLUDES})
    target_compile_definitions(test_pqc_drbg PRIVATE ${QUDO_TEST_COMPILE_DEFS})
    target_link_libraries(test_pqc_drbg PRIVATE qudo-pqc ${QUDO_TEST_PLATFORM_LIBS})
    set_target_properties(test_pqc_drbg PROPERTIES
        RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/tests"
    )
    add_test(NAME pqc_drbg COMMAND test_pqc_drbg ${QUDO_TEST_FIPS_ARGS})
    set_tests_properties(pqc_drbg PROPERTIES WORKING_DIRECTORY "${CMAKE_BINARY_DIR}/tests" ENVIRONMENT "${QUDO_TEST_ENV}")
    add_test(NAME pqc_drbg_ctrdrbg COMMAND test_pqc_drbg --ctrdrbg ${QUDO_TEST_FIPS_ARGS})
    set_tests_properties(pqc_drbg_ctrdrbg PROPERTIES WORKING_DIRECTORY "${CMAKE_BINARY_DIR}/tests" ENVIRONMENT "${QUDO_TEST_ENV}")
    add_test(NAME pqc_drbg_edge COMMAND test_pqc_drbg --edge ${QUDO_TEST_FIPS_ARGS})
    set_tests_properties(pqc_drbg_edge PROPERTIES WORKING_DIRECTORY "${CMAKE_BINARY_DIR}/tests" ENVIRONMENT "${QUDO_TEST_ENV}")
    add_test(NAME pqc_drbg_rand COMMAND test_pqc_drbg --rand ${QUDO_TEST_FIPS_ARGS})
    set_tests_properties(pqc_drbg_rand PROPERTIES WORKING_DIRECTORY "${CMAKE_BINARY_DIR}/tests" ENVIRONMENT "${QUDO_TEST_ENV}")
    add_test(NAME pqc_drbg_api COMMAND test_pqc_drbg --api ${QUDO_TEST_FIPS_ARGS})
    set_tests_properties(pqc_drbg_api PROPERTIES WORKING_DIRECTORY "${CMAKE_BINARY_DIR}/tests" ENVIRONMENT "${QUDO_TEST_ENV}")
    add_test(NAME pqc_drbg_kat COMMAND test_pqc_drbg --kat ${QUDO_TEST_FIPS_ARGS})
    set_tests_properties(pqc_drbg_kat PROPERTIES WORKING_DIRECTORY "${CMAKE_BINARY_DIR}/tests" ENVIRONMENT "${QUDO_TEST_ENV}")
    add_test(NAME pqc_drbg_stress COMMAND test_pqc_drbg --stress ${QUDO_TEST_FIPS_ARGS})

    # --- test_pqc_host_rand: host-primitive DRBG hook ---
    add_executable(test_pqc_host_rand tests/test_pqc_host_rand.c)
    target_include_directories(test_pqc_host_rand PRIVATE ${QUDO_TEST_COMMON_INCLUDES})
    target_compile_definitions(test_pqc_host_rand PRIVATE ${QUDO_TEST_COMPILE_DEFS})
    target_link_libraries(test_pqc_host_rand PRIVATE qudo-pqc ${QUDO_TEST_PLATFORM_LIBS})
    set_target_properties(test_pqc_host_rand PROPERTIES
        RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/tests)
    add_test(NAME pqc_host_rand COMMAND test_pqc_host_rand ${QUDO_TEST_FIPS_ARGS})
    set_tests_properties(pqc_drbg_stress PROPERTIES WORKING_DIRECTORY "${CMAKE_BINARY_DIR}/tests" ENVIRONMENT "${QUDO_TEST_ENV}")

    # --- test_fips_aes_backends: KAT both AES backends (CT + NI) + equivalence ---
    add_executable(test_fips_aes_backends tests/test_fips_aes_backends.c
        src/fips/qudo_fips_aes_ct.c)
    if(CMAKE_SYSTEM_PROCESSOR MATCHES "(x86_64|amd64|AMD64|i[3-6]86)")
        target_sources(test_fips_aes_backends PRIVATE src/fips/qudo_fips_aes_ni.c)
        if(NOT MSVC)
            set_source_files_properties(src/fips/qudo_fips_aes_ni.c PROPERTIES
                COMPILE_FLAGS "-maes -msse4.1")
        endif()
    endif()
    target_include_directories(test_fips_aes_backends PRIVATE ${QUDO_TEST_COMMON_INCLUDES})
    target_compile_definitions(test_fips_aes_backends PRIVATE ${QUDO_TEST_COMPILE_DEFS})
    set_target_properties(test_fips_aes_backends PROPERTIES
        RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/tests"
    )
    add_test(NAME pqc_aes_backends COMMAND test_fips_aes_backends)
    set_tests_properties(pqc_aes_backends PROPERTIES WORKING_DIRECTORY "${CMAKE_BINARY_DIR}/tests")

    # --- test_fips_ctrdrbg_cavp: NIST CTR_DRBG byte-for-byte test vector ---
    add_executable(test_fips_ctrdrbg_cavp tests/test_fips_ctrdrbg_cavp.c)
    target_include_directories(test_fips_ctrdrbg_cavp PRIVATE ${QUDO_TEST_COMMON_INCLUDES})
    target_compile_definitions(test_fips_ctrdrbg_cavp PRIVATE ${QUDO_TEST_COMPILE_DEFS})
    target_link_libraries(test_fips_ctrdrbg_cavp PRIVATE qudo-pqc ${QUDO_TEST_PLATFORM_LIBS})
    set_target_properties(test_fips_ctrdrbg_cavp PROPERTIES
        RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/tests"
    )
    add_test(NAME fips_ctrdrbg_cavp COMMAND test_fips_ctrdrbg_cavp ${QUDO_TEST_FIPS_ARGS})
    set_tests_properties(fips_ctrdrbg_cavp PROPERTIES WORKING_DIRECTORY "${CMAKE_BINARY_DIR}/tests" ENVIRONMENT "${QUDO_TEST_ENV}")

    # --- test_pqc_interop: DER/PEM import/export across ML-KEM, ML-DSA, SLH-DSA ---
    add_executable(test_pqc_interop tests/test_pqc_interop.c)
    target_include_directories(test_pqc_interop PRIVATE ${QUDO_TEST_COMMON_INCLUDES})
    target_compile_definitions(test_pqc_interop PRIVATE ${QUDO_TEST_COMPILE_DEFS})
    target_link_libraries(test_pqc_interop PRIVATE qudo-pqc ${QUDO_TEST_PLATFORM_LIBS})
    set_target_properties(test_pqc_interop PROPERTIES
        RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/tests"
    )
    if(NOT ENABLE_MSAN)
    add_test(NAME pqc_interop COMMAND test_pqc_interop ${QUDO_TEST_FIPS_ARGS})
    set_tests_properties(pqc_interop PROPERTIES WORKING_DIRECTORY "${CMAKE_BINARY_DIR}/tests" ENVIRONMENT "${QUDO_TEST_ENV}")
    endif()

    # --- test_pqc_endurance: long-running deterministic walk over ML-KEM, ML-DSA, SLH-DSA ---
    #
    # Opt-in soak test: exits 77 (skipped) unless QUDO_ENDURANCE is set.
    # Run with: QUDO_ENDURANCE=1 ctest -R pqc_endurance, or invoke the
    # binary directly with --num <count> (and optional --mlkem/--mldsa/--slhdsa).
    add_executable(test_pqc_endurance tests/test_pqc_endurance.c)
    target_include_directories(test_pqc_endurance PRIVATE ${QUDO_TEST_COMMON_INCLUDES})
    target_compile_definitions(test_pqc_endurance PRIVATE ${QUDO_TEST_COMPILE_DEFS})
    target_link_libraries(test_pqc_endurance PRIVATE qudo-pqc ${QUDO_TEST_PLATFORM_LIBS})
    set_target_properties(test_pqc_endurance PROPERTIES
        RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/tests"
    )
    add_test(NAME pqc_endurance COMMAND test_pqc_endurance ${QUDO_TEST_FIPS_ARGS})
    set_tests_properties(pqc_endurance PROPERTIES WORKING_DIRECTORY "${CMAKE_BINARY_DIR}/tests" ENVIRONMENT "${QUDO_TEST_ENV}" SKIP_RETURN_CODE 77)

    # --- test_openssl_pem_interop: PEM interop with OpenSSL 4.0+ ML-DSA/ML-KEM/SLH-DSA ---
    # Optional: requires OpenSSL >= 4.0 (knows the ML-* / SLH-* OIDs).
    find_package(OpenSSL QUIET)
    if(OpenSSL_FOUND AND OPENSSL_VERSION VERSION_GREATER_EQUAL "4.0.0")
        add_executable(test_openssl_pem_interop tests/test_openssl_pem_interop.c)
        target_include_directories(test_openssl_pem_interop PRIVATE ${QUDO_TEST_COMMON_INCLUDES})
        target_compile_definitions(test_openssl_pem_interop PRIVATE ${QUDO_TEST_COMPILE_DEFS})
        target_link_libraries(test_openssl_pem_interop PRIVATE qudo-pqc OpenSSL::Crypto ${QUDO_TEST_PLATFORM_LIBS})
        set_target_properties(test_openssl_pem_interop PROPERTIES
            RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/tests"
        )
        if(NOT ENABLE_MSAN)
        add_test(NAME openssl_pem_interop COMMAND test_openssl_pem_interop ${QUDO_TEST_FIPS_ARGS})
        set_tests_properties(openssl_pem_interop PROPERTIES WORKING_DIRECTORY "${CMAKE_BINARY_DIR}/tests" ENVIRONMENT "${QUDO_TEST_ENV}")
        endif()
    endif()

    # --- test_pqc_wrapper_advanced: init/cleanup/is_initialized + ML-DSA _internal/_extmu/_prehash + ML-KEM derand ---
    add_executable(test_pqc_wrapper_advanced tests/test_pqc_wrapper_advanced.c)
    target_include_directories(test_pqc_wrapper_advanced PRIVATE ${QUDO_TEST_COMMON_INCLUDES})
    target_compile_definitions(test_pqc_wrapper_advanced PRIVATE ${QUDO_TEST_COMPILE_DEFS})
    target_link_libraries(test_pqc_wrapper_advanced PRIVATE qudo-pqc ${QUDO_TEST_PLATFORM_LIBS})
    set_target_properties(test_pqc_wrapper_advanced PROPERTIES
        RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/tests"
    )
    if(NOT ENABLE_MSAN)
    add_test(NAME pqc_wrapper_advanced COMMAND test_pqc_wrapper_advanced ${QUDO_TEST_FIPS_ARGS})
    set_tests_properties(pqc_wrapper_advanced PROPERTIES WORKING_DIRECTORY "${CMAKE_BINARY_DIR}/tests" ENVIRONMENT "${QUDO_TEST_ENV}")
    endif()

    # --- FIPS-only: test_pqc_indicator ---
    if(QUDO_FIPS_MODULE AND NOT ENABLE_MSAN)

    # --- test_pqc_indicator: FIPS indicator mechanism tests ---
    add_executable(test_pqc_indicator tests/test_pqc_indicator.c)
    target_include_directories(test_pqc_indicator PRIVATE ${QUDO_TEST_COMMON_INCLUDES})
    target_compile_definitions(test_pqc_indicator PRIVATE ${QUDO_TEST_COMPILE_DEFS})
    target_link_libraries(test_pqc_indicator PRIVATE qudo-pqc ${QUDO_TEST_PLATFORM_LIBS})
    set_target_properties(test_pqc_indicator PROPERTIES
        RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/tests"
    )
    add_test(NAME pqc_indicator COMMAND test_pqc_indicator ${QUDO_TEST_FIPS_ARGS})
    set_tests_properties(pqc_indicator PROPERTIES WORKING_DIRECTORY "${CMAKE_BINARY_DIR}/tests" ENVIRONMENT "${QUDO_TEST_ENV}")
    add_test(NAME pqc_indicator_init COMMAND test_pqc_indicator --init ${QUDO_TEST_FIPS_ARGS})
    set_tests_properties(pqc_indicator_init PROPERTIES WORKING_DIRECTORY "${CMAKE_BINARY_DIR}/tests" ENVIRONMENT "${QUDO_TEST_ENV}")
    add_test(NAME pqc_indicator_unapproved COMMAND test_pqc_indicator --unapproved ${QUDO_TEST_FIPS_ARGS})
    set_tests_properties(pqc_indicator_unapproved PROPERTIES WORKING_DIRECTORY "${CMAKE_BINARY_DIR}/tests" ENVIRONMENT "${QUDO_TEST_ENV}")
    add_test(NAME pqc_indicator_approval COMMAND test_pqc_indicator --approval ${QUDO_TEST_FIPS_ARGS})
    set_tests_properties(pqc_indicator_approval PROPERTIES WORKING_DIRECTORY "${CMAKE_BINARY_DIR}/tests" ENVIRONMENT "${QUDO_TEST_ENV}")
    add_test(NAME pqc_indicator_check COMMAND test_pqc_indicator --check ${QUDO_TEST_FIPS_ARGS})
    set_tests_properties(pqc_indicator_check PROPERTIES WORKING_DIRECTORY "${CMAKE_BINARY_DIR}/tests" ENVIRONMENT "${QUDO_TEST_ENV}")
    add_test(NAME pqc_indicator_security COMMAND test_pqc_indicator --security ${QUDO_TEST_FIPS_ARGS})
    set_tests_properties(pqc_indicator_security PROPERTIES WORKING_DIRECTORY "${CMAKE_BINARY_DIR}/tests" ENVIRONMENT "${QUDO_TEST_ENV}")

    endif() # QUDO_FIPS_MODULE (indicator)

    # --- FIPS-only: test_pqc_cast ---
    if(QUDO_FIPS_MODULE AND NOT ENABLE_MSAN)

    # --- test_pqc_cast: Conditional Algorithm Self-Test tests ---
    add_executable(test_pqc_cast tests/test_pqc_cast.c)
    target_include_directories(test_pqc_cast PRIVATE ${QUDO_TEST_COMMON_INCLUDES})
    target_compile_definitions(test_pqc_cast PRIVATE ${QUDO_TEST_COMPILE_DEFS})
    target_link_libraries(test_pqc_cast PRIVATE qudo-pqc ${QUDO_TEST_PLATFORM_LIBS})
    set_target_properties(test_pqc_cast PROPERTIES
        RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/tests"
    )
    add_test(NAME pqc_cast COMMAND test_pqc_cast ${QUDO_TEST_FIPS_ARGS})
    set_tests_properties(pqc_cast PROPERTIES WORKING_DIRECTORY "${CMAKE_BINARY_DIR}/tests" ENVIRONMENT "${QUDO_TEST_ENV}")
    add_test(NAME pqc_cast_init COMMAND test_pqc_cast --init ${QUDO_TEST_FIPS_ARGS})
    set_tests_properties(pqc_cast_init PROPERTIES WORKING_DIRECTORY "${CMAKE_BINARY_DIR}/tests" ENVIRONMENT "${QUDO_TEST_ENV}")
    add_test(NAME pqc_cast_individual COMMAND test_pqc_cast --individual ${QUDO_TEST_FIPS_ARGS})
    set_tests_properties(pqc_cast_individual PROPERTIES WORKING_DIRECTORY "${CMAKE_BINARY_DIR}/tests" ENVIRONMENT "${QUDO_TEST_ENV}")
    add_test(NAME pqc_cast_runall COMMAND test_pqc_cast --runall ${QUDO_TEST_FIPS_ARGS})
    set_tests_properties(pqc_cast_runall PROPERTIES WORKING_DIRECTORY "${CMAKE_BINARY_DIR}/tests" ENVIRONMENT "${QUDO_TEST_ENV}")
    add_test(NAME pqc_cast_invalid COMMAND test_pqc_cast --invalid ${QUDO_TEST_FIPS_ARGS})
    set_tests_properties(pqc_cast_invalid PROPERTIES WORKING_DIRECTORY "${CMAKE_BINARY_DIR}/tests" ENVIRONMENT "${QUDO_TEST_ENV}")

    endif() # QUDO_FIPS_MODULE (CAST)

    # --- test_pqc_audit: Audit/logging framework tests ---
    add_executable(test_pqc_audit tests/test_pqc_audit.c)
    target_include_directories(test_pqc_audit PRIVATE ${QUDO_TEST_COMMON_INCLUDES})
    target_compile_definitions(test_pqc_audit PRIVATE ${QUDO_TEST_COMPILE_DEFS})
    target_link_libraries(test_pqc_audit PRIVATE qudo-pqc ${QUDO_TEST_PLATFORM_LIBS})
    set_target_properties(test_pqc_audit PROPERTIES
        RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/tests"
    )
    add_test(NAME pqc_audit COMMAND test_pqc_audit ${QUDO_TEST_FIPS_ARGS})
    set_tests_properties(pqc_audit PROPERTIES WORKING_DIRECTORY "${CMAKE_BINARY_DIR}/tests" ENVIRONMENT "${QUDO_TEST_ENV}")
    add_test(NAME pqc_audit_basic COMMAND test_pqc_audit --basic ${QUDO_TEST_FIPS_ARGS})
    set_tests_properties(pqc_audit_basic PROPERTIES WORKING_DIRECTORY "${CMAKE_BINARY_DIR}/tests" ENVIRONMENT "${QUDO_TEST_ENV}")
    add_test(NAME pqc_audit_severity COMMAND test_pqc_audit --severity ${QUDO_TEST_FIPS_ARGS})
    set_tests_properties(pqc_audit_severity PROPERTIES WORKING_DIRECTORY "${CMAKE_BINARY_DIR}/tests" ENVIRONMENT "${QUDO_TEST_ENV}")
    add_test(NAME pqc_audit_components COMMAND test_pqc_audit --components ${QUDO_TEST_FIPS_ARGS})
    set_tests_properties(pqc_audit_components PROPERTIES WORKING_DIRECTORY "${CMAKE_BINARY_DIR}/tests" ENVIRONMENT "${QUDO_TEST_ENV}")
    add_test(NAME pqc_audit_rate COMMAND test_pqc_audit --rate ${QUDO_TEST_FIPS_ARGS})
    set_tests_properties(pqc_audit_rate PROPERTIES WORKING_DIRECTORY "${CMAKE_BINARY_DIR}/tests" ENVIRONMENT "${QUDO_TEST_ENV}")
    add_test(NAME pqc_audit_errstr COMMAND test_pqc_audit --errstr ${QUDO_TEST_FIPS_ARGS})
    set_tests_properties(pqc_audit_errstr PROPERTIES WORKING_DIRECTORY "${CMAKE_BINARY_DIR}/tests" ENVIRONMENT "${QUDO_TEST_ENV}")
    add_test(NAME pqc_audit_init COMMAND test_pqc_audit --init ${QUDO_TEST_FIPS_ARGS})
    set_tests_properties(pqc_audit_init PROPERTIES WORKING_DIRECTORY "${CMAKE_BINARY_DIR}/tests" ENVIRONMENT "${QUDO_TEST_ENV}")

    # --- test_pqc_threading: Concurrent access safety tests ---
    add_executable(test_pqc_threading tests/test_pqc_threading.c)
    target_include_directories(test_pqc_threading PRIVATE ${QUDO_TEST_COMMON_INCLUDES})
    target_compile_definitions(test_pqc_threading PRIVATE ${QUDO_TEST_COMPILE_DEFS})
    target_link_libraries(test_pqc_threading PRIVATE qudo-pqc ${QUDO_TEST_PLATFORM_LIBS})
    set_target_properties(test_pqc_threading PROPERTIES
        RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/tests"
    )
    # Skipped under MSan in FIPS mode (false positives on POST constant-time code).
    if(NOT (ENABLE_MSAN AND QUDO_FIPS_MODULE))
    add_test(NAME pqc_threading COMMAND test_pqc_threading ${QUDO_TEST_FIPS_ARGS})
    set_tests_properties(pqc_threading PROPERTIES WORKING_DIRECTORY "${CMAKE_BINARY_DIR}/tests" ENVIRONMENT "${QUDO_TEST_ENV}")
    endif()

    # --- test_pct_concurrent_tsan: concurrent keygen and PCT ---
    # Race detection under -fsanitize=thread; also runs as a functional check.
    add_executable(test_pct_concurrent_tsan tests/test_pct_concurrent_tsan.c)
    target_include_directories(test_pct_concurrent_tsan PRIVATE ${QUDO_TEST_COMMON_INCLUDES})
    target_compile_definitions(test_pct_concurrent_tsan PRIVATE ${QUDO_TEST_COMPILE_DEFS})
    target_link_libraries(test_pct_concurrent_tsan PRIVATE qudo-pqc ${QUDO_TEST_PLATFORM_LIBS})
    set_target_properties(test_pct_concurrent_tsan PROPERTIES
        RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/tests"
    )
    if(NOT (ENABLE_MSAN AND QUDO_FIPS_MODULE))
    add_test(NAME pct_concurrent_tsan COMMAND test_pct_concurrent_tsan ${QUDO_TEST_FIPS_ARGS})
    set_tests_properties(pct_concurrent_tsan PROPERTIES WORKING_DIRECTORY "${CMAKE_BINARY_DIR}/tests" ENVIRONMENT "${QUDO_TEST_ENV}")
    endif()

    # --- test_pct_fail_zeroize: PCT failure -> caller buffer zeroize + ERROR ---
    # On PCT failure the keypair in caller buffers is zeroized and the module
    # enters the ERROR state.
    add_executable(test_pct_fail_zeroize tests/test_pct_fail_zeroize.c)
    target_include_directories(test_pct_fail_zeroize PRIVATE ${QUDO_TEST_COMMON_INCLUDES})
    target_compile_definitions(test_pct_fail_zeroize PRIVATE ${QUDO_TEST_COMPILE_DEFS})
    target_link_libraries(test_pct_fail_zeroize PRIVATE qudo-pqc ${QUDO_TEST_PLATFORM_LIBS})
    set_target_properties(test_pct_fail_zeroize PROPERTIES
        RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/tests"
    )
    if(NOT (ENABLE_MSAN AND QUDO_FIPS_MODULE))
    add_test(NAME pct_fail_zeroize COMMAND test_pct_fail_zeroize ${QUDO_TEST_FIPS_ARGS})
    set_tests_properties(pct_fail_zeroize PROPERTIES WORKING_DIRECTORY "${CMAKE_BINARY_DIR}/tests" ENVIRONMENT "${QUDO_TEST_ENV}")
    endif()

    # --- test_pqc_newapi: New API unit tests (check_pk, pre-hash, internal) ---
    add_executable(test_pqc_newapi tests/test_pqc_newapi.c)
    target_include_directories(test_pqc_newapi PRIVATE ${QUDO_TEST_COMMON_INCLUDES})
    target_compile_definitions(test_pqc_newapi PRIVATE ${QUDO_TEST_COMPILE_DEFS})
    target_link_libraries(test_pqc_newapi PRIVATE qudo-pqc ${QUDO_TEST_PLATFORM_LIBS})
    set_target_properties(test_pqc_newapi PROPERTIES
        RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/tests"
    )
    # MSan reports false positives on constant-time value barriers used by the
    # POST KATs in qudo_pqc_init(); skipped under MSan in FIPS mode.
    if(NOT ENABLE_MSAN)
    add_test(NAME pqc_newapi COMMAND test_pqc_newapi ${QUDO_TEST_FIPS_ARGS})
    set_tests_properties(pqc_newapi PROPERTIES WORKING_DIRECTORY "${CMAKE_BINARY_DIR}/tests" ENVIRONMENT "${QUDO_TEST_ENV}")
    add_test(NAME pqc_check_pk COMMAND test_pqc_newapi --check_pk ${QUDO_TEST_FIPS_ARGS})
    set_tests_properties(pqc_check_pk PROPERTIES WORKING_DIRECTORY "${CMAKE_BINARY_DIR}/tests" ENVIRONMENT "${QUDO_TEST_ENV}")
    add_test(NAME pqc_mldsa_prehash COMMAND test_pqc_newapi --mldsa_prehash ${QUDO_TEST_FIPS_ARGS})
    set_tests_properties(pqc_mldsa_prehash PROPERTIES WORKING_DIRECTORY "${CMAKE_BINARY_DIR}/tests" ENVIRONMENT "${QUDO_TEST_ENV}")
    add_test(NAME pqc_slhdsa_prehash COMMAND test_pqc_newapi --slhdsa_prehash ${QUDO_TEST_FIPS_ARGS})
    set_tests_properties(pqc_slhdsa_prehash PROPERTIES WORKING_DIRECTORY "${CMAKE_BINARY_DIR}/tests" ENVIRONMENT "${QUDO_TEST_ENV}")
    add_test(NAME pqc_slhdsa_internal COMMAND test_pqc_newapi --slhdsa_internal ${QUDO_TEST_FIPS_ARGS})
    set_tests_properties(pqc_slhdsa_internal PROPERTIES WORKING_DIRECTORY "${CMAKE_BINARY_DIR}/tests" ENVIRONMENT "${QUDO_TEST_ENV}")
    endif()

    # --- test_pqc_slhdsa_paramsets: Exhaustive per-parameter-set coverage ---
    # Exercises all 12 FIPS 205 SLH-DSA parameter sets through keypair/sign/
    # verify plus context-string and negative-name paths.
    add_executable(test_pqc_slhdsa_paramsets tests/test_pqc_slhdsa_paramsets.c)
    target_include_directories(test_pqc_slhdsa_paramsets PRIVATE ${QUDO_TEST_COMMON_INCLUDES})
    target_compile_definitions(test_pqc_slhdsa_paramsets PRIVATE ${QUDO_TEST_COMPILE_DEFS})
    target_link_libraries(test_pqc_slhdsa_paramsets PRIVATE qudo-pqc ${QUDO_TEST_PLATFORM_LIBS})
    set_target_properties(test_pqc_slhdsa_paramsets PROPERTIES
        RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/tests"
    )
    if(NOT ENABLE_MSAN)
    add_test(NAME pqc_slhdsa_paramsets COMMAND test_pqc_slhdsa_paramsets ${QUDO_TEST_FIPS_ARGS})
    set_tests_properties(pqc_slhdsa_paramsets PROPERTIES WORKING_DIRECTORY "${CMAKE_BINARY_DIR}/tests" ENVIRONMENT "${QUDO_TEST_ENV}" TIMEOUT 1200)
    add_test(NAME pqc_slhdsa_paramsets_roundtrip COMMAND test_pqc_slhdsa_paramsets --roundtrip ${QUDO_TEST_FIPS_ARGS})
    set_tests_properties(pqc_slhdsa_paramsets_roundtrip PROPERTIES WORKING_DIRECTORY "${CMAKE_BINARY_DIR}/tests" ENVIRONMENT "${QUDO_TEST_ENV}" TIMEOUT 1200)
    add_test(NAME pqc_slhdsa_paramsets_context COMMAND test_pqc_slhdsa_paramsets --context ${QUDO_TEST_FIPS_ARGS})
    set_tests_properties(pqc_slhdsa_paramsets_context PROPERTIES WORKING_DIRECTORY "${CMAKE_BINARY_DIR}/tests" ENVIRONMENT "${QUDO_TEST_ENV}" TIMEOUT 600)
    add_test(NAME pqc_slhdsa_paramsets_negative COMMAND test_pqc_slhdsa_paramsets --negative ${QUDO_TEST_FIPS_ARGS})
    set_tests_properties(pqc_slhdsa_paramsets_negative PROPERTIES WORKING_DIRECTORY "${CMAKE_BINARY_DIR}/tests" ENVIRONMENT "${QUDO_TEST_ENV}")
    add_test(NAME pqc_slhdsa_paramsets_registry COMMAND test_pqc_slhdsa_paramsets --registry ${QUDO_TEST_FIPS_ARGS})
    set_tests_properties(pqc_slhdsa_paramsets_registry PROPERTIES WORKING_DIRECTORY "${CMAKE_BINARY_DIR}/tests" ENVIRONMENT "${QUDO_TEST_ENV}")
    endif()

    # --- test_pqc_mlkem_seed_derand: ML-KEM deterministic / seed paths ---
    # Exercises QUDO_KEM_keypair_from_seed, QUDO_KEM_keypair_derand, and
    # QUDO_KEM_encaps_derand for all three security levels.
    add_executable(test_pqc_mlkem_seed_derand tests/test_pqc_mlkem_seed_derand.c)
    target_include_directories(test_pqc_mlkem_seed_derand PRIVATE ${QUDO_TEST_COMMON_INCLUDES})
    target_compile_definitions(test_pqc_mlkem_seed_derand PRIVATE ${QUDO_TEST_COMPILE_DEFS})
    target_link_libraries(test_pqc_mlkem_seed_derand PRIVATE qudo-pqc ${QUDO_TEST_PLATFORM_LIBS})
    set_target_properties(test_pqc_mlkem_seed_derand PROPERTIES
        RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/tests"
    )
    if(NOT ENABLE_MSAN)
    add_test(NAME pqc_mlkem_seed_derand COMMAND test_pqc_mlkem_seed_derand ${QUDO_TEST_FIPS_ARGS})
    set_tests_properties(pqc_mlkem_seed_derand PROPERTIES WORKING_DIRECTORY "${CMAKE_BINARY_DIR}/tests" ENVIRONMENT "${QUDO_TEST_ENV}")
    add_test(NAME pqc_mlkem_seed_determinism COMMAND test_pqc_mlkem_seed_derand --determinism ${QUDO_TEST_FIPS_ARGS})
    set_tests_properties(pqc_mlkem_seed_determinism PROPERTIES WORKING_DIRECTORY "${CMAKE_BINARY_DIR}/tests" ENVIRONMENT "${QUDO_TEST_ENV}")
    add_test(NAME pqc_mlkem_derand_roundtrip COMMAND test_pqc_mlkem_seed_derand --derand ${QUDO_TEST_FIPS_ARGS})
    set_tests_properties(pqc_mlkem_derand_roundtrip PROPERTIES WORKING_DIRECTORY "${CMAKE_BINARY_DIR}/tests" ENVIRONMENT "${QUDO_TEST_ENV}")
    add_test(NAME pqc_mlkem_encaps_derand COMMAND test_pqc_mlkem_seed_derand --encaps ${QUDO_TEST_FIPS_ARGS})
    set_tests_properties(pqc_mlkem_encaps_derand PROPERTIES WORKING_DIRECTORY "${CMAKE_BINARY_DIR}/tests" ENVIRONMENT "${QUDO_TEST_ENV}")
    add_test(NAME pqc_mlkem_seed_roundtrip COMMAND test_pqc_mlkem_seed_derand --roundtrip ${QUDO_TEST_FIPS_ARGS})
    set_tests_properties(pqc_mlkem_seed_roundtrip PROPERTIES WORKING_DIRECTORY "${CMAKE_BINARY_DIR}/tests" ENVIRONMENT "${QUDO_TEST_ENV}")
    add_test(NAME pqc_mlkem_seed_negative COMMAND test_pqc_mlkem_seed_derand --negative ${QUDO_TEST_FIPS_ARGS})
    set_tests_properties(pqc_mlkem_seed_negative PROPERTIES WORKING_DIRECTORY "${CMAKE_BINARY_DIR}/tests" ENVIRONMENT "${QUDO_TEST_ENV}")
    endif()

    # --- test_pqc_mldsa_seed_context: ML-DSA internal / context / prehash paths ---
    # Exercises QUDO_MLDSA_keypair_internal, sign_internal, sign_extmu,
    # sign_concat / open, sign_with_context, and sign_pre_hash_internal across
    # security levels.
    add_executable(test_pqc_mldsa_seed_context tests/test_pqc_mldsa_seed_context.c)
    target_include_directories(test_pqc_mldsa_seed_context PRIVATE ${QUDO_TEST_COMMON_INCLUDES})
    target_compile_definitions(test_pqc_mldsa_seed_context PRIVATE ${QUDO_TEST_COMPILE_DEFS})
    target_link_libraries(test_pqc_mldsa_seed_context PRIVATE qudo-pqc ${QUDO_TEST_PLATFORM_LIBS})
    set_target_properties(test_pqc_mldsa_seed_context PROPERTIES
        RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/tests"
    )
    if(NOT ENABLE_MSAN)
    add_test(NAME pqc_mldsa_seed_context COMMAND test_pqc_mldsa_seed_context ${QUDO_TEST_FIPS_ARGS})
    set_tests_properties(pqc_mldsa_seed_context PROPERTIES WORKING_DIRECTORY "${CMAKE_BINARY_DIR}/tests" ENVIRONMENT "${QUDO_TEST_ENV}")
    add_test(NAME pqc_mldsa_seed_determinism COMMAND test_pqc_mldsa_seed_context --seed ${QUDO_TEST_FIPS_ARGS})
    set_tests_properties(pqc_mldsa_seed_determinism PROPERTIES WORKING_DIRECTORY "${CMAKE_BINARY_DIR}/tests" ENVIRONMENT "${QUDO_TEST_ENV}")
    add_test(NAME pqc_mldsa_sign_internal COMMAND test_pqc_mldsa_seed_context --sign_internal ${QUDO_TEST_FIPS_ARGS})
    set_tests_properties(pqc_mldsa_sign_internal PROPERTIES WORKING_DIRECTORY "${CMAKE_BINARY_DIR}/tests" ENVIRONMENT "${QUDO_TEST_ENV}")
    add_test(NAME pqc_mldsa_extmu COMMAND test_pqc_mldsa_seed_context --extmu ${QUDO_TEST_FIPS_ARGS})
    set_tests_properties(pqc_mldsa_extmu PROPERTIES WORKING_DIRECTORY "${CMAKE_BINARY_DIR}/tests" ENVIRONMENT "${QUDO_TEST_ENV}")
    add_test(NAME pqc_mldsa_concat COMMAND test_pqc_mldsa_seed_context --concat ${QUDO_TEST_FIPS_ARGS})
    set_tests_properties(pqc_mldsa_concat PROPERTIES WORKING_DIRECTORY "${CMAKE_BINARY_DIR}/tests" ENVIRONMENT "${QUDO_TEST_ENV}")
    add_test(NAME pqc_mldsa_ctx COMMAND test_pqc_mldsa_seed_context --ctx ${QUDO_TEST_FIPS_ARGS})
    set_tests_properties(pqc_mldsa_ctx PROPERTIES WORKING_DIRECTORY "${CMAKE_BINARY_DIR}/tests" ENVIRONMENT "${QUDO_TEST_ENV}")
    add_test(NAME pqc_mldsa_prehash_internal COMMAND test_pqc_mldsa_seed_context --prehash ${QUDO_TEST_FIPS_ARGS})
    set_tests_properties(pqc_mldsa_prehash_internal PROPERTIES WORKING_DIRECTORY "${CMAKE_BINARY_DIR}/tests" ENVIRONMENT "${QUDO_TEST_ENV}")
    add_test(NAME pqc_mldsa_seed_negative COMMAND test_pqc_mldsa_seed_context --negative ${QUDO_TEST_FIPS_ARGS})
    set_tests_properties(pqc_mldsa_seed_negative PROPERTIES WORKING_DIRECTORY "${CMAKE_BINARY_DIR}/tests" ENVIRONMENT "${QUDO_TEST_ENV}")
    endif()

    # --- test_pqc_init_errors: qudo_pqc_init error paths + state transitions ---
    # Each section is a separate ctest invocation because the module state is
    # a process-wide singleton and some sections latch into ERROR state. Covers
    # the QUDO_PQC_FIPS_CONF env var being ignored, re-init callback swap,
    # state transitions, and integrity failure with error_cb invocation.
    if(QUDO_FIPS_MODULE AND NOT ENABLE_MSAN)
    add_executable(test_pqc_init_errors tests/test_pqc_init_errors.c)
    target_include_directories(test_pqc_init_errors PRIVATE ${QUDO_TEST_COMMON_INCLUDES})
    target_compile_definitions(test_pqc_init_errors PRIVATE ${QUDO_TEST_COMPILE_DEFS})
    target_link_libraries(test_pqc_init_errors PRIVATE qudo-pqc ${QUDO_TEST_PLATFORM_LIBS})
    set_target_properties(test_pqc_init_errors PROPERTIES
        RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/tests"
    )
    add_test(NAME pqc_init_auto_populate_bad COMMAND test_pqc_init_errors --auto-populate-bad ${QUDO_TEST_FIPS_ARGS})
    set_tests_properties(pqc_init_auto_populate_bad PROPERTIES WORKING_DIRECTORY "${CMAKE_BINARY_DIR}/lib" ENVIRONMENT "${QUDO_TEST_ENV}")
    add_test(NAME pqc_init_auto_populate_ok COMMAND test_pqc_init_errors --auto-populate-ok ${QUDO_TEST_FIPS_ARGS})
    set_tests_properties(pqc_init_auto_populate_ok PROPERTIES WORKING_DIRECTORY "${CMAKE_BINARY_DIR}/lib" ENVIRONMENT "${QUDO_TEST_ENV}")
    add_test(NAME pqc_init_reinit COMMAND test_pqc_init_errors --reinit ${QUDO_TEST_FIPS_ARGS})
    set_tests_properties(pqc_init_reinit PROPERTIES WORKING_DIRECTORY "${CMAKE_BINARY_DIR}/tests" ENVIRONMENT "${QUDO_TEST_ENV}")
    add_test(NAME pqc_init_state COMMAND test_pqc_init_errors --state ${QUDO_TEST_FIPS_ARGS})
    set_tests_properties(pqc_init_state PROPERTIES WORKING_DIRECTORY "${CMAKE_BINARY_DIR}/tests" ENVIRONMENT "${QUDO_TEST_ENV}")
    add_test(NAME pqc_init_wrong_checksum COMMAND test_pqc_init_errors --wrong-checksum ${QUDO_TEST_FIPS_ARGS})
    set_tests_properties(pqc_init_wrong_checksum PROPERTIES WORKING_DIRECTORY "${CMAKE_BINARY_DIR}/lib" ENVIRONMENT "${QUDO_TEST_ENV}")
    add_test(NAME pqc_init_rand_init_gate COMMAND test_pqc_init_errors --rand-init-gate ${QUDO_TEST_FIPS_ARGS})
    set_tests_properties(pqc_init_rand_init_gate PROPERTIES WORKING_DIRECTORY "${CMAKE_BINARY_DIR}/tests" ENVIRONMENT "${QUDO_TEST_ENV}")
    add_test(NAME pqc_init_reinit_cycle COMMAND test_pqc_init_errors --reinit-cycle ${QUDO_TEST_FIPS_ARGS})
    set_tests_properties(pqc_init_reinit_cycle PROPERTIES WORKING_DIRECTORY "${CMAKE_BINARY_DIR}/tests" ENVIRONMENT "${QUDO_TEST_ENV}")
    add_test(NAME pqc_init_unregister_cb COMMAND test_pqc_init_errors --unregister-cb ${QUDO_TEST_FIPS_ARGS})
    set_tests_properties(pqc_init_unregister_cb PROPERTIES WORKING_DIRECTORY "${CMAKE_BINARY_DIR}/tests" ENVIRONMENT "${QUDO_TEST_ENV}")
    endif()

    # --- test_integrity_path_pinning: integrity config path pinning ------------
    # Asserts QUDO_PQC_FIPS_CONF has zero effect on qudo_pqc_init(NULL).
    if(NOT ENABLE_MSAN)
    add_executable(test_integrity_path_pinning tests/test_integrity_path_pinning.c)
    target_include_directories(test_integrity_path_pinning PRIVATE ${QUDO_TEST_COMMON_INCLUDES})
    target_compile_definitions(test_integrity_path_pinning PRIVATE ${QUDO_TEST_COMPILE_DEFS})
    target_link_libraries(test_integrity_path_pinning PRIVATE qudo-pqc ${QUDO_TEST_PLATFORM_LIBS})
    set_target_properties(test_integrity_path_pinning PROPERTIES
        RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/tests"
    )
    add_test(NAME pqc_integrity_path_pinning COMMAND test_integrity_path_pinning ${QUDO_TEST_FIPS_ARGS})
    set_tests_properties(pqc_integrity_path_pinning PROPERTIES WORKING_DIRECTORY "${CMAKE_BINARY_DIR}/lib" ENVIRONMENT "${QUDO_TEST_ENV}")
    endif()

    # --- test_pqc_drbg_limits: CTR-DRBG reseed + chunking + explicit reseed ---
    # Covers RESEED_INTERVAL-triggered auto-reseed, > QUDO_CTRDRBG_MAX_REQUEST chunking loop, explicit reseed
    # API with valid + invalid entropy, is_ready transitions.
    add_executable(test_pqc_drbg_limits tests/test_pqc_drbg_limits.c)
    target_include_directories(test_pqc_drbg_limits PRIVATE ${QUDO_TEST_COMMON_INCLUDES})
    target_compile_definitions(test_pqc_drbg_limits PRIVATE ${QUDO_TEST_COMPILE_DEFS})
    target_link_libraries(test_pqc_drbg_limits PRIVATE qudo-pqc ${QUDO_TEST_PLATFORM_LIBS})
    set_target_properties(test_pqc_drbg_limits PROPERTIES
        RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/tests"
    )
    if(NOT ENABLE_MSAN)
    # reseed-interval test issues >1M generate calls; 300 s upper bound.
    add_test(NAME pqc_drbg_reseed_interval COMMAND test_pqc_drbg_limits --reseed-interval ${QUDO_TEST_FIPS_ARGS})
    set_tests_properties(pqc_drbg_reseed_interval PROPERTIES WORKING_DIRECTORY "${CMAKE_BINARY_DIR}/tests" ENVIRONMENT "${QUDO_TEST_ENV}" TIMEOUT 300)
    add_test(NAME pqc_drbg_chunking COMMAND test_pqc_drbg_limits --chunking ${QUDO_TEST_FIPS_ARGS})
    set_tests_properties(pqc_drbg_chunking PROPERTIES WORKING_DIRECTORY "${CMAKE_BINARY_DIR}/tests" ENVIRONMENT "${QUDO_TEST_ENV}")
    add_test(NAME pqc_drbg_explicit_reseed COMMAND test_pqc_drbg_limits --explicit-reseed ${QUDO_TEST_FIPS_ARGS})
    set_tests_properties(pqc_drbg_explicit_reseed PROPERTIES WORKING_DIRECTORY "${CMAKE_BINARY_DIR}/tests" ENVIRONMENT "${QUDO_TEST_ENV}")
    add_test(NAME pqc_drbg_adin COMMAND test_pqc_drbg_limits --adin ${QUDO_TEST_FIPS_ARGS})
    set_tests_properties(pqc_drbg_adin PROPERTIES WORKING_DIRECTORY "${CMAKE_BINARY_DIR}/tests" ENVIRONMENT "${QUDO_TEST_ENV}")
    add_test(NAME pqc_drbg_sequential COMMAND test_pqc_drbg_limits --sequential ${QUDO_TEST_FIPS_ARGS})
    set_tests_properties(pqc_drbg_sequential PROPERTIES WORKING_DIRECTORY "${CMAKE_BINARY_DIR}/tests" ENVIRONMENT "${QUDO_TEST_ENV}")
    add_test(NAME pqc_drbg_is_ready COMMAND test_pqc_drbg_limits --is-ready ${QUDO_TEST_FIPS_ARGS})
    set_tests_properties(pqc_drbg_is_ready PROPERTIES WORKING_DIRECTORY "${CMAKE_BINARY_DIR}/tests" ENVIRONMENT "${QUDO_TEST_ENV}")
    endif()

    # --- test_pqc_utils_edge: qudo_pqc_utils.c wrapper edge cases ---
    # Covers cleanse edge cases,
    # HMAC one-shot + context lifecycle, CTR-DRBG wrapper lifecycle with
    # is_zeroized + reseed, module-boundary and integrity-HMAC getters.
    add_executable(test_pqc_utils_edge tests/test_pqc_utils_edge.c)
    target_include_directories(test_pqc_utils_edge PRIVATE ${QUDO_TEST_COMMON_INCLUDES})
    target_compile_definitions(test_pqc_utils_edge PRIVATE ${QUDO_TEST_COMPILE_DEFS})
    target_link_libraries(test_pqc_utils_edge PRIVATE qudo-pqc ${QUDO_TEST_PLATFORM_LIBS})
    set_target_properties(test_pqc_utils_edge PROPERTIES
        RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/tests"
    )
    if(NOT ENABLE_MSAN)
    add_test(NAME pqc_utils_edge COMMAND test_pqc_utils_edge ${QUDO_TEST_FIPS_ARGS})
    set_tests_properties(pqc_utils_edge PROPERTIES WORKING_DIRECTORY "${CMAKE_BINARY_DIR}/tests" ENVIRONMENT "${QUDO_TEST_ENV}")
    add_test(NAME pqc_utils_cleanse COMMAND test_pqc_utils_edge --cleanse ${QUDO_TEST_FIPS_ARGS})
    set_tests_properties(pqc_utils_cleanse PROPERTIES WORKING_DIRECTORY "${CMAKE_BINARY_DIR}/tests" ENVIRONMENT "${QUDO_TEST_ENV}")
    add_test(NAME pqc_utils_hmac COMMAND test_pqc_utils_edge --hmac ${QUDO_TEST_FIPS_ARGS})
    set_tests_properties(pqc_utils_hmac PROPERTIES WORKING_DIRECTORY "${CMAKE_BINARY_DIR}/tests" ENVIRONMENT "${QUDO_TEST_ENV}")
    add_test(NAME pqc_utils_hmac_ctx COMMAND test_pqc_utils_edge --hmac-ctx ${QUDO_TEST_FIPS_ARGS})
    set_tests_properties(pqc_utils_hmac_ctx PROPERTIES WORKING_DIRECTORY "${CMAKE_BINARY_DIR}/tests" ENVIRONMENT "${QUDO_TEST_ENV}")
    add_test(NAME pqc_utils_ctrdrbg COMMAND test_pqc_utils_edge --ctrdrbg ${QUDO_TEST_FIPS_ARGS})
    set_tests_properties(pqc_utils_ctrdrbg PROPERTIES WORKING_DIRECTORY "${CMAKE_BINARY_DIR}/tests" ENVIRONMENT "${QUDO_TEST_ENV}")
    add_test(NAME pqc_utils_boundary COMMAND test_pqc_utils_edge --boundary ${QUDO_TEST_FIPS_ARGS})
    set_tests_properties(pqc_utils_boundary PROPERTIES WORKING_DIRECTORY "${CMAKE_BINARY_DIR}/tests" ENVIRONMENT "${QUDO_TEST_ENV}")
    endif()

    # --- test_pqc_wrapper_coverage: function-coverage sweep of all wrappers ---
    # Calls every public entry point in mldsa_wrapper.c, mlkem_wrapper.c and
    # slhdsa_wrapper.c: info getters, level-based convenience APIs, per-paramset convenience
    # variants, SHAKE256 context, and error-string enumeration.
    add_executable(test_pqc_wrapper_coverage tests/test_pqc_wrapper_coverage.c)
    target_include_directories(test_pqc_wrapper_coverage PRIVATE ${QUDO_TEST_COMMON_INCLUDES})
    target_compile_definitions(test_pqc_wrapper_coverage PRIVATE ${QUDO_TEST_COMPILE_DEFS})
    target_link_libraries(test_pqc_wrapper_coverage PRIVATE qudo-pqc ${QUDO_TEST_PLATFORM_LIBS})
    set_target_properties(test_pqc_wrapper_coverage PROPERTIES
        RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/tests"
    )
    if(NOT ENABLE_MSAN)
    add_test(NAME pqc_wrapper_coverage COMMAND test_pqc_wrapper_coverage ${QUDO_TEST_FIPS_ARGS})
    set_tests_properties(pqc_wrapper_coverage PROPERTIES WORKING_DIRECTORY "${CMAKE_BINARY_DIR}/tests" ENVIRONMENT "${QUDO_TEST_ENV}" TIMEOUT 300)
    add_test(NAME pqc_wrapper_mlkem_info COMMAND test_pqc_wrapper_coverage --mlkem-info ${QUDO_TEST_FIPS_ARGS})
    set_tests_properties(pqc_wrapper_mlkem_info PROPERTIES WORKING_DIRECTORY "${CMAKE_BINARY_DIR}/tests" ENVIRONMENT "${QUDO_TEST_ENV}")
    add_test(NAME pqc_wrapper_mlkem_level COMMAND test_pqc_wrapper_coverage --mlkem-level ${QUDO_TEST_FIPS_ARGS})
    set_tests_properties(pqc_wrapper_mlkem_level PROPERTIES WORKING_DIRECTORY "${CMAKE_BINARY_DIR}/tests" ENVIRONMENT "${QUDO_TEST_ENV}")
    add_test(NAME pqc_wrapper_mldsa COMMAND test_pqc_wrapper_coverage --mldsa ${QUDO_TEST_FIPS_ARGS})
    set_tests_properties(pqc_wrapper_mldsa PROPERTIES WORKING_DIRECTORY "${CMAKE_BINARY_DIR}/tests" ENVIRONMENT "${QUDO_TEST_ENV}")
    add_test(NAME pqc_wrapper_mldsa_level COMMAND test_pqc_wrapper_coverage --mldsa-level ${QUDO_TEST_FIPS_ARGS})
    set_tests_properties(pqc_wrapper_mldsa_level PROPERTIES WORKING_DIRECTORY "${CMAKE_BINARY_DIR}/tests" ENVIRONMENT "${QUDO_TEST_ENV}")
    add_test(NAME pqc_wrapper_mldsa_shake COMMAND test_pqc_wrapper_coverage --mldsa-shake ${QUDO_TEST_FIPS_ARGS})
    set_tests_properties(pqc_wrapper_mldsa_shake PROPERTIES WORKING_DIRECTORY "${CMAKE_BINARY_DIR}/tests" ENVIRONMENT "${QUDO_TEST_ENV}")
    add_test(NAME pqc_wrapper_slhdsa COMMAND test_pqc_wrapper_coverage --slhdsa ${QUDO_TEST_FIPS_ARGS})
    set_tests_properties(pqc_wrapper_slhdsa PROPERTIES WORKING_DIRECTORY "${CMAKE_BINARY_DIR}/tests" ENVIRONMENT "${QUDO_TEST_ENV}")
    add_test(NAME pqc_wrapper_slhdsa_f COMMAND test_pqc_wrapper_coverage --slhdsa-f ${QUDO_TEST_FIPS_ARGS})
    set_tests_properties(pqc_wrapper_slhdsa_f PROPERTIES WORKING_DIRECTORY "${CMAKE_BINARY_DIR}/tests" ENVIRONMENT "${QUDO_TEST_ENV}" TIMEOUT 300)
    add_test(NAME pqc_wrapper_slhdsa_ex COMMAND test_pqc_wrapper_coverage --slhdsa-ex ${QUDO_TEST_FIPS_ARGS})
    set_tests_properties(pqc_wrapper_slhdsa_ex PROPERTIES WORKING_DIRECTORY "${CMAKE_BINARY_DIR}/tests" ENVIRONMENT "${QUDO_TEST_ENV}")
    endif()

    # --- test_pqc_final_coverage: per-level MLDSA advanced + error/memory ---
    # Per-level MLDSA 44/65/87
    # advanced variants (keypair_internal, sign_internal/verify_internal,
    # sign_concat/open, sign_extmu/verify_extmu, sign_pre_hash/verify_pre_hash),
    # full error-enum enumeration across the three families, and the
    # public memory helpers (secure_zero/alloc/free, constant_time).
    add_executable(test_pqc_final_coverage tests/test_pqc_final_coverage.c)
    target_include_directories(test_pqc_final_coverage PRIVATE ${QUDO_TEST_COMMON_INCLUDES})
    target_compile_definitions(test_pqc_final_coverage PRIVATE ${QUDO_TEST_COMPILE_DEFS})
    target_link_libraries(test_pqc_final_coverage PRIVATE qudo-pqc ${QUDO_TEST_PLATFORM_LIBS})
    set_target_properties(test_pqc_final_coverage PROPERTIES
        RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/tests"
    )
    if(NOT ENABLE_MSAN)
    add_test(NAME pqc_final_coverage COMMAND test_pqc_final_coverage ${QUDO_TEST_FIPS_ARGS})
    set_tests_properties(pqc_final_coverage PROPERTIES WORKING_DIRECTORY "${CMAKE_BINARY_DIR}/tests" ENVIRONMENT "${QUDO_TEST_ENV}")
    add_test(NAME pqc_final_mldsa_adv COMMAND test_pqc_final_coverage --mldsa-adv ${QUDO_TEST_FIPS_ARGS})
    set_tests_properties(pqc_final_mldsa_adv PROPERTIES WORKING_DIRECTORY "${CMAKE_BINARY_DIR}/tests" ENVIRONMENT "${QUDO_TEST_ENV}")
    add_test(NAME pqc_final_errors COMMAND test_pqc_final_coverage --errors ${QUDO_TEST_FIPS_ARGS})
    set_tests_properties(pqc_final_errors PROPERTIES WORKING_DIRECTORY "${CMAKE_BINARY_DIR}/tests" ENVIRONMENT "${QUDO_TEST_ENV}")
    add_test(NAME pqc_final_memory COMMAND test_pqc_final_coverage --memory ${QUDO_TEST_FIPS_ARGS})
    set_tests_properties(pqc_final_memory PROPERTIES WORKING_DIRECTORY "${CMAKE_BINARY_DIR}/tests" ENVIRONMENT "${QUDO_TEST_ENV}")
    endif()

    # --- SLH-DSA sign output-buffer bounds ---
    add_executable(test_slhdsa_sign_bounds tests/test_slhdsa_sign_bounds.c)
    target_include_directories(test_slhdsa_sign_bounds PRIVATE ${QUDO_TEST_COMMON_INCLUDES})
    target_compile_definitions(test_slhdsa_sign_bounds PRIVATE ${QUDO_TEST_COMPILE_DEFS})
    target_link_libraries(test_slhdsa_sign_bounds PRIVATE qudo-pqc ${QUDO_TEST_PLATFORM_LIBS})
    set_target_properties(test_slhdsa_sign_bounds PROPERTIES
        RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/tests"
    )
    if(NOT ENABLE_MSAN)
    add_test(NAME slhdsa_sign_bounds COMMAND test_slhdsa_sign_bounds ${QUDO_TEST_FIPS_ARGS})
    set_tests_properties(slhdsa_sign_bounds PROPERTIES WORKING_DIRECTORY "${CMAKE_BINARY_DIR}/tests" ENVIRONMENT "${QUDO_TEST_ENV}")
    endif()

    # --- ML-DSA sign capacity + verify length bounds ---
    add_executable(test_mldsa_sign_verify_bounds tests/test_mldsa_sign_verify_bounds.c)
    target_include_directories(test_mldsa_sign_verify_bounds PRIVATE ${QUDO_TEST_COMMON_INCLUDES})
    target_compile_definitions(test_mldsa_sign_verify_bounds PRIVATE ${QUDO_TEST_COMPILE_DEFS})
    target_link_libraries(test_mldsa_sign_verify_bounds PRIVATE qudo-pqc ${QUDO_TEST_PLATFORM_LIBS})
    set_target_properties(test_mldsa_sign_verify_bounds PROPERTIES
        RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/tests"
    )
    if(NOT ENABLE_MSAN)
    add_test(NAME mldsa_sign_verify_bounds COMMAND test_mldsa_sign_verify_bounds ${QUDO_TEST_FIPS_ARGS})
    set_tests_properties(mldsa_sign_verify_bounds PROPERTIES WORKING_DIRECTORY "${CMAKE_BINARY_DIR}/tests" ENVIRONMENT "${QUDO_TEST_ENV}")
    endif()

    # --- ML-KEM keypair_derand seed-length validation ---
    add_executable(test_mlkem_keypair_derand_seed_len tests/test_mlkem_keypair_derand_seed_len.c)
    target_include_directories(test_mlkem_keypair_derand_seed_len PRIVATE ${QUDO_TEST_COMMON_INCLUDES})
    target_compile_definitions(test_mlkem_keypair_derand_seed_len PRIVATE ${QUDO_TEST_COMPILE_DEFS})
    target_link_libraries(test_mlkem_keypair_derand_seed_len PRIVATE qudo-pqc ${QUDO_TEST_PLATFORM_LIBS})
    set_target_properties(test_mlkem_keypair_derand_seed_len PROPERTIES
        RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/tests"
    )
    if(NOT ENABLE_MSAN)
    add_test(NAME mlkem_keypair_derand_seed_len COMMAND test_mlkem_keypair_derand_seed_len ${QUDO_TEST_FIPS_ARGS})
    set_tests_properties(mlkem_keypair_derand_seed_len PROPERTIES WORKING_DIRECTORY "${CMAKE_BINARY_DIR}/tests" ENVIRONMENT "${QUDO_TEST_ENV}")
    endif()

    # --- Public config API coverage: QUDO_KEM_config_* / QUDO_MLDSA_config_* ---
    add_executable(test_mlkem_config tests/test_mlkem_config.c)
    target_include_directories(test_mlkem_config PRIVATE ${QUDO_TEST_COMMON_INCLUDES})
    target_compile_definitions(test_mlkem_config PRIVATE ${QUDO_TEST_COMPILE_DEFS})
    target_link_libraries(test_mlkem_config PRIVATE qudo-pqc ${QUDO_TEST_PLATFORM_LIBS})
    set_target_properties(test_mlkem_config PROPERTIES
        RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/tests"
    )

    add_executable(test_mldsa_config tests/test_mldsa_config.c)
    target_include_directories(test_mldsa_config PRIVATE ${QUDO_TEST_COMMON_INCLUDES})
    target_compile_definitions(test_mldsa_config PRIVATE ${QUDO_TEST_COMPILE_DEFS})
    target_link_libraries(test_mldsa_config PRIVATE qudo-pqc ${QUDO_TEST_PLATFORM_LIBS})
    set_target_properties(test_mldsa_config PROPERTIES
        RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/tests"
    )

    add_executable(test_slhdsa_config tests/test_slhdsa_config.c)
    target_include_directories(test_slhdsa_config PRIVATE ${QUDO_TEST_COMMON_INCLUDES})
    target_compile_definitions(test_slhdsa_config PRIVATE ${QUDO_TEST_COMPILE_DEFS})
    target_link_libraries(test_slhdsa_config PRIVATE qudo-pqc ${QUDO_TEST_PLATFORM_LIBS})
    set_target_properties(test_slhdsa_config PROPERTIES
        RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/tests"
    )

    # --- DER/PEM interop roundtrip across mlkem/mldsa/slhdsa ---
    add_executable(test_interop_roundtrip tests/test_interop_roundtrip.c)
    target_include_directories(test_interop_roundtrip PRIVATE ${QUDO_TEST_COMMON_INCLUDES})
    target_compile_definitions(test_interop_roundtrip PRIVATE ${QUDO_TEST_COMPILE_DEFS})
    target_link_libraries(test_interop_roundtrip PRIVATE qudo-pqc ${QUDO_TEST_PLATFORM_LIBS})
    set_target_properties(test_interop_roundtrip PROPERTIES
        RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/tests"
    )

    if(NOT ENABLE_MSAN)
    add_test(NAME mlkem_config COMMAND test_mlkem_config)
    set_tests_properties(mlkem_config PROPERTIES WORKING_DIRECTORY "${CMAKE_BINARY_DIR}/tests" ENVIRONMENT "${QUDO_TEST_ENV}")
    add_test(NAME mldsa_config COMMAND test_mldsa_config)
    set_tests_properties(mldsa_config PROPERTIES WORKING_DIRECTORY "${CMAKE_BINARY_DIR}/tests" ENVIRONMENT "${QUDO_TEST_ENV}")
    add_test(NAME slhdsa_config COMMAND test_slhdsa_config)
    set_tests_properties(slhdsa_config PROPERTIES WORKING_DIRECTORY "${CMAKE_BINARY_DIR}/tests" ENVIRONMENT "${QUDO_TEST_ENV}")
    add_test(NAME interop_roundtrip COMMAND test_interop_roundtrip ${QUDO_TEST_FIPS_ARGS})
    set_tests_properties(interop_roundtrip PROPERTIES WORKING_DIRECTORY "${CMAKE_BINARY_DIR}/tests" ENVIRONMENT "${QUDO_TEST_ENV}")
    endif()

    # ==========================================================================
    # Fuzz corpus replay (opt-in): replays each fuzz corpus through its harness
    # without libFuzzer. Corpus directories are generated, not committed:
    #     bash qudo-mlkem/fuzz/run_fuzz.sh        # generate corpus_*
    #     cmake -DQUDO_FUZZ_REPLAY=ON -B build && cmake --build build
    #     ctest -L fuzz_replay
    # ==========================================================================
    if(QUDO_FUZZ_REPLAY AND NOT ENABLE_MSAN)
        function(qudo_add_fuzz_replay name harness)
            add_executable(${name} tests/fuzz_corpus_replay.c ${harness})
            target_include_directories(${name} PRIVATE ${QUDO_TEST_COMMON_INCLUDES})
            target_compile_definitions(${name} PRIVATE ${QUDO_TEST_COMPILE_DEFS})
            target_link_libraries(${name} PRIVATE qudo-pqc ${QUDO_TEST_PLATFORM_LIBS})
            set_target_properties(${name} PROPERTIES
                RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/tests")
            add_test(NAME ${name} COMMAND ${name} ${ARGN})
            set_tests_properties(${name} PROPERTIES
                WORKING_DIRECTORY "${CMAKE_BINARY_DIR}/tests"
                ENVIRONMENT "${QUDO_TEST_ENV}"
                LABELS "fuzz_replay")
        endfunction()

        set(QUDO_MLKEM_FUZZ ${CMAKE_CURRENT_SOURCE_DIR}/qudo-mlkem/fuzz)
        set(QUDO_MLDSA_FUZZ ${CMAKE_CURRENT_SOURCE_DIR}/qudo-mldsa/fuzz)
        set(QUDO_SLHDSA_FUZZ ${CMAKE_CURRENT_SOURCE_DIR}/qudo-slhdsa/fuzz)

        qudo_add_fuzz_replay(replay_mlkem_der_import ${QUDO_MLKEM_FUZZ}/fuzz_mlkem_der_import.c
            ${QUDO_MLKEM_FUZZ}/corpus_der ${QUDO_MLKEM_FUZZ}/seed_corpus_der)
        qudo_add_fuzz_replay(replay_mlkem_pem_import ${QUDO_MLKEM_FUZZ}/fuzz_mlkem_pem_import.c
            ${QUDO_MLKEM_FUZZ}/corpus_pem)
        qudo_add_fuzz_replay(replay_mlkem_kem_ops ${QUDO_MLKEM_FUZZ}/fuzz_mlkem_kem_ops.c
            ${QUDO_MLKEM_FUZZ}/corpus_kem)

        qudo_add_fuzz_replay(replay_mldsa_der_import ${QUDO_MLDSA_FUZZ}/fuzz_mldsa_der_import.c
            ${QUDO_MLDSA_FUZZ}/corpus_der ${QUDO_MLDSA_FUZZ}/seed_corpus_der)
        qudo_add_fuzz_replay(replay_mldsa_pem_import ${QUDO_MLDSA_FUZZ}/fuzz_mldsa_pem_import.c
            ${QUDO_MLDSA_FUZZ}/corpus_pem)
        qudo_add_fuzz_replay(replay_mldsa_sig_ops ${QUDO_MLDSA_FUZZ}/fuzz_mldsa_sig_ops.c
            ${QUDO_MLDSA_FUZZ}/corpus_sig)

        qudo_add_fuzz_replay(replay_slhdsa_der_import ${QUDO_SLHDSA_FUZZ}/fuzz_slhdsa_der_import.c
            ${QUDO_SLHDSA_FUZZ}/corpus_der ${QUDO_SLHDSA_FUZZ}/seed_corpus_der)
        qudo_add_fuzz_replay(replay_slhdsa_pem_import ${QUDO_SLHDSA_FUZZ}/fuzz_slhdsa_pem_import.c
            ${QUDO_SLHDSA_FUZZ}/corpus_pem)
        qudo_add_fuzz_replay(replay_slhdsa_sig_ops ${QUDO_SLHDSA_FUZZ}/fuzz_slhdsa_sig_ops.c
            ${QUDO_SLHDSA_FUZZ}/corpus_sig)
    endif()

endif()

# ========================================================================== #
# ACVP Test Runner                                                            #
# ========================================================================== #

if(BUILD_ACVP)
    add_subdirectory(acvp)
endif()

# ========================================================================== #
# Build Summary                                                               #
# ========================================================================== #

message(STATUS "")
message(STATUS "=== QUDO PQC Crypto Library Build ===")
message(STATUS "Version: ${PROJECT_VERSION}")
message(STATUS "FIPS module: ${QUDO_FIPS_MODULE}")
message(STATUS "OpenSSL: ${QUDO_PQC_USE_OPENSSL}")
message(STATUS "Build tests: ${QUDO_PQC_BUILD_TESTS}")
message(STATUS "ACVP runner: ${BUILD_ACVP}")
message(STATUS "Coverage: ${ENABLE_COVERAGE}")
message(STATUS "Sanitizers (ASan+UBSan): ${ENABLE_SANITIZERS}")
message(STATUS "MemorySanitizer: ${ENABLE_MSAN}")
message(STATUS "ThreadSanitizer: ${ENABLE_TSAN}")
message(STATUS "=====================================")
message(STATUS "")

# ========================================================================== #
# Static Analysis Targets (optional)                                          #
# ========================================================================== #

include(cmake/clang-tidy.cmake)
include(cmake/cppcheck.cmake)
