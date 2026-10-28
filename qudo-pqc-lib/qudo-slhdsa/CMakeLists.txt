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
    project(QUDO_SLHDSA VERSION 1.0.0 LANGUAGES C)
else()
    project(QUDO_SLHDSA VERSION 1.0.0 LANGUAGES C ASM)
endif()

# Version information
set(SLHDSA_VERSION_MAJOR 1)
set(SLHDSA_VERSION_MINOR 0)
set(SLHDSA_VERSION_PATCH 0)
set(SLHDSA_VERSION_TEXT "${SLHDSA_VERSION_MAJOR}.${SLHDSA_VERSION_MINOR}.${SLHDSA_VERSION_PATCH}")

# Build options
option(BUILD_SHARED_LIBS "Build shared libraries" ON)
option(BUILD_TESTS "Build test programs" ON)
option(BUILD_EXAMPLES "Build example programs" ON)
option(ENABLE_SANITIZERS "Enable AddressSanitizer and UndefinedBehaviorSanitizer" OFF)
option(ENABLE_COVERAGE "Enable code coverage instrumentation" OFF)
option(BUILD_FUZZ "Build fuzzing harnesses (requires Clang with libFuzzer)" OFF)
option(SLHDSA_STRICT_WARNINGS "Enable strict compiler warnings" OFF)

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
    set(SLHDSA_QUIET ON)
endif()

if(NOT SLHDSA_QUIET)
    message(STATUS "Building qudo-slhdsa for platform: ${PLATFORM_NAME}")
endif()

# Include standard modules
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
    if(NOT WIN32)
        add_compile_options(-fstack-protector-strong)
    endif()
    if(UNIX AND NOT APPLE AND NOT WIN32)
        add_link_options(-Wl,-z,relro -Wl,-z,now -Wl,-z,noexecstack)
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

# Note: Fuzz instrumentation is applied per-target below (after library creation)
# to avoid conflicts with SHA-NI intrinsics.

# Strict warnings
if(SLHDSA_STRICT_WARNINGS)
    if(CMAKE_C_COMPILER_ID MATCHES "GNU|Clang")
        add_compile_options(-Wall -Wextra -Wpedantic -Werror)
    elseif(MSVC)
        add_compile_options(/W4 /WX)
    endif()
endif()

# OpenSSL — optional when built as subdirectory with SLHDSA_USE_OPENSSL=OFF
if(NOT DEFINED SLHDSA_USE_OPENSSL)
    set(SLHDSA_USE_OPENSSL ON)
endif()

if(SLHDSA_USE_OPENSSL)
    if(SLHDSA_QUIET)
        find_package(OpenSSL QUIET)
    else()
        find_package(OpenSSL)
    endif()
    if(OPENSSL_FOUND)
        if(NOT SLHDSA_QUIET)
            message(STATUS "OpenSSL found: ${OPENSSL_VERSION}")
            message(STATUS "OpenSSL include: ${OPENSSL_INCLUDE_DIR}")
        endif()
        add_definitions(-DQUDO_SLHDSA_USE_OPENSSL)
    else()
        message(WARNING "OpenSSL requested but not found. DER/PEM interop disabled.")
    endif()
endif()

# Detect architecture for assembly optimizations
if(CMAKE_SYSTEM_PROCESSOR MATCHES "x86_64|AMD64")
    set(HAVE_X86_64 TRUE)
    if(NOT SLHDSA_QUIET)
        message(STATUS "SLH-DSA: Architecture x86_64 detected")
    endif()
    if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
        set(HAVE_X86_64_ASM TRUE)
        set(KECCAK_ASM_FILE "keccak1600-x86_64.s")
        if(NOT SLHDSA_QUIET)
            message(STATUS "Keccak assembly optimizations enabled (ELF)")
        endif()
    elseif(APPLE)
        set(HAVE_X86_64_ASM TRUE)
        set(KECCAK_ASM_FILE "keccak1600-x86_64-macho.s")
        if(NOT SLHDSA_QUIET)
            message(STATUS "Keccak assembly optimizations enabled (Mach-O)")
        endif()
    else()
        if(NOT SLHDSA_QUIET)
            message(STATUS "Keccak assembly disabled (${CMAKE_SYSTEM_NAME}) - using portable C implementation")
        endif()
    endif()
elseif(CMAKE_SYSTEM_PROCESSOR MATCHES "aarch64|arm64|ARM64")
    if(NOT SLHDSA_QUIET)
        message(STATUS "SLH-DSA: Architecture ARM64 (portable C, no NEON assembly)")
    endif()
elseif(CMAKE_SYSTEM_PROCESSOR MATCHES "^arm|^armv7|^armhf")
    if(NOT SLHDSA_QUIET)
        message(STATUS "SLH-DSA: Architecture ARM32 (portable C, no assembly)")
    endif()
elseif(CMAKE_SYSTEM_PROCESSOR MATCHES "i[3456]86|x86")
    if(NOT SLHDSA_QUIET)
        message(STATUS "SLH-DSA: Architecture x86 32-bit (portable C)")
    endif()
endif()

# slhdsa-native source files
set(SLHDSA_NATIVE_SOURCES
    ${CMAKE_CURRENT_SOURCE_DIR}/slhdsa-native/slh_dsa.c
    ${CMAKE_CURRENT_SOURCE_DIR}/slhdsa-native/slh_sha2.c
    ${CMAKE_CURRENT_SOURCE_DIR}/slhdsa-native/slh_shake.c
    ${CMAKE_CURRENT_SOURCE_DIR}/slhdsa-native/slh_prehash.c
    ${CMAKE_CURRENT_SOURCE_DIR}/slhdsa-native/sha2_256.c
    ${CMAKE_CURRENT_SOURCE_DIR}/slhdsa-native/sha2_512.c
    ${CMAKE_CURRENT_SOURCE_DIR}/slhdsa-native/sha3_api.c
    ${CMAKE_CURRENT_SOURCE_DIR}/slhdsa-native/sha3_f1600.c
)

# Add assembly optimizations for x86-64 (GNU AS syntax — GCC/Clang only)
if(HAVE_X86_64_ASM)
    list(APPEND SLHDSA_NATIVE_SOURCES
        ${CMAKE_CURRENT_SOURCE_DIR}/slhdsa-native/${KECCAK_ASM_FILE}
    )
    if(NOT SLHDSA_QUIET)
        message(STATUS "SLH-DSA: Keccak assembly optimization enabled (${KECCAK_ASM_FILE})")
    endif()
endif()

# SHA-NI acceleration (Linux x86_64); sha2_256.c falls back to portable C at
# runtime on CPUs without SHA extensions.
if(CMAKE_SYSTEM_PROCESSOR MATCHES "x86_64|AMD64|amd64" AND CMAKE_SYSTEM_NAME STREQUAL "Linux")
    set(HAVE_SHA_NI TRUE)
    if(BUILD_FUZZ OR CMAKE_C_COMPILER_ID MATCHES "Clang")
        # Build SHA-NI as separate object library:
        # - Fuzz builds: avoids sanitizer flags on intrinsics
        # - Clang: requires explicit flags (#pragma GCC target is ignored)
        add_library(slhdsa_shani_obj OBJECT
            ${CMAKE_CURRENT_SOURCE_DIR}/slhdsa-native/sha2_256_shani.c)
        target_include_directories(slhdsa_shani_obj PRIVATE
            ${CMAKE_CURRENT_SOURCE_DIR}/slhdsa-native
            ${CMAKE_CURRENT_SOURCE_DIR}/include)
        target_compile_options(slhdsa_shani_obj PRIVATE -msha -msse4.1 -mssse3)
        set(SLHDSA_SHANI_EXTRA_LIB slhdsa_shani_obj)
    else()
        list(APPEND SLHDSA_NATIVE_SOURCES
            ${CMAKE_CURRENT_SOURCE_DIR}/slhdsa-native/sha2_256_shani.c
        )
    endif()
    if(NOT SLHDSA_QUIET)
        message(STATUS "SLH-DSA: SHA-NI acceleration enabled (x86_64)")
    endif()
endif()

# QUDO wrapper sources
set(SLHDSA_WRAPPER_SOURCES
    ${CMAKE_CURRENT_SOURCE_DIR}/src/slhdsa_wrapper.c
    ${CMAKE_CURRENT_SOURCE_DIR}/src/slhdsa_config.c
    ${CMAKE_CURRENT_SOURCE_DIR}/src/slhdsa_error.c
    ${CMAKE_CURRENT_SOURCE_DIR}/src/slhdsa_interop.c
    ${CMAKE_CURRENT_SOURCE_DIR}/src/slhdsa_memory.c
    ${CMAKE_CURRENT_SOURCE_DIR}/src/platform_utils.c
    ${CMAKE_CURRENT_SOURCE_DIR}/src/slhdsa_rand.c
)

# Build the library
add_library(qudo-slhdsa ${SLHDSA_WRAPPER_SOURCES} ${SLHDSA_NATIVE_SOURCES})

# Tell sha3_f1600.c to use portable C when assembly is not available
if(HAVE_X86_64 AND NOT HAVE_X86_64_ASM)
    target_compile_definitions(qudo-slhdsa PRIVATE SLH_NO_ASM=1)
endif()
# Tell sha2_256.c to enable SHA-NI runtime dispatch
if(HAVE_SHA_NI)
    target_compile_definitions(qudo-slhdsa PRIVATE SLH_HAS_SHA_NI)
endif()

# Link SHA-NI object library (built with explicit flags for Clang/fuzz builds)
if(SLHDSA_SHANI_EXTRA_LIB)
    target_sources(qudo-slhdsa PRIVATE $<TARGET_OBJECTS:${SLHDSA_SHANI_EXTRA_LIB}>)
endif()

# Fuzz instrumentation: when BUILD_FUZZ=ON, compile the library with sanitizer
# coverage so libFuzzer can instrument all branches (not just the harness).
if(BUILD_FUZZ AND CMAKE_C_COMPILER_ID MATCHES "Clang")
    target_compile_options(qudo-slhdsa PRIVATE -fsanitize=fuzzer-no-link,address,undefined -fno-omit-frame-pointer)
    target_link_options(qudo-slhdsa PRIVATE -fsanitize=address,undefined)
endif()

# Export all source files to parent scope for combined library (libqudo-pqc.so)
set(_slhdsa_all_objs ${SLHDSA_WRAPPER_SOURCES} ${SLHDSA_NATIVE_SOURCES})
if(SLHDSA_SHANI_EXTRA_LIB)
    list(APPEND _slhdsa_all_objs $<TARGET_OBJECTS:${SLHDSA_SHANI_EXTRA_LIB}>)
endif()
set(QUDO_SLHDSA_ALL_OBJS ${_slhdsa_all_objs} PARENT_SCOPE)

target_include_directories(qudo-slhdsa
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
        $<INSTALL_INTERFACE:include>
    PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/slhdsa-native
        ${CMAKE_CURRENT_SOURCE_DIR}/src
)

# Internal FIPS DRBG headers — provided by parent in combined build,
# or discovered from relative path in standalone build.
if(NOT QUDO_COMBINED_BUILD)
    if(EXISTS ${CMAKE_CURRENT_SOURCE_DIR}/../src/fips)
        target_include_directories(qudo-slhdsa PRIVATE
            ${CMAKE_CURRENT_SOURCE_DIR}/../src
        )
    endif()
endif()

if(OPENSSL_FOUND AND SLHDSA_USE_OPENSSL)
    target_link_libraries(qudo-slhdsa PUBLIC OpenSSL::Crypto)
endif()

# Platform-specific libraries
if(WIN32)
    target_link_libraries(qudo-slhdsa PRIVATE ws2_32 bcrypt)
elseif(UNIX AND NOT APPLE)
    target_link_libraries(qudo-slhdsa PRIVATE pthread)
endif()

target_compile_definitions(qudo-slhdsa PRIVATE QUDO_SLHDSA_BUILD_SHARED)

# Compiler warnings
if(NOT MSVC)
    target_compile_options(qudo-slhdsa PRIVATE -Wall -Wextra -Wpedantic)
    # Suppress warnings from slhdsa-native code
    set_source_files_properties(${SLHDSA_NATIVE_SOURCES} PROPERTIES
        COMPILE_FLAGS "-Wno-unused-parameter -Wno-sign-compare -Wno-pedantic -Wno-long-long")
elseif(MSVC)
    target_compile_options(qudo-slhdsa PRIVATE /W3)
endif()

# Export compile commands for IDE support
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# Enable CTest at top level
enable_testing()

# Tests
if(BUILD_TESTS AND NOT CMAKE_CURRENT_SOURCE_DIR STREQUAL CMAKE_SOURCE_DIR)
    # Built as subdirectory - skip tests
    message(STATUS "qudo-slhdsa: Skipping tests (built as subdirectory)")
elseif(BUILD_TESTS)
    add_subdirectory(tests)
endif()

# Examples
if(BUILD_EXAMPLES AND NOT CMAKE_CURRENT_SOURCE_DIR STREQUAL CMAKE_SOURCE_DIR)
    message(STATUS "qudo-slhdsa: Skipping examples (built as subdirectory)")
elseif(BUILD_EXAMPLES)
    add_subdirectory(examples)
endif()

# Fuzzing
if(BUILD_FUZZ)
    add_subdirectory(fuzz)
endif()

# Set library properties
set_target_properties(qudo-slhdsa PROPERTIES
    VERSION ${PROJECT_VERSION}
    SOVERSION ${PROJECT_VERSION_MAJOR}
)

# Symbol versioning (Linux/ELF only)
if(UNIX AND NOT APPLE)
    set_target_properties(qudo-slhdsa PROPERTIES
        LINK_FLAGS "-Wl,--version-script=${CMAKE_CURRENT_SOURCE_DIR}/config/libqudo-slhdsa.map"
    )
endif()

# Skip individual installation when built as part of qudo-pqc.
# The combined libqudo-pqc.so includes all SLH-DSA code.
if(NOT QUDO_COMBINED_BUILD)

install(TARGETS qudo-slhdsa
    EXPORT qudo-slhdsa-targets
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
    ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
)
install(DIRECTORY include/ DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})

# Export targets
install(EXPORT qudo-slhdsa-targets
    FILE qudo-slhdsa-targets.cmake
    NAMESPACE qudo::
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/qudo-slhdsa
)

# Generate and install package config
configure_package_config_file(
    ${CMAKE_CURRENT_SOURCE_DIR}/config/qudo-slhdsa-config.cmake.in
    ${CMAKE_CURRENT_BINARY_DIR}/qudo-slhdsa-config.cmake
    INSTALL_DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/qudo-slhdsa
)

install(FILES
    ${CMAKE_CURRENT_BINARY_DIR}/qudo-slhdsa-config.cmake
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/qudo-slhdsa
)

# pkg-config
configure_file(config/qudo-slhdsa.pc.in ${CMAKE_BINARY_DIR}/qudo-slhdsa.pc @ONLY)
install(FILES ${CMAKE_BINARY_DIR}/qudo-slhdsa.pc
        DESTINATION ${CMAKE_INSTALL_LIBDIR}/pkgconfig)

endif() # NOT QUDO_COMBINED_BUILD
