# Tests CMakeLists.txt

# Treat implicit function declarations and int/pointer conversions as errors.
if(CMAKE_C_COMPILER_ID MATCHES "GNU|Clang")
    add_compile_options(-Werror=implicit-function-declaration -Werror=int-conversion)
endif()

# Basic functionality tests
add_executable(test_mldsa test_mldsa.c)
target_link_libraries(test_mldsa qudo-mldsa OpenSSL::Crypto)

# Advanced API test - all modes supported
add_executable(test_advanced_api test_advanced_api.c)
target_link_libraries(test_advanced_api qudo-mldsa)

add_executable(test_liboqs_compat test_liboqs_compat.c)
target_link_libraries(test_liboqs_compat qudo-mldsa)

# NIST Known Answer Test (KAT) - Functional
add_executable(test_kat test_kat.c)
target_link_libraries(test_kat qudo-mldsa OpenSSL::Crypto)

# NIST Known Answer Test (KAT) - NIST Format
find_package(OpenSSL REQUIRED)
add_executable(test_kat_nist test_kat_nist.c nist_drbg.c)
target_link_libraries(test_kat_nist qudo-mldsa OpenSSL::Crypto)

# DER/PEM Serialization Test (requires OpenSSL)
if(OPENSSL_FOUND)
    add_executable(test_der_pem test_der_pem.c)
    target_link_libraries(test_der_pem qudo-mldsa OpenSSL::SSL OpenSSL::Crypto)

    # SEED_PRIV Cross-Format Interop Test (standalone <-> OpenSSL 3.5+ native ML-DSA)
    # Only build when OpenSSL >= 3.5 (native ML-DSA support required)
    if(OPENSSL_VERSION VERSION_GREATER_EQUAL "3.5")
        add_executable(test_seed_priv_interop test_seed_priv_interop.c)
        target_link_libraries(test_seed_priv_interop qudo-mldsa OpenSSL::SSL OpenSSL::Crypto)
    else()
        message(STATUS "Skipping seed_priv_interop test (requires OpenSSL 3.5+, found ${OPENSSL_VERSION})")
    endif()
endif()

## Coverage tests — Object API, Direct API, utilities, config
add_executable(test_object_api test_object_api.c)
target_link_libraries(test_object_api qudo-mldsa)

## Coverage tests — DER/PEM interop
add_executable(test_interop_cov test_interop_cov.c)
target_link_libraries(test_interop_cov qudo-mldsa)

## Coverage tests — Secure memory functions
add_executable(test_memory test_memory.c)
target_link_libraries(test_memory qudo-mldsa)

## Coverage tests — Platform detection
add_executable(test_platform test_platform.c)
target_link_libraries(test_platform qudo-mldsa)

enable_testing()
add_test(NAME test_mldsa COMMAND test_mldsa)
add_test(NAME test_advanced_api COMMAND test_advanced_api)
add_test(NAME test_liboqs_compat COMMAND test_liboqs_compat)
add_test(NAME kat_test COMMAND test_kat)
add_test(NAME kat_nist_44 COMMAND test_kat_nist ML-DSA-44 1)
add_test(NAME kat_nist_65 COMMAND test_kat_nist ML-DSA-65 1)
add_test(NAME kat_nist_87 COMMAND test_kat_nist ML-DSA-87 1)
if(OPENSSL_FOUND)
    add_test(NAME der_pem_test COMMAND test_der_pem)
    if(OPENSSL_VERSION VERSION_GREATER_EQUAL "3.5")
        add_test(NAME seed_priv_interop_test COMMAND test_seed_priv_interop)
    endif()
endif()
add_test(NAME object_api_test COMMAND test_object_api)
add_test(NAME interop_cov_test COMMAND test_interop_cov)
add_test(NAME memory_test COMMAND test_memory)
add_test(NAME platform_test COMMAND test_platform)

# Constant-time check under Valgrind secret poisoning (-DMLDSA_CT_VALGRIND=ON
# defines MLD_CONFIG_CT_TESTING_ENABLED).
if(MLDSA_CT_VALGRIND)
    find_program(CT_VALGRIND_EXECUTABLE valgrind)
    add_executable(test_ct_valgrind test_ct_valgrind.c)
    target_link_libraries(test_ct_valgrind qudo-mldsa)
    if(CT_VALGRIND_EXECUTABLE)
        add_test(NAME constant_time_valgrind
                 COMMAND ${CT_VALGRIND_EXECUTABLE}
                         --error-exitcode=1 --exit-on-first-error=yes
                         --track-origins=yes -q
                         $<TARGET_FILE:test_ct_valgrind>)
    else()
        message(WARNING "MLDSA_CT_VALGRIND=ON but valgrind not found; CT test will not run")
    endif()
endif()

# Memory leak testing with Valgrind (optional)
find_program(VALGRIND_EXECUTABLE valgrind)
if(VALGRIND_EXECUTABLE)
    message(STATUS "Valgrind found: ${VALGRIND_EXECUTABLE}")
    add_test(NAME valgrind_memory_leak_test
             COMMAND bash ${CMAKE_CURRENT_SOURCE_DIR}/test_valgrind.sh
             WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR})
else()
    message(STATUS "Valgrind not found - memory leak tests will be skipped")
endif()
