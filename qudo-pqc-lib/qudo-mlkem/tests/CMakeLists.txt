# Tests CMakeLists.txt

# Treat implicit function declarations and int/pointer conversions as errors.
if(CMAKE_C_COMPILER_ID MATCHES "GNU|Clang")
    add_compile_options(-Werror=implicit-function-declaration -Werror=int-conversion)
endif()

# Basic functionality test
add_executable(test_basic test_basic.c)
target_link_libraries(test_basic qudo-mlkem)

# NIST Known Answer Test (KAT) - Functional
add_executable(test_kat test_kat.c)
target_link_libraries(test_kat qudo-mlkem)

# NIST Known Answer Test (KAT) - NIST Format
add_executable(test_kat_nist test_kat_nist.c nist_drbg.c)
target_link_libraries(test_kat_nist qudo-mlkem OpenSSL::Crypto)

## Coverage tests — Object API, Direct API, utilities, config
add_executable(test_object_api test_object_api.c)
target_link_libraries(test_object_api qudo-mlkem)

## Coverage tests — DER/PEM interop
add_executable(test_interop test_interop.c)
target_link_libraries(test_interop qudo-mlkem)

## Coverage tests — Secure memory functions
add_executable(test_memory test_memory.c)
target_link_libraries(test_memory qudo-mlkem)

## Coverage tests — Platform detection
add_executable(test_platform test_platform.c)
target_link_libraries(test_platform qudo-mlkem)

enable_testing()
add_test(NAME basic_test COMMAND test_basic)
add_test(NAME kat_test COMMAND test_kat)
add_test(NAME kat_nist_512 COMMAND test_kat_nist ML-KEM-512 1)
add_test(NAME kat_nist_768 COMMAND test_kat_nist ML-KEM-768 1)
add_test(NAME kat_nist_1024 COMMAND test_kat_nist ML-KEM-1024 1)
add_test(NAME object_api_test COMMAND test_object_api)
add_test(NAME interop_test COMMAND test_interop)
add_test(NAME memory_test COMMAND test_memory)
add_test(NAME platform_test COMMAND test_platform)

# Constant-time check under Valgrind secret poisoning (-DMLKEM_CT_VALGRIND=ON
# defines MLK_CONFIG_CT_TESTING_ENABLED).
if(MLKEM_CT_VALGRIND)
    find_program(CT_VALGRIND_EXECUTABLE valgrind)
    add_executable(test_ct_valgrind test_ct_valgrind.c)
    target_link_libraries(test_ct_valgrind qudo-mlkem)
    if(CT_VALGRIND_EXECUTABLE)
        add_test(NAME constant_time_valgrind
                 COMMAND ${CT_VALGRIND_EXECUTABLE}
                         --error-exitcode=1 --exit-on-first-error=yes
                         --track-origins=yes -q
                         $<TARGET_FILE:test_ct_valgrind>)
    else()
        message(WARNING "MLKEM_CT_VALGRIND=ON but valgrind not found; CT test will not run")
    endif()
endif()

# Memory leak testing with Valgrind (optional - requires valgrind installed)
find_program(VALGRIND_EXECUTABLE valgrind)
if(VALGRIND_EXECUTABLE)
    message(STATUS "Valgrind found: ${VALGRIND_EXECUTABLE}")
    add_test(NAME valgrind_memory_leak_test
             COMMAND bash ${CMAKE_CURRENT_SOURCE_DIR}/test_valgrind.sh
             WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR})
else()
    message(STATUS "Valgrind not found - memory leak tests will be skipped")
    message(STATUS "Install with: sudo apt-get install valgrind")
endif()
