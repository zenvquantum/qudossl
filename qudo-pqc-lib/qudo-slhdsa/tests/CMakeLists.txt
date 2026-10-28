# Tests CMakeLists.txt

# Treat implicit function declarations and int/pointer conversions as errors.
if(CMAKE_C_COMPILER_ID MATCHES "GNU|Clang")
    add_compile_options(-Werror=implicit-function-declaration -Werror=int-conversion)
endif()

# Basic functionality test (all 12 parameter sets)
add_executable(test_slhdsa test_slhdsa.c)
target_link_libraries(test_slhdsa qudo-slhdsa)

# DER/PEM serialization test
add_executable(test_der_pem test_der_pem.c)
target_link_libraries(test_der_pem qudo-slhdsa)

# Sign/verify consistency tests
add_executable(test_kat test_kat.c)
target_link_libraries(test_kat qudo-slhdsa)

# Constant-time validation tests
add_executable(test_constant_time test_constant_time.c)
target_link_libraries(test_constant_time qudo-slhdsa)
if(NOT MSVC)
    target_link_libraries(test_constant_time m)
endif()

# Compatibility tests
add_executable(test_liboqs_compat test_liboqs_compat.c)
target_link_libraries(test_liboqs_compat qudo-slhdsa)

## Coverage tests — Object API, Direct API, utilities, config
add_executable(test_object_api test_object_api.c)
target_link_libraries(test_object_api qudo-slhdsa)

## Coverage tests — DER/PEM interop
add_executable(test_interop_cov test_interop_cov.c)
target_link_libraries(test_interop_cov qudo-slhdsa)

## Coverage tests — Secure memory functions
add_executable(test_memory test_memory.c)
target_link_libraries(test_memory qudo-slhdsa)

## Coverage tests — Platform detection
add_executable(test_platform test_platform.c)
target_link_libraries(test_platform qudo-slhdsa)

add_test(NAME test_slhdsa COMMAND test_slhdsa)
add_test(NAME test_der_pem COMMAND test_der_pem)
add_test(NAME test_kat COMMAND test_kat)
add_test(NAME test_constant_time COMMAND test_constant_time)
add_test(NAME test_liboqs_compat COMMAND test_liboqs_compat)
add_test(NAME object_api_test COMMAND test_object_api)
add_test(NAME interop_cov_test COMMAND test_interop_cov)
add_test(NAME memory_test COMMAND test_memory)
add_test(NAME platform_test COMMAND test_platform)

