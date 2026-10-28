# SPDX-License-Identifier: Apache-2.0 AND MIT
#
# Fuzzing harnesses for qudo-slhdsa
#
# Usage:
#   cmake -DBUILD_FUZZ=ON -DBUILD_SHARED_LIBS=OFF -DCMAKE_C_COMPILER=clang -B build-fuzz
#   cmake --build build-fuzz --parallel
#   ./build-fuzz/fuzz/fuzz_slhdsa_der_import -max_len=4096

if(NOT CMAKE_C_COMPILER_ID MATCHES "Clang")
    message(WARNING "Fuzzing harnesses require Clang with libFuzzer. Skipping fuzz targets.")
    return()
endif()

set(FUZZ_COMPILE_FLAGS -fsanitize=fuzzer,address,undefined -fno-omit-frame-pointer)
set(FUZZ_LINK_FLAGS -fsanitize=fuzzer,address,undefined)

# Fuzz target: DER import parser
add_executable(fuzz_slhdsa_der_import fuzz_slhdsa_der_import.c)
target_link_libraries(fuzz_slhdsa_der_import PRIVATE qudo-slhdsa)
target_compile_options(fuzz_slhdsa_der_import PRIVATE ${FUZZ_COMPILE_FLAGS})
target_link_options(fuzz_slhdsa_der_import PRIVATE ${FUZZ_LINK_FLAGS})

# Fuzz target: PEM import parser
add_executable(fuzz_slhdsa_pem_import fuzz_slhdsa_pem_import.c)
target_link_libraries(fuzz_slhdsa_pem_import PRIVATE qudo-slhdsa)
target_compile_options(fuzz_slhdsa_pem_import PRIVATE ${FUZZ_COMPILE_FLAGS})
target_link_options(fuzz_slhdsa_pem_import PRIVATE ${FUZZ_LINK_FLAGS})

# Fuzz target: Signature operations with malformed inputs
add_executable(fuzz_slhdsa_sig_ops fuzz_slhdsa_sig_ops.c)
target_link_libraries(fuzz_slhdsa_sig_ops PRIVATE qudo-slhdsa)
target_compile_options(fuzz_slhdsa_sig_ops PRIVATE ${FUZZ_COMPILE_FLAGS})
target_link_options(fuzz_slhdsa_sig_ops PRIVATE ${FUZZ_LINK_FLAGS})

# Fuzz target: Raw key import
add_executable(fuzz_slhdsa_key_import fuzz_slhdsa_key_import.c)
target_link_libraries(fuzz_slhdsa_key_import PRIVATE qudo-slhdsa)
target_compile_options(fuzz_slhdsa_key_import PRIVATE ${FUZZ_COMPILE_FLAGS})
target_link_options(fuzz_slhdsa_key_import PRIVATE ${FUZZ_LINK_FLAGS})

# Fuzz target: Signature verification with malformed inputs
add_executable(fuzz_slhdsa_sig_verify fuzz_slhdsa_sig_verify.c)
target_link_libraries(fuzz_slhdsa_sig_verify PRIVATE qudo-slhdsa)
target_compile_options(fuzz_slhdsa_sig_verify PRIVATE ${FUZZ_COMPILE_FLAGS})
target_link_options(fuzz_slhdsa_sig_verify PRIVATE ${FUZZ_LINK_FLAGS})

message(STATUS "Fuzzing harnesses enabled for qudo-slhdsa (5 targets)")
