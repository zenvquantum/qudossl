# SPDX-License-Identifier: Apache-2.0 AND MIT
#
# Fuzzing harnesses for qudo-mlkem
#
# Usage:
#   cmake -DBUILD_FUZZ=ON -DCMAKE_C_COMPILER=clang ..
#   make
#   ./fuzz/fuzz_mlkem_der_import -max_len=4096
#
# For sanitizer-instrumented fuzzing (recommended):
#   cmake -DBUILD_FUZZ=ON -DENABLE_SANITIZERS=ON -DCMAKE_C_COMPILER=clang ..

if(NOT CMAKE_C_COMPILER_ID MATCHES "Clang")
    message(WARNING "Fuzzing harnesses require Clang with libFuzzer. Skipping fuzz targets.")
    return()
endif()

set(FUZZ_COMPILE_FLAGS -fsanitize=fuzzer,address,undefined -fno-omit-frame-pointer)
set(FUZZ_LINK_FLAGS -fsanitize=fuzzer,address,undefined)

# Fuzz target: DER import parser
add_executable(fuzz_mlkem_der_import fuzz_mlkem_der_import.c)
target_link_libraries(fuzz_mlkem_der_import PRIVATE qudo-mlkem)
target_compile_options(fuzz_mlkem_der_import PRIVATE ${FUZZ_COMPILE_FLAGS})
target_link_options(fuzz_mlkem_der_import PRIVATE ${FUZZ_LINK_FLAGS})

# Fuzz target: PEM import parser
add_executable(fuzz_mlkem_pem_import fuzz_mlkem_pem_import.c)
target_link_libraries(fuzz_mlkem_pem_import PRIVATE qudo-mlkem)
target_compile_options(fuzz_mlkem_pem_import PRIVATE ${FUZZ_COMPILE_FLAGS})
target_link_options(fuzz_mlkem_pem_import PRIVATE ${FUZZ_LINK_FLAGS})

# Fuzz target: KEM operations with malformed inputs
add_executable(fuzz_mlkem_kem_ops fuzz_mlkem_kem_ops.c)
target_link_libraries(fuzz_mlkem_kem_ops PRIVATE qudo-mlkem)
target_compile_options(fuzz_mlkem_kem_ops PRIVATE ${FUZZ_COMPILE_FLAGS})
target_link_options(fuzz_mlkem_kem_ops PRIVATE ${FUZZ_LINK_FLAGS})

message(STATUS "Fuzzing harnesses enabled for qudo-mlkem (3 targets)")
