# SPDX-License-Identifier: Apache-2.0 AND MIT
#
# Fuzzing harnesses for qudo-mldsa
#
# Usage:
#   cmake -DBUILD_FUZZ=ON -DBUILD_SHARED_LIBS=OFF -DCMAKE_C_COMPILER=clang -B build-fuzz
#   cmake --build build-fuzz --parallel
#   ./build-fuzz/fuzz/fuzz_mldsa_der_import -max_len=4096

if(NOT CMAKE_C_COMPILER_ID MATCHES "Clang")
    message(WARNING "Fuzzing harnesses require Clang with libFuzzer. Skipping fuzz targets.")
    return()
endif()

set(FUZZ_COMPILE_FLAGS -fsanitize=fuzzer,address,undefined -fno-omit-frame-pointer)
set(FUZZ_LINK_FLAGS -fsanitize=fuzzer,address,undefined)

# Fuzz target: DER import parser
add_executable(fuzz_mldsa_der_import fuzz_mldsa_der_import.c)
target_link_libraries(fuzz_mldsa_der_import PRIVATE qudo-mldsa)
target_compile_options(fuzz_mldsa_der_import PRIVATE ${FUZZ_COMPILE_FLAGS})
target_link_options(fuzz_mldsa_der_import PRIVATE ${FUZZ_LINK_FLAGS})

# Fuzz target: PEM import parser
add_executable(fuzz_mldsa_pem_import fuzz_mldsa_pem_import.c)
target_link_libraries(fuzz_mldsa_pem_import PRIVATE qudo-mldsa)
target_compile_options(fuzz_mldsa_pem_import PRIVATE ${FUZZ_COMPILE_FLAGS})
target_link_options(fuzz_mldsa_pem_import PRIVATE ${FUZZ_LINK_FLAGS})

# Fuzz target: Signature operations with malformed inputs
add_executable(fuzz_mldsa_sig_ops fuzz_mldsa_sig_ops.c)
target_link_libraries(fuzz_mldsa_sig_ops PRIVATE qudo-mldsa)
target_compile_options(fuzz_mldsa_sig_ops PRIVATE ${FUZZ_COMPILE_FLAGS})
target_link_options(fuzz_mldsa_sig_ops PRIVATE ${FUZZ_LINK_FLAGS})

# Fuzz target: Private-key DER import
add_executable(fuzz_mldsa_privkey_der_import fuzz_mldsa_privkey_der_import.c)
target_link_libraries(fuzz_mldsa_privkey_der_import PRIVATE qudo-mldsa)
target_compile_options(fuzz_mldsa_privkey_der_import PRIVATE ${FUZZ_COMPILE_FLAGS})
target_link_options(fuzz_mldsa_privkey_der_import PRIVATE ${FUZZ_LINK_FLAGS})

# Fuzz target: Public-key DER import
add_executable(fuzz_mldsa_pubkey_der_import fuzz_mldsa_pubkey_der_import.c)
target_link_libraries(fuzz_mldsa_pubkey_der_import PRIVATE qudo-mldsa)
target_compile_options(fuzz_mldsa_pubkey_der_import PRIVATE ${FUZZ_COMPILE_FLAGS})
target_link_options(fuzz_mldsa_pubkey_der_import PRIVATE ${FUZZ_LINK_FLAGS})

# Fuzz target: Signature verification with malformed inputs
add_executable(fuzz_mldsa_sig_verify fuzz_mldsa_sig_verify.c)
target_link_libraries(fuzz_mldsa_sig_verify PRIVATE qudo-mldsa)
target_compile_options(fuzz_mldsa_sig_verify PRIVATE ${FUZZ_COMPILE_FLAGS})
target_link_options(fuzz_mldsa_sig_verify PRIVATE ${FUZZ_LINK_FLAGS})

message(STATUS "Fuzzing harnesses enabled for qudo-mldsa (6 targets)")
