# SPDX-License-Identifier: MIT
# ACVP Test Runner — builds CLI binaries that replay NIST ACVP test vectors
#
# Binaries call through libqudo-pqc.
# Enable with -DBUILD_ACVP=ON on the cmake command line.

# Shared utilities (hex encode/decode, arg parsing)
add_library(acvp_common STATIC acvp_common.c)
target_include_directories(acvp_common PRIVATE
    ${CMAKE_SOURCE_DIR}/qudo-mlkem/include
    ${CMAKE_SOURCE_DIR}/qudo-mldsa/include
    ${CMAKE_SOURCE_DIR}/qudo-slhdsa/include
    ${CMAKE_SOURCE_DIR}/include
)

# ML-KEM ACVP binary (FIPS 203)
add_executable(qudo_acvp_mlkem acvp_mlkem.c)
target_include_directories(qudo_acvp_mlkem PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_SOURCE_DIR}/qudo-mlkem/include
    ${CMAKE_SOURCE_DIR}/include
)
target_link_libraries(qudo_acvp_mlkem PRIVATE acvp_common qudo-pqc)

# ML-DSA ACVP binary (FIPS 204)
add_executable(qudo_acvp_mldsa acvp_mldsa.c)
target_include_directories(qudo_acvp_mldsa PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_SOURCE_DIR}/qudo-mldsa/include
    ${CMAKE_SOURCE_DIR}/include
)
target_link_libraries(qudo_acvp_mldsa PRIVATE acvp_common qudo-pqc)

# SLH-DSA ACVP binary (FIPS 205)
add_executable(qudo_acvp_slhdsa acvp_slhdsa.c)
target_include_directories(qudo_acvp_slhdsa PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_SOURCE_DIR}/qudo-slhdsa/include
    ${CMAKE_SOURCE_DIR}/include
)
target_link_libraries(qudo_acvp_slhdsa PRIVATE acvp_common qudo-pqc)

# Set output directory
set_target_properties(qudo_acvp_mlkem qudo_acvp_mldsa qudo_acvp_slhdsa
    PROPERTIES RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/acvp"
)

# Install Python clients and runner script
install(FILES
    acvp_client_mlkem.py
    acvp_client_mldsa.py
    acvp_client_slhdsa.py
    run_acvp.sh
    DESTINATION share/qudo-pqc/acvp
)

install(TARGETS qudo_acvp_mlkem qudo_acvp_mldsa qudo_acvp_slhdsa
    RUNTIME DESTINATION bin
)

message(STATUS "ACVP test runner: enabled (3 binaries)")
