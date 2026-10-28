# Examples CMakeLists.txt

# Treat implicit function declarations and int/pointer conversions as errors.
if(CMAKE_C_COMPILER_ID MATCHES "GNU|Clang")
    add_compile_options(-Werror=implicit-function-declaration -Werror=int-conversion)
endif()

# Context and signature examples
add_executable(context_signature context_signature.c)
target_link_libraries(context_signature qudo-mldsa)

add_executable(speed_mldsa speed_mldsa.c)
target_link_libraries(speed_mldsa qudo-mldsa)

# Advanced API examples - only in single-variant mode
if(NOT MLDSA_DIST_BUILD)
    add_executable(deterministic_keygen deterministic_keygen.c)
    target_link_libraries(deterministic_keygen qudo-mldsa)

    add_executable(deterministic_sign deterministic_sign.c)
    target_link_libraries(deterministic_sign qudo-mldsa)

    add_executable(external_mu external_mu.c)
    target_link_libraries(external_mu qudo-mldsa)

    add_executable(concat_format concat_format.c)
    target_link_libraries(concat_format qudo-mldsa)

    add_executable(prehash_sha256 prehash_sha256.c)
    target_link_libraries(prehash_sha256 qudo-mldsa)
endif()

# Install examples
set(MLDSA_INSTALL_TARGETS context_signature speed_mldsa)
if(NOT MLDSA_DIST_BUILD)
    list(APPEND MLDSA_INSTALL_TARGETS deterministic_keygen deterministic_sign external_mu concat_format prehash_sha256)
endif()
install(TARGETS ${MLDSA_INSTALL_TARGETS}
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}/qudo-mldsa-examples
)
