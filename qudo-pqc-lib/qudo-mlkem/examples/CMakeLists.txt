# Examples CMakeLists.txt

# Treat implicit function declarations and int/pointer conversions as errors.
if(CMAKE_C_COMPILER_ID MATCHES "GNU|Clang")
    add_compile_options(-Werror=implicit-function-declaration -Werror=int-conversion)
endif()

# Simple KEM example
add_executable(simple_kem simple_kem.c)
target_link_libraries(simple_kem qudo-mlkem)

# DER/PEM export/import example
add_executable(test_der_pem test_der_pem.c)
target_link_libraries(test_der_pem qudo-mlkem)

# Client/Server examples - Direct API
add_executable(server_direct server_direct.c)
target_link_libraries(server_direct qudo-mlkem)
if(WIN32)
    target_link_libraries(server_direct ws2_32)
endif()

add_executable(client_direct client_direct.c)
target_link_libraries(client_direct qudo-mlkem)
if(WIN32)
    target_link_libraries(client_direct ws2_32)
endif()

# Client/Server examples - Object API
add_executable(server_object server_object.c)
target_link_libraries(server_object qudo-mlkem)
if(WIN32)
    target_link_libraries(server_object ws2_32)
endif()

add_executable(client_object client_object.c)
target_link_libraries(client_object qudo-mlkem)
if(WIN32)
    target_link_libraries(client_object ws2_32)
endif()

# Performance benchmark
add_executable(speed_mlkem speed_mlkem.c)
target_link_libraries(speed_mlkem qudo-mlkem)
# Link math library on Unix only (MSVC has math in standard library)
if(UNIX)
    target_link_libraries(speed_mlkem m)
endif()

# Heap allocation example
add_executable(test_heap_allocation test_heap_allocation.c)
target_link_libraries(test_heap_allocation qudo-mlkem)

# Install examples
set(MLKEM_INSTALL_TARGETS simple_kem test_der_pem server_direct client_direct server_object client_object)
install(TARGETS ${MLKEM_INSTALL_TARGETS}
    RUNTIME DESTINATION bin/examples
)
