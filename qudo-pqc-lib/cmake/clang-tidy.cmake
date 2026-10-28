# clang-tidy.cmake -- Static analysis target for FIPS 140-3 crypto code
# Requires compile_commands.json (set CMAKE_EXPORT_COMPILE_COMMANDS=ON)

find_program(CLANG_TIDY_EXE
    NAMES clang-tidy clang-tidy-18 clang-tidy-17 clang-tidy-16 clang-tidy-15 clang-tidy-14
    DOC "Path to clang-tidy executable"
)

if(NOT CLANG_TIDY_EXE)
    message(STATUS "clang-tidy not found -- 'clang-tidy' target will not be available")
    return()
endif()

message(STATUS "Found clang-tidy: ${CLANG_TIDY_EXE}")

# Collect all .c source files under src/ and header files under include/
file(GLOB_RECURSE QUDO_PQC_SOURCES
    "${CMAKE_CURRENT_SOURCE_DIR}/src/*.c"
)
file(GLOB_RECURSE QUDO_PQC_HEADERS
    "${CMAKE_CURRENT_SOURCE_DIR}/include/*.h"
)

# Require compile_commands.json for accurate analysis
if(NOT CMAKE_EXPORT_COMPILE_COMMANDS)
    message(STATUS "CMAKE_EXPORT_COMPILE_COMMANDS is OFF -- enabling for clang-tidy support")
    set(CMAKE_EXPORT_COMPILE_COMMANDS ON CACHE BOOL "Generate compile_commands.json" FORCE)
endif()

add_custom_target(clang-tidy
    COMMAND ${CLANG_TIDY_EXE}
        -p ${CMAKE_BINARY_DIR}
        ${QUDO_PQC_SOURCES}
    WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
    COMMENT "Running clang-tidy static analysis on qudo-pqc sources"
)

# Optional: target that applies fixes automatically (use with caution)
add_custom_target(clang-tidy-fix
    COMMAND ${CLANG_TIDY_EXE}
        -p ${CMAKE_BINARY_DIR}
        --fix
        --fix-errors
        ${QUDO_PQC_SOURCES}
    WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
    COMMENT "Running clang-tidy with auto-fix on qudo-pqc sources"
)
