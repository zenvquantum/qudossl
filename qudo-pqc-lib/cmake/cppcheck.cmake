# SPDX-License-Identifier: Apache-2.0 AND MIT
#
# cppcheck.cmake — Static analysis target for FIPS 140-3 crypto module
#
# Adds a 'cppcheck' custom target for the C99 sources.
#
# Usage in CMakeLists.txt:
#   include(cmake/cppcheck.cmake)

find_program(CPPCHECK_EXECUTABLE NAMES cppcheck)

if(CPPCHECK_EXECUTABLE)
    message(STATUS "cppcheck found: ${CPPCHECK_EXECUTABLE}")

    # Determine include paths
    set(QUDO_PQC_INCLUDE_DIRS
        ${CMAKE_CURRENT_SOURCE_DIR}/include
        ${CMAKE_CURRENT_SOURCE_DIR}/src
        ${CMAKE_CURRENT_SOURCE_DIR}/src/fips
    )

    # Build the -I flags list
    set(CPPCHECK_INCLUDE_FLAGS "")
    foreach(inc_dir ${QUDO_PQC_INCLUDE_DIRS})
        list(APPEND CPPCHECK_INCLUDE_FLAGS "-I${inc_dir}")
    endforeach()

    # Source directories to scan
    set(QUDO_PQC_SRC_DIRS
        ${CMAKE_CURRENT_SOURCE_DIR}/src
    )

    # XML output file for CI integration
    set(CPPCHECK_XML_OUTPUT "${CMAKE_CURRENT_BINARY_DIR}/cppcheck-report.xml")

    add_custom_target(cppcheck
        COMMAND ${CPPCHECK_EXECUTABLE}
            --enable=warning,performance,portability,style
            --std=c99
            --suppress=missingIncludeSystem
            --suppress=unusedFunction
            --error-exitcode=1
            --xml
            --output-file=${CPPCHECK_XML_OUTPUT}
            ${CPPCHECK_INCLUDE_FLAGS}
            ${QUDO_PQC_SRC_DIRS}
        WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
        COMMENT "Running cppcheck static analysis on qudo-pqc sources"
        VERBATIM
    )

else()
    message(STATUS "cppcheck not found — 'cppcheck' target will not be available")
endif()
