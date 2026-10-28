# SPDX-License-Identifier: Apache-2.0 AND MIT
#
# fips_partial_link.cmake — Create qudo_fips_module.o via ld -r
#
# Extracts objects from the static library, then partial-links them
# with boundary_start FIRST and boundary_end LAST.
#
# Arguments (passed via -D):
#   STATIC_LIB   — path to libqudo-pqc.a
#   OUTPUT_OBJ   — path to output qudo_fips_module.o
#   AR           — path to ar tool
#   CC           — path to C compiler (used as linker driver)
#   TMPDIR       — temp directory for extraction

cmake_minimum_required(VERSION 3.15)

# Create temp dir
file(MAKE_DIRECTORY ${TMPDIR})

# Extract all objects from static library
execute_process(
    COMMAND ${AR} x ${STATIC_LIB}
    WORKING_DIRECTORY ${TMPDIR}
    RESULT_VARIABLE ar_result
)
if(NOT ar_result EQUAL 0)
    message(FATAL_ERROR "ar x failed: ${ar_result}")
endif()

# Collect all .o files
file(GLOB all_objects "${TMPDIR}/*.o")

# Separate boundary files from inner objects
set(boundary_start "")
set(boundary_end "")
set(inner_objects "")

foreach(obj ${all_objects})
    get_filename_component(name ${obj} NAME)
    if(name STREQUAL "qudo_fips_boundary_start.c.o")
        set(boundary_start ${obj})
    elseif(name STREQUAL "qudo_fips_boundary_end.c.o")
        set(boundary_end ${obj})
    else()
        list(APPEND inner_objects ${obj})
    endif()
endforeach()

if(NOT boundary_start)
    message(FATAL_ERROR "qudo_fips_boundary_start.c.o not found in archive")
endif()
if(NOT boundary_end)
    message(FATAL_ERROR "qudo_fips_boundary_end.c.o not found in archive")
endif()

# Sort inner objects for reproducible builds
list(SORT inner_objects)

# Partial link: start + inner + end → single .o
execute_process(
    COMMAND ${CC} -r -nostdlib
        -o ${OUTPUT_OBJ}
        ${boundary_start}
        ${inner_objects}
        ${boundary_end}
    RESULT_VARIABLE ld_result
)
if(NOT ld_result EQUAL 0)
    message(FATAL_ERROR "Partial link (ld -r) failed: ${ld_result}")
endif()

# Cleanup
file(REMOVE_RECURSE ${TMPDIR})

message(STATUS "Created ${OUTPUT_OBJ}")
