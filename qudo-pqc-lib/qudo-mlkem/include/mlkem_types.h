/* SPDX-License-Identifier: Apache-2.0 AND MIT */

#ifndef MLKEM_TYPES_H
#define MLKEM_TYPES_H

#ifdef __cplusplus
extern "C" {
#endif

#ifndef QUDO_KEM_API
#    if defined(_WIN32) || defined(__CYGWIN__)
/* A static build must expand to nothing: MSVC rejects dllimport on the
 * library's own definitions (C2491). */
#        if defined(QUDO_KEM_STATIC_LINK) || defined(QUDO_PQC_STATIC_LINK)
#            define QUDO_KEM_API
#        elif defined(QUDO_KEM_BUILD_SHARED)
#            define QUDO_KEM_API __declspec(dllexport)
#        else
#            define QUDO_KEM_API __declspec(dllimport)
#        endif
#    else
#        if __GNUC__ >= 4
#            define QUDO_KEM_API __attribute__((visibility("default")))
#        else
#            define QUDO_KEM_API
#        endif
#    endif
#endif

typedef enum {
    QUDO_KEM_LEVEL_512 = 1,
    QUDO_KEM_LEVEL_768 = 3,
    QUDO_KEM_LEVEL_1024 = 5,

    QUDO_KEM_512 = QUDO_KEM_LEVEL_512,
    QUDO_KEM_768 = QUDO_KEM_LEVEL_768,
    QUDO_KEM_1024 = QUDO_KEM_LEVEL_1024
} QUDO_KEM_security_level_t;

typedef enum {
    QUDO_KEM_SUCCESS = 0,
    QUDO_KEM_ERROR = -1,
    QUDO_KEM_ERROR_INVALID_ARG = -2,
    QUDO_KEM_ERROR_NULL_PTR = -3,
    QUDO_KEM_ERROR_ALLOC = -4,
    QUDO_KEM_ERROR_RNG = -5,
    QUDO_KEM_ERROR_VERIFY = -6,
    QUDO_KEM_ERROR_DECODE = -7,
    QUDO_KEM_ERROR_NOT_IMPL = -8,
    QUDO_KEM_ERROR_CRYPTO = -9,
    QUDO_KEM_ERROR_FILE_IO = -10,
    QUDO_KEM_ERROR_ENCODE = -12,
    QUDO_KEM_ERROR_BUFFER_TOO_SMALL = -13
} QUDO_KEM_status_t;

#ifdef __cplusplus
}
#endif

#endif
