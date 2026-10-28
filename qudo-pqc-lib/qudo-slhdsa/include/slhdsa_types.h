/* SPDX-License-Identifier: Apache-2.0 AND MIT */

#ifndef SLHDSA_TYPES_H
#define SLHDSA_TYPES_H

#ifdef __cplusplus
extern "C" {
#endif

#ifndef QUDO_SLHDSA_API
#    if defined(_WIN32) || defined(__CYGWIN__)
/* A static build must expand to nothing: MSVC rejects dllimport on the
 * library's own definitions (C2491). */
#        if defined(QUDO_SLHDSA_STATIC_LINK) || defined(QUDO_PQC_STATIC_LINK)
#            define QUDO_SLHDSA_API
#        elif defined(QUDO_SLHDSA_BUILD_SHARED)
#            define QUDO_SLHDSA_API __declspec(dllexport)
#        else
#            define QUDO_SLHDSA_API __declspec(dllimport)
#        endif
#    else
#        if __GNUC__ >= 4
#            define QUDO_SLHDSA_API __attribute__((visibility("default")))
#        else
#            define QUDO_SLHDSA_API
#        endif
#    endif
#endif

typedef enum {
    QUDO_SLHDSA_SHA2_128s = 1,
    QUDO_SLHDSA_SHA2_128f = 2,
    QUDO_SLHDSA_SHA2_192s = 3,
    QUDO_SLHDSA_SHA2_192f = 4,
    QUDO_SLHDSA_SHA2_256s = 5,
    QUDO_SLHDSA_SHA2_256f = 6,
    QUDO_SLHDSA_SHAKE_128s = 7,
    QUDO_SLHDSA_SHAKE_128f = 8,
    QUDO_SLHDSA_SHAKE_192s = 9,
    QUDO_SLHDSA_SHAKE_192f = 10,
    QUDO_SLHDSA_SHAKE_256s = 11,
    QUDO_SLHDSA_SHAKE_256f = 12
} QUDO_SLHDSA_parameter_set_t;

typedef enum {
    QUDO_SLHDSA_SUCCESS = 0,
    QUDO_SLHDSA_ERROR = -1,
    QUDO_SLHDSA_ERROR_INVALID_ARG = -2,
    QUDO_SLHDSA_ERROR_NULL_PTR = -3,
    QUDO_SLHDSA_ERROR_ALLOC = -4,
    QUDO_SLHDSA_ERROR_RNG = -5,
    QUDO_SLHDSA_ERROR_VERIFY = -6,
    QUDO_SLHDSA_ERROR_DECODE = -7,
    QUDO_SLHDSA_ERROR_NOT_IMPL = -8,
    QUDO_SLHDSA_ERROR_CRYPTO = -9,
    QUDO_SLHDSA_ERROR_FILE_IO = -10,
    QUDO_SLHDSA_ERROR_ENCODE = -12,
    QUDO_SLHDSA_ERROR_BUFFER_TOO_SMALL = -13,
    QUDO_SLHDSA_ERROR_INVALID_SIGNATURE = -14
} QUDO_SLHDSA_status_t;

typedef enum {
    QUDO_SLHDSA_PKCS8_FORMAT_PRIV_ONLY = 1,
    QUDO_SLHDSA_PKCS8_FORMAT_KEYPAIR = 2
} QUDO_SLHDSA_pkcs8_format_t;

#define SLHDSA_NUM_PARAMETER_SETS 12

#define SLHDSA_MAX_CONTEXT_BYTES 255

#ifdef __cplusplus
}
#endif

#endif
