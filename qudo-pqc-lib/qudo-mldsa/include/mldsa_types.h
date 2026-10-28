/* SPDX-License-Identifier: Apache-2.0 AND MIT */

#ifndef MLDSA_TYPES_H
#define MLDSA_TYPES_H

#ifdef __cplusplus
extern "C" {
#endif

#ifndef QUDO_MLDSA_API
#    if defined(_WIN32) || defined(__CYGWIN__)
/* A static build must expand to nothing: MSVC rejects dllimport on the
 * library's own definitions (C2491). */
#        if defined(QUDO_MLDSA_STATIC_LINK) || defined(QUDO_PQC_STATIC_LINK)
#            define QUDO_MLDSA_API
#        elif defined(QUDO_MLDSA_BUILD_SHARED)
#            define QUDO_MLDSA_API __declspec(dllexport)
#        else
#            define QUDO_MLDSA_API __declspec(dllimport)
#        endif
#    else
#        if __GNUC__ >= 4
#            define QUDO_MLDSA_API __attribute__((visibility("default")))
#        else
#            define QUDO_MLDSA_API
#        endif
#    endif
#endif

typedef enum {
    QUDO_MLDSA_LEVEL_44 = 2,
    QUDO_MLDSA_LEVEL_65 = 3,
    QUDO_MLDSA_LEVEL_87 = 5,

    QUDO_MLDSA_44 = QUDO_MLDSA_LEVEL_44,
    QUDO_MLDSA_65 = QUDO_MLDSA_LEVEL_65,
    QUDO_MLDSA_87 = QUDO_MLDSA_LEVEL_87
} QUDO_MLDSA_security_level_t;

typedef enum {
    QUDO_MLDSA_SUCCESS = 0,
    QUDO_MLDSA_ERROR = -1,
    QUDO_MLDSA_ERROR_INVALID_ARG = -2,
    QUDO_MLDSA_ERROR_NULL_PTR = -3,
    QUDO_MLDSA_ERROR_ALLOC = -4,
    QUDO_MLDSA_ERROR_RNG = -5,
    QUDO_MLDSA_ERROR_VERIFY = -6,
    QUDO_MLDSA_ERROR_DECODE = -7,
    QUDO_MLDSA_ERROR_NOT_IMPL = -8,
    QUDO_MLDSA_ERROR_CRYPTO = -9,
    QUDO_MLDSA_ERROR_FILE_IO = -10,
    QUDO_MLDSA_ERROR_ENCODE = -12,
    QUDO_MLDSA_ERROR_BUFFER_TOO_SMALL = -13,
    QUDO_MLDSA_ERROR_INVALID_SIGNATURE = -14
} QUDO_MLDSA_status_t;

#define MLDSA_SEEDBYTES 32

#define MLDSA_RNDBYTES 32

#define MLDSA_CRHBYTES 64

#define MLDSA_TRBYTES 64

typedef enum {
    QUDO_MLDSA_PKCS8_FORMAT_SEED_PRIV = 1,
    QUDO_MLDSA_PKCS8_FORMAT_PRIV_ONLY = 2,
    QUDO_MLDSA_PKCS8_FORMAT_OQSKEYPAIR = 3
} QUDO_MLDSA_pkcs8_format_t;

#ifdef __cplusplus
}
#endif

#endif
