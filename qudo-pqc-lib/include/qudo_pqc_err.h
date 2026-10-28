/* SPDX-License-Identifier: Apache-2.0 AND MIT */

#ifndef QUDO_PQC_ERR_H
#define QUDO_PQC_ERR_H

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    QUDO_SEV_INFO = 0,
    QUDO_SEV_WARN = 1,
    QUDO_SEV_ERROR = 2,
    QUDO_SEV_FATAL = 3
} qudo_sev_t;

typedef enum {
    QUDO_ERR_NONE = 0x0000,

    QUDO_ERR_STATE_INVALID = 0x0100,
    QUDO_ERR_MODULE_NOT_RUNNING = 0x0101,
    QUDO_ERR_MODULE_ERROR_STATE = 0x0102,
    QUDO_ERR_INIT_LOCK_FAIL = 0x0103,
    QUDO_ERR_INIT_ONCE_FAIL = 0x0104,

    QUDO_ERR_POST_INTEGRITY_FAIL = 0x0200,
    QUDO_ERR_POST_KAT_FAIL = 0x0201,
    QUDO_ERR_POST_KEYGEN_KAT_FAIL = 0x0202,
    QUDO_ERR_POST_KEM_KAT_FAIL = 0x0203,
    QUDO_ERR_POST_SIG_KAT_FAIL = 0x0204,
    QUDO_ERR_INTEGRITY_HMAC_FAIL = 0x0205,
    QUDO_ERR_INTEGRITY_MISMATCH = 0x0206,
    QUDO_ERR_INTEGRITY_NO_CONFIG = 0x0207,

    QUDO_ERR_PCT_KEYGEN_FAIL = 0x0300,
    QUDO_ERR_PCT_IMPORT_FAIL = 0x0301,
    QUDO_ERR_PCT_ENCAPS_FAIL = 0x0302,
    QUDO_ERR_PCT_SIGN_FAIL = 0x0303,

    QUDO_ERR_CAST_NOT_RUN = 0x0400,
    QUDO_ERR_CAST_FAIL = 0x0401,
    QUDO_ERR_CAST_KEYGEN_FAIL = 0x0402,

    QUDO_ERR_DRBG_NOT_SEEDED = 0x0500,
    QUDO_ERR_DRBG_SEED_FAIL = 0x0501,
    QUDO_ERR_DRBG_HEALTH_FAIL = 0x0502,
    QUDO_ERR_DRBG_RESEED_FAIL = 0x0503,
    QUDO_ERR_DRBG_GENERATE_FAIL = 0x0504,

    QUDO_ERR_KEY_INVALID = 0x0600,
    QUDO_ERR_KEY_SIZE_MISMATCH = 0x0601,
    QUDO_ERR_KEY_ZEROIZE_FAIL = 0x0602,

    QUDO_ERR_ALLOC = 0x0F00,
    QUDO_ERR_PARAM_INVALID = 0x0F01,
    QUDO_ERR_PARAM_NULL = 0x0F02,
    QUDO_ERR_NOT_SUPPORTED = 0x0F03,
    QUDO_ERR_INTERNAL = 0x0FFF
} qudo_err_t;

#ifndef QUDO_PQC_API
#    if defined(_WIN32) || defined(__CYGWIN__)
#        ifdef QUDO_PQC_BUILDING
#            define QUDO_PQC_API __declspec(dllexport)
#        else
#            define QUDO_PQC_API __declspec(dllimport)
#        endif
#    elif defined(__GNUC__) && __GNUC__ >= 4
#        define QUDO_PQC_API __attribute__((visibility("default")))
#    else
#        define QUDO_PQC_API
#    endif
#endif

QUDO_PQC_API const char *qudo_err_string(qudo_err_t err);

#ifdef __cplusplus
}
#endif

#endif
