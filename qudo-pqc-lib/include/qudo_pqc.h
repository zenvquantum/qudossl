/* SPDX-License-Identifier: Apache-2.0 AND MIT */

#ifndef QUDO_PQC_H
#define QUDO_PQC_H

#include <stddef.h>
#include <stdint.h>

#if defined(__has_include)
#    if __has_include("qudo_pqc_build_config.h")
#        include "qudo_pqc_build_config.h"
#    endif
#endif

#if defined(_WIN32) || defined(__CYGWIN__)
#    if defined(QUDO_PQC_STATIC_LINK)
#        define QUDO_PQC_API
#    elif defined(QUDO_PQC_BUILDING)
#        define QUDO_PQC_API __declspec(dllexport)
#    else
#        define QUDO_PQC_API __declspec(dllimport)
#    endif
#elif defined(__GNUC__) && __GNUC__ >= 4
#    define QUDO_PQC_API __attribute__((visibility("default")))
#else
#    define QUDO_PQC_API
#endif

#include "qudo_pqc_audit.h"
#include "qudo_pqc_err.h"
#include "qudo_pqc_indicator.h"

#ifdef __cplusplus
extern "C" {
#endif

#define QUDO_PQC_VERSION_MAJOR  1
#define QUDO_PQC_VERSION_MINOR  0
#define QUDO_PQC_VERSION_PATCH  0
#define QUDO_PQC_VERSION_STRING "1.0.0"

QUDO_PQC_API const char *qudo_pqc_version(void);

#define QUDO_PQC_STATE_INIT     0
#define QUDO_PQC_STATE_SELFTEST 1
#define QUDO_PQC_STATE_RUNNING  2
#define QUDO_PQC_STATE_ERROR    3

#define QUDO_ST_TYPE_NONE             "None"
#define QUDO_ST_TYPE_MODULE_INTEGRITY "Module_Integrity"
#define QUDO_ST_TYPE_KAT_INTEGRITY    "KAT_Integrity"
#define QUDO_ST_TYPE_KAT_ASYM_KEYGEN  "KAT_AsymmetricKeyGeneration"
#define QUDO_ST_TYPE_KAT_KEM          "KAT_KEM"
#define QUDO_ST_TYPE_KAT_SIGNATURE    "KAT_Signature"
#define QUDO_ST_TYPE_PCT              "PCT"
#define QUDO_ST_TYPE_PCT_IMPORT       "Import_PCT"
#define QUDO_ST_TYPE_DRBG_HEALTH      "DRBG_Health"
#define QUDO_ST_TYPE_KAT_DRBG         "KAT_DRBG"
#define QUDO_ST_TYPE_KAT_DIGEST       "KAT_Digest"
#define QUDO_ST_TYPE_KAT_MAC          "KAT_MAC"

#define QUDO_ST_DESC_INTEGRITY_HMAC     "HMAC"
#define QUDO_ST_DESC_ML_KEM_512         "ML-KEM-512"
#define QUDO_ST_DESC_ML_KEM_768         "ML-KEM-768"
#define QUDO_ST_DESC_ML_KEM_1024        "ML-KEM-1024"
#define QUDO_ST_DESC_ML_DSA_44          "ML-DSA-44"
#define QUDO_ST_DESC_ML_DSA_65          "ML-DSA-65"
#define QUDO_ST_DESC_ML_DSA_87          "ML-DSA-87"
#define QUDO_ST_DESC_SLH_DSA_SHA2_128F  "SLH-DSA-SHA2-128f"
#define QUDO_ST_DESC_SLH_DSA_SHAKE_128F "SLH-DSA-SHAKE-128f"
#define QUDO_ST_DESC_PCT_ML_KEM         "ML-KEM"
#define QUDO_ST_DESC_PCT_ML_DSA         "ML-DSA"
#define QUDO_ST_DESC_PCT_SLH_DSA        "SLH-DSA"

typedef enum {
    QUDO_ST_PHASE_BEGIN = 0,
    QUDO_ST_PHASE_CORRUPT = 1,
    QUDO_ST_PHASE_END = 2
} qudo_st_phase_t;

typedef int (*qudo_st_event_cb)(qudo_st_phase_t phase, const char *type,
                                const char *desc, int result,
                                unsigned char *data, void **event,
                                void *cb_arg);

typedef void *(*qudo_io_open_fn)(const char *path, const char *mode);
typedef int (*qudo_io_read_fn)(void *handle, void *buf, size_t len,
                               size_t *bytes_read);
typedef void (*qudo_io_close_fn)(void *handle);

typedef void (*qudo_error_cb)(int code, const char *msg, void *cb_arg);

typedef struct qudo_pqc_config_st {
    qudo_st_event_cb self_test_cb;
    void *self_test_cb_arg;

    qudo_error_cb error_cb;
    void *error_cb_arg;

    qudo_io_open_fn io_open;
    qudo_io_read_fn io_read;
    qudo_io_close_fn io_close;

    const char *module_path;

    const char *module_checksum_hex;

    int conditional_errors;

    qudo_audit_cb audit_cb;
    void *audit_cb_arg;
} qudo_pqc_config_t;

QUDO_PQC_API int qudo_pqc_init(const qudo_pqc_config_t *config);

QUDO_PQC_API int qudo_pqc_is_running(void);

QUDO_PQC_API int qudo_pqc_is_running_or_selftest(void);

QUDO_PQC_API int qudo_pqc_is_self_testing(void);

QUDO_PQC_API int qudo_pqc_get_state(void);

QUDO_PQC_API int qudo_pqc_self_test(void);

QUDO_PQC_API void qudo_pqc_unregister_callbacks(const void *self_test_cb_arg);

QUDO_PQC_API void qudo_pqc_fini(void);

QUDO_PQC_API void qudo_pqc_set_error_state(const char *type);

QUDO_PQC_API int qudo_pqc_is_fips(void);

QUDO_PQC_API int qudo_pqc_is_fips_approved(const char *algorithm_name);

typedef enum {
    QUDO_CAST_ML_KEM_512 = 0,
    QUDO_CAST_ML_KEM_768 = 1,
    QUDO_CAST_ML_KEM_1024 = 2,
    QUDO_CAST_ML_DSA_44 = 3,
    QUDO_CAST_ML_DSA_65 = 4,
    QUDO_CAST_ML_DSA_87 = 5,
    QUDO_CAST_SLH_DSA_SHA2_128 = 6,
    QUDO_CAST_SLH_DSA_SHA2_192 = 7,
    QUDO_CAST_SLH_DSA_SHA2_256 = 8,
    QUDO_CAST_SLH_DSA_SHAKE_128 = 9,
    QUDO_CAST_SLH_DSA_SHAKE_192 = 10,
    QUDO_CAST_SLH_DSA_SHAKE_256 = 11,
    QUDO_CAST_COUNT = 12
} qudo_cast_id_t;

#define QUDO_CAST_STATE_INIT       0
#define QUDO_CAST_STATE_PROCESSING 1
#define QUDO_CAST_STATE_SUCCESS    2
#define QUDO_CAST_STATE_FAILURE    3

QUDO_PQC_API int qudo_pqc_get_cast_status(int cast_id);

QUDO_PQC_API int qudo_pqc_run_all_casts(void);

QUDO_PQC_API void qudo_pqc_set_cast_status(int cast_id, int status);

QUDO_PQC_API int qudo_pqc_post_drbg_kat_passed(void);

QUDO_PQC_API int qudo_pqc_post_integrity_passed(void);

QUDO_PQC_API int qudo_pqc_mlkem_pct(const void *kem, const uint8_t *pk,
                                    const uint8_t *sk, int use_random);

QUDO_PQC_API int qudo_pqc_mldsa_pct(const void *sig, const uint8_t *pk,
                                    const uint8_t *sk);

QUDO_PQC_API int qudo_pqc_slhdsa_pct(const void *sig, const uint8_t *pk,
                                     const uint8_t *sk);

QUDO_PQC_API int qudo_pqc_get_security_level(const char *algorithm_name);

QUDO_PQC_API void qudo_pqc_set_min_security_level(int level);

QUDO_PQC_API int qudo_pqc_get_min_security_level(void);

QUDO_PQC_API int qudo_pqc_check_security_level(const char *algorithm_name,
                                               qudo_fips_ind_t *ind);

QUDO_PQC_API int qudo_pqc_rand_bytes(uint8_t *out, size_t out_len);

QUDO_PQC_API int qudo_pqc_rand_seed_from_platform(void);

#ifdef QUDO_PQC_USE_HOST_DRBG
/*
 * Host-primitive DRBG hook.
 *
 * When built with QUDO_PQC_USE_HOST_DRBG, every internal random-byte request —
 * qudo_pqc_rand_bytes() and the per-algorithm QUDO_*_randombytes(), all of which
 * funnel through qudo_fips_rand_bytes() — is drawn from a host-provided RNG
 * instead of the embedded CTR-DRBG.
 *
 * Contract:
 *   - Register once at module init, before any crypto operation runs.
 *   - fn returns 0 on success, non-zero on failure (routing fails closed).
 *   - Deterministic KAT/ACVP paths use *_derand(seed) and never call the DRBG,
 *     so they are unaffected by this hook.
 *   - Passing NULL unregisters the provider and reverts to the embedded DRBG.
 */
typedef int (*qudo_pqc_rand_fn)(uint8_t *buf, size_t len);
QUDO_PQC_API void qudo_pqc_set_rand_provider(qudo_pqc_rand_fn fn);
#endif /* QUDO_PQC_USE_HOST_DRBG */

QUDO_PQC_API int qudo_pqc_get_module_boundary(const void **start_addr,
                                              const void **end_addr);

QUDO_PQC_API int qudo_pqc_get_integrity_hmac(const uint8_t **hmac,
                                             size_t *hmac_len);

QUDO_PQC_API int qudo_pqc_integrity_hmac_is_patched(void);

QUDO_PQC_API void qudo_pqc_hmac_sha256(const uint8_t *key, size_t key_len,
                                       const uint8_t *data, size_t data_len,
                                       uint8_t out[32]);

typedef struct qudo_pqc_hmac_ctx_st qudo_pqc_hmac_ctx_t;

QUDO_PQC_API qudo_pqc_hmac_ctx_t *qudo_pqc_hmac_ctx_new(void);

QUDO_PQC_API void qudo_pqc_hmac_ctx_init(qudo_pqc_hmac_ctx_t *ctx,
                                         const uint8_t *key, size_t key_len);

QUDO_PQC_API void qudo_pqc_hmac_ctx_update(qudo_pqc_hmac_ctx_t *ctx,
                                           const uint8_t *data,
                                           size_t data_len);

QUDO_PQC_API void qudo_pqc_hmac_ctx_final(qudo_pqc_hmac_ctx_t *ctx,
                                          uint8_t out[32]);

QUDO_PQC_API void qudo_pqc_hmac_ctx_free(qudo_pqc_hmac_ctx_t *ctx);

#define QUDO_PQC_CTRDRBG_MAX_REQUEST 65536

typedef struct qudo_pqc_ctrdrbg_ctx_st qudo_pqc_ctrdrbg_ctx_t;

QUDO_PQC_API qudo_pqc_ctrdrbg_ctx_t *qudo_pqc_ctrdrbg_new(void);

QUDO_PQC_API int qudo_pqc_ctrdrbg_init(qudo_pqc_ctrdrbg_ctx_t *ctx,
                                       size_t keylen, const uint8_t *seed,
                                       size_t seedlen);

QUDO_PQC_API int qudo_pqc_ctrdrbg_generate(qudo_pqc_ctrdrbg_ctx_t *ctx,
                                           uint8_t *out, size_t out_len,
                                           const uint8_t *additional,
                                           size_t additional_len);

QUDO_PQC_API int qudo_pqc_ctrdrbg_reseed(qudo_pqc_ctrdrbg_ctx_t *ctx,
                                         const uint8_t *seed, size_t seedlen);

QUDO_PQC_API void qudo_pqc_ctrdrbg_uninit(qudo_pqc_ctrdrbg_ctx_t *ctx);

QUDO_PQC_API void qudo_pqc_ctrdrbg_free(qudo_pqc_ctrdrbg_ctx_t *ctx);

QUDO_PQC_API int
qudo_pqc_ctrdrbg_is_zeroized(const qudo_pqc_ctrdrbg_ctx_t *ctx);

QUDO_PQC_API int qudo_pqc_rand_init(const uint8_t *entropy, size_t entropy_len);

QUDO_PQC_API int qudo_pqc_rand_reseed(const uint8_t *entropy,
                                      size_t entropy_len);

QUDO_PQC_API int qudo_pqc_rand_is_ready(void);

QUDO_PQC_API void qudo_pqc_rand_cleanup(void);

QUDO_PQC_API void qudo_pqc_cleanse(void *ptr, size_t len);

#ifdef __cplusplus
}
#endif

#endif
