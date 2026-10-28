/* SPDX-License-Identifier: Apache-2.0 AND MIT */
/* Copyright (c) 2026 ZenV Quantum */

#ifndef MLDSA_WRAPPER_H
#define MLDSA_WRAPPER_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef _MSC_VER
#    include <BaseTsd.h>
typedef SSIZE_T ssize_t;
#    define strcasecmp  _stricmp
#    define strncasecmp _strnicmp
#endif

#include "mldsa_types.h"

#include "mldsa_config.h"

#ifdef QUDO_FIPS_MODULE
#    include "qudo_pqc_indicator.h"
#endif

struct mldsa_config;

#define QUDO_MLDSA_alg_ml_dsa_44 "ML-DSA-44"

#define QUDO_MLDSA_alg_ml_dsa_65 "ML-DSA-65"

#define QUDO_MLDSA_alg_ml_dsa_87 "ML-DSA-87"

typedef struct QUDO_MLDSA {
    const char *method_name;
    const char *alg_version;
    uint8_t claimed_nist_level;
    uint16_t security_bits;

    bool euf_cma;
    bool suf_cma;
    bool sig_with_ctx_support;
    size_t length_public_key;
    size_t length_secret_key;
    size_t length_signature;

    QUDO_MLDSA_status_t (*keypair)(uint8_t *public_key, uint8_t *secret_key);
    QUDO_MLDSA_status_t (*sign)(uint8_t *signature, size_t *signature_len,
                                const uint8_t *message, size_t message_len,
                                const uint8_t *secret_key);
    QUDO_MLDSA_status_t (*sign_with_ctx_str)(
        uint8_t *signature, size_t *signature_len, const uint8_t *message,
        size_t message_len, const uint8_t *context, size_t context_len,
        const uint8_t *secret_key);
    QUDO_MLDSA_status_t (*verify)(const uint8_t *message, size_t message_len,
                                  const uint8_t *signature,
                                  size_t signature_len,
                                  const uint8_t *public_key);
    QUDO_MLDSA_status_t (*verify_with_ctx_str)(
        const uint8_t *message, size_t message_len, const uint8_t *signature,
        size_t signature_len, const uint8_t *context, size_t context_len,
        const uint8_t *public_key);

    void *ctx;
    struct mldsa_config *config;

#ifdef QUDO_FIPS_MODULE

    qudo_fips_ind_t fips_ind;
#endif

} QUDO_MLDSA;

QUDO_MLDSA_API QUDO_MLDSA_status_t QUDO_MLDSA_init(void);

QUDO_MLDSA_API void QUDO_MLDSA_cleanup(void);

QUDO_MLDSA_API int QUDO_MLDSA_is_initialized(void);

QUDO_MLDSA_API QUDO_MLDSA *QUDO_MLDSA_new(const char *algorithm);

QUDO_MLDSA_API void QUDO_MLDSA_free(QUDO_MLDSA *sig);

QUDO_MLDSA_API QUDO_MLDSA_status_t QUDO_MLDSA_keypair(QUDO_MLDSA *sig,
                                                      uint8_t *public_key,
                                                      uint8_t *secret_key);

QUDO_MLDSA_API QUDO_MLDSA_status_t QUDO_MLDSA_sign(
    QUDO_MLDSA *sig, uint8_t *signature, size_t *signature_len,
    const uint8_t *message, size_t message_len, const uint8_t *secret_key);

QUDO_MLDSA_API QUDO_MLDSA_status_t QUDO_MLDSA_sign_with_context(
    QUDO_MLDSA *sig, uint8_t *signature, size_t *signature_len,
    const uint8_t *message, size_t message_len, const uint8_t *context,
    size_t context_len, const uint8_t *secret_key);

QUDO_MLDSA_API QUDO_MLDSA_status_t QUDO_MLDSA_verify(
    QUDO_MLDSA *sig, const uint8_t *signature, size_t signature_len,
    const uint8_t *message, size_t message_len, const uint8_t *public_key);

QUDO_MLDSA_API QUDO_MLDSA_status_t QUDO_MLDSA_verify_with_context(
    QUDO_MLDSA *sig, const uint8_t *signature, size_t signature_len,
    const uint8_t *message, size_t message_len, const uint8_t *context,
    size_t context_len, const uint8_t *public_key);

QUDO_MLDSA_API QUDO_MLDSA_status_t
QUDO_MLDSA_keypair_internal(QUDO_MLDSA *sig, uint8_t *public_key,
                            uint8_t *secret_key, const uint8_t *seed);

QUDO_MLDSA_API QUDO_MLDSA_status_t QUDO_MLDSA_sign_internal(
    QUDO_MLDSA *sig, uint8_t *signature, size_t *signature_len,
    const uint8_t *message, size_t message_len, const uint8_t *prefix,
    size_t prefix_len, const uint8_t *rnd, const uint8_t *secret_key,
    int external_mu);

QUDO_MLDSA_API QUDO_MLDSA_status_t QUDO_MLDSA_sign_extmu(
    QUDO_MLDSA *sig, uint8_t *signature, size_t *signature_len,
    const uint8_t *mu, const uint8_t *secret_key);

QUDO_MLDSA_API QUDO_MLDSA_status_t QUDO_MLDSA_sign_concat(
    QUDO_MLDSA *sig, uint8_t *signed_message, size_t *signed_message_len,
    const uint8_t *message, size_t message_len, const uint8_t *context,
    size_t context_len, const uint8_t *secret_key);

QUDO_MLDSA_API QUDO_MLDSA_status_t QUDO_MLDSA_verify_internal(
    QUDO_MLDSA *sig, const uint8_t *signature, size_t signature_len,
    const uint8_t *message, size_t message_len, const uint8_t *prefix,
    size_t prefix_len, const uint8_t *public_key, int external_mu);

QUDO_MLDSA_API QUDO_MLDSA_status_t QUDO_MLDSA_verify_extmu(
    QUDO_MLDSA *sig, const uint8_t *signature, size_t signature_len,
    const uint8_t *mu, const uint8_t *public_key);

QUDO_MLDSA_API QUDO_MLDSA_status_t QUDO_MLDSA_open(
    QUDO_MLDSA *sig, uint8_t *message, size_t *message_len,
    const uint8_t *signed_message, size_t signed_message_len,
    const uint8_t *context, size_t context_len, const uint8_t *public_key);

#define QUDO_PREHASH_SHA2_224     1
#define QUDO_PREHASH_SHA2_256     2
#define QUDO_PREHASH_SHA2_384     3
#define QUDO_PREHASH_SHA2_512     4
#define QUDO_PREHASH_SHA2_512_224 5
#define QUDO_PREHASH_SHA2_512_256 6
#define QUDO_PREHASH_SHA3_224     7
#define QUDO_PREHASH_SHA3_256     8
#define QUDO_PREHASH_SHA3_384     9
#define QUDO_PREHASH_SHA3_512     10
#define QUDO_PREHASH_SHAKE_128    11
#define QUDO_PREHASH_SHAKE_256    12

QUDO_MLDSA_API QUDO_MLDSA_status_t QUDO_MLDSA_sign_pre_hash_internal(
    QUDO_MLDSA *sig, uint8_t *signature, size_t *signature_len,
    const uint8_t *pre_hash, size_t pre_hash_len, const uint8_t *context,
    size_t context_len, const uint8_t *rnd, const uint8_t *secret_key,
    int hash_alg);

QUDO_MLDSA_API QUDO_MLDSA_status_t QUDO_MLDSA_verify_pre_hash_internal(
    QUDO_MLDSA *sig, const uint8_t *signature, size_t signature_len,
    const uint8_t *pre_hash, size_t pre_hash_len, const uint8_t *context,
    size_t context_len, const uint8_t *public_key, int hash_alg);

QUDO_MLDSA_API QUDO_MLDSA_status_t QUDO_MLDSA_sign_pre_hash(
    QUDO_MLDSA *sig, uint8_t *signature, size_t *signature_len,
    const uint8_t *message, size_t message_len, const uint8_t *context,
    size_t context_len, const uint8_t *rnd, const uint8_t *secret_key,
    int hash_alg);

QUDO_MLDSA_API QUDO_MLDSA_status_t QUDO_MLDSA_verify_pre_hash(
    QUDO_MLDSA *sig, const uint8_t *signature, size_t signature_len,
    const uint8_t *message, size_t message_len, const uint8_t *context,
    size_t context_len, const uint8_t *public_key, int hash_alg);

QUDO_MLDSA_API QUDO_MLDSA_status_t
QUDO_MLDSA_ML_DSA_44_keypair(uint8_t public_key[ML_DSA_44_PUBLIC_KEY_BYTES],
                             uint8_t secret_key[ML_DSA_44_SECRET_KEY_BYTES]);

QUDO_MLDSA_API QUDO_MLDSA_status_t QUDO_MLDSA_ML_DSA_44_sign(
    uint8_t *signature, size_t *signature_len, const uint8_t *message,
    size_t message_len, const uint8_t secret_key[ML_DSA_44_SECRET_KEY_BYTES]);

QUDO_MLDSA_API QUDO_MLDSA_status_t QUDO_MLDSA_ML_DSA_44_verify(
    const uint8_t *signature, size_t signature_len, const uint8_t *message,
    size_t message_len, const uint8_t public_key[ML_DSA_44_PUBLIC_KEY_BYTES]);

QUDO_MLDSA_API QUDO_MLDSA_status_t
QUDO_MLDSA_ML_DSA_65_keypair(uint8_t public_key[ML_DSA_65_PUBLIC_KEY_BYTES],
                             uint8_t secret_key[ML_DSA_65_SECRET_KEY_BYTES]);

QUDO_MLDSA_API QUDO_MLDSA_status_t QUDO_MLDSA_ML_DSA_65_sign(
    uint8_t *signature, size_t *signature_len, const uint8_t *message,
    size_t message_len, const uint8_t secret_key[ML_DSA_65_SECRET_KEY_BYTES]);

QUDO_MLDSA_API QUDO_MLDSA_status_t QUDO_MLDSA_ML_DSA_65_verify(
    const uint8_t *signature, size_t signature_len, const uint8_t *message,
    size_t message_len, const uint8_t public_key[ML_DSA_65_PUBLIC_KEY_BYTES]);

QUDO_MLDSA_API QUDO_MLDSA_status_t
QUDO_MLDSA_ML_DSA_87_keypair(uint8_t public_key[ML_DSA_87_PUBLIC_KEY_BYTES],
                             uint8_t secret_key[ML_DSA_87_SECRET_KEY_BYTES]);

QUDO_MLDSA_API QUDO_MLDSA_status_t QUDO_MLDSA_ML_DSA_87_sign(
    uint8_t *signature, size_t *signature_len, const uint8_t *message,
    size_t message_len, const uint8_t secret_key[ML_DSA_87_SECRET_KEY_BYTES]);

QUDO_MLDSA_API QUDO_MLDSA_status_t QUDO_MLDSA_ML_DSA_87_verify(
    const uint8_t *signature, size_t signature_len, const uint8_t *message,
    size_t message_len, const uint8_t public_key[ML_DSA_87_PUBLIC_KEY_BYTES]);

QUDO_MLDSA_API size_t QUDO_MLDSA_get_public_key_bytes(const QUDO_MLDSA *sig);

QUDO_MLDSA_API size_t QUDO_MLDSA_get_secret_key_bytes(const QUDO_MLDSA *sig);

QUDO_MLDSA_API size_t QUDO_MLDSA_get_signature_bytes(const QUDO_MLDSA *sig);

QUDO_MLDSA_API const char *QUDO_MLDSA_get_algorithm_name(const QUDO_MLDSA *sig);

QUDO_MLDSA_API QUDO_MLDSA_security_level_t
QUDO_MLDSA_get_security_level(const QUDO_MLDSA *sig);

QUDO_MLDSA_API const char *
QUDO_MLDSA_get_error_string(QUDO_MLDSA_status_t status);

QUDO_MLDSA_API const char *QUDO_MLDSA_get_version(void);

QUDO_MLDSA_API const char *QUDO_MLDSA_get_platform(void);

QUDO_MLDSA_API const char *QUDO_MLDSA_get_architecture(void);

QUDO_MLDSA_API int QUDO_MLDSA_has_avx2(void);

QUDO_MLDSA_API int QUDO_MLDSA_has_neon(void);

QUDO_MLDSA_API int QUDO_MLDSA_get_cpu_count(void);

QUDO_MLDSA_API const char *QUDO_MLDSA_get_features(void);

QUDO_MLDSA_API void QUDO_MLDSA_print_system_info(void);

QUDO_MLDSA_API int QUDO_MLDSA_is_platform_supported(void);

QUDO_MLDSA_API size_t QUDO_MLDSA_get_cache_line_size(void);

QUDO_MLDSA_API QUDO_MLDSA_status_t QUDO_MLDSA_export_public_key_der(
    const uint8_t *public_key, size_t public_key_len, uint8_t *der_buffer,
    size_t *der_len);

QUDO_MLDSA_API QUDO_MLDSA_status_t
QUDO_MLDSA_import_public_key_der(const uint8_t *der_buffer, size_t der_len,
                                 uint8_t *public_key, size_t *public_key_len);

QUDO_MLDSA_API QUDO_MLDSA_status_t QUDO_MLDSA_export_public_key_pem(
    const uint8_t *public_key, size_t public_key_len, char *pem_buffer,
    size_t *pem_len);

QUDO_MLDSA_API QUDO_MLDSA_status_t QUDO_MLDSA_import_public_key_pem(
    const char *pem_buffer, uint8_t *public_key, size_t *public_key_len);

QUDO_MLDSA_API QUDO_MLDSA_status_t QUDO_MLDSA_export_private_key_der(
    const uint8_t *private_key, size_t private_key_len, uint8_t *der_buffer,
    size_t *der_len);

QUDO_MLDSA_API QUDO_MLDSA_status_t QUDO_MLDSA_import_private_key_der(
    const uint8_t *der_buffer, size_t der_len, uint8_t *private_key,
    size_t *private_key_len);

QUDO_MLDSA_API QUDO_MLDSA_status_t QUDO_MLDSA_export_private_key_pem(
    const uint8_t *private_key, size_t private_key_len, char *pem_buffer,
    size_t *pem_len);

QUDO_MLDSA_API QUDO_MLDSA_status_t QUDO_MLDSA_import_private_key_pem(
    const char *pem_buffer, uint8_t *private_key, size_t *private_key_len);

QUDO_MLDSA_API QUDO_MLDSA_status_t QUDO_MLDSA_export_private_key_der_format(
    const uint8_t *private_key, size_t private_key_len, uint8_t *der_buffer,
    size_t *der_len, QUDO_MLDSA_pkcs8_format_t format);

QUDO_MLDSA_API QUDO_MLDSA_status_t QUDO_MLDSA_import_private_key_der_format(
    const uint8_t *der_buffer, size_t der_len, uint8_t *private_key,
    size_t *private_key_len, uint8_t *public_key, size_t *public_key_len);

QUDO_MLDSA_API QUDO_MLDSA_status_t QUDO_MLDSA_export_private_key_pem_format(
    const uint8_t *private_key, size_t private_key_len, char *pem_buffer,
    size_t *pem_len, QUDO_MLDSA_pkcs8_format_t format);

QUDO_MLDSA_API QUDO_MLDSA_status_t QUDO_MLDSA_import_private_key_pem_format(
    const char *pem_buffer, uint8_t *private_key, size_t *private_key_len,
    uint8_t *public_key, size_t *public_key_len);

typedef struct QUDO_MLDSA_shake256_st QUDO_MLDSA_shake256_ctx;

QUDO_MLDSA_API QUDO_MLDSA_status_t
QUDO_MLDSA_shake256_init(QUDO_MLDSA_shake256_ctx **ctx);

QUDO_MLDSA_API QUDO_MLDSA_status_t QUDO_MLDSA_shake256_absorb(
    QUDO_MLDSA_shake256_ctx *ctx, const uint8_t *data, size_t len);

QUDO_MLDSA_API QUDO_MLDSA_status_t QUDO_MLDSA_shake256_squeeze(
    QUDO_MLDSA_shake256_ctx *ctx, uint8_t *out, size_t outlen);

QUDO_MLDSA_API QUDO_MLDSA_status_t QUDO_MLDSA_shake256_dup(
    QUDO_MLDSA_shake256_ctx **dst, const QUDO_MLDSA_shake256_ctx *src);

QUDO_MLDSA_API void QUDO_MLDSA_shake256_free(QUDO_MLDSA_shake256_ctx *ctx);

QUDO_MLDSA_API QUDO_MLDSA_status_t QUDO_MLDSA_shake256(uint8_t *out,
                                                       size_t outlen,
                                                       const uint8_t *in,
                                                       size_t inlen);

QUDO_MLDSA_API QUDO_MLDSA_status_t QUDO_MLDSA_ML_DSA_44_keypair_internal(
    uint8_t public_key[ML_DSA_44_PUBLIC_KEY_BYTES],
    uint8_t secret_key[ML_DSA_44_SECRET_KEY_BYTES],
    const uint8_t seed[MLDSA_SEEDBYTES]);

QUDO_MLDSA_API QUDO_MLDSA_status_t QUDO_MLDSA_ML_DSA_44_sign_internal(
    uint8_t *signature, size_t *signature_len, const uint8_t *message,
    size_t message_len, const uint8_t *prefix, size_t prefix_len,
    const uint8_t rnd[MLDSA_RNDBYTES],
    const uint8_t secret_key[ML_DSA_44_SECRET_KEY_BYTES], int external_mu);

QUDO_MLDSA_API QUDO_MLDSA_status_t QUDO_MLDSA_ML_DSA_44_sign_extmu(
    uint8_t *signature, size_t *signature_len, const uint8_t mu[MLDSA_CRHBYTES],
    const uint8_t secret_key[ML_DSA_44_SECRET_KEY_BYTES]);

QUDO_MLDSA_API QUDO_MLDSA_status_t QUDO_MLDSA_ML_DSA_44_sign_concat(
    uint8_t *signed_message, size_t *signed_message_len, const uint8_t *message,
    size_t message_len, const uint8_t *context, size_t context_len,
    const uint8_t secret_key[ML_DSA_44_SECRET_KEY_BYTES]);

QUDO_MLDSA_API QUDO_MLDSA_status_t QUDO_MLDSA_ML_DSA_44_verify_internal(
    const uint8_t *signature, size_t signature_len, const uint8_t *message,
    size_t message_len, const uint8_t *prefix, size_t prefix_len,
    const uint8_t public_key[ML_DSA_44_PUBLIC_KEY_BYTES], int external_mu);

QUDO_MLDSA_API QUDO_MLDSA_status_t QUDO_MLDSA_ML_DSA_44_verify_extmu(
    const uint8_t *signature, size_t signature_len,
    const uint8_t mu[MLDSA_CRHBYTES],
    const uint8_t public_key[ML_DSA_44_PUBLIC_KEY_BYTES]);

QUDO_MLDSA_API QUDO_MLDSA_status_t QUDO_MLDSA_ML_DSA_44_open(
    uint8_t *message, size_t *message_len, const uint8_t *signed_message,
    size_t signed_message_len, const uint8_t *context, size_t context_len,
    const uint8_t public_key[ML_DSA_44_PUBLIC_KEY_BYTES]);

QUDO_MLDSA_API QUDO_MLDSA_status_t QUDO_MLDSA_ML_DSA_44_sign_pre_hash(
    uint8_t *signature, size_t *signature_len, const uint8_t *pre_hash,
    size_t pre_hash_len, const uint8_t *context, size_t context_len,
    const uint8_t rnd[MLDSA_RNDBYTES],
    const uint8_t secret_key[ML_DSA_44_SECRET_KEY_BYTES], int hash_alg);

QUDO_MLDSA_API QUDO_MLDSA_status_t QUDO_MLDSA_ML_DSA_44_verify_pre_hash(
    const uint8_t *signature, size_t signature_len, const uint8_t *pre_hash,
    size_t pre_hash_len, const uint8_t *context, size_t context_len,
    const uint8_t public_key[ML_DSA_44_PUBLIC_KEY_BYTES], int hash_alg);

QUDO_MLDSA_API QUDO_MLDSA_status_t QUDO_MLDSA_ML_DSA_65_keypair_internal(
    uint8_t public_key[ML_DSA_65_PUBLIC_KEY_BYTES],
    uint8_t secret_key[ML_DSA_65_SECRET_KEY_BYTES],
    const uint8_t seed[MLDSA_SEEDBYTES]);

QUDO_MLDSA_API QUDO_MLDSA_status_t QUDO_MLDSA_ML_DSA_65_sign_internal(
    uint8_t *signature, size_t *signature_len, const uint8_t *message,
    size_t message_len, const uint8_t *prefix, size_t prefix_len,
    const uint8_t rnd[MLDSA_RNDBYTES],
    const uint8_t secret_key[ML_DSA_65_SECRET_KEY_BYTES], int external_mu);

QUDO_MLDSA_API QUDO_MLDSA_status_t QUDO_MLDSA_ML_DSA_65_sign_extmu(
    uint8_t *signature, size_t *signature_len, const uint8_t mu[MLDSA_CRHBYTES],
    const uint8_t secret_key[ML_DSA_65_SECRET_KEY_BYTES]);

QUDO_MLDSA_API QUDO_MLDSA_status_t QUDO_MLDSA_ML_DSA_65_sign_concat(
    uint8_t *signed_message, size_t *signed_message_len, const uint8_t *message,
    size_t message_len, const uint8_t *context, size_t context_len,
    const uint8_t secret_key[ML_DSA_65_SECRET_KEY_BYTES]);

QUDO_MLDSA_API QUDO_MLDSA_status_t QUDO_MLDSA_ML_DSA_65_verify_internal(
    const uint8_t *signature, size_t signature_len, const uint8_t *message,
    size_t message_len, const uint8_t *prefix, size_t prefix_len,
    const uint8_t public_key[ML_DSA_65_PUBLIC_KEY_BYTES], int external_mu);

QUDO_MLDSA_API QUDO_MLDSA_status_t QUDO_MLDSA_ML_DSA_65_verify_extmu(
    const uint8_t *signature, size_t signature_len,
    const uint8_t mu[MLDSA_CRHBYTES],
    const uint8_t public_key[ML_DSA_65_PUBLIC_KEY_BYTES]);

QUDO_MLDSA_API QUDO_MLDSA_status_t QUDO_MLDSA_ML_DSA_65_open(
    uint8_t *message, size_t *message_len, const uint8_t *signed_message,
    size_t signed_message_len, const uint8_t *context, size_t context_len,
    const uint8_t public_key[ML_DSA_65_PUBLIC_KEY_BYTES]);

QUDO_MLDSA_API QUDO_MLDSA_status_t QUDO_MLDSA_ML_DSA_65_sign_pre_hash(
    uint8_t *signature, size_t *signature_len, const uint8_t *pre_hash,
    size_t pre_hash_len, const uint8_t *context, size_t context_len,
    const uint8_t rnd[MLDSA_RNDBYTES],
    const uint8_t secret_key[ML_DSA_65_SECRET_KEY_BYTES], int hash_alg);

QUDO_MLDSA_API QUDO_MLDSA_status_t QUDO_MLDSA_ML_DSA_65_verify_pre_hash(
    const uint8_t *signature, size_t signature_len, const uint8_t *pre_hash,
    size_t pre_hash_len, const uint8_t *context, size_t context_len,
    const uint8_t public_key[ML_DSA_65_PUBLIC_KEY_BYTES], int hash_alg);

QUDO_MLDSA_API QUDO_MLDSA_status_t QUDO_MLDSA_ML_DSA_87_keypair_internal(
    uint8_t public_key[ML_DSA_87_PUBLIC_KEY_BYTES],
    uint8_t secret_key[ML_DSA_87_SECRET_KEY_BYTES],
    const uint8_t seed[MLDSA_SEEDBYTES]);

QUDO_MLDSA_API QUDO_MLDSA_status_t QUDO_MLDSA_ML_DSA_87_sign_internal(
    uint8_t *signature, size_t *signature_len, const uint8_t *message,
    size_t message_len, const uint8_t *prefix, size_t prefix_len,
    const uint8_t rnd[MLDSA_RNDBYTES],
    const uint8_t secret_key[ML_DSA_87_SECRET_KEY_BYTES], int external_mu);

QUDO_MLDSA_API QUDO_MLDSA_status_t QUDO_MLDSA_ML_DSA_87_sign_extmu(
    uint8_t *signature, size_t *signature_len, const uint8_t mu[MLDSA_CRHBYTES],
    const uint8_t secret_key[ML_DSA_87_SECRET_KEY_BYTES]);

QUDO_MLDSA_API QUDO_MLDSA_status_t QUDO_MLDSA_ML_DSA_87_sign_concat(
    uint8_t *signed_message, size_t *signed_message_len, const uint8_t *message,
    size_t message_len, const uint8_t *context, size_t context_len,
    const uint8_t secret_key[ML_DSA_87_SECRET_KEY_BYTES]);

QUDO_MLDSA_API QUDO_MLDSA_status_t QUDO_MLDSA_ML_DSA_87_verify_internal(
    const uint8_t *signature, size_t signature_len, const uint8_t *message,
    size_t message_len, const uint8_t *prefix, size_t prefix_len,
    const uint8_t public_key[ML_DSA_87_PUBLIC_KEY_BYTES], int external_mu);

QUDO_MLDSA_API QUDO_MLDSA_status_t QUDO_MLDSA_ML_DSA_87_verify_extmu(
    const uint8_t *signature, size_t signature_len,
    const uint8_t mu[MLDSA_CRHBYTES],
    const uint8_t public_key[ML_DSA_87_PUBLIC_KEY_BYTES]);

QUDO_MLDSA_API QUDO_MLDSA_status_t QUDO_MLDSA_ML_DSA_87_open(
    uint8_t *message, size_t *message_len, const uint8_t *signed_message,
    size_t signed_message_len, const uint8_t *context, size_t context_len,
    const uint8_t public_key[ML_DSA_87_PUBLIC_KEY_BYTES]);

QUDO_MLDSA_API QUDO_MLDSA_status_t QUDO_MLDSA_ML_DSA_87_sign_pre_hash(
    uint8_t *signature, size_t *signature_len, const uint8_t *pre_hash,
    size_t pre_hash_len, const uint8_t *context, size_t context_len,
    const uint8_t rnd[MLDSA_RNDBYTES],
    const uint8_t secret_key[ML_DSA_87_SECRET_KEY_BYTES], int hash_alg);

QUDO_MLDSA_API QUDO_MLDSA_status_t QUDO_MLDSA_ML_DSA_87_verify_pre_hash(
    const uint8_t *signature, size_t signature_len, const uint8_t *pre_hash,
    size_t pre_hash_len, const uint8_t *context, size_t context_len,
    const uint8_t public_key[ML_DSA_87_PUBLIC_KEY_BYTES], int hash_alg);

QUDO_MLDSA_API int QUDO_MLDSA_alg_count(void);

QUDO_MLDSA_API const char *QUDO_MLDSA_alg_identifier(size_t i);

QUDO_MLDSA_API int QUDO_MLDSA_alg_is_enabled(const char *method_name);

QUDO_MLDSA_API int QUDO_MLDSA_supports_ctx_str(const char *alg_name);

QUDO_MLDSA_API void QUDO_MLDSA_constant_time_select(void *result, const void *a,
                                                    const void *b, size_t len,
                                                    int condition);

#ifdef __cplusplus
}
#endif

#endif
