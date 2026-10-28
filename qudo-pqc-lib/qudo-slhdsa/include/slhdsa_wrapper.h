/* SPDX-License-Identifier: Apache-2.0 AND MIT */
/* Copyright (c) 2026 ZenV Quantum */

#ifndef SLHDSA_WRAPPER_H
#define SLHDSA_WRAPPER_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef _MSC_VER
#    include <BaseTsd.h>
typedef SSIZE_T ssize_t;
#    define strcasecmp _stricmp
#endif

#include "slhdsa_config.h"
#include "slhdsa_types.h"

#ifdef QUDO_FIPS_MODULE
#    include "qudo_pqc_indicator.h"
#endif

typedef struct QUDO_SLHDSA {
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

    QUDO_SLHDSA_status_t (*keypair)(uint8_t *public_key, uint8_t *secret_key);
    QUDO_SLHDSA_status_t (*sign)(uint8_t *signature, size_t *signature_len,
                                 const uint8_t *message, size_t message_len,
                                 const uint8_t *secret_key);
    QUDO_SLHDSA_status_t (*sign_with_ctx_str)(
        uint8_t *signature, size_t *signature_len, const uint8_t *message,
        size_t message_len, const uint8_t *context, size_t context_len,
        const uint8_t *secret_key);
    QUDO_SLHDSA_status_t (*verify)(const uint8_t *message, size_t message_len,
                                   const uint8_t *signature,
                                   size_t signature_len,
                                   const uint8_t *public_key);
    QUDO_SLHDSA_status_t (*verify_with_ctx_str)(
        const uint8_t *message, size_t message_len, const uint8_t *signature,
        size_t signature_len, const uint8_t *context, size_t context_len,
        const uint8_t *public_key);

    QUDO_SLHDSA_parameter_set_t param_set;

#ifdef QUDO_FIPS_MODULE

    qudo_fips_ind_t fips_ind;
#endif

} QUDO_SLHDSA;

QUDO_SLHDSA_API QUDO_SLHDSA_status_t QUDO_SLHDSA_init(void);

QUDO_SLHDSA_API void QUDO_SLHDSA_cleanup(void);

QUDO_SLHDSA_API int QUDO_SLHDSA_is_initialized(void);

QUDO_SLHDSA_API QUDO_SLHDSA *QUDO_SLHDSA_new(const char *algorithm);

QUDO_SLHDSA_API void QUDO_SLHDSA_free(QUDO_SLHDSA *sig);

QUDO_SLHDSA_API QUDO_SLHDSA_status_t QUDO_SLHDSA_keypair(const QUDO_SLHDSA *sig,
                                                         uint8_t *public_key,
                                                         uint8_t *secret_key);

QUDO_SLHDSA_API QUDO_SLHDSA_status_t QUDO_SLHDSA_keypair_internal(
    const QUDO_SLHDSA *sig, uint8_t *public_key, uint8_t *secret_key,
    const uint8_t *sk_seed, const uint8_t *sk_prf, const uint8_t *pk_seed);

QUDO_SLHDSA_API QUDO_SLHDSA_status_t QUDO_SLHDSA_sign(
    const QUDO_SLHDSA *sig, uint8_t *signature, size_t *signature_len,
    const uint8_t *message, size_t message_len, const uint8_t *secret_key);

QUDO_SLHDSA_API QUDO_SLHDSA_status_t QUDO_SLHDSA_sign_with_ctx_str(
    const QUDO_SLHDSA *sig, uint8_t *signature, size_t *signature_len,
    const uint8_t *message, size_t message_len, const uint8_t *context,
    size_t context_len, const uint8_t *secret_key);

QUDO_SLHDSA_API QUDO_SLHDSA_status_t QUDO_SLHDSA_sign_ex(
    const QUDO_SLHDSA *sig, uint8_t *signature, size_t *signature_len,
    const uint8_t *message, size_t message_len, const uint8_t *context,
    size_t context_len, const uint8_t *addrnd, const uint8_t *secret_key);

QUDO_SLHDSA_API QUDO_SLHDSA_status_t QUDO_SLHDSA_sign_internal(
    const QUDO_SLHDSA *sig, uint8_t *signature, size_t *signature_len,
    const uint8_t *message, size_t message_len, const uint8_t *addrnd,
    const uint8_t *secret_key);

QUDO_SLHDSA_API QUDO_SLHDSA_status_t
QUDO_SLHDSA_verify_internal(const QUDO_SLHDSA *sig, const uint8_t *message,
                            size_t message_len, const uint8_t *signature_buf,
                            size_t signature_len, const uint8_t *public_key);

QUDO_SLHDSA_API QUDO_SLHDSA_status_t QUDO_SLHDSA_sign_pre_hash(
    const QUDO_SLHDSA *sig, uint8_t *signature, size_t *signature_len,
    const uint8_t *message, size_t message_len, const uint8_t *context,
    size_t context_len, const char *hash_alg, const uint8_t *addrnd,
    const uint8_t *secret_key);

QUDO_SLHDSA_API QUDO_SLHDSA_status_t QUDO_SLHDSA_verify_pre_hash(
    const QUDO_SLHDSA *sig, const uint8_t *message, size_t message_len,
    const uint8_t *signature_buf, size_t signature_len, const uint8_t *context,
    size_t context_len, const char *hash_alg, const uint8_t *public_key);

QUDO_SLHDSA_API QUDO_SLHDSA_status_t QUDO_SLHDSA_verify(
    const QUDO_SLHDSA *sig, const uint8_t *message, size_t message_len,
    const uint8_t *signature, size_t signature_len, const uint8_t *public_key);

QUDO_SLHDSA_API QUDO_SLHDSA_status_t QUDO_SLHDSA_verify_with_ctx_str(
    const QUDO_SLHDSA *sig, const uint8_t *message, size_t message_len,
    const uint8_t *signature, size_t signature_len, const uint8_t *context,
    size_t context_len, const uint8_t *public_key);

QUDO_SLHDSA_API QUDO_SLHDSA_status_t QUDO_SLHDSA_SHA2_128s_keypair(uint8_t *pk,
                                                                   uint8_t *sk);
QUDO_SLHDSA_API QUDO_SLHDSA_status_t
QUDO_SLHDSA_SHA2_128s_sign(uint8_t *sig, size_t *sig_len, const uint8_t *msg,
                           size_t msg_len, const uint8_t *sk);
QUDO_SLHDSA_API QUDO_SLHDSA_status_t QUDO_SLHDSA_SHA2_128s_verify(
    const uint8_t *msg, size_t msg_len, const uint8_t *sig, size_t sig_len,
    const uint8_t *pk);

QUDO_SLHDSA_API QUDO_SLHDSA_status_t QUDO_SLHDSA_SHA2_128f_keypair(uint8_t *pk,
                                                                   uint8_t *sk);
QUDO_SLHDSA_API QUDO_SLHDSA_status_t
QUDO_SLHDSA_SHA2_128f_sign(uint8_t *sig, size_t *sig_len, const uint8_t *msg,
                           size_t msg_len, const uint8_t *sk);
QUDO_SLHDSA_API QUDO_SLHDSA_status_t QUDO_SLHDSA_SHA2_128f_verify(
    const uint8_t *msg, size_t msg_len, const uint8_t *sig, size_t sig_len,
    const uint8_t *pk);

QUDO_SLHDSA_API QUDO_SLHDSA_status_t QUDO_SLHDSA_SHA2_192s_keypair(uint8_t *pk,
                                                                   uint8_t *sk);
QUDO_SLHDSA_API QUDO_SLHDSA_status_t
QUDO_SLHDSA_SHA2_192s_sign(uint8_t *sig, size_t *sig_len, const uint8_t *msg,
                           size_t msg_len, const uint8_t *sk);
QUDO_SLHDSA_API QUDO_SLHDSA_status_t QUDO_SLHDSA_SHA2_192s_verify(
    const uint8_t *msg, size_t msg_len, const uint8_t *sig, size_t sig_len,
    const uint8_t *pk);

QUDO_SLHDSA_API QUDO_SLHDSA_status_t QUDO_SLHDSA_SHA2_192f_keypair(uint8_t *pk,
                                                                   uint8_t *sk);
QUDO_SLHDSA_API QUDO_SLHDSA_status_t
QUDO_SLHDSA_SHA2_192f_sign(uint8_t *sig, size_t *sig_len, const uint8_t *msg,
                           size_t msg_len, const uint8_t *sk);
QUDO_SLHDSA_API QUDO_SLHDSA_status_t QUDO_SLHDSA_SHA2_192f_verify(
    const uint8_t *msg, size_t msg_len, const uint8_t *sig, size_t sig_len,
    const uint8_t *pk);

QUDO_SLHDSA_API QUDO_SLHDSA_status_t QUDO_SLHDSA_SHA2_256s_keypair(uint8_t *pk,
                                                                   uint8_t *sk);
QUDO_SLHDSA_API QUDO_SLHDSA_status_t
QUDO_SLHDSA_SHA2_256s_sign(uint8_t *sig, size_t *sig_len, const uint8_t *msg,
                           size_t msg_len, const uint8_t *sk);
QUDO_SLHDSA_API QUDO_SLHDSA_status_t QUDO_SLHDSA_SHA2_256s_verify(
    const uint8_t *msg, size_t msg_len, const uint8_t *sig, size_t sig_len,
    const uint8_t *pk);

QUDO_SLHDSA_API QUDO_SLHDSA_status_t QUDO_SLHDSA_SHA2_256f_keypair(uint8_t *pk,
                                                                   uint8_t *sk);
QUDO_SLHDSA_API QUDO_SLHDSA_status_t
QUDO_SLHDSA_SHA2_256f_sign(uint8_t *sig, size_t *sig_len, const uint8_t *msg,
                           size_t msg_len, const uint8_t *sk);
QUDO_SLHDSA_API QUDO_SLHDSA_status_t QUDO_SLHDSA_SHA2_256f_verify(
    const uint8_t *msg, size_t msg_len, const uint8_t *sig, size_t sig_len,
    const uint8_t *pk);

QUDO_SLHDSA_API QUDO_SLHDSA_status_t
QUDO_SLHDSA_SHAKE_128s_keypair(uint8_t *pk, uint8_t *sk);
QUDO_SLHDSA_API QUDO_SLHDSA_status_t
QUDO_SLHDSA_SHAKE_128s_sign(uint8_t *sig, size_t *sig_len, const uint8_t *msg,
                            size_t msg_len, const uint8_t *sk);
QUDO_SLHDSA_API QUDO_SLHDSA_status_t QUDO_SLHDSA_SHAKE_128s_verify(
    const uint8_t *msg, size_t msg_len, const uint8_t *sig, size_t sig_len,
    const uint8_t *pk);

QUDO_SLHDSA_API QUDO_SLHDSA_status_t
QUDO_SLHDSA_SHAKE_128f_keypair(uint8_t *pk, uint8_t *sk);
QUDO_SLHDSA_API QUDO_SLHDSA_status_t
QUDO_SLHDSA_SHAKE_128f_sign(uint8_t *sig, size_t *sig_len, const uint8_t *msg,
                            size_t msg_len, const uint8_t *sk);
QUDO_SLHDSA_API QUDO_SLHDSA_status_t QUDO_SLHDSA_SHAKE_128f_verify(
    const uint8_t *msg, size_t msg_len, const uint8_t *sig, size_t sig_len,
    const uint8_t *pk);

QUDO_SLHDSA_API QUDO_SLHDSA_status_t
QUDO_SLHDSA_SHAKE_192s_keypair(uint8_t *pk, uint8_t *sk);
QUDO_SLHDSA_API QUDO_SLHDSA_status_t
QUDO_SLHDSA_SHAKE_192s_sign(uint8_t *sig, size_t *sig_len, const uint8_t *msg,
                            size_t msg_len, const uint8_t *sk);
QUDO_SLHDSA_API QUDO_SLHDSA_status_t QUDO_SLHDSA_SHAKE_192s_verify(
    const uint8_t *msg, size_t msg_len, const uint8_t *sig, size_t sig_len,
    const uint8_t *pk);

QUDO_SLHDSA_API QUDO_SLHDSA_status_t
QUDO_SLHDSA_SHAKE_192f_keypair(uint8_t *pk, uint8_t *sk);
QUDO_SLHDSA_API QUDO_SLHDSA_status_t
QUDO_SLHDSA_SHAKE_192f_sign(uint8_t *sig, size_t *sig_len, const uint8_t *msg,
                            size_t msg_len, const uint8_t *sk);
QUDO_SLHDSA_API QUDO_SLHDSA_status_t QUDO_SLHDSA_SHAKE_192f_verify(
    const uint8_t *msg, size_t msg_len, const uint8_t *sig, size_t sig_len,
    const uint8_t *pk);

QUDO_SLHDSA_API QUDO_SLHDSA_status_t
QUDO_SLHDSA_SHAKE_256s_keypair(uint8_t *pk, uint8_t *sk);
QUDO_SLHDSA_API QUDO_SLHDSA_status_t
QUDO_SLHDSA_SHAKE_256s_sign(uint8_t *sig, size_t *sig_len, const uint8_t *msg,
                            size_t msg_len, const uint8_t *sk);
QUDO_SLHDSA_API QUDO_SLHDSA_status_t QUDO_SLHDSA_SHAKE_256s_verify(
    const uint8_t *msg, size_t msg_len, const uint8_t *sig, size_t sig_len,
    const uint8_t *pk);

QUDO_SLHDSA_API QUDO_SLHDSA_status_t
QUDO_SLHDSA_SHAKE_256f_keypair(uint8_t *pk, uint8_t *sk);
QUDO_SLHDSA_API QUDO_SLHDSA_status_t
QUDO_SLHDSA_SHAKE_256f_sign(uint8_t *sig, size_t *sig_len, const uint8_t *msg,
                            size_t msg_len, const uint8_t *sk);
QUDO_SLHDSA_API QUDO_SLHDSA_status_t QUDO_SLHDSA_SHAKE_256f_verify(
    const uint8_t *msg, size_t msg_len, const uint8_t *sig, size_t sig_len,
    const uint8_t *pk);

QUDO_SLHDSA_API QUDO_SLHDSA_status_t QUDO_SLHDSA_export_public_key_der(
    const uint8_t *public_key, size_t public_key_len,
    QUDO_SLHDSA_parameter_set_t param_set, uint8_t *der_out,
    size_t *der_out_len);

QUDO_SLHDSA_API QUDO_SLHDSA_status_t
QUDO_SLHDSA_import_public_key_der(const uint8_t *der_in, size_t der_in_len,
                                  uint8_t *public_key, size_t *public_key_len);

QUDO_SLHDSA_API QUDO_SLHDSA_status_t QUDO_SLHDSA_export_private_key_der(
    const uint8_t *private_key, size_t private_key_len,
    QUDO_SLHDSA_parameter_set_t param_set, uint8_t *der_out,
    size_t *der_out_len);

QUDO_SLHDSA_API QUDO_SLHDSA_status_t QUDO_SLHDSA_import_private_key_der(
    const uint8_t *der_in, size_t der_in_len, uint8_t *private_key,
    size_t *private_key_len);

QUDO_SLHDSA_API QUDO_SLHDSA_status_t QUDO_SLHDSA_export_public_key_pem(
    const uint8_t *public_key, size_t public_key_len,
    QUDO_SLHDSA_parameter_set_t param_set, char *pem_out, size_t *pem_out_len);

QUDO_SLHDSA_API QUDO_SLHDSA_status_t
QUDO_SLHDSA_import_public_key_pem(const char *pem_in, size_t pem_in_len,
                                  uint8_t *public_key, size_t *public_key_len);

QUDO_SLHDSA_API QUDO_SLHDSA_status_t QUDO_SLHDSA_export_private_key_pem(
    const uint8_t *private_key, size_t private_key_len,
    QUDO_SLHDSA_parameter_set_t param_set, char *pem_out, size_t *pem_out_len);

QUDO_SLHDSA_API QUDO_SLHDSA_status_t QUDO_SLHDSA_import_private_key_pem(
    const char *pem_in, size_t pem_in_len, uint8_t *private_key,
    size_t *private_key_len);

QUDO_SLHDSA_API const char *QUDO_SLHDSA_get_version(void);

QUDO_SLHDSA_API const char *QUDO_SLHDSA_get_platform(void);

QUDO_SLHDSA_API const char *QUDO_SLHDSA_get_architecture(void);

QUDO_SLHDSA_API int QUDO_SLHDSA_has_avx2(void);

QUDO_SLHDSA_API int QUDO_SLHDSA_has_neon(void);

QUDO_SLHDSA_API int QUDO_SLHDSA_get_cpu_count(void);

QUDO_SLHDSA_API const char *QUDO_SLHDSA_get_features(void);

QUDO_SLHDSA_API void QUDO_SLHDSA_print_system_info(void);

QUDO_SLHDSA_API int QUDO_SLHDSA_is_platform_supported(void);

QUDO_SLHDSA_API size_t QUDO_SLHDSA_get_cache_line_size(void);

QUDO_SLHDSA_API const char *
QUDO_SLHDSA_get_error_string(QUDO_SLHDSA_status_t status);

QUDO_SLHDSA_API int
QUDO_SLHDSA_get_security_level(QUDO_SLHDSA_parameter_set_t param_set);

QUDO_SLHDSA_API int QUDO_SLHDSA_alg_count(void);

QUDO_SLHDSA_API const char *QUDO_SLHDSA_alg_identifier(size_t i);

QUDO_SLHDSA_API int QUDO_SLHDSA_alg_is_enabled(const char *method_name);

#ifdef __cplusplus
}
#endif

#endif
