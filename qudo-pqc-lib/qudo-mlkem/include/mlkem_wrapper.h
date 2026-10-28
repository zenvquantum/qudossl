/* SPDX-License-Identifier: Apache-2.0 AND MIT */
/* Copyright (c) 2026 ZenV Quantum */

#ifndef MLKEM_WRAPPER_H
#define MLKEM_WRAPPER_H

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

#include "mlkem_types.h"

#include "mlkem_config.h"

#ifdef QUDO_FIPS_MODULE
#    include "qudo_pqc_indicator.h"
#endif

struct mlkem_config;

#include "mlkem_auto_generated.h"

#define QUDO_KEM_alg_mlkem_512 "ML-KEM-512"

#define QUDO_KEM_alg_mlkem_768 "ML-KEM-768"

#define QUDO_KEM_alg_mlkem_1024 "ML-KEM-1024"

#define QUDO_KEM_SEED_BYTES 64

#define QUDO_KEM_mlkem_512_length_public_key    ML_KEM_512_PUBLIC_KEY_BYTES
#define QUDO_KEM_mlkem_512_length_secret_key    ML_KEM_512_SECRET_KEY_BYTES
#define QUDO_KEM_mlkem_512_length_ciphertext    ML_KEM_512_CIPHERTEXT_BYTES
#define QUDO_KEM_mlkem_512_length_shared_secret ML_KEM_512_SHARED_SECRET_BYTES

#define QUDO_KEM_mlkem_768_length_public_key    ML_KEM_768_PUBLIC_KEY_BYTES
#define QUDO_KEM_mlkem_768_length_secret_key    ML_KEM_768_SECRET_KEY_BYTES
#define QUDO_KEM_mlkem_768_length_ciphertext    ML_KEM_768_CIPHERTEXT_BYTES
#define QUDO_KEM_mlkem_768_length_shared_secret ML_KEM_768_SHARED_SECRET_BYTES

#define QUDO_KEM_mlkem_1024_length_public_key    ML_KEM_1024_PUBLIC_KEY_BYTES
#define QUDO_KEM_mlkem_1024_length_secret_key    ML_KEM_1024_SECRET_KEY_BYTES
#define QUDO_KEM_mlkem_1024_length_ciphertext    ML_KEM_1024_CIPHERTEXT_BYTES
#define QUDO_KEM_mlkem_1024_length_shared_secret ML_KEM_1024_SHARED_SECRET_BYTES

typedef struct QUDO_KEM {

    const char *algorithm_name;

    QUDO_KEM_security_level_t security_level;

    uint8_t claimed_nist_level;

    bool ind_cca;

    size_t length_public_key;

    size_t length_secret_key;

    size_t length_ciphertext;

    size_t length_shared_secret;

    QUDO_KEM_status_t (*keypair)(uint8_t *public_key, uint8_t *secret_key);

    QUDO_KEM_status_t (*encaps)(uint8_t *ciphertext, uint8_t *shared_secret,
                                const uint8_t *public_key);

    QUDO_KEM_status_t (*decaps)(uint8_t *shared_secret,
                                const uint8_t *ciphertext,
                                const uint8_t *secret_key);

#ifdef QUDO_FIPS_MODULE

    qudo_fips_ind_t fips_ind;
#endif

} QUDO_KEM;

QUDO_KEM_API QUDO_KEM_status_t QUDO_KEM_init(void);

QUDO_KEM_API void QUDO_KEM_cleanup(void);

QUDO_KEM_API int QUDO_KEM_is_initialized(void);

QUDO_KEM_API QUDO_KEM *QUDO_KEM_new(const char *algorithm_name);

QUDO_KEM_API QUDO_KEM *QUDO_KEM_new_by_level(QUDO_KEM_security_level_t level);

QUDO_KEM_API QUDO_KEM_status_t QUDO_KEM_keypair(const QUDO_KEM *kem,
                                                uint8_t *public_key,
                                                uint8_t *secret_key);

QUDO_KEM_API QUDO_KEM_status_t QUDO_KEM_keypair_derand(const QUDO_KEM *kem,
                                                       uint8_t *public_key,
                                                       uint8_t *secret_key,
                                                       uint8_t *seed_out,
                                                       size_t seed_out_len);

QUDO_KEM_API QUDO_KEM_status_t QUDO_KEM_keypair_from_seed(
    const QUDO_KEM *kem, uint8_t *public_key, uint8_t *secret_key,
    const uint8_t seed[QUDO_KEM_SEED_BYTES]);

QUDO_KEM_API QUDO_KEM_status_t QUDO_KEM_encaps(const QUDO_KEM *kem,
                                               uint8_t *ciphertext,
                                               uint8_t *shared_secret,
                                               const uint8_t *public_key);

QUDO_KEM_API QUDO_KEM_status_t QUDO_KEM_encaps_derand(
    const QUDO_KEM *kem, uint8_t *ciphertext, uint8_t *shared_secret,
    const uint8_t *public_key, const uint8_t randomness[32]);

QUDO_KEM_API QUDO_KEM_status_t QUDO_KEM_decaps(const QUDO_KEM *kem,
                                               uint8_t *shared_secret,
                                               const uint8_t *ciphertext,
                                               const uint8_t *secret_key);

QUDO_KEM_API void QUDO_KEM_free(QUDO_KEM *kem);

QUDO_KEM_API QUDO_KEM_status_t QUDO_KEM_check_pk(const QUDO_KEM *kem,
                                                 const uint8_t *public_key,
                                                 size_t pk_len);

QUDO_KEM_API QUDO_KEM_status_t QUDO_KEM_check_sk(const QUDO_KEM *kem,
                                                 const uint8_t *secret_key,
                                                 size_t sk_len);

QUDO_KEM_API QUDO_KEM_status_t QUDO_KEM_keypair_generate(
    QUDO_KEM_security_level_t level, uint8_t *public_key, uint8_t *secret_key);

QUDO_KEM_API QUDO_KEM_status_t
QUDO_KEM_encapsulate(QUDO_KEM_security_level_t level, uint8_t *ciphertext,
                     uint8_t *shared_secret, const uint8_t *public_key);

QUDO_KEM_API QUDO_KEM_status_t
QUDO_KEM_decapsulate(QUDO_KEM_security_level_t level, uint8_t *shared_secret,
                     const uint8_t *ciphertext, const uint8_t *secret_key);

QUDO_KEM_API size_t
QUDO_KEM_get_public_key_size(QUDO_KEM_security_level_t level);
QUDO_KEM_API size_t
QUDO_KEM_get_secret_key_size(QUDO_KEM_security_level_t level);
QUDO_KEM_API size_t
QUDO_KEM_get_ciphertext_size(QUDO_KEM_security_level_t level);
QUDO_KEM_API size_t
QUDO_KEM_get_shared_secret_size(QUDO_KEM_security_level_t level);

QUDO_KEM_API const char *
QUDO_KEM_get_algorithm_name(QUDO_KEM_security_level_t level);

QUDO_KEM_API QUDO_KEM_status_t QUDO_KEM_get_level_from_name(
    const char *name, QUDO_KEM_security_level_t *level);

QUDO_KEM_API const char *QUDO_KEM_get_version(void);

QUDO_KEM_API const char *QUDO_KEM_get_features(void);

QUDO_KEM_API const char *QUDO_KEM_get_platform(void);

QUDO_KEM_API const char *QUDO_KEM_get_architecture(void);

QUDO_KEM_API int QUDO_KEM_has_avx2(void);

QUDO_KEM_API int QUDO_KEM_has_neon(void);

QUDO_KEM_API int QUDO_KEM_get_cpu_count(void);

QUDO_KEM_API size_t QUDO_KEM_get_cache_line_size(void);

QUDO_KEM_API int QUDO_KEM_is_platform_supported(void);

QUDO_KEM_API void QUDO_KEM_print_system_info(void);

QUDO_KEM_API const char *QUDO_KEM_get_error_string(QUDO_KEM_status_t status);

QUDO_KEM_API const char **QUDO_KEM_list_algorithms(size_t *count);

QUDO_KEM_API int QUDO_KEM_is_algorithm_supported(const char *algorithm_name);

QUDO_KEM_API QUDO_KEM_status_t
QUDO_KEM_get_algorithm_info(const char *algorithm_name, const QUDO_KEM **kem);

QUDO_KEM_API QUDO_KEM_status_t
QUDO_KEM_export_public_key_der(const uint8_t *public_key, size_t public_key_len,
                               uint8_t *der_buffer, size_t *der_len);

QUDO_KEM_API QUDO_KEM_status_t
QUDO_KEM_import_public_key_der(const uint8_t *der_buffer, size_t der_len,
                               uint8_t *public_key, size_t *public_key_len);

QUDO_KEM_API QUDO_KEM_status_t
QUDO_KEM_export_public_key_pem(const uint8_t *public_key, size_t public_key_len,
                               char *pem_buffer, size_t *pem_len);

QUDO_KEM_API QUDO_KEM_status_t QUDO_KEM_import_public_key_pem(
    const char *pem_buffer, uint8_t *public_key, size_t *public_key_len);

#ifdef __cplusplus
}
#endif

#endif
