/* SPDX-License-Identifier: Apache-2.0 AND MIT */

#ifndef SLHDSA_CONFIG_H
#define SLHDSA_CONFIG_H

#include "slhdsa_types.h"
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define QUDO_SLHDSA_VERSION_MAJOR  1
#define QUDO_SLHDSA_VERSION_MINOR  0
#define QUDO_SLHDSA_VERSION_PATCH  0
#define QUDO_SLHDSA_VERSION_STRING "1.0.0"

#define QUDO_SLHDSA_alg_sha2_128s  "SLH-DSA-SHA2-128s"
#define QUDO_SLHDSA_alg_sha2_128f  "SLH-DSA-SHA2-128f"
#define QUDO_SLHDSA_alg_sha2_192s  "SLH-DSA-SHA2-192s"
#define QUDO_SLHDSA_alg_sha2_192f  "SLH-DSA-SHA2-192f"
#define QUDO_SLHDSA_alg_sha2_256s  "SLH-DSA-SHA2-256s"
#define QUDO_SLHDSA_alg_sha2_256f  "SLH-DSA-SHA2-256f"
#define QUDO_SLHDSA_alg_shake_128s "SLH-DSA-SHAKE-128s"
#define QUDO_SLHDSA_alg_shake_128f "SLH-DSA-SHAKE-128f"
#define QUDO_SLHDSA_alg_shake_192s "SLH-DSA-SHAKE-192s"
#define QUDO_SLHDSA_alg_shake_192f "SLH-DSA-SHAKE-192f"
#define QUDO_SLHDSA_alg_shake_256s "SLH-DSA-SHAKE-256s"
#define QUDO_SLHDSA_alg_shake_256f "SLH-DSA-SHAKE-256f"

#define SLH_DSA_SHA2_128S_PUBLIC_KEY_BYTES  32
#define SLH_DSA_SHA2_128S_SECRET_KEY_BYTES  64
#define SLH_DSA_SHA2_128S_SIGNATURE_BYTES   7856
#define SLH_DSA_SHAKE_128S_PUBLIC_KEY_BYTES 32
#define SLH_DSA_SHAKE_128S_SECRET_KEY_BYTES 64
#define SLH_DSA_SHAKE_128S_SIGNATURE_BYTES  7856

#define SLH_DSA_SHA2_128F_PUBLIC_KEY_BYTES  32
#define SLH_DSA_SHA2_128F_SECRET_KEY_BYTES  64
#define SLH_DSA_SHA2_128F_SIGNATURE_BYTES   17088
#define SLH_DSA_SHAKE_128F_PUBLIC_KEY_BYTES 32
#define SLH_DSA_SHAKE_128F_SECRET_KEY_BYTES 64
#define SLH_DSA_SHAKE_128F_SIGNATURE_BYTES  17088

#define SLH_DSA_SHA2_192S_PUBLIC_KEY_BYTES  48
#define SLH_DSA_SHA2_192S_SECRET_KEY_BYTES  96
#define SLH_DSA_SHA2_192S_SIGNATURE_BYTES   16224
#define SLH_DSA_SHAKE_192S_PUBLIC_KEY_BYTES 48
#define SLH_DSA_SHAKE_192S_SECRET_KEY_BYTES 96
#define SLH_DSA_SHAKE_192S_SIGNATURE_BYTES  16224

#define SLH_DSA_SHA2_192F_PUBLIC_KEY_BYTES  48
#define SLH_DSA_SHA2_192F_SECRET_KEY_BYTES  96
#define SLH_DSA_SHA2_192F_SIGNATURE_BYTES   35664
#define SLH_DSA_SHAKE_192F_PUBLIC_KEY_BYTES 48
#define SLH_DSA_SHAKE_192F_SECRET_KEY_BYTES 96
#define SLH_DSA_SHAKE_192F_SIGNATURE_BYTES  35664

#define SLH_DSA_SHA2_256S_PUBLIC_KEY_BYTES  64
#define SLH_DSA_SHA2_256S_SECRET_KEY_BYTES  128
#define SLH_DSA_SHA2_256S_SIGNATURE_BYTES   29792
#define SLH_DSA_SHAKE_256S_PUBLIC_KEY_BYTES 64
#define SLH_DSA_SHAKE_256S_SECRET_KEY_BYTES 128
#define SLH_DSA_SHAKE_256S_SIGNATURE_BYTES  29792

#define SLH_DSA_SHA2_256F_PUBLIC_KEY_BYTES  64
#define SLH_DSA_SHA2_256F_SECRET_KEY_BYTES  128
#define SLH_DSA_SHA2_256F_SIGNATURE_BYTES   49856
#define SLH_DSA_SHAKE_256F_PUBLIC_KEY_BYTES 64
#define SLH_DSA_SHAKE_256F_SECRET_KEY_BYTES 128
#define SLH_DSA_SHAKE_256F_SIGNATURE_BYTES  49856

#define SLH_DSA_MAX_PUBLIC_KEY_BYTES 64
#define SLH_DSA_MAX_SECRET_KEY_BYTES 128
#define SLH_DSA_MAX_SIGNATURE_BYTES  49856

QUDO_SLHDSA_API const char *
slhdsa_get_algorithm_name(QUDO_SLHDSA_parameter_set_t param_set);

QUDO_SLHDSA_API size_t
slhdsa_get_public_key_bytes(QUDO_SLHDSA_parameter_set_t param_set);

QUDO_SLHDSA_API size_t
slhdsa_get_secret_key_bytes(QUDO_SLHDSA_parameter_set_t param_set);

QUDO_SLHDSA_API size_t
slhdsa_get_signature_bytes(QUDO_SLHDSA_parameter_set_t param_set);

QUDO_SLHDSA_API int
slhdsa_get_nist_level(QUDO_SLHDSA_parameter_set_t param_set);

QUDO_SLHDSA_API QUDO_SLHDSA_parameter_set_t
slhdsa_get_parameter_set(const char *algorithm_name);

typedef struct slhdsa_config {
    int enable_sha2_128s;
    int enable_sha2_128f;
    int enable_sha2_192s;
    int enable_sha2_192f;
    int enable_sha2_256s;
    int enable_sha2_256f;
    int enable_shake_128s;
    int enable_shake_128f;
    int enable_shake_192s;
    int enable_shake_192f;
    int enable_shake_256s;
    int enable_shake_256f;

    int use_avx2;
    int use_neon;

    int secure_memory;

    int verbose;
    char log_file_path[256];
} slhdsa_config_t;

QUDO_SLHDSA_API slhdsa_config_t *QUDO_SLHDSA_config_default(void);
QUDO_SLHDSA_API slhdsa_config_t *
QUDO_SLHDSA_config_load(const char *config_file);
QUDO_SLHDSA_API int QUDO_SLHDSA_config_save(const slhdsa_config_t *config,
                                            const char *config_file);
QUDO_SLHDSA_API void QUDO_SLHDSA_config_free(slhdsa_config_t *config);
QUDO_SLHDSA_API int QUDO_SLHDSA_config_validate(const slhdsa_config_t *config);
QUDO_SLHDSA_API int QUDO_SLHDSA_config_apply(const slhdsa_config_t *config);

QUDO_SLHDSA_API void QUDO_SLHDSA_secure_zero(void *ptr, size_t len);
QUDO_SLHDSA_API void *QUDO_SLHDSA_secure_alloc(size_t size);
QUDO_SLHDSA_API void QUDO_SLHDSA_secure_free(void *ptr, size_t size);
QUDO_SLHDSA_API int
QUDO_SLHDSA_constant_time_compare(const void *a, const void *b, size_t len);
QUDO_SLHDSA_API void *QUDO_SLHDSA_aligned_alloc(size_t alignment, size_t size);
QUDO_SLHDSA_API void QUDO_SLHDSA_aligned_free(void *ptr);

QUDO_SLHDSA_API int QUDO_SLHDSA_randombytes_init(void);
QUDO_SLHDSA_API int QUDO_SLHDSA_randombytes(uint8_t *out, size_t outlen);
QUDO_SLHDSA_API void QUDO_SLHDSA_randombytes_cleanup(void);
QUDO_SLHDSA_API int QUDO_SLHDSA_randombytes_test(void);

#ifdef __cplusplus
}
#endif

#endif
