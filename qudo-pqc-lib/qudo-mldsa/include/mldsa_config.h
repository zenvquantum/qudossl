/* SPDX-License-Identifier: Apache-2.0 AND MIT */

#ifndef MLDSA_CONFIG_H
#define MLDSA_CONFIG_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stddef.h>
#include <stdint.h>

#include "mldsa_types.h"

#define QUDO_MLDSA_VERSION_MAJOR  1
#define QUDO_MLDSA_VERSION_MINOR  0
#define QUDO_MLDSA_VERSION_PATCH  0
#define QUDO_MLDSA_VERSION_STRING "1.0.0"

#define ML_DSA_44_PUBLIC_KEY_BYTES 1312
#define ML_DSA_44_SECRET_KEY_BYTES 2560
#define ML_DSA_44_SIGNATURE_BYTES  2420

#define ML_DSA_65_PUBLIC_KEY_BYTES 1952
#define ML_DSA_65_SECRET_KEY_BYTES 4032
#define ML_DSA_65_SIGNATURE_BYTES  3309

#define ML_DSA_87_PUBLIC_KEY_BYTES 2592
#define ML_DSA_87_SECRET_KEY_BYTES 4896
#define ML_DSA_87_SIGNATURE_BYTES  4627

#define ML_DSA_CONTEXT_MAX_BYTES 255

typedef struct mldsa_config {
    QUDO_MLDSA_security_level_t default_level;

    int enable_44;
    int enable_65;
    int enable_87;

    int use_avx2;
    int use_neon;
    int runtime_cpu_detect;

    int use_openssl;

    int constant_time;
    int secure_memory;
    int memory_lock;

    int deterministic;
    int enable_context;

    int verbose;
    int enable_logging;
    char log_file_path[256];

    int max_threads;
    int thread_safe;
} mldsa_config_t;

QUDO_MLDSA_API const mldsa_config_t *mldsa_get_default_config(void);

QUDO_MLDSA_API const char *mldsa_get_version(void);

QUDO_MLDSA_API const char *
mldsa_get_algorithm_name(QUDO_MLDSA_security_level_t level);

QUDO_MLDSA_API size_t
mldsa_get_public_key_bytes(QUDO_MLDSA_security_level_t level);

QUDO_MLDSA_API size_t
mldsa_get_secret_key_bytes(QUDO_MLDSA_security_level_t level);

QUDO_MLDSA_API size_t
mldsa_get_signature_bytes(QUDO_MLDSA_security_level_t level);

QUDO_MLDSA_API int QUDO_MLDSA_randombytes_init(void);

QUDO_MLDSA_API int QUDO_MLDSA_randombytes(uint8_t *out, size_t outlen);

QUDO_MLDSA_API void QUDO_MLDSA_randombytes_cleanup(void);

QUDO_MLDSA_API int QUDO_MLDSA_randombytes_test(void);

QUDO_MLDSA_API void QUDO_MLDSA_secure_zero(void *ptr, size_t len);

QUDO_MLDSA_API void *QUDO_MLDSA_secure_alloc(size_t size);

QUDO_MLDSA_API void QUDO_MLDSA_secure_free(void *ptr, size_t size);

QUDO_MLDSA_API int QUDO_MLDSA_constant_time_compare(const void *a,
                                                    const void *b, size_t len);

QUDO_MLDSA_API void *QUDO_MLDSA_aligned_alloc(size_t alignment, size_t size);

QUDO_MLDSA_API void QUDO_MLDSA_aligned_free(void *ptr);

QUDO_MLDSA_API mldsa_config_t *QUDO_MLDSA_config_default(void);

QUDO_MLDSA_API mldsa_config_t *QUDO_MLDSA_config_load(const char *config_file);

QUDO_MLDSA_API int QUDO_MLDSA_config_save(const mldsa_config_t *config,
                                          const char *config_file);

QUDO_MLDSA_API void QUDO_MLDSA_config_free(mldsa_config_t *config);

QUDO_MLDSA_API int QUDO_MLDSA_config_validate(const mldsa_config_t *config);

QUDO_MLDSA_API int QUDO_MLDSA_config_apply(const mldsa_config_t *config);

#ifdef __cplusplus
}
#endif

#endif
