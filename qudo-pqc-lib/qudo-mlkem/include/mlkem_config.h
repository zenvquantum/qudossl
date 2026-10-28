/* SPDX-License-Identifier: Apache-2.0 AND MIT */

#ifndef MLKEM_CONFIG_H
#define MLKEM_CONFIG_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stddef.h>
#include <stdint.h>

#include "mlkem_types.h"

#include "mlkem_auto_generated.h"

#define QUDO_KEM_VERSION_MAJOR  1
#define QUDO_KEM_VERSION_MINOR  0
#define QUDO_KEM_VERSION_PATCH  0
#define QUDO_KEM_VERSION_STRING "1.0.0"

#define QUDO_KEM_512_PUBLIC_KEY_BYTES    ML_KEM_512_PUBLIC_KEY_BYTES
#define QUDO_KEM_512_SECRET_KEY_BYTES    ML_KEM_512_SECRET_KEY_BYTES
#define QUDO_KEM_512_CIPHERTEXT_BYTES    ML_KEM_512_CIPHERTEXT_BYTES
#define QUDO_KEM_512_SHARED_SECRET_BYTES ML_KEM_512_SHARED_SECRET_BYTES

#define QUDO_KEM_768_PUBLIC_KEY_BYTES    ML_KEM_768_PUBLIC_KEY_BYTES
#define QUDO_KEM_768_SECRET_KEY_BYTES    ML_KEM_768_SECRET_KEY_BYTES
#define QUDO_KEM_768_CIPHERTEXT_BYTES    ML_KEM_768_CIPHERTEXT_BYTES
#define QUDO_KEM_768_SHARED_SECRET_BYTES ML_KEM_768_SHARED_SECRET_BYTES

#define QUDO_KEM_1024_PUBLIC_KEY_BYTES    ML_KEM_1024_PUBLIC_KEY_BYTES
#define QUDO_KEM_1024_SECRET_KEY_BYTES    ML_KEM_1024_SECRET_KEY_BYTES
#define QUDO_KEM_1024_CIPHERTEXT_BYTES    ML_KEM_1024_CIPHERTEXT_BYTES
#define QUDO_KEM_1024_SHARED_SECRET_BYTES ML_KEM_1024_SHARED_SECRET_BYTES

typedef struct mlkem_config {
    QUDO_KEM_security_level_t default_level;

    int enable_512;
    int enable_768;
    int enable_1024;

    int use_avx2;
    int use_neon;
    int use_rvv;

    int use_openssl;

    int runtime_cpu_detect;

    int replace_rsa;
    int hybrid_mode;

    int constant_time;
    int secure_memory;
    int memory_lock;

    int verbose;
    int log_to_file;
    char log_file_path[256];

    int max_threads;
    int thread_safe;
} QUDO_KEM_config_t;

QUDO_KEM_API int QUDO_KEM_randombytes_init(void);

QUDO_KEM_API int QUDO_KEM_randombytes(uint8_t *out, size_t outlen);

QUDO_KEM_API void QUDO_KEM_randombytes_cleanup(void);

QUDO_KEM_API int QUDO_KEM_randombytes_test(void);

QUDO_KEM_API void QUDO_KEM_secure_zero(void *ptr, size_t len);

QUDO_KEM_API void *QUDO_KEM_secure_alloc(size_t size);

QUDO_KEM_API void QUDO_KEM_secure_free(void *ptr, size_t size);

QUDO_KEM_API int QUDO_KEM_constant_time_compare(const void *a, const void *b,
                                                size_t len);

QUDO_KEM_API void QUDO_KEM_constant_time_select(void *result, const void *a,
                                                const void *b, size_t len,
                                                int condition);

QUDO_KEM_API void *QUDO_KEM_aligned_alloc(size_t alignment, size_t size);

QUDO_KEM_API void QUDO_KEM_aligned_free(void *ptr);

QUDO_KEM_API QUDO_KEM_config_t *QUDO_KEM_config_load(const char *config_file);

QUDO_KEM_API QUDO_KEM_config_t *QUDO_KEM_config_default(void);

QUDO_KEM_API int QUDO_KEM_config_save(const QUDO_KEM_config_t *config,
                                      const char *config_file);

QUDO_KEM_API void QUDO_KEM_config_free(QUDO_KEM_config_t *config);

QUDO_KEM_API int QUDO_KEM_config_validate(const QUDO_KEM_config_t *config);

QUDO_KEM_API int QUDO_KEM_config_apply(const QUDO_KEM_config_t *config);

#ifdef __cplusplus
}
#endif

#endif
