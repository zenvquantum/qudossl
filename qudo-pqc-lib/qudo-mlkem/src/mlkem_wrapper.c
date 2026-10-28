/* SPDX-License-Identifier: Apache-2.0 AND MIT */

#include "../include/mlkem_wrapper.h"
#include "../include/mlkem_config.h"
#include "../include/mlkem_error.h"
#include "../include/mlkem_native_all.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#if defined(_WIN32) || defined(_MSC_VER)
#    define strcasecmp  _stricmp
#    define strncasecmp _strnicmp
#else
#    include <strings.h>
#endif

#ifdef MLK_CONFIG_RUNTIME_DISPATCH
#    include "../mlkem-native/qudo_runtime_dispatch/cpu_features.h"

#    include "../include/mlkem_dispatch.h"

#endif

#ifdef QUDO_FIPS_MODULE
#    include "qudo_pqc.h"
#    define QUDO_FIPS_GATE_PTR()                    \
        do {                                        \
            if (!qudo_pqc_is_running_or_selftest()) \
                return NULL;                        \
        } while (0)
#    define QUDO_FIPS_GATE(err)                     \
        do {                                        \
            if (!qudo_pqc_is_running_or_selftest()) \
                return (err);                       \
        } while (0)

#    include "qudo_fips_rand.h"
#    include "qudo_pqc_audit.h"
#    include "qudo_pqc_platform.h"
#    define QUDO_FIPS_IND_CHECK(kem_ptr, err)                                  \
        do {                                                                   \
            if ((kem_ptr) != NULL && !qudo_fips_rand_is_ready()) {             \
                qudo_audit_log(QUDO_SEV_ERROR, QUDO_ERR_DRBG_NOT_SEEDED,       \
                               QUDO_AUDIT_COMP_INDICATOR, "DRBG not ready");   \
                return (err);                                                  \
            }                                                                  \
            if ((kem_ptr) != NULL) {                                           \
                qudo_fips_ind_t _ind;                                          \
                qudo_fips_ind_init(&_ind, qudo_fips_ind_get_default_strict()); \
                if (!qudo_pqc_check_security_level((kem_ptr)->algorithm_name,  \
                                                   &_ind))                     \
                    return (err);                                              \
            }                                                                  \
        } while (0)

#else
#    define QUDO_FIPS_GATE_PTR()              ((void)0)
#    define QUDO_FIPS_GATE(err)               ((void)0)
#    define QUDO_FIPS_IND_CHECK(kem_ptr, err) ((void)0)
#endif

#if defined(_MSC_VER)
#    include <intrin.h>
#    pragma intrinsic(_InterlockedCompareExchange)
static volatile long g_mlkem_init_state = 0;
#    define MLKEM_INIT_STORE(val) \
        (void)_InterlockedExchange(&g_mlkem_init_state, (val))
#    define MLKEM_INIT_LOAD() g_mlkem_init_state
#elif defined(__GNUC__) || defined(__clang__)
static volatile int g_mlkem_init_state = 0;
#    define MLKEM_INIT_STORE(val) \
        __atomic_store_n(&g_mlkem_init_state, (val), __ATOMIC_SEQ_CST)
#    define MLKEM_INIT_LOAD() \
        __atomic_load_n(&g_mlkem_init_state, __ATOMIC_SEQ_CST)
#else
static volatile int g_mlkem_init_state = 0;
#    define MLKEM_INIT_STORE(val) (g_mlkem_init_state = (val))
#    define MLKEM_INIT_LOAD()     g_mlkem_init_state
#endif

#if defined(_WIN32)
#    ifndef WIN32_LEAN_AND_MEAN
#        define WIN32_LEAN_AND_MEAN
#    endif
#    include <windows.h>
static SRWLOCK g_mlkem_init_lock = SRWLOCK_INIT;
#    define MLKEM_INIT_LOCK()   AcquireSRWLockExclusive(&g_mlkem_init_lock)
#    define MLKEM_INIT_UNLOCK() ReleaseSRWLockExclusive(&g_mlkem_init_lock)
#else
#    include <pthread.h>
static pthread_mutex_t g_mlkem_init_lock = PTHREAD_MUTEX_INITIALIZER;
#    define MLKEM_INIT_LOCK()   (void)pthread_mutex_lock(&g_mlkem_init_lock)
#    define MLKEM_INIT_UNLOCK() (void)pthread_mutex_unlock(&g_mlkem_init_lock)
#endif

QUDO_KEM_API QUDO_KEM_status_t QUDO_KEM_init(void)
{
    QUDO_KEM_status_t rc = QUDO_KEM_SUCCESS;

    if (MLKEM_INIT_LOAD() == 2)
        return QUDO_KEM_SUCCESS;

    MLKEM_INIT_LOCK();
    if (MLKEM_INIT_LOAD() == 2) {
        MLKEM_INIT_UNLOCK();
        return QUDO_KEM_SUCCESS;
    }

#ifdef MLK_CONFIG_RUNTIME_DISPATCH
    mlk_cpu_init();
#endif

    /* Math-only build: the caller supplies all randomness, so no platform
     * entropy source is initialised. */
#ifndef QUDO_PQC_MATH_ONLY
    if (QUDO_KEM_randombytes_init() != QUDO_KEM_SUCCESS
        || QUDO_KEM_randombytes_test() != QUDO_KEM_SUCCESS) {
        rc = QUDO_KEM_ERROR_RNG;
        MLKEM_INIT_UNLOCK();
        return rc;
    }
#endif
    MLKEM_INIT_STORE(2);
    MLKEM_INIT_UNLOCK();
    return rc;
}

QUDO_KEM_API void QUDO_KEM_cleanup(void)
{
    MLKEM_INIT_LOCK();
    if (MLKEM_INIT_LOAD() == 2) {
        QUDO_KEM_randombytes_cleanup();
        MLKEM_INIT_STORE(0);
    }
    MLKEM_INIT_UNLOCK();
}

QUDO_KEM_API int QUDO_KEM_is_initialized(void)
{
    return (MLKEM_INIT_LOAD() == 2);
}

static size_t get_public_key_size(QUDO_KEM_security_level_t level)
{
    switch (level) {
    case QUDO_KEM_512:
        return QUDO_KEM_mlkem_512_length_public_key;
    case QUDO_KEM_768:
        return QUDO_KEM_mlkem_768_length_public_key;
    case QUDO_KEM_1024:
        return QUDO_KEM_mlkem_1024_length_public_key;
    default:
        return 0;
    }
}

static size_t get_secret_key_size(QUDO_KEM_security_level_t level)
{
    switch (level) {
    case QUDO_KEM_512:
        return QUDO_KEM_mlkem_512_length_secret_key;
    case QUDO_KEM_768:
        return QUDO_KEM_mlkem_768_length_secret_key;
    case QUDO_KEM_1024:
        return QUDO_KEM_mlkem_1024_length_secret_key;
    default:
        return 0;
    }
}

static size_t get_ciphertext_size(QUDO_KEM_security_level_t level)
{
    switch (level) {
    case QUDO_KEM_512:
        return QUDO_KEM_mlkem_512_length_ciphertext;
    case QUDO_KEM_768:
        return QUDO_KEM_mlkem_768_length_ciphertext;
    case QUDO_KEM_1024:
        return QUDO_KEM_mlkem_1024_length_ciphertext;
    default:
        return 0;
    }
}

static QUDO_KEM_status_t qudo_mlkem_keypair_512(uint8_t *public_key,
                                                uint8_t *secret_key)
{
#ifdef MLK_CONFIG_RUNTIME_DISPATCH
    int rc;
#    ifdef QUDO_HAS_AVX2_VARIANT
    if (mlk_cpu_has_extension(MLK_CPU_EXT_AVX2)) {
        rc = mlkem_avx2512_keypair(public_key, secret_key);
    } else
#    endif
#    ifdef QUDO_HAS_NEON_VARIANT
        if (mlk_cpu_has_extension(MLK_CPU_EXT_NEON)) {
        rc = mlkem_neon512_keypair(public_key, secret_key);
    } else
#    endif
    {
        rc = mlkem_ref512_keypair(public_key, secret_key);
    }
#else
    int rc = mlkem512_keypair(public_key, secret_key);
#endif
    return (rc == 0) ? QUDO_KEM_SUCCESS : QUDO_KEM_ERROR_CRYPTO;
}

static QUDO_KEM_status_t qudo_mlkem_keypair_768(uint8_t *public_key,
                                                uint8_t *secret_key)
{
#ifdef MLK_CONFIG_RUNTIME_DISPATCH
    int rc;
#    ifdef QUDO_HAS_AVX2_VARIANT
    if (mlk_cpu_has_extension(MLK_CPU_EXT_AVX2)) {
        rc = mlkem_avx2768_keypair(public_key, secret_key);
    } else
#    endif
#    ifdef QUDO_HAS_NEON_VARIANT
        if (mlk_cpu_has_extension(MLK_CPU_EXT_NEON)) {
        rc = mlkem_neon768_keypair(public_key, secret_key);
    } else
#    endif
    {
        rc = mlkem_ref768_keypair(public_key, secret_key);
    }
#else
    int rc = mlkem768_keypair(public_key, secret_key);
#endif
    return (rc == 0) ? QUDO_KEM_SUCCESS : QUDO_KEM_ERROR_CRYPTO;
}

static QUDO_KEM_status_t qudo_mlkem_keypair_1024(uint8_t *public_key,
                                                 uint8_t *secret_key)
{
#ifdef MLK_CONFIG_RUNTIME_DISPATCH
    int rc;
#    ifdef QUDO_HAS_AVX2_VARIANT
    if (mlk_cpu_has_extension(MLK_CPU_EXT_AVX2)) {
        rc = mlkem_avx21024_keypair(public_key, secret_key);
    } else
#    endif
#    ifdef QUDO_HAS_NEON_VARIANT
        if (mlk_cpu_has_extension(MLK_CPU_EXT_NEON)) {
        rc = mlkem_neon1024_keypair(public_key, secret_key);
    } else
#    endif
    {
        rc = mlkem_ref1024_keypair(public_key, secret_key);
    }
#else
    int rc = mlkem1024_keypair(public_key, secret_key);
#endif
    return (rc == 0) ? QUDO_KEM_SUCCESS : QUDO_KEM_ERROR_CRYPTO;
}

static QUDO_KEM_status_t qudo_mlkem_keypair_derand_512(uint8_t *public_key,
                                                       uint8_t *secret_key,
                                                       uint8_t *seed_out)
{
    uint8_t seed[64];
    if (QUDO_KEM_randombytes(seed, 64) != QUDO_KEM_SUCCESS) {
        QUDO_KEM_secure_zero(seed, sizeof(seed));
        return QUDO_KEM_ERROR_RNG;
    }
#ifdef MLK_CONFIG_RUNTIME_DISPATCH
    int rc;
#    ifdef QUDO_HAS_AVX2_VARIANT
    if (mlk_cpu_has_extension(MLK_CPU_EXT_AVX2)) {
        rc = mlkem_avx2512_keypair_derand(public_key, secret_key, seed);
    } else
#    endif
#    ifdef QUDO_HAS_NEON_VARIANT
        if (mlk_cpu_has_extension(MLK_CPU_EXT_NEON)) {
        rc = mlkem_neon512_keypair_derand(public_key, secret_key, seed);
    } else
#    endif
    {
        rc = mlkem_ref512_keypair_derand(public_key, secret_key, seed);
    }
#else
    int rc = mlkem512_keypair_derand(public_key, secret_key, seed);
#endif
    if (rc == 0 && seed_out != NULL)
        memcpy(seed_out, seed, 64);
    QUDO_KEM_secure_zero(seed, sizeof(seed));
    return (rc == 0) ? QUDO_KEM_SUCCESS : QUDO_KEM_ERROR_CRYPTO;
}

static QUDO_KEM_status_t qudo_mlkem_keypair_derand_768(uint8_t *public_key,
                                                       uint8_t *secret_key,
                                                       uint8_t *seed_out)
{
    uint8_t seed[64];
    if (QUDO_KEM_randombytes(seed, 64) != QUDO_KEM_SUCCESS) {
        QUDO_KEM_secure_zero(seed, sizeof(seed));
        return QUDO_KEM_ERROR_RNG;
    }
#ifdef MLK_CONFIG_RUNTIME_DISPATCH
    int rc;
#    ifdef QUDO_HAS_AVX2_VARIANT
    if (mlk_cpu_has_extension(MLK_CPU_EXT_AVX2)) {
        rc = mlkem_avx2768_keypair_derand(public_key, secret_key, seed);
    } else
#    endif
#    ifdef QUDO_HAS_NEON_VARIANT
        if (mlk_cpu_has_extension(MLK_CPU_EXT_NEON)) {
        rc = mlkem_neon768_keypair_derand(public_key, secret_key, seed);
    } else
#    endif
    {
        rc = mlkem_ref768_keypair_derand(public_key, secret_key, seed);
    }
#else
    int rc = mlkem768_keypair_derand(public_key, secret_key, seed);
#endif
    if (rc == 0 && seed_out != NULL)
        memcpy(seed_out, seed, 64);
    QUDO_KEM_secure_zero(seed, sizeof(seed));
    return (rc == 0) ? QUDO_KEM_SUCCESS : QUDO_KEM_ERROR_CRYPTO;
}

static QUDO_KEM_status_t qudo_mlkem_keypair_derand_1024(uint8_t *public_key,
                                                        uint8_t *secret_key,
                                                        uint8_t *seed_out)
{
    uint8_t seed[64];
    if (QUDO_KEM_randombytes(seed, 64) != QUDO_KEM_SUCCESS) {
        QUDO_KEM_secure_zero(seed, sizeof(seed));
        return QUDO_KEM_ERROR_RNG;
    }
#ifdef MLK_CONFIG_RUNTIME_DISPATCH
    int rc;
#    ifdef QUDO_HAS_AVX2_VARIANT
    if (mlk_cpu_has_extension(MLK_CPU_EXT_AVX2)) {
        rc = mlkem_avx21024_keypair_derand(public_key, secret_key, seed);
    } else
#    endif
#    ifdef QUDO_HAS_NEON_VARIANT
        if (mlk_cpu_has_extension(MLK_CPU_EXT_NEON)) {
        rc = mlkem_neon1024_keypair_derand(public_key, secret_key, seed);
    } else
#    endif
    {
        rc = mlkem_ref1024_keypair_derand(public_key, secret_key, seed);
    }
#else
    int rc = mlkem1024_keypair_derand(public_key, secret_key, seed);
#endif
    if (rc == 0 && seed_out != NULL)
        memcpy(seed_out, seed, 64);
    QUDO_KEM_secure_zero(seed, sizeof(seed));
    return (rc == 0) ? QUDO_KEM_SUCCESS : QUDO_KEM_ERROR_CRYPTO;
}

static QUDO_KEM_status_t qudo_mlkem_keypair_from_seed_512(uint8_t *public_key,
                                                          uint8_t *secret_key,
                                                          const uint8_t *seed)
{
#ifdef MLK_CONFIG_RUNTIME_DISPATCH
    int rc;
#    ifdef QUDO_HAS_AVX2_VARIANT
    if (mlk_cpu_has_extension(MLK_CPU_EXT_AVX2)) {
        rc = mlkem_avx2512_keypair_derand(public_key, secret_key, seed);
    } else
#    endif
#    ifdef QUDO_HAS_NEON_VARIANT
        if (mlk_cpu_has_extension(MLK_CPU_EXT_NEON)) {
        rc = mlkem_neon512_keypair_derand(public_key, secret_key, seed);
    } else
#    endif
    {
        rc = mlkem_ref512_keypair_derand(public_key, secret_key, seed);
    }
#else
    int rc = mlkem512_keypair_derand(public_key, secret_key, seed);
#endif
    return (rc == 0) ? QUDO_KEM_SUCCESS : QUDO_KEM_ERROR_CRYPTO;
}

static QUDO_KEM_status_t qudo_mlkem_keypair_from_seed_768(uint8_t *public_key,
                                                          uint8_t *secret_key,
                                                          const uint8_t *seed)
{
#ifdef MLK_CONFIG_RUNTIME_DISPATCH
    int rc;
#    ifdef QUDO_HAS_AVX2_VARIANT
    if (mlk_cpu_has_extension(MLK_CPU_EXT_AVX2)) {
        rc = mlkem_avx2768_keypair_derand(public_key, secret_key, seed);
    } else
#    endif
#    ifdef QUDO_HAS_NEON_VARIANT
        if (mlk_cpu_has_extension(MLK_CPU_EXT_NEON)) {
        rc = mlkem_neon768_keypair_derand(public_key, secret_key, seed);
    } else
#    endif
    {
        rc = mlkem_ref768_keypair_derand(public_key, secret_key, seed);
    }
#else
    int rc = mlkem768_keypair_derand(public_key, secret_key, seed);
#endif
    return (rc == 0) ? QUDO_KEM_SUCCESS : QUDO_KEM_ERROR_CRYPTO;
}

static QUDO_KEM_status_t qudo_mlkem_keypair_from_seed_1024(uint8_t *public_key,
                                                           uint8_t *secret_key,
                                                           const uint8_t *seed)
{
#ifdef MLK_CONFIG_RUNTIME_DISPATCH
    int rc;
#    ifdef QUDO_HAS_AVX2_VARIANT
    if (mlk_cpu_has_extension(MLK_CPU_EXT_AVX2)) {
        rc = mlkem_avx21024_keypair_derand(public_key, secret_key, seed);
    } else
#    endif
#    ifdef QUDO_HAS_NEON_VARIANT
        if (mlk_cpu_has_extension(MLK_CPU_EXT_NEON)) {
        rc = mlkem_neon1024_keypair_derand(public_key, secret_key, seed);
    } else
#    endif
    {
        rc = mlkem_ref1024_keypair_derand(public_key, secret_key, seed);
    }
#else
    int rc = mlkem1024_keypair_derand(public_key, secret_key, seed);
#endif
    return (rc == 0) ? QUDO_KEM_SUCCESS : QUDO_KEM_ERROR_CRYPTO;
}

static QUDO_KEM_status_t qudo_mlkem_encaps_512(uint8_t *ciphertext,
                                               uint8_t *shared_secret,
                                               const uint8_t *public_key)
{
#ifdef MLK_CONFIG_RUNTIME_DISPATCH
    int rc;
#    ifdef QUDO_HAS_AVX2_VARIANT
    if (mlk_cpu_has_extension(MLK_CPU_EXT_AVX2)) {
        rc = mlkem_avx2512_enc(ciphertext, shared_secret, public_key);
    } else
#    endif
#    ifdef QUDO_HAS_NEON_VARIANT
        if (mlk_cpu_has_extension(MLK_CPU_EXT_NEON)) {
        rc = mlkem_neon512_enc(ciphertext, shared_secret, public_key);
    } else
#    endif
    {
        rc = mlkem_ref512_enc(ciphertext, shared_secret, public_key);
    }
#else
    int rc = mlkem512_enc(ciphertext, shared_secret, public_key);
#endif
    return (rc == 0) ? QUDO_KEM_SUCCESS : QUDO_KEM_ERROR_CRYPTO;
}

static QUDO_KEM_status_t qudo_mlkem_encaps_768(uint8_t *ciphertext,
                                               uint8_t *shared_secret,
                                               const uint8_t *public_key)
{
#ifdef MLK_CONFIG_RUNTIME_DISPATCH
    int rc;
#    ifdef QUDO_HAS_AVX2_VARIANT
    if (mlk_cpu_has_extension(MLK_CPU_EXT_AVX2)) {
        rc = mlkem_avx2768_enc(ciphertext, shared_secret, public_key);
    } else
#    endif
#    ifdef QUDO_HAS_NEON_VARIANT
        if (mlk_cpu_has_extension(MLK_CPU_EXT_NEON)) {
        rc = mlkem_neon768_enc(ciphertext, shared_secret, public_key);
    } else
#    endif
    {
        rc = mlkem_ref768_enc(ciphertext, shared_secret, public_key);
    }
#else
    int rc = mlkem768_enc(ciphertext, shared_secret, public_key);
#endif
    return (rc == 0) ? QUDO_KEM_SUCCESS : QUDO_KEM_ERROR_CRYPTO;
}

static QUDO_KEM_status_t qudo_mlkem_encaps_1024(uint8_t *ciphertext,
                                                uint8_t *shared_secret,
                                                const uint8_t *public_key)
{
#ifdef MLK_CONFIG_RUNTIME_DISPATCH
    int rc;
#    ifdef QUDO_HAS_AVX2_VARIANT
    if (mlk_cpu_has_extension(MLK_CPU_EXT_AVX2)) {
        rc = mlkem_avx21024_enc(ciphertext, shared_secret, public_key);
    } else
#    endif
#    ifdef QUDO_HAS_NEON_VARIANT
        if (mlk_cpu_has_extension(MLK_CPU_EXT_NEON)) {
        rc = mlkem_neon1024_enc(ciphertext, shared_secret, public_key);
    } else
#    endif
    {
        rc = mlkem_ref1024_enc(ciphertext, shared_secret, public_key);
    }
#else
    int rc = mlkem1024_enc(ciphertext, shared_secret, public_key);
#endif
    return (rc == 0) ? QUDO_KEM_SUCCESS : QUDO_KEM_ERROR_CRYPTO;
}

static QUDO_KEM_status_t qudo_mlkem_encaps_derand_512(uint8_t *ciphertext,
                                                      uint8_t *shared_secret,
                                                      const uint8_t *public_key,
                                                      const uint8_t *randomness)
{
#ifdef MLK_CONFIG_RUNTIME_DISPATCH
    int rc;
#    ifdef QUDO_HAS_AVX2_VARIANT
    if (mlk_cpu_has_extension(MLK_CPU_EXT_AVX2)) {
        rc = mlkem_avx2512_enc_derand(ciphertext, shared_secret, public_key,
                                      randomness);
    } else
#    endif
#    ifdef QUDO_HAS_NEON_VARIANT
        if (mlk_cpu_has_extension(MLK_CPU_EXT_NEON)) {
        rc = mlkem_neon512_enc_derand(ciphertext, shared_secret, public_key,
                                      randomness);
    } else
#    endif
    {
        rc = mlkem_ref512_enc_derand(ciphertext, shared_secret, public_key,
                                     randomness);
    }
#else
    int rc = mlkem512_enc_derand(ciphertext, shared_secret, public_key,
                                 randomness);
#endif
    return (rc == 0) ? QUDO_KEM_SUCCESS : QUDO_KEM_ERROR_CRYPTO;
}

static QUDO_KEM_status_t qudo_mlkem_encaps_derand_768(uint8_t *ciphertext,
                                                      uint8_t *shared_secret,
                                                      const uint8_t *public_key,
                                                      const uint8_t *randomness)
{
#ifdef MLK_CONFIG_RUNTIME_DISPATCH
    int rc;
#    ifdef QUDO_HAS_AVX2_VARIANT
    if (mlk_cpu_has_extension(MLK_CPU_EXT_AVX2)) {
        rc = mlkem_avx2768_enc_derand(ciphertext, shared_secret, public_key,
                                      randomness);
    } else
#    endif
#    ifdef QUDO_HAS_NEON_VARIANT
        if (mlk_cpu_has_extension(MLK_CPU_EXT_NEON)) {
        rc = mlkem_neon768_enc_derand(ciphertext, shared_secret, public_key,
                                      randomness);
    } else
#    endif
    {
        rc = mlkem_ref768_enc_derand(ciphertext, shared_secret, public_key,
                                     randomness);
    }
#else
    int rc = mlkem768_enc_derand(ciphertext, shared_secret, public_key,
                                 randomness);
#endif
    return (rc == 0) ? QUDO_KEM_SUCCESS : QUDO_KEM_ERROR_CRYPTO;
}

static QUDO_KEM_status_t
qudo_mlkem_encaps_derand_1024(uint8_t *ciphertext, uint8_t *shared_secret,
                              const uint8_t *public_key,
                              const uint8_t *randomness)
{
#ifdef MLK_CONFIG_RUNTIME_DISPATCH
    int rc;
#    ifdef QUDO_HAS_AVX2_VARIANT
    if (mlk_cpu_has_extension(MLK_CPU_EXT_AVX2)) {
        rc = mlkem_avx21024_enc_derand(ciphertext, shared_secret, public_key,
                                       randomness);
    } else
#    endif
#    ifdef QUDO_HAS_NEON_VARIANT
        if (mlk_cpu_has_extension(MLK_CPU_EXT_NEON)) {
        rc = mlkem_neon1024_enc_derand(ciphertext, shared_secret, public_key,
                                       randomness);
    } else
#    endif
    {
        rc = mlkem_ref1024_enc_derand(ciphertext, shared_secret, public_key,
                                      randomness);
    }
#else
    int rc = mlkem1024_enc_derand(ciphertext, shared_secret, public_key,
                                  randomness);
#endif
    return (rc == 0) ? QUDO_KEM_SUCCESS : QUDO_KEM_ERROR_CRYPTO;
}

static QUDO_KEM_status_t qudo_mlkem_decaps_512(uint8_t *shared_secret,
                                               const uint8_t *ciphertext,
                                               const uint8_t *secret_key)
{
#ifdef MLK_CONFIG_RUNTIME_DISPATCH
    int rc;
#    ifdef QUDO_HAS_AVX2_VARIANT
    if (mlk_cpu_has_extension(MLK_CPU_EXT_AVX2)) {
        rc = mlkem_avx2512_dec(shared_secret, ciphertext, secret_key);
    } else
#    endif
#    ifdef QUDO_HAS_NEON_VARIANT
        if (mlk_cpu_has_extension(MLK_CPU_EXT_NEON)) {
        rc = mlkem_neon512_dec(shared_secret, ciphertext, secret_key);
    } else
#    endif
    {
        rc = mlkem_ref512_dec(shared_secret, ciphertext, secret_key);
    }
#else
    int rc = mlkem512_dec(shared_secret, ciphertext, secret_key);
#endif
    return (rc == 0) ? QUDO_KEM_SUCCESS : QUDO_KEM_ERROR_CRYPTO;
}

static QUDO_KEM_status_t qudo_mlkem_decaps_768(uint8_t *shared_secret,
                                               const uint8_t *ciphertext,
                                               const uint8_t *secret_key)
{
#ifdef MLK_CONFIG_RUNTIME_DISPATCH
    int rc;
#    ifdef QUDO_HAS_AVX2_VARIANT
    if (mlk_cpu_has_extension(MLK_CPU_EXT_AVX2)) {
        rc = mlkem_avx2768_dec(shared_secret, ciphertext, secret_key);
    } else
#    endif
#    ifdef QUDO_HAS_NEON_VARIANT
        if (mlk_cpu_has_extension(MLK_CPU_EXT_NEON)) {
        rc = mlkem_neon768_dec(shared_secret, ciphertext, secret_key);
    } else
#    endif
    {
        rc = mlkem_ref768_dec(shared_secret, ciphertext, secret_key);
    }
#else
    int rc = mlkem768_dec(shared_secret, ciphertext, secret_key);
#endif
    return (rc == 0) ? QUDO_KEM_SUCCESS : QUDO_KEM_ERROR_CRYPTO;
}

static QUDO_KEM_status_t qudo_mlkem_decaps_1024(uint8_t *shared_secret,
                                                const uint8_t *ciphertext,
                                                const uint8_t *secret_key)
{
#ifdef MLK_CONFIG_RUNTIME_DISPATCH
    int rc;
#    ifdef QUDO_HAS_AVX2_VARIANT
    if (mlk_cpu_has_extension(MLK_CPU_EXT_AVX2)) {
        rc = mlkem_avx21024_dec(shared_secret, ciphertext, secret_key);
    } else
#    endif
#    ifdef QUDO_HAS_NEON_VARIANT
        if (mlk_cpu_has_extension(MLK_CPU_EXT_NEON)) {
        rc = mlkem_neon1024_dec(shared_secret, ciphertext, secret_key);
    } else
#    endif
    {
        rc = mlkem_ref1024_dec(shared_secret, ciphertext, secret_key);
    }
#else
    int rc = mlkem1024_dec(shared_secret, ciphertext, secret_key);
#endif
    return (rc == 0) ? QUDO_KEM_SUCCESS : QUDO_KEM_ERROR_CRYPTO;
}

static int qudo_mlkem_check_pk_512(const uint8_t *pk)
{
#ifdef MLK_CONFIG_RUNTIME_DISPATCH
#    ifdef QUDO_HAS_AVX2_VARIANT
    if (mlk_cpu_has_extension(MLK_CPU_EXT_AVX2))
        return mlkem_avx2512_check_pk(pk);
#    endif
#    ifdef QUDO_HAS_NEON_VARIANT
    if (mlk_cpu_has_extension(MLK_CPU_EXT_NEON))
        return mlkem_neon512_check_pk(pk);
#    endif
    return mlkem_ref512_check_pk(pk);
#else
    return mlkem512_check_pk(pk);
#endif
}

static int qudo_mlkem_check_pk_768(const uint8_t *pk)
{
#ifdef MLK_CONFIG_RUNTIME_DISPATCH
#    ifdef QUDO_HAS_AVX2_VARIANT
    if (mlk_cpu_has_extension(MLK_CPU_EXT_AVX2))
        return mlkem_avx2768_check_pk(pk);
#    endif
#    ifdef QUDO_HAS_NEON_VARIANT
    if (mlk_cpu_has_extension(MLK_CPU_EXT_NEON))
        return mlkem_neon768_check_pk(pk);
#    endif
    return mlkem_ref768_check_pk(pk);
#else
    return mlkem768_check_pk(pk);
#endif
}

static int qudo_mlkem_check_pk_1024(const uint8_t *pk)
{
#ifdef MLK_CONFIG_RUNTIME_DISPATCH
#    ifdef QUDO_HAS_AVX2_VARIANT
    if (mlk_cpu_has_extension(MLK_CPU_EXT_AVX2))
        return mlkem_avx21024_check_pk(pk);
#    endif
#    ifdef QUDO_HAS_NEON_VARIANT
    if (mlk_cpu_has_extension(MLK_CPU_EXT_NEON))
        return mlkem_neon1024_check_pk(pk);
#    endif
    return mlkem_ref1024_check_pk(pk);
#else
    return mlkem1024_check_pk(pk);
#endif
}

static int qudo_mlkem_check_sk_512(const uint8_t *sk)
{
#ifdef MLK_CONFIG_RUNTIME_DISPATCH
#    ifdef QUDO_HAS_AVX2_VARIANT
    if (mlk_cpu_has_extension(MLK_CPU_EXT_AVX2))
        return mlkem_avx2512_check_sk(sk);
#    endif
#    ifdef QUDO_HAS_NEON_VARIANT
    if (mlk_cpu_has_extension(MLK_CPU_EXT_NEON))
        return mlkem_neon512_check_sk(sk);
#    endif
    return mlkem_ref512_check_sk(sk);
#else
    return mlkem512_check_sk(sk);
#endif
}

static int qudo_mlkem_check_sk_768(const uint8_t *sk)
{
#ifdef MLK_CONFIG_RUNTIME_DISPATCH
#    ifdef QUDO_HAS_AVX2_VARIANT
    if (mlk_cpu_has_extension(MLK_CPU_EXT_AVX2))
        return mlkem_avx2768_check_sk(sk);
#    endif
#    ifdef QUDO_HAS_NEON_VARIANT
    if (mlk_cpu_has_extension(MLK_CPU_EXT_NEON))
        return mlkem_neon768_check_sk(sk);
#    endif
    return mlkem_ref768_check_sk(sk);
#else
    return mlkem768_check_sk(sk);
#endif
}

static int qudo_mlkem_check_sk_1024(const uint8_t *sk)
{
#ifdef MLK_CONFIG_RUNTIME_DISPATCH
#    ifdef QUDO_HAS_AVX2_VARIANT
    if (mlk_cpu_has_extension(MLK_CPU_EXT_AVX2))
        return mlkem_avx21024_check_sk(sk);
#    endif
#    ifdef QUDO_HAS_NEON_VARIANT
    if (mlk_cpu_has_extension(MLK_CPU_EXT_NEON))
        return mlkem_neon1024_check_sk(sk);
#    endif
    return mlkem_ref1024_check_sk(sk);
#else
    return mlkem1024_check_sk(sk);
#endif
}

static QUDO_KEM mlkem_512_kem
    = {.algorithm_name = QUDO_KEM_alg_mlkem_512,
       .security_level = QUDO_KEM_512,
       .claimed_nist_level = 1,
       .ind_cca = true,
       .length_public_key = QUDO_KEM_mlkem_512_length_public_key,
       .length_secret_key = QUDO_KEM_mlkem_512_length_secret_key,
       .length_ciphertext = QUDO_KEM_mlkem_512_length_ciphertext,
       .length_shared_secret = QUDO_KEM_mlkem_512_length_shared_secret,
       .keypair = qudo_mlkem_keypair_512,
       .encaps = qudo_mlkem_encaps_512,
       .decaps = qudo_mlkem_decaps_512};

static QUDO_KEM mlkem_768_kem
    = {.algorithm_name = QUDO_KEM_alg_mlkem_768,
       .security_level = QUDO_KEM_768,
       .claimed_nist_level = 3,
       .ind_cca = true,
       .length_public_key = QUDO_KEM_mlkem_768_length_public_key,
       .length_secret_key = QUDO_KEM_mlkem_768_length_secret_key,
       .length_ciphertext = QUDO_KEM_mlkem_768_length_ciphertext,
       .length_shared_secret = QUDO_KEM_mlkem_768_length_shared_secret,
       .keypair = qudo_mlkem_keypair_768,
       .encaps = qudo_mlkem_encaps_768,
       .decaps = qudo_mlkem_decaps_768};

static QUDO_KEM mlkem_1024_kem
    = {.algorithm_name = QUDO_KEM_alg_mlkem_1024,
       .security_level = QUDO_KEM_1024,
       .claimed_nist_level = 5,
       .ind_cca = true,
       .length_public_key = QUDO_KEM_mlkem_1024_length_public_key,
       .length_secret_key = QUDO_KEM_mlkem_1024_length_secret_key,
       .length_ciphertext = QUDO_KEM_mlkem_1024_length_ciphertext,
       .length_shared_secret = QUDO_KEM_mlkem_1024_length_shared_secret,
       .keypair = qudo_mlkem_keypair_1024,
       .encaps = qudo_mlkem_encaps_1024,
       .decaps = qudo_mlkem_decaps_1024};

QUDO_KEM_API QUDO_KEM *QUDO_KEM_new(const char *algorithm_name)
{
    QUDO_FIPS_GATE_PTR();

    if (MLKEM_INIT_LOAD() != 2) {
        if (QUDO_KEM_init() != QUDO_KEM_SUCCESS) {
            return NULL;
        }
    }

    if (!algorithm_name) {
        return NULL;
    }

    const QUDO_KEM *template = NULL;

    if (strcasecmp(algorithm_name, QUDO_KEM_alg_mlkem_512) == 0) {
        template = &mlkem_512_kem;
    } else if (strcasecmp(algorithm_name, QUDO_KEM_alg_mlkem_768) == 0) {
        template = &mlkem_768_kem;
    } else if (strcasecmp(algorithm_name, QUDO_KEM_alg_mlkem_1024) == 0) {
        template = &mlkem_1024_kem;
    } else {
        return NULL;
    }

    QUDO_KEM *kem = (QUDO_KEM *)calloc(1, sizeof(QUDO_KEM));
    if (!kem) {
        return NULL;
    }

    memcpy(kem, template, sizeof(QUDO_KEM));

#ifdef QUDO_FIPS_MODULE
    qudo_fips_ind_init(&kem->fips_ind, qudo_fips_ind_get_default_strict());
#endif

    return kem;
}

QUDO_KEM_API QUDO_KEM *QUDO_KEM_new_by_level(QUDO_KEM_security_level_t level)
{
    QUDO_FIPS_GATE_PTR();

    if (MLKEM_INIT_LOAD() != 2) {
        if (QUDO_KEM_init() != QUDO_KEM_SUCCESS) {
            return NULL;
        }
    }

    const QUDO_KEM *template = NULL;

    switch (level) {
    case QUDO_KEM_512:
        template = &mlkem_512_kem;
        break;
    case QUDO_KEM_768:
        template = &mlkem_768_kem;
        break;
    case QUDO_KEM_1024:
        template = &mlkem_1024_kem;
        break;
    default:
        return NULL;
    }

    QUDO_KEM *kem = (QUDO_KEM *)calloc(1, sizeof(QUDO_KEM));
    if (!kem) {
        return NULL;
    }

    memcpy(kem, template, sizeof(QUDO_KEM));

#ifdef QUDO_FIPS_MODULE
    qudo_fips_ind_init(&kem->fips_ind, qudo_fips_ind_get_default_strict());
#endif

    return kem;
}

QUDO_KEM_API QUDO_KEM_status_t QUDO_KEM_keypair(const QUDO_KEM *kem,
                                                uint8_t *public_key,
                                                uint8_t *secret_key)
{
    QUDO_FIPS_GATE(QUDO_KEM_ERROR);
    QUDO_FIPS_IND_CHECK(kem, QUDO_KEM_ERROR);
    if (!kem || !public_key || !secret_key) {
        return QUDO_KEM_ERROR_INVALID_ARG;
    }
    {
        QUDO_KEM_status_t rc = kem->keypair(public_key, secret_key);
        if (rc != QUDO_KEM_SUCCESS)
            return rc;
#ifdef QUDO_FIPS_MODULE

        if (!qudo_pqc_is_self_testing()
            && !qudo_pqc_mlkem_pct(kem, public_key, secret_key, 0)) {

            QUDO_KEM_secure_zero(public_key, kem->length_public_key);
            QUDO_KEM_secure_zero(secret_key, kem->length_secret_key);
            qudo_pqc_set_error_state(QUDO_ST_TYPE_PCT);
            return QUDO_KEM_ERROR_CRYPTO;
        }
#endif
        return QUDO_KEM_SUCCESS;
    }
}

QUDO_KEM_API QUDO_KEM_status_t QUDO_KEM_keypair_derand(const QUDO_KEM *kem,
                                                       uint8_t *public_key,
                                                       uint8_t *secret_key,
                                                       uint8_t *seed_out,
                                                       size_t seed_out_len)
{
    QUDO_FIPS_GATE(QUDO_KEM_ERROR);
    QUDO_FIPS_IND_CHECK(kem, QUDO_KEM_ERROR);
    if (!kem || !public_key || !secret_key) {
        return QUDO_KEM_ERROR_INVALID_ARG;
    }

    if (seed_out != NULL && seed_out_len < QUDO_KEM_SEED_BYTES) {
        return QUDO_KEM_ERROR_BUFFER_TOO_SMALL;
    }

    {
        QUDO_KEM_status_t rc;
        uint8_t seed_scratch[QUDO_KEM_SEED_BYTES];
        uint8_t *seed_target = seed_out != NULL ? seed_out : seed_scratch;
        switch (kem->security_level) {
        case QUDO_KEM_512:
            rc = qudo_mlkem_keypair_derand_512(public_key, secret_key,
                                               seed_target);
            break;
        case QUDO_KEM_768:
            rc = qudo_mlkem_keypair_derand_768(public_key, secret_key,
                                               seed_target);
            break;
        case QUDO_KEM_1024:
            rc = qudo_mlkem_keypair_derand_1024(public_key, secret_key,
                                                seed_target);
            break;
        default:
            QUDO_KEM_secure_zero(seed_scratch, sizeof(seed_scratch));
            return QUDO_KEM_ERROR_INVALID_ARG;
        }

        if (seed_out == NULL) {
            QUDO_KEM_secure_zero(seed_scratch, sizeof(seed_scratch));
        }
        if (rc != QUDO_KEM_SUCCESS)
            return rc;
#ifdef QUDO_FIPS_MODULE

        if (!qudo_pqc_is_self_testing()
            && !qudo_pqc_mlkem_pct(kem, public_key, secret_key, 0)) {

            QUDO_KEM_secure_zero(public_key, kem->length_public_key);
            QUDO_KEM_secure_zero(secret_key, kem->length_secret_key);
            qudo_pqc_set_error_state(QUDO_ST_TYPE_PCT);
            return QUDO_KEM_ERROR_CRYPTO;
        }
#endif
        return QUDO_KEM_SUCCESS;
    }
}

QUDO_KEM_API QUDO_KEM_status_t QUDO_KEM_keypair_from_seed(
    const QUDO_KEM *kem, uint8_t *public_key, uint8_t *secret_key,
    const uint8_t seed[QUDO_KEM_SEED_BYTES])
{
    QUDO_FIPS_GATE(QUDO_KEM_ERROR);
    QUDO_FIPS_IND_CHECK(kem, QUDO_KEM_ERROR);
    if (!kem || !public_key || !secret_key || !seed) {
        return QUDO_KEM_ERROR_INVALID_ARG;
    }

    {
        QUDO_KEM_status_t rc;
        switch (kem->security_level) {
        case QUDO_KEM_512:
            rc = qudo_mlkem_keypair_from_seed_512(public_key, secret_key, seed);
            break;
        case QUDO_KEM_768:
            rc = qudo_mlkem_keypair_from_seed_768(public_key, secret_key, seed);
            break;
        case QUDO_KEM_1024:
            rc = qudo_mlkem_keypair_from_seed_1024(public_key, secret_key,
                                                   seed);
            break;
        default:
            return QUDO_KEM_ERROR_INVALID_ARG;
        }
        if (rc != QUDO_KEM_SUCCESS)
            return rc;
#ifdef QUDO_FIPS_MODULE

        if (!qudo_pqc_is_self_testing()
            && !qudo_pqc_mlkem_pct(kem, public_key, secret_key, 0)) {

            QUDO_KEM_secure_zero(public_key, kem->length_public_key);
            QUDO_KEM_secure_zero(secret_key, kem->length_secret_key);
            qudo_pqc_set_error_state(QUDO_ST_TYPE_PCT);
            return QUDO_KEM_ERROR_CRYPTO;
        }
#endif
        return QUDO_KEM_SUCCESS;
    }
}

QUDO_KEM_API QUDO_KEM_status_t QUDO_KEM_encaps(const QUDO_KEM *kem,
                                               uint8_t *ciphertext,
                                               uint8_t *shared_secret,
                                               const uint8_t *public_key)
{
    QUDO_FIPS_GATE(QUDO_KEM_ERROR);
    QUDO_FIPS_IND_CHECK(kem, QUDO_KEM_ERROR);
    if (!kem || !ciphertext || !shared_secret || !public_key) {
        return QUDO_KEM_ERROR_INVALID_ARG;
    }
    return kem->encaps(ciphertext, shared_secret, public_key);
}

QUDO_KEM_API QUDO_KEM_status_t QUDO_KEM_encaps_derand(
    const QUDO_KEM *kem, uint8_t *ciphertext, uint8_t *shared_secret,
    const uint8_t *public_key, const uint8_t randomness[32])
{
    QUDO_FIPS_GATE(QUDO_KEM_ERROR);
    QUDO_FIPS_IND_CHECK(kem, QUDO_KEM_ERROR);
    if (!kem || !ciphertext || !shared_secret || !public_key || !randomness) {
        return QUDO_KEM_ERROR_INVALID_ARG;
    }

    switch (kem->security_level) {
    case QUDO_KEM_512:
        return qudo_mlkem_encaps_derand_512(ciphertext, shared_secret,
                                            public_key, randomness);
    case QUDO_KEM_768:
        return qudo_mlkem_encaps_derand_768(ciphertext, shared_secret,
                                            public_key, randomness);
    case QUDO_KEM_1024:
        return qudo_mlkem_encaps_derand_1024(ciphertext, shared_secret,
                                             public_key, randomness);
    default:
        return QUDO_KEM_ERROR_INVALID_ARG;
    }
}

QUDO_KEM_API QUDO_KEM_status_t QUDO_KEM_decaps(const QUDO_KEM *kem,
                                               uint8_t *shared_secret,
                                               const uint8_t *ciphertext,
                                               const uint8_t *secret_key)
{
    QUDO_FIPS_GATE(QUDO_KEM_ERROR);
    QUDO_FIPS_IND_CHECK(kem, QUDO_KEM_ERROR);
    if (!kem || !shared_secret || !ciphertext || !secret_key) {
        return QUDO_KEM_ERROR_INVALID_ARG;
    }
    return kem->decaps(shared_secret, ciphertext, secret_key);
}

QUDO_KEM_API void QUDO_KEM_free(QUDO_KEM *kem)
{

    if (kem) {
        QUDO_KEM_secure_zero(kem, sizeof(QUDO_KEM));
        free(kem);
    }
}

QUDO_KEM_API QUDO_KEM_status_t QUDO_KEM_check_pk(const QUDO_KEM *kem,
                                                 const uint8_t *public_key,
                                                 size_t pk_len)
{
    if (!kem || !public_key)
        return QUDO_KEM_ERROR_INVALID_ARG;

    if (pk_len != kem->length_public_key)
        return QUDO_KEM_ERROR_VERIFY;

    int rc;
    switch (kem->security_level) {
    case QUDO_KEM_512:
        rc = qudo_mlkem_check_pk_512(public_key);
        break;
    case QUDO_KEM_768:
        rc = qudo_mlkem_check_pk_768(public_key);
        break;
    case QUDO_KEM_1024:
        rc = qudo_mlkem_check_pk_1024(public_key);
        break;
    default:
        return QUDO_KEM_ERROR_INVALID_ARG;
    }
    return (rc == 0) ? QUDO_KEM_SUCCESS : QUDO_KEM_ERROR_VERIFY;
}

QUDO_KEM_API QUDO_KEM_status_t QUDO_KEM_check_sk(const QUDO_KEM *kem,
                                                 const uint8_t *secret_key,
                                                 size_t sk_len)
{
    if (!kem || !secret_key)
        return QUDO_KEM_ERROR_INVALID_ARG;

    if (sk_len != kem->length_secret_key)
        return QUDO_KEM_ERROR_VERIFY;

    int rc;
    switch (kem->security_level) {
    case QUDO_KEM_512:
        rc = qudo_mlkem_check_sk_512(secret_key);
        break;
    case QUDO_KEM_768:
        rc = qudo_mlkem_check_sk_768(secret_key);
        break;
    case QUDO_KEM_1024:
        rc = qudo_mlkem_check_sk_1024(secret_key);
        break;
    default:
        return QUDO_KEM_ERROR_INVALID_ARG;
    }
    return (rc == 0) ? QUDO_KEM_SUCCESS : QUDO_KEM_ERROR_VERIFY;
}

QUDO_KEM_API QUDO_KEM_status_t QUDO_KEM_keypair_generate(
    QUDO_KEM_security_level_t level, uint8_t *public_key, uint8_t *secret_key)
{
    QUDO_FIPS_GATE(QUDO_KEM_ERROR);
    if (!public_key || !secret_key) {
        return QUDO_KEM_ERROR_INVALID_ARG;
    }

    if (level == QUDO_KEM_512) {
        return qudo_mlkem_keypair_512(public_key, secret_key);
    } else if (level == QUDO_KEM_768) {
        return qudo_mlkem_keypair_768(public_key, secret_key);
    } else if (level == QUDO_KEM_1024) {
        return qudo_mlkem_keypair_1024(public_key, secret_key);
    }
    return QUDO_KEM_ERROR_INVALID_ARG;
}

QUDO_KEM_API QUDO_KEM_status_t
QUDO_KEM_encapsulate(QUDO_KEM_security_level_t level, uint8_t *ciphertext,
                     uint8_t *shared_secret, const uint8_t *public_key)
{
    QUDO_FIPS_GATE(QUDO_KEM_ERROR);
    if (!ciphertext || !shared_secret || !public_key) {
        return QUDO_KEM_ERROR_INVALID_ARG;
    }

    if (level == QUDO_KEM_512) {
        return qudo_mlkem_encaps_512(ciphertext, shared_secret, public_key);
    } else if (level == QUDO_KEM_768) {
        return qudo_mlkem_encaps_768(ciphertext, shared_secret, public_key);
    } else if (level == QUDO_KEM_1024) {
        return qudo_mlkem_encaps_1024(ciphertext, shared_secret, public_key);
    }
    return QUDO_KEM_ERROR_INVALID_ARG;
}

QUDO_KEM_API QUDO_KEM_status_t
QUDO_KEM_decapsulate(QUDO_KEM_security_level_t level, uint8_t *shared_secret,
                     const uint8_t *ciphertext, const uint8_t *secret_key)
{
    QUDO_FIPS_GATE(QUDO_KEM_ERROR);
    if (!shared_secret || !ciphertext || !secret_key) {
        return QUDO_KEM_ERROR_INVALID_ARG;
    }

    if (level == QUDO_KEM_512) {
        return qudo_mlkem_decaps_512(shared_secret, ciphertext, secret_key);
    } else if (level == QUDO_KEM_768) {
        return qudo_mlkem_decaps_768(shared_secret, ciphertext, secret_key);
    } else if (level == QUDO_KEM_1024) {
        return qudo_mlkem_decaps_1024(shared_secret, ciphertext, secret_key);
    }
    return QUDO_KEM_ERROR_INVALID_ARG;
}

QUDO_KEM_API size_t
QUDO_KEM_get_public_key_size(QUDO_KEM_security_level_t level)
{
    return get_public_key_size(level);
}

QUDO_KEM_API size_t
QUDO_KEM_get_secret_key_size(QUDO_KEM_security_level_t level)
{
    return get_secret_key_size(level);
}

QUDO_KEM_API size_t
QUDO_KEM_get_ciphertext_size(QUDO_KEM_security_level_t level)
{
    return get_ciphertext_size(level);
}

QUDO_KEM_API size_t
QUDO_KEM_get_shared_secret_size(QUDO_KEM_security_level_t level)
{
    switch (level) {
    case QUDO_KEM_512:
    case QUDO_KEM_768:
    case QUDO_KEM_1024:
        return 32;
    default:
        return 0;
    }
}

QUDO_KEM_API const char *
QUDO_KEM_get_algorithm_name(QUDO_KEM_security_level_t level)
{
    switch (level) {
    case QUDO_KEM_512:
        return QUDO_KEM_alg_mlkem_512;
    case QUDO_KEM_768:
        return QUDO_KEM_alg_mlkem_768;
    case QUDO_KEM_1024:
        return QUDO_KEM_alg_mlkem_1024;
    default:
        return NULL;
    }
}

QUDO_KEM_API const char *QUDO_KEM_get_version(void)
{
    return QUDO_KEM_VERSION_STRING;
}

QUDO_KEM_API const char *QUDO_KEM_get_error_string(QUDO_KEM_status_t status)
{
    return QUDO_KEM_error_string(status);
}

QUDO_KEM_API const char **QUDO_KEM_list_algorithms(size_t *count)
{
    static const char *algorithms[]
        = {QUDO_KEM_alg_mlkem_512, QUDO_KEM_alg_mlkem_768,
           QUDO_KEM_alg_mlkem_1024, NULL};

    if (!count) {
        return NULL;
    }

    *count = 3;
    return algorithms;
}

QUDO_KEM_API int QUDO_KEM_is_algorithm_supported(const char *algorithm_name)
{
    if (!algorithm_name) {
        return 0;
    }

    if (strcasecmp(algorithm_name, QUDO_KEM_alg_mlkem_512) == 0
        || strcasecmp(algorithm_name, QUDO_KEM_alg_mlkem_768) == 0
        || strcasecmp(algorithm_name, QUDO_KEM_alg_mlkem_1024) == 0) {
        return 1;
    }

    return 0;
}

QUDO_KEM_API QUDO_KEM_status_t
QUDO_KEM_get_algorithm_info(const char *algorithm_name, const QUDO_KEM **kem)
{
    if (!algorithm_name || !kem) {
        return QUDO_KEM_ERROR_INVALID_ARG;
    }

    if (strcasecmp(algorithm_name, QUDO_KEM_alg_mlkem_512) == 0) {
        *kem = &mlkem_512_kem;
        return QUDO_KEM_SUCCESS;
    } else if (strcasecmp(algorithm_name, QUDO_KEM_alg_mlkem_768) == 0) {
        *kem = &mlkem_768_kem;
        return QUDO_KEM_SUCCESS;
    } else if (strcasecmp(algorithm_name, QUDO_KEM_alg_mlkem_1024) == 0) {
        *kem = &mlkem_1024_kem;
        return QUDO_KEM_SUCCESS;
    }

    *kem = NULL;
    return QUDO_KEM_ERROR_INVALID_ARG;
}

QUDO_KEM_API QUDO_KEM_status_t
QUDO_KEM_get_level_from_name(const char *name, QUDO_KEM_security_level_t *level)
{
    if (!name || !level) {
        return QUDO_KEM_ERROR_INVALID_ARG;
    }

    if (strcasecmp(name, QUDO_KEM_alg_mlkem_512) == 0) {
        *level = QUDO_KEM_512;
        return QUDO_KEM_SUCCESS;
    } else if (strcasecmp(name, QUDO_KEM_alg_mlkem_768) == 0) {
        *level = QUDO_KEM_768;
        return QUDO_KEM_SUCCESS;
    } else if (strcasecmp(name, QUDO_KEM_alg_mlkem_1024) == 0) {
        *level = QUDO_KEM_1024;
        return QUDO_KEM_SUCCESS;
    }

    return QUDO_KEM_ERROR_INVALID_ARG;
}
