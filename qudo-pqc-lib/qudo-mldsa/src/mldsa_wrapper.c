/* SPDX-License-Identifier: Apache-2.0 AND MIT */

#include "mldsa_wrapper.h"
#include "mldsa_error.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef MLDSA_DIST_BUILD
#    include "../mldsa-native/qudo_runtime_dispatch/cpu_features.h"
#endif

#include "mldsa_dispatch.h"

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
#    define QUDO_FIPS_IND_CHECK(sig_ptr, err)                                  \
        do {                                                                   \
            if ((sig_ptr) != NULL && !qudo_fips_rand_is_ready()) {             \
                qudo_audit_log(QUDO_SEV_ERROR, QUDO_ERR_DRBG_NOT_SEEDED,       \
                               QUDO_AUDIT_COMP_INDICATOR, "DRBG not ready");   \
                return (err);                                                  \
            }                                                                  \
            if ((sig_ptr) != NULL) {                                           \
                qudo_fips_ind_t _ind;                                          \
                qudo_fips_ind_init(&_ind, qudo_fips_ind_get_default_strict()); \
                if (!qudo_pqc_check_security_level((sig_ptr)->method_name,     \
                                                   &_ind))                     \
                    return (err);                                              \
            }                                                                  \
        } while (0)

#else
#    define QUDO_FIPS_GATE_PTR()              ((void)0)
#    define QUDO_FIPS_GATE(err)               ((void)0)
#    define QUDO_FIPS_IND_CHECK(sig_ptr, err) ((void)0)
#endif

typedef struct {
    void *variant_ctx;
    mldsa_config_t *config;
} mldsa_internal_ctx;

#if defined(_MSC_VER)
#    include <intrin.h>
#    pragma intrinsic(_InterlockedExchange)
static volatile long g_mldsa_init_state = 0;
#    define MLDSA_INIT_STORE(val) \
        (void)_InterlockedExchange(&g_mldsa_init_state, (val))
#    define MLDSA_INIT_LOAD() g_mldsa_init_state
#elif defined(__GNUC__) || defined(__clang__)
static volatile int g_mldsa_init_state = 0;
#    define MLDSA_INIT_STORE(val) \
        __atomic_store_n(&g_mldsa_init_state, (val), __ATOMIC_SEQ_CST)
#    define MLDSA_INIT_LOAD() \
        __atomic_load_n(&g_mldsa_init_state, __ATOMIC_SEQ_CST)
#else
static volatile int g_mldsa_init_state = 0;
#    define MLDSA_INIT_STORE(val) (g_mldsa_init_state = (val))
#    define MLDSA_INIT_LOAD()     g_mldsa_init_state
#endif

#if defined(_WIN32)
#    ifndef WIN32_LEAN_AND_MEAN
#        define WIN32_LEAN_AND_MEAN
#    endif
#    include <windows.h>
static SRWLOCK g_mldsa_init_lock = SRWLOCK_INIT;
#    define MLDSA_INIT_LOCK()   AcquireSRWLockExclusive(&g_mldsa_init_lock)
#    define MLDSA_INIT_UNLOCK() ReleaseSRWLockExclusive(&g_mldsa_init_lock)
#else
#    include <pthread.h>
static pthread_mutex_t g_mldsa_init_lock = PTHREAD_MUTEX_INITIALIZER;
#    define MLDSA_INIT_LOCK()   (void)pthread_mutex_lock(&g_mldsa_init_lock)
#    define MLDSA_INIT_UNLOCK() (void)pthread_mutex_unlock(&g_mldsa_init_lock)
#endif

static QUDO_MLDSA_status_t convert_mldsa_error(int ret)
{
    if (ret == 0)
        return QUDO_MLDSA_SUCCESS;
    if (ret == -2)
        return QUDO_MLDSA_ERROR_ALLOC;
    if (ret == -3)
        return QUDO_MLDSA_ERROR_RNG;
    return QUDO_MLDSA_ERROR;
}

static QUDO_MLDSA_security_level_t get_level_from_mldsa(const QUDO_MLDSA *sig)
{
    if (!sig || !sig->method_name)
        return (QUDO_MLDSA_security_level_t)0;
    if (strcmp(sig->method_name, "ML-DSA-44") == 0)
        return QUDO_MLDSA_44;
    if (strcmp(sig->method_name, "ML-DSA-65") == 0)
        return QUDO_MLDSA_65;
    if (strcmp(sig->method_name, "ML-DSA-87") == 0)
        return QUDO_MLDSA_87;
    return (QUDO_MLDSA_security_level_t)0;
}

static int (*mldsa44_keypair_impl)(uint8_t *pk, uint8_t *sk) = NULL;
static int (*mldsa44_sign_impl)(uint8_t *sig, size_t *siglen, const uint8_t *m,
                                size_t mlen, const uint8_t *ctx, size_t ctxlen,
                                const uint8_t *sk)
    = NULL;
static int (*mldsa44_verify_impl)(const uint8_t *sig, size_t siglen,
                                  const uint8_t *m, size_t mlen,
                                  const uint8_t *ctx, size_t ctxlen,
                                  const uint8_t *pk)
    = NULL;
static int (*mldsa44_sign_pre_hash_impl)(uint8_t *sig, size_t *siglen,
                                         const uint8_t *ph, size_t phlen,
                                         const uint8_t *ctx, size_t ctxlen,
                                         const uint8_t rnd[32],
                                         const uint8_t *sk, int hashalg)
    = NULL;
static int (*mldsa44_verify_pre_hash_impl)(const uint8_t *sig, size_t siglen,
                                           const uint8_t *ph, size_t phlen,
                                           const uint8_t *ctx, size_t ctxlen,
                                           const uint8_t *pk, int hashalg)
    = NULL;
static int (*mldsa44_keypair_internal_impl)(uint8_t *pk, uint8_t *sk,
                                            const uint8_t seed[32])
    = NULL;
static int (*mldsa44_sign_internal_impl)(uint8_t *sig, size_t *siglen,
                                         const uint8_t *m, size_t mlen,
                                         const uint8_t *pre, size_t prelen,
                                         const uint8_t rnd[32],
                                         const uint8_t *sk, int externalmu)
    = NULL;
static int (*mldsa44_sign_extmu_impl)(uint8_t *sig, size_t *siglen,
                                      const uint8_t mu[64], const uint8_t *sk)
    = NULL;
static int (*mldsa44_sign_concat_impl)(uint8_t *sm, size_t *smlen,
                                       const uint8_t *m, size_t mlen,
                                       const uint8_t *ctx, size_t ctxlen,
                                       const uint8_t *sk)
    = NULL;
static int (*mldsa44_verify_internal_impl)(const uint8_t *sig, size_t siglen,
                                           const uint8_t *m, size_t mlen,
                                           const uint8_t *pre, size_t prelen,
                                           const uint8_t *pk, int externalmu)
    = NULL;
static int (*mldsa44_verify_extmu_impl)(const uint8_t *sig, size_t siglen,
                                        const uint8_t mu[64], const uint8_t *pk)
    = NULL;
static int (*mldsa44_open_impl)(uint8_t *m, size_t *mlen, const uint8_t *sm,
                                size_t smlen, const uint8_t *ctx, size_t ctxlen,
                                const uint8_t *pk)
    = NULL;

static int (*mldsa65_keypair_impl)(uint8_t *pk, uint8_t *sk) = NULL;
static int (*mldsa65_sign_impl)(uint8_t *sig, size_t *siglen, const uint8_t *m,
                                size_t mlen, const uint8_t *ctx, size_t ctxlen,
                                const uint8_t *sk)
    = NULL;
static int (*mldsa65_verify_impl)(const uint8_t *sig, size_t siglen,
                                  const uint8_t *m, size_t mlen,
                                  const uint8_t *ctx, size_t ctxlen,
                                  const uint8_t *pk)
    = NULL;
static int (*mldsa65_sign_pre_hash_impl)(uint8_t *sig, size_t *siglen,
                                         const uint8_t *ph, size_t phlen,
                                         const uint8_t *ctx, size_t ctxlen,
                                         const uint8_t rnd[32],
                                         const uint8_t *sk, int hashalg)
    = NULL;
static int (*mldsa65_verify_pre_hash_impl)(const uint8_t *sig, size_t siglen,
                                           const uint8_t *ph, size_t phlen,
                                           const uint8_t *ctx, size_t ctxlen,
                                           const uint8_t *pk, int hashalg)
    = NULL;
static int (*mldsa65_keypair_internal_impl)(uint8_t *pk, uint8_t *sk,
                                            const uint8_t seed[32])
    = NULL;
static int (*mldsa65_sign_internal_impl)(uint8_t *sig, size_t *siglen,
                                         const uint8_t *m, size_t mlen,
                                         const uint8_t *pre, size_t prelen,
                                         const uint8_t rnd[32],
                                         const uint8_t *sk, int externalmu)
    = NULL;
static int (*mldsa65_sign_extmu_impl)(uint8_t *sig, size_t *siglen,
                                      const uint8_t mu[64], const uint8_t *sk)
    = NULL;
static int (*mldsa65_sign_concat_impl)(uint8_t *sm, size_t *smlen,
                                       const uint8_t *m, size_t mlen,
                                       const uint8_t *ctx, size_t ctxlen,
                                       const uint8_t *sk)
    = NULL;
static int (*mldsa65_verify_internal_impl)(const uint8_t *sig, size_t siglen,
                                           const uint8_t *m, size_t mlen,
                                           const uint8_t *pre, size_t prelen,
                                           const uint8_t *pk, int externalmu)
    = NULL;
static int (*mldsa65_verify_extmu_impl)(const uint8_t *sig, size_t siglen,
                                        const uint8_t mu[64], const uint8_t *pk)
    = NULL;
static int (*mldsa65_open_impl)(uint8_t *m, size_t *mlen, const uint8_t *sm,
                                size_t smlen, const uint8_t *ctx, size_t ctxlen,
                                const uint8_t *pk)
    = NULL;

static int (*mldsa87_keypair_impl)(uint8_t *pk, uint8_t *sk) = NULL;
static int (*mldsa87_sign_impl)(uint8_t *sig, size_t *siglen, const uint8_t *m,
                                size_t mlen, const uint8_t *ctx, size_t ctxlen,
                                const uint8_t *sk)
    = NULL;
static int (*mldsa87_verify_impl)(const uint8_t *sig, size_t siglen,
                                  const uint8_t *m, size_t mlen,
                                  const uint8_t *ctx, size_t ctxlen,
                                  const uint8_t *pk)
    = NULL;
static int (*mldsa87_sign_pre_hash_impl)(uint8_t *sig, size_t *siglen,
                                         const uint8_t *ph, size_t phlen,
                                         const uint8_t *ctx, size_t ctxlen,
                                         const uint8_t rnd[32],
                                         const uint8_t *sk, int hashalg)
    = NULL;
static int (*mldsa87_verify_pre_hash_impl)(const uint8_t *sig, size_t siglen,
                                           const uint8_t *ph, size_t phlen,
                                           const uint8_t *ctx, size_t ctxlen,
                                           const uint8_t *pk, int hashalg)
    = NULL;
static int (*mldsa87_keypair_internal_impl)(uint8_t *pk, uint8_t *sk,
                                            const uint8_t seed[32])
    = NULL;
static int (*mldsa87_sign_internal_impl)(uint8_t *sig, size_t *siglen,
                                         const uint8_t *m, size_t mlen,
                                         const uint8_t *pre, size_t prelen,
                                         const uint8_t rnd[32],
                                         const uint8_t *sk, int externalmu)
    = NULL;
static int (*mldsa87_sign_extmu_impl)(uint8_t *sig, size_t *siglen,
                                      const uint8_t mu[64], const uint8_t *sk)
    = NULL;
static int (*mldsa87_sign_concat_impl)(uint8_t *sm, size_t *smlen,
                                       const uint8_t *m, size_t mlen,
                                       const uint8_t *ctx, size_t ctxlen,
                                       const uint8_t *sk)
    = NULL;
static int (*mldsa87_verify_internal_impl)(const uint8_t *sig, size_t siglen,
                                           const uint8_t *m, size_t mlen,
                                           const uint8_t *pre, size_t prelen,
                                           const uint8_t *pk, int externalmu)
    = NULL;
static int (*mldsa87_verify_extmu_impl)(const uint8_t *sig, size_t siglen,
                                        const uint8_t mu[64], const uint8_t *pk)
    = NULL;
static int (*mldsa87_open_impl)(uint8_t *m, size_t *mlen, const uint8_t *sm,
                                size_t smlen, const uint8_t *ctx, size_t ctxlen,
                                const uint8_t *pk)
    = NULL;

QUDO_MLDSA_API QUDO_MLDSA_status_t QUDO_MLDSA_init(void)
{
    QUDO_MLDSA_status_t rc = QUDO_MLDSA_SUCCESS;

    if (MLDSA_INIT_LOAD() == 2)
        return QUDO_MLDSA_SUCCESS;

    MLDSA_INIT_LOCK();
    if (MLDSA_INIT_LOAD() == 2) {
        MLDSA_INIT_UNLOCK();
        return QUDO_MLDSA_SUCCESS;
    }

#ifdef MLDSA_DIST_BUILD
    mld_cpu_init();

#    ifdef QUDO_HAS_AVX2_VARIANT
    if (mld_cpu_has_extension(MLD_CPU_EXT_AVX2)) {
        mldsa44_keypair_impl = mldsa_avx244_keypair;
        mldsa44_sign_impl = mldsa_avx244_signature;
        mldsa44_verify_impl = mldsa_avx244_verify;
        mldsa44_sign_pre_hash_impl = mldsa_avx244_signature_pre_hash_internal;
        mldsa44_verify_pre_hash_impl = mldsa_avx244_verify_pre_hash_internal;
        mldsa44_keypair_internal_impl = mldsa_avx244_keypair_internal;
        mldsa44_sign_internal_impl = mldsa_avx244_signature_internal;
        mldsa44_sign_extmu_impl = mldsa_avx244_signature_extmu;
        mldsa44_sign_concat_impl = mldsa_avx244_sign;
        mldsa44_verify_internal_impl = mldsa_avx244_verify_internal;
        mldsa44_verify_extmu_impl = mldsa_avx244_verify_extmu;
        mldsa44_open_impl = mldsa_avx244_open;

        mldsa65_keypair_impl = mldsa_avx265_keypair;
        mldsa65_sign_impl = mldsa_avx265_signature;
        mldsa65_verify_impl = mldsa_avx265_verify;
        mldsa65_sign_pre_hash_impl = mldsa_avx265_signature_pre_hash_internal;
        mldsa65_verify_pre_hash_impl = mldsa_avx265_verify_pre_hash_internal;
        mldsa65_keypair_internal_impl = mldsa_avx265_keypair_internal;
        mldsa65_sign_internal_impl = mldsa_avx265_signature_internal;
        mldsa65_sign_extmu_impl = mldsa_avx265_signature_extmu;
        mldsa65_sign_concat_impl = mldsa_avx265_sign;
        mldsa65_verify_internal_impl = mldsa_avx265_verify_internal;
        mldsa65_verify_extmu_impl = mldsa_avx265_verify_extmu;
        mldsa65_open_impl = mldsa_avx265_open;

        mldsa87_keypair_impl = mldsa_avx287_keypair;
        mldsa87_sign_impl = mldsa_avx287_signature;
        mldsa87_verify_impl = mldsa_avx287_verify;
        mldsa87_sign_pre_hash_impl = mldsa_avx287_signature_pre_hash_internal;
        mldsa87_verify_pre_hash_impl = mldsa_avx287_verify_pre_hash_internal;
        mldsa87_keypair_internal_impl = mldsa_avx287_keypair_internal;
        mldsa87_sign_internal_impl = mldsa_avx287_signature_internal;
        mldsa87_sign_extmu_impl = mldsa_avx287_signature_extmu;
        mldsa87_sign_concat_impl = mldsa_avx287_sign;
        mldsa87_verify_internal_impl = mldsa_avx287_verify_internal;
        mldsa87_verify_extmu_impl = mldsa_avx287_verify_extmu;
        mldsa87_open_impl = mldsa_avx287_open;
    } else
#    endif
#    ifdef QUDO_HAS_NEON_VARIANT
        if (mld_cpu_has_extension(MLD_CPU_EXT_NEON)) {
        mldsa44_keypair_impl = mldsa_neon44_keypair;
        mldsa44_sign_impl = mldsa_neon44_signature;
        mldsa44_verify_impl = mldsa_neon44_verify;
        mldsa44_sign_pre_hash_impl = mldsa_neon44_signature_pre_hash_internal;
        mldsa44_verify_pre_hash_impl = mldsa_neon44_verify_pre_hash_internal;
        mldsa44_keypair_internal_impl = mldsa_neon44_keypair_internal;
        mldsa44_sign_internal_impl = mldsa_neon44_signature_internal;
        mldsa44_sign_extmu_impl = mldsa_neon44_signature_extmu;
        mldsa44_sign_concat_impl = mldsa_neon44_sign;
        mldsa44_verify_internal_impl = mldsa_neon44_verify_internal;
        mldsa44_verify_extmu_impl = mldsa_neon44_verify_extmu;
        mldsa44_open_impl = mldsa_neon44_open;

        mldsa65_keypair_impl = mldsa_neon65_keypair;
        mldsa65_sign_impl = mldsa_neon65_signature;
        mldsa65_verify_impl = mldsa_neon65_verify;
        mldsa65_sign_pre_hash_impl = mldsa_neon65_signature_pre_hash_internal;
        mldsa65_verify_pre_hash_impl = mldsa_neon65_verify_pre_hash_internal;
        mldsa65_keypair_internal_impl = mldsa_neon65_keypair_internal;
        mldsa65_sign_internal_impl = mldsa_neon65_signature_internal;
        mldsa65_sign_extmu_impl = mldsa_neon65_signature_extmu;
        mldsa65_sign_concat_impl = mldsa_neon65_sign;
        mldsa65_verify_internal_impl = mldsa_neon65_verify_internal;
        mldsa65_verify_extmu_impl = mldsa_neon65_verify_extmu;
        mldsa65_open_impl = mldsa_neon65_open;

        mldsa87_keypair_impl = mldsa_neon87_keypair;
        mldsa87_sign_impl = mldsa_neon87_signature;
        mldsa87_verify_impl = mldsa_neon87_verify;
        mldsa87_sign_pre_hash_impl = mldsa_neon87_signature_pre_hash_internal;
        mldsa87_verify_pre_hash_impl = mldsa_neon87_verify_pre_hash_internal;
        mldsa87_keypair_internal_impl = mldsa_neon87_keypair_internal;
        mldsa87_sign_internal_impl = mldsa_neon87_signature_internal;
        mldsa87_sign_extmu_impl = mldsa_neon87_signature_extmu;
        mldsa87_sign_concat_impl = mldsa_neon87_sign;
        mldsa87_verify_internal_impl = mldsa_neon87_verify_internal;
        mldsa87_verify_extmu_impl = mldsa_neon87_verify_extmu;
        mldsa87_open_impl = mldsa_neon87_open;
    } else
#    endif
    {
        mldsa44_keypair_impl = mldsa_ref44_keypair;
        mldsa44_sign_impl = mldsa_ref44_signature;
        mldsa44_verify_impl = mldsa_ref44_verify;
        mldsa44_sign_pre_hash_impl = mldsa_ref44_signature_pre_hash_internal;
        mldsa44_verify_pre_hash_impl = mldsa_ref44_verify_pre_hash_internal;
        mldsa44_keypair_internal_impl = mldsa_ref44_keypair_internal;
        mldsa44_sign_internal_impl = mldsa_ref44_signature_internal;
        mldsa44_sign_extmu_impl = mldsa_ref44_signature_extmu;
        mldsa44_sign_concat_impl = mldsa_ref44_sign;
        mldsa44_verify_internal_impl = mldsa_ref44_verify_internal;
        mldsa44_verify_extmu_impl = mldsa_ref44_verify_extmu;
        mldsa44_open_impl = mldsa_ref44_open;

        mldsa65_keypair_impl = mldsa_ref65_keypair;
        mldsa65_sign_impl = mldsa_ref65_signature;
        mldsa65_verify_impl = mldsa_ref65_verify;
        mldsa65_sign_pre_hash_impl = mldsa_ref65_signature_pre_hash_internal;
        mldsa65_verify_pre_hash_impl = mldsa_ref65_verify_pre_hash_internal;
        mldsa65_keypair_internal_impl = mldsa_ref65_keypair_internal;
        mldsa65_sign_internal_impl = mldsa_ref65_signature_internal;
        mldsa65_sign_extmu_impl = mldsa_ref65_signature_extmu;
        mldsa65_sign_concat_impl = mldsa_ref65_sign;
        mldsa65_verify_internal_impl = mldsa_ref65_verify_internal;
        mldsa65_verify_extmu_impl = mldsa_ref65_verify_extmu;
        mldsa65_open_impl = mldsa_ref65_open;

        mldsa87_keypair_impl = mldsa_ref87_keypair;
        mldsa87_sign_impl = mldsa_ref87_signature;
        mldsa87_verify_impl = mldsa_ref87_verify;
        mldsa87_sign_pre_hash_impl = mldsa_ref87_signature_pre_hash_internal;
        mldsa87_verify_pre_hash_impl = mldsa_ref87_verify_pre_hash_internal;
        mldsa87_keypair_internal_impl = mldsa_ref87_keypair_internal;
        mldsa87_sign_internal_impl = mldsa_ref87_signature_internal;
        mldsa87_sign_extmu_impl = mldsa_ref87_signature_extmu;
        mldsa87_sign_concat_impl = mldsa_ref87_sign;
        mldsa87_verify_internal_impl = mldsa_ref87_verify_internal;
        mldsa87_verify_extmu_impl = mldsa_ref87_verify_extmu;
        mldsa87_open_impl = mldsa_ref87_open;
    }
#else

    mldsa44_keypair_impl = mldsa44_keypair;
    mldsa44_sign_impl = mldsa44_signature;
    mldsa44_verify_impl = mldsa44_verify;
    mldsa44_sign_pre_hash_impl = mldsa44_signature_pre_hash_internal;
    mldsa44_verify_pre_hash_impl = mldsa44_verify_pre_hash_internal;
    mldsa44_keypair_internal_impl = mldsa44_keypair_internal;
    mldsa44_sign_internal_impl = mldsa44_signature_internal;
    mldsa44_sign_extmu_impl = mldsa44_signature_extmu;
    mldsa44_sign_concat_impl = mldsa44_sign;
    mldsa44_verify_internal_impl = mldsa44_verify_internal;
    mldsa44_verify_extmu_impl = mldsa44_verify_extmu;
    mldsa44_open_impl = mldsa44_open;

    mldsa65_keypair_impl = mldsa65_keypair;
    mldsa65_sign_impl = mldsa65_signature;
    mldsa65_verify_impl = mldsa65_verify;
    mldsa65_sign_pre_hash_impl = mldsa65_signature_pre_hash_internal;
    mldsa65_verify_pre_hash_impl = mldsa65_verify_pre_hash_internal;
    mldsa65_keypair_internal_impl = mldsa65_keypair_internal;
    mldsa65_sign_internal_impl = mldsa65_signature_internal;
    mldsa65_sign_extmu_impl = mldsa65_signature_extmu;
    mldsa65_sign_concat_impl = mldsa65_sign;
    mldsa65_verify_internal_impl = mldsa65_verify_internal;
    mldsa65_verify_extmu_impl = mldsa65_verify_extmu;
    mldsa65_open_impl = mldsa65_open;

    mldsa87_keypair_impl = mldsa87_keypair;
    mldsa87_sign_impl = mldsa87_signature;
    mldsa87_verify_impl = mldsa87_verify;
    mldsa87_sign_pre_hash_impl = mldsa87_signature_pre_hash_internal;
    mldsa87_verify_pre_hash_impl = mldsa87_verify_pre_hash_internal;
    mldsa87_keypair_internal_impl = mldsa87_keypair_internal;
    mldsa87_sign_internal_impl = mldsa87_signature_internal;
    mldsa87_sign_extmu_impl = mldsa87_signature_extmu;
    mldsa87_sign_concat_impl = mldsa87_sign;
    mldsa87_verify_internal_impl = mldsa87_verify_internal;
    mldsa87_verify_extmu_impl = mldsa87_verify_extmu;
    mldsa87_open_impl = mldsa87_open;
#endif

    /* Math-only build: the caller supplies all randomness, so no platform
     * entropy source is initialised. */
#ifndef QUDO_PQC_MATH_ONLY
    if (QUDO_MLDSA_randombytes_init() != QUDO_MLDSA_SUCCESS
        || QUDO_MLDSA_randombytes_test() != QUDO_MLDSA_SUCCESS) {
        rc = QUDO_MLDSA_ERROR_RNG;
        MLDSA_INIT_UNLOCK();
        return rc;
    }
#endif

    MLDSA_INIT_STORE(2);
    MLDSA_INIT_UNLOCK();
    return rc;
}

QUDO_MLDSA_API void QUDO_MLDSA_cleanup(void)
{
    MLDSA_INIT_LOCK();
    if (MLDSA_INIT_LOAD() == 2) {
        QUDO_MLDSA_randombytes_cleanup();
        MLDSA_INIT_STORE(0);
    }
    MLDSA_INIT_UNLOCK();
}

QUDO_MLDSA_API int QUDO_MLDSA_is_initialized(void)
{
    return (MLDSA_INIT_LOAD() == 2);
}

static QUDO_MLDSA_status_t internal_keypair_44(uint8_t *public_key,
                                               uint8_t *secret_key);
static QUDO_MLDSA_status_t internal_keypair_65(uint8_t *public_key,
                                               uint8_t *secret_key);
static QUDO_MLDSA_status_t internal_keypair_87(uint8_t *public_key,
                                               uint8_t *secret_key);
static QUDO_MLDSA_status_t internal_sign_44(uint8_t *sig, size_t *sig_len,
                                            const uint8_t *msg, size_t msg_len,
                                            const uint8_t *sk);
static QUDO_MLDSA_status_t internal_sign_65(uint8_t *sig, size_t *sig_len,
                                            const uint8_t *msg, size_t msg_len,
                                            const uint8_t *sk);
static QUDO_MLDSA_status_t internal_sign_87(uint8_t *sig, size_t *sig_len,
                                            const uint8_t *msg, size_t msg_len,
                                            const uint8_t *sk);
static QUDO_MLDSA_status_t
internal_verify_44(const uint8_t *msg, size_t msg_len, const uint8_t *sig,
                   size_t sig_len, const uint8_t *pk);
static QUDO_MLDSA_status_t
internal_verify_65(const uint8_t *msg, size_t msg_len, const uint8_t *sig,
                   size_t sig_len, const uint8_t *pk);
static QUDO_MLDSA_status_t
internal_verify_87(const uint8_t *msg, size_t msg_len, const uint8_t *sig,
                   size_t sig_len, const uint8_t *pk);

static QUDO_MLDSA_status_t
internal_sign_with_ctx_44(uint8_t *signature, size_t *signature_len,
                          const uint8_t *message, size_t message_len,
                          const uint8_t *context, size_t context_len,
                          const uint8_t *secret_key)
{
    int ret = mldsa44_sign_impl(signature, signature_len, message, message_len,
                                context, context_len, secret_key);
    return convert_mldsa_error(ret);
}

static QUDO_MLDSA_status_t
internal_sign_with_ctx_65(uint8_t *signature, size_t *signature_len,
                          const uint8_t *message, size_t message_len,
                          const uint8_t *context, size_t context_len,
                          const uint8_t *secret_key)
{
    int ret = mldsa65_sign_impl(signature, signature_len, message, message_len,
                                context, context_len, secret_key);
    return convert_mldsa_error(ret);
}

static QUDO_MLDSA_status_t
internal_sign_with_ctx_87(uint8_t *signature, size_t *signature_len,
                          const uint8_t *message, size_t message_len,
                          const uint8_t *context, size_t context_len,
                          const uint8_t *secret_key)
{
    int ret = mldsa87_sign_impl(signature, signature_len, message, message_len,
                                context, context_len, secret_key);
    return convert_mldsa_error(ret);
}

static QUDO_MLDSA_status_t
internal_verify_with_ctx_44(const uint8_t *message, size_t message_len,
                            const uint8_t *signature, size_t signature_len,
                            const uint8_t *context, size_t context_len,
                            const uint8_t *public_key)
{
    int ret
        = mldsa44_verify_impl(signature, signature_len, message, message_len,
                              context, context_len, public_key);
    return (ret == 0) ? QUDO_MLDSA_SUCCESS : QUDO_MLDSA_ERROR_VERIFY;
}

static QUDO_MLDSA_status_t
internal_verify_with_ctx_65(const uint8_t *message, size_t message_len,
                            const uint8_t *signature, size_t signature_len,
                            const uint8_t *context, size_t context_len,
                            const uint8_t *public_key)
{
    int ret
        = mldsa65_verify_impl(signature, signature_len, message, message_len,
                              context, context_len, public_key);
    return (ret == 0) ? QUDO_MLDSA_SUCCESS : QUDO_MLDSA_ERROR_VERIFY;
}

static QUDO_MLDSA_status_t
internal_verify_with_ctx_87(const uint8_t *message, size_t message_len,
                            const uint8_t *signature, size_t signature_len,
                            const uint8_t *context, size_t context_len,
                            const uint8_t *public_key)
{
    int ret
        = mldsa87_verify_impl(signature, signature_len, message, message_len,
                              context, context_len, public_key);
    return (ret == 0) ? QUDO_MLDSA_SUCCESS : QUDO_MLDSA_ERROR_VERIFY;
}

QUDO_MLDSA *QUDO_MLDSA_new(const char *algorithm)
{
    QUDO_FIPS_GATE_PTR();
    if (!algorithm)
        return NULL;

    if (MLDSA_INIT_LOAD() != 2) {
        if (QUDO_MLDSA_init() != QUDO_MLDSA_SUCCESS)
            return NULL;
    }

    QUDO_MLDSA *sig = (QUDO_MLDSA *)malloc(sizeof(QUDO_MLDSA));
    if (!sig)
        return NULL;

    sig->ctx = NULL;
    sig->config = NULL;

    if (strcmp(algorithm, "ML-DSA-44") == 0
        || strcmp(algorithm, "MLDSA44") == 0) {
        sig->method_name = "ML-DSA-44";
        sig->alg_version = "FIPS 204";
        sig->claimed_nist_level = 2;
        sig->security_bits = 128;
        sig->euf_cma = true;
        sig->suf_cma = true;
        sig->sig_with_ctx_support = true;
        sig->length_public_key = ML_DSA_44_PUBLIC_KEY_BYTES;
        sig->length_secret_key = ML_DSA_44_SECRET_KEY_BYTES;
        sig->length_signature = ML_DSA_44_SIGNATURE_BYTES;
        sig->keypair = internal_keypair_44;
        sig->sign = internal_sign_44;
        sig->sign_with_ctx_str = internal_sign_with_ctx_44;
        sig->verify = internal_verify_44;
        sig->verify_with_ctx_str = internal_verify_with_ctx_44;
    } else if (strcmp(algorithm, "ML-DSA-65") == 0
               || strcmp(algorithm, "MLDSA65") == 0) {
        sig->method_name = "ML-DSA-65";
        sig->alg_version = "FIPS 204";
        sig->claimed_nist_level = 3;
        sig->security_bits = 192;
        sig->euf_cma = true;
        sig->suf_cma = true;
        sig->sig_with_ctx_support = true;
        sig->length_public_key = ML_DSA_65_PUBLIC_KEY_BYTES;
        sig->length_secret_key = ML_DSA_65_SECRET_KEY_BYTES;
        sig->length_signature = ML_DSA_65_SIGNATURE_BYTES;
        sig->keypair = internal_keypair_65;
        sig->sign = internal_sign_65;
        sig->sign_with_ctx_str = internal_sign_with_ctx_65;
        sig->verify = internal_verify_65;
        sig->verify_with_ctx_str = internal_verify_with_ctx_65;
    } else if (strcmp(algorithm, "ML-DSA-87") == 0
               || strcmp(algorithm, "MLDSA87") == 0) {
        sig->method_name = "ML-DSA-87";
        sig->alg_version = "FIPS 204";
        sig->claimed_nist_level = 5;
        sig->security_bits = 256;
        sig->euf_cma = true;
        sig->suf_cma = true;
        sig->sig_with_ctx_support = true;
        sig->length_public_key = ML_DSA_87_PUBLIC_KEY_BYTES;
        sig->length_secret_key = ML_DSA_87_SECRET_KEY_BYTES;
        sig->length_signature = ML_DSA_87_SIGNATURE_BYTES;
        sig->keypair = internal_keypair_87;
        sig->sign = internal_sign_87;
        sig->sign_with_ctx_str = internal_sign_with_ctx_87;
        sig->verify = internal_verify_87;
        sig->verify_with_ctx_str = internal_verify_with_ctx_87;
    } else {
        free(sig);
        return NULL;
    }

#ifdef QUDO_FIPS_MODULE
    qudo_fips_ind_init(&sig->fips_ind, qudo_fips_ind_get_default_strict());
#endif

    return sig;
}

void QUDO_MLDSA_free(QUDO_MLDSA *sig)
{

    if (sig) {
        QUDO_MLDSA_secure_zero(sig, sizeof(QUDO_MLDSA));
        free(sig);
    }
}

QUDO_MLDSA_status_t QUDO_MLDSA_keypair(QUDO_MLDSA *sig, uint8_t *public_key,
                                       uint8_t *secret_key)
{
    QUDO_MLDSA_status_t rc;
    QUDO_FIPS_GATE(QUDO_MLDSA_ERROR);
    QUDO_FIPS_IND_CHECK(sig, QUDO_MLDSA_ERROR);
    if (!sig || !public_key || !secret_key) {
        return QUDO_MLDSA_ERROR_NULL_PTR;
    }

    switch (get_level_from_mldsa(sig)) {
    case QUDO_MLDSA_44:
        rc = QUDO_MLDSA_ML_DSA_44_keypair(public_key, secret_key);
        break;
    case QUDO_MLDSA_65:
        rc = QUDO_MLDSA_ML_DSA_65_keypair(public_key, secret_key);
        break;
    case QUDO_MLDSA_87:
        rc = QUDO_MLDSA_ML_DSA_87_keypair(public_key, secret_key);
        break;
    default:
        return QUDO_MLDSA_ERROR_INVALID_ARG;
    }
    if (rc != QUDO_MLDSA_SUCCESS)
        return rc;
#ifdef QUDO_FIPS_MODULE

    if (!qudo_pqc_is_self_testing()
        && !qudo_pqc_mldsa_pct(sig, public_key, secret_key)) {

        qudo_cleanse(public_key, sig->length_public_key);
        qudo_cleanse(secret_key, sig->length_secret_key);
        qudo_pqc_set_error_state(QUDO_ST_TYPE_PCT);
        return QUDO_MLDSA_ERROR_CRYPTO;
    }
#endif
    return QUDO_MLDSA_SUCCESS;
}

QUDO_MLDSA_status_t QUDO_MLDSA_sign(QUDO_MLDSA *sig, uint8_t *signature,
                                    size_t *signature_len,
                                    const uint8_t *message, size_t message_len,
                                    const uint8_t *secret_key)
{
    QUDO_FIPS_GATE(QUDO_MLDSA_ERROR);
    QUDO_FIPS_IND_CHECK(sig, QUDO_MLDSA_ERROR);

    if (!sig || !signature_len || !message || !secret_key) {
        return QUDO_MLDSA_ERROR_NULL_PTR;
    }

    return QUDO_MLDSA_sign_with_context(sig, signature, signature_len, message,
                                        message_len, NULL, 0, secret_key);
}

QUDO_MLDSA_status_t
QUDO_MLDSA_sign_with_context(QUDO_MLDSA *sig, uint8_t *signature,
                             size_t *signature_len, const uint8_t *message,
                             size_t message_len, const uint8_t *context,
                             size_t context_len, const uint8_t *secret_key)
{
    QUDO_FIPS_GATE(QUDO_MLDSA_ERROR);
    QUDO_FIPS_IND_CHECK(sig, QUDO_MLDSA_ERROR);

    if (!sig || !signature_len || !message || !secret_key) {
        return QUDO_MLDSA_ERROR_NULL_PTR;
    }

    if (!sig->sign_with_ctx_str) {
        return QUDO_MLDSA_ERROR_INVALID_ARG;
    }

    static const uint8_t empty_ctx = 0;
    if (context == NULL) {
        context = &empty_ctx;
        context_len = 0;
    }

    if (context_len > ML_DSA_CONTEXT_MAX_BYTES) {
        return QUDO_MLDSA_ERROR_INVALID_ARG;
    }

    size_t expected = sig->length_signature;
    if (signature == NULL) {
        *signature_len = expected;
        return QUDO_MLDSA_SUCCESS;
    }
    if (*signature_len < expected) {
        return QUDO_MLDSA_ERROR_BUFFER_TOO_SMALL;
    }

    memset(signature, 0, expected);

    QUDO_MLDSA_status_t rc
        = sig->sign_with_ctx_str(signature, signature_len, message, message_len,
                                 context, context_len, secret_key);
    if (rc == QUDO_MLDSA_SUCCESS) {
        *signature_len = expected;
    }
    return rc;
}

QUDO_MLDSA_status_t QUDO_MLDSA_verify(QUDO_MLDSA *sig, const uint8_t *signature,
                                      size_t signature_len,
                                      const uint8_t *message,
                                      size_t message_len,
                                      const uint8_t *public_key)
{
    QUDO_FIPS_GATE(QUDO_MLDSA_ERROR);
    QUDO_FIPS_IND_CHECK(sig, QUDO_MLDSA_ERROR);
    if (!sig || !signature || !message || !public_key) {
        return QUDO_MLDSA_ERROR_NULL_PTR;
    }

    if (signature_len != sig->length_signature) {
        return QUDO_MLDSA_ERROR_INVALID_SIGNATURE;
    }

    return QUDO_MLDSA_verify_with_context(sig, signature, signature_len,
                                          message, message_len, NULL, 0,
                                          public_key);
}

QUDO_MLDSA_status_t
QUDO_MLDSA_verify_with_context(QUDO_MLDSA *sig, const uint8_t *signature,
                               size_t signature_len, const uint8_t *message,
                               size_t message_len, const uint8_t *context,
                               size_t context_len, const uint8_t *public_key)
{
    QUDO_FIPS_GATE(QUDO_MLDSA_ERROR);
    QUDO_FIPS_IND_CHECK(sig, QUDO_MLDSA_ERROR);
    if (!sig || !signature || !message || !public_key) {
        return QUDO_MLDSA_ERROR_NULL_PTR;
    }

    if (signature_len != sig->length_signature) {
        return QUDO_MLDSA_ERROR_INVALID_SIGNATURE;
    }

    if (!sig->verify_with_ctx_str) {
        return QUDO_MLDSA_ERROR_INVALID_ARG;
    }

    static const uint8_t empty_ctx = 0;
    if (context == NULL) {
        context = &empty_ctx;
        context_len = 0;
    }

    if (context_len > ML_DSA_CONTEXT_MAX_BYTES) {
        return QUDO_MLDSA_ERROR_INVALID_ARG;
    }

    return sig->verify_with_ctx_str(message, message_len, signature,
                                    signature_len, context, context_len,
                                    public_key);
}

QUDO_MLDSA_status_t
QUDO_MLDSA_ML_DSA_44_keypair(uint8_t public_key[ML_DSA_44_PUBLIC_KEY_BYTES],
                             uint8_t secret_key[ML_DSA_44_SECRET_KEY_BYTES])
{
    QUDO_FIPS_GATE(QUDO_MLDSA_ERROR);
    if (!public_key || !secret_key) {
        return QUDO_MLDSA_ERROR_NULL_PTR;
    }

    int ret;
#ifdef MLDSA_DIST_BUILD
#    ifdef QUDO_HAS_AVX2_VARIANT
    if (mld_cpu_has_extension(MLD_CPU_EXT_AVX2)) {
        ret = mldsa_avx244_keypair(public_key, secret_key);
    } else
#    endif
#    ifdef QUDO_HAS_NEON_VARIANT
        if (mld_cpu_has_extension(MLD_CPU_EXT_NEON)) {
        ret = mldsa_neon44_keypair(public_key, secret_key);
    } else
#    endif
    {
        ret = mldsa_ref44_keypair(public_key, secret_key);
    }
#else
    ret = mldsa44_keypair(public_key, secret_key);
#endif
    return convert_mldsa_error(ret);
}

QUDO_MLDSA_status_t
QUDO_MLDSA_ML_DSA_44_sign(uint8_t *signature, size_t *signature_len,
                          const uint8_t *message, size_t message_len,
                          const uint8_t secret_key[ML_DSA_44_SECRET_KEY_BYTES])
{
    QUDO_FIPS_GATE(QUDO_MLDSA_ERROR);
    if (!signature || !signature_len || !message || !secret_key) {
        return QUDO_MLDSA_ERROR_NULL_PTR;
    }

    int ret;
#ifdef MLDSA_DIST_BUILD
#    ifdef QUDO_HAS_AVX2_VARIANT
    if (mld_cpu_has_extension(MLD_CPU_EXT_AVX2)) {
        ret = mldsa_avx244_signature(signature, signature_len, message,
                                     message_len, NULL, 0, secret_key);
    } else
#    endif
#    ifdef QUDO_HAS_NEON_VARIANT
        if (mld_cpu_has_extension(MLD_CPU_EXT_NEON)) {
        ret = mldsa_neon44_signature(signature, signature_len, message,
                                     message_len, NULL, 0, secret_key);
    } else
#    endif
    {
        ret = mldsa_ref44_signature(signature, signature_len, message,
                                    message_len, NULL, 0, secret_key);
    }
#else
    ret = mldsa44_signature(signature, signature_len, message, message_len,
                            NULL, 0, secret_key);
#endif
    return convert_mldsa_error(ret);
}

QUDO_MLDSA_status_t QUDO_MLDSA_ML_DSA_44_verify(
    const uint8_t *signature, size_t signature_len, const uint8_t *message,
    size_t message_len, const uint8_t public_key[ML_DSA_44_PUBLIC_KEY_BYTES])
{
    QUDO_FIPS_GATE(QUDO_MLDSA_ERROR);
    if (!signature || !message || !public_key) {
        return QUDO_MLDSA_ERROR_NULL_PTR;
    }

    int ret;
#ifdef MLDSA_DIST_BUILD
#    ifdef QUDO_HAS_AVX2_VARIANT
    if (mld_cpu_has_extension(MLD_CPU_EXT_AVX2)) {
        ret = mldsa_avx244_verify(signature, signature_len, message,
                                  message_len, NULL, 0, public_key);
    } else
#    endif
#    ifdef QUDO_HAS_NEON_VARIANT
        if (mld_cpu_has_extension(MLD_CPU_EXT_NEON)) {
        ret = mldsa_neon44_verify(signature, signature_len, message,
                                  message_len, NULL, 0, public_key);
    } else
#    endif
    {
        ret = mldsa_ref44_verify(signature, signature_len, message, message_len,
                                 NULL, 0, public_key);
    }
#else
    ret = mldsa44_verify(signature, signature_len, message, message_len, NULL,
                         0, public_key);
#endif
    return (ret == 0) ? QUDO_MLDSA_SUCCESS : QUDO_MLDSA_ERROR_VERIFY;
}

QUDO_MLDSA_status_t
QUDO_MLDSA_ML_DSA_65_keypair(uint8_t public_key[ML_DSA_65_PUBLIC_KEY_BYTES],
                             uint8_t secret_key[ML_DSA_65_SECRET_KEY_BYTES])
{
    QUDO_FIPS_GATE(QUDO_MLDSA_ERROR);
    if (!public_key || !secret_key) {
        return QUDO_MLDSA_ERROR_NULL_PTR;
    }

    int ret;
#ifdef MLDSA_DIST_BUILD
#    ifdef QUDO_HAS_AVX2_VARIANT
    if (mld_cpu_has_extension(MLD_CPU_EXT_AVX2)) {
        ret = mldsa_avx265_keypair(public_key, secret_key);
    } else
#    endif
#    ifdef QUDO_HAS_NEON_VARIANT
        if (mld_cpu_has_extension(MLD_CPU_EXT_NEON)) {
        ret = mldsa_neon65_keypair(public_key, secret_key);
    } else
#    endif
    {
        ret = mldsa_ref65_keypair(public_key, secret_key);
    }
#else
    ret = mldsa65_keypair(public_key, secret_key);
#endif
    return convert_mldsa_error(ret);
}

QUDO_MLDSA_status_t
QUDO_MLDSA_ML_DSA_65_sign(uint8_t *signature, size_t *signature_len,
                          const uint8_t *message, size_t message_len,
                          const uint8_t secret_key[ML_DSA_65_SECRET_KEY_BYTES])
{
    QUDO_FIPS_GATE(QUDO_MLDSA_ERROR);
    if (!signature || !signature_len || !message || !secret_key) {
        return QUDO_MLDSA_ERROR_NULL_PTR;
    }

    int ret;
#ifdef MLDSA_DIST_BUILD
#    ifdef QUDO_HAS_AVX2_VARIANT
    if (mld_cpu_has_extension(MLD_CPU_EXT_AVX2)) {
        ret = mldsa_avx265_signature(signature, signature_len, message,
                                     message_len, NULL, 0, secret_key);
    } else
#    endif
#    ifdef QUDO_HAS_NEON_VARIANT
        if (mld_cpu_has_extension(MLD_CPU_EXT_NEON)) {
        ret = mldsa_neon65_signature(signature, signature_len, message,
                                     message_len, NULL, 0, secret_key);
    } else
#    endif
    {
        ret = mldsa_ref65_signature(signature, signature_len, message,
                                    message_len, NULL, 0, secret_key);
    }
#else
    ret = mldsa65_signature(signature, signature_len, message, message_len,
                            NULL, 0, secret_key);
#endif
    return convert_mldsa_error(ret);
}

QUDO_MLDSA_status_t QUDO_MLDSA_ML_DSA_65_verify(
    const uint8_t *signature, size_t signature_len, const uint8_t *message,
    size_t message_len, const uint8_t public_key[ML_DSA_65_PUBLIC_KEY_BYTES])
{
    QUDO_FIPS_GATE(QUDO_MLDSA_ERROR);
    if (!signature || !message || !public_key) {
        return QUDO_MLDSA_ERROR_NULL_PTR;
    }

    int ret;
#ifdef MLDSA_DIST_BUILD
#    ifdef QUDO_HAS_AVX2_VARIANT
    if (mld_cpu_has_extension(MLD_CPU_EXT_AVX2)) {
        ret = mldsa_avx265_verify(signature, signature_len, message,
                                  message_len, NULL, 0, public_key);
    } else
#    endif
#    ifdef QUDO_HAS_NEON_VARIANT
        if (mld_cpu_has_extension(MLD_CPU_EXT_NEON)) {
        ret = mldsa_neon65_verify(signature, signature_len, message,
                                  message_len, NULL, 0, public_key);
    } else
#    endif
    {
        ret = mldsa_ref65_verify(signature, signature_len, message, message_len,
                                 NULL, 0, public_key);
    }
#else
    ret = mldsa65_verify(signature, signature_len, message, message_len, NULL,
                         0, public_key);
#endif
    return (ret == 0) ? QUDO_MLDSA_SUCCESS : QUDO_MLDSA_ERROR_VERIFY;
}

QUDO_MLDSA_status_t
QUDO_MLDSA_ML_DSA_87_keypair(uint8_t public_key[ML_DSA_87_PUBLIC_KEY_BYTES],
                             uint8_t secret_key[ML_DSA_87_SECRET_KEY_BYTES])
{
    QUDO_FIPS_GATE(QUDO_MLDSA_ERROR);
    if (!public_key || !secret_key) {
        return QUDO_MLDSA_ERROR_NULL_PTR;
    }

    int ret;
#ifdef MLDSA_DIST_BUILD
#    ifdef QUDO_HAS_AVX2_VARIANT
    if (mld_cpu_has_extension(MLD_CPU_EXT_AVX2)) {
        ret = mldsa_avx287_keypair(public_key, secret_key);
    } else
#    endif
#    ifdef QUDO_HAS_NEON_VARIANT
        if (mld_cpu_has_extension(MLD_CPU_EXT_NEON)) {
        ret = mldsa_neon87_keypair(public_key, secret_key);
    } else
#    endif
    {
        ret = mldsa_ref87_keypair(public_key, secret_key);
    }
#else
    ret = mldsa87_keypair(public_key, secret_key);
#endif
    return convert_mldsa_error(ret);
}

QUDO_MLDSA_status_t
QUDO_MLDSA_ML_DSA_87_sign(uint8_t *signature, size_t *signature_len,
                          const uint8_t *message, size_t message_len,
                          const uint8_t secret_key[ML_DSA_87_SECRET_KEY_BYTES])
{
    QUDO_FIPS_GATE(QUDO_MLDSA_ERROR);
    if (!signature || !signature_len || !message || !secret_key) {
        return QUDO_MLDSA_ERROR_NULL_PTR;
    }

    int ret;
#ifdef MLDSA_DIST_BUILD
#    ifdef QUDO_HAS_AVX2_VARIANT
    if (mld_cpu_has_extension(MLD_CPU_EXT_AVX2)) {
        ret = mldsa_avx287_signature(signature, signature_len, message,
                                     message_len, NULL, 0, secret_key);
    } else
#    endif
#    ifdef QUDO_HAS_NEON_VARIANT
        if (mld_cpu_has_extension(MLD_CPU_EXT_NEON)) {
        ret = mldsa_neon87_signature(signature, signature_len, message,
                                     message_len, NULL, 0, secret_key);
    } else
#    endif
    {
        ret = mldsa_ref87_signature(signature, signature_len, message,
                                    message_len, NULL, 0, secret_key);
    }
#else
    ret = mldsa87_signature(signature, signature_len, message, message_len,
                            NULL, 0, secret_key);
#endif
    return convert_mldsa_error(ret);
}

QUDO_MLDSA_status_t QUDO_MLDSA_ML_DSA_87_verify(
    const uint8_t *signature, size_t signature_len, const uint8_t *message,
    size_t message_len, const uint8_t public_key[ML_DSA_87_PUBLIC_KEY_BYTES])
{
    QUDO_FIPS_GATE(QUDO_MLDSA_ERROR);
    if (!signature || !message || !public_key) {
        return QUDO_MLDSA_ERROR_NULL_PTR;
    }

    int ret;
#ifdef MLDSA_DIST_BUILD
#    ifdef QUDO_HAS_AVX2_VARIANT
    if (mld_cpu_has_extension(MLD_CPU_EXT_AVX2)) {
        ret = mldsa_avx287_verify(signature, signature_len, message,
                                  message_len, NULL, 0, public_key);
    } else
#    endif
#    ifdef QUDO_HAS_NEON_VARIANT
        if (mld_cpu_has_extension(MLD_CPU_EXT_NEON)) {
        ret = mldsa_neon87_verify(signature, signature_len, message,
                                  message_len, NULL, 0, public_key);
    } else
#    endif
    {
        ret = mldsa_ref87_verify(signature, signature_len, message, message_len,
                                 NULL, 0, public_key);
    }
#else
    ret = mldsa87_verify(signature, signature_len, message, message_len, NULL,
                         0, public_key);
#endif
    return (ret == 0) ? QUDO_MLDSA_SUCCESS : QUDO_MLDSA_ERROR_VERIFY;
}

static QUDO_MLDSA_status_t internal_keypair_44(uint8_t *public_key,
                                               uint8_t *secret_key)
{
    int ret = mldsa44_keypair_impl(public_key, secret_key);
    return convert_mldsa_error(ret);
}

static QUDO_MLDSA_status_t internal_keypair_65(uint8_t *public_key,
                                               uint8_t *secret_key)
{
    int ret = mldsa65_keypair_impl(public_key, secret_key);
    return convert_mldsa_error(ret);
}

static QUDO_MLDSA_status_t internal_keypair_87(uint8_t *public_key,
                                               uint8_t *secret_key)
{
    int ret = mldsa87_keypair_impl(public_key, secret_key);
    return convert_mldsa_error(ret);
}

static QUDO_MLDSA_status_t internal_sign_44(uint8_t *sig, size_t *sig_len,
                                            const uint8_t *msg, size_t msg_len,
                                            const uint8_t *sk)
{
    int ret = mldsa44_sign_impl(sig, sig_len, msg, msg_len, NULL, 0, sk);
    return convert_mldsa_error(ret);
}

static QUDO_MLDSA_status_t internal_sign_65(uint8_t *sig, size_t *sig_len,
                                            const uint8_t *msg, size_t msg_len,
                                            const uint8_t *sk)
{
    int ret = mldsa65_sign_impl(sig, sig_len, msg, msg_len, NULL, 0, sk);
    return convert_mldsa_error(ret);
}

static QUDO_MLDSA_status_t internal_sign_87(uint8_t *sig, size_t *sig_len,
                                            const uint8_t *msg, size_t msg_len,
                                            const uint8_t *sk)
{
    int ret = mldsa87_sign_impl(sig, sig_len, msg, msg_len, NULL, 0, sk);
    return convert_mldsa_error(ret);
}

static QUDO_MLDSA_status_t internal_verify_44(const uint8_t *msg,
                                              size_t msg_len,
                                              const uint8_t *sig,
                                              size_t sig_len, const uint8_t *pk)
{
    int ret = mldsa44_verify_impl(sig, sig_len, msg, msg_len, NULL, 0, pk);
    return (ret == 0) ? QUDO_MLDSA_SUCCESS : QUDO_MLDSA_ERROR_VERIFY;
}

static QUDO_MLDSA_status_t internal_verify_65(const uint8_t *msg,
                                              size_t msg_len,
                                              const uint8_t *sig,
                                              size_t sig_len, const uint8_t *pk)
{
    int ret = mldsa65_verify_impl(sig, sig_len, msg, msg_len, NULL, 0, pk);
    return (ret == 0) ? QUDO_MLDSA_SUCCESS : QUDO_MLDSA_ERROR_VERIFY;
}

static QUDO_MLDSA_status_t internal_verify_87(const uint8_t *msg,
                                              size_t msg_len,
                                              const uint8_t *sig,
                                              size_t sig_len, const uint8_t *pk)
{
    int ret = mldsa87_verify_impl(sig, sig_len, msg, msg_len, NULL, 0, pk);
    return (ret == 0) ? QUDO_MLDSA_SUCCESS : QUDO_MLDSA_ERROR_VERIFY;
}

const char *QUDO_MLDSA_get_algorithm_name(const QUDO_MLDSA *sig)
{
    return sig ? sig->method_name : NULL;
}

size_t QUDO_MLDSA_get_public_key_bytes(const QUDO_MLDSA *sig)
{
    return sig ? sig->length_public_key : 0;
}

size_t QUDO_MLDSA_get_secret_key_bytes(const QUDO_MLDSA *sig)
{
    return sig ? sig->length_secret_key : 0;
}

size_t QUDO_MLDSA_get_signature_bytes(const QUDO_MLDSA *sig)
{
    return sig ? sig->length_signature : 0;
}

int QUDO_MLDSA_alg_count(void)
{
    return 3;
}

const char *QUDO_MLDSA_alg_identifier(size_t i)
{
    switch (i) {
    case 0:
        return "ML-DSA-44";
    case 1:
        return "ML-DSA-65";
    case 2:
        return "ML-DSA-87";
    default:
        return NULL;
    }
}

int QUDO_MLDSA_alg_is_enabled(const char *method_name)
{
    if (!method_name)
        return 0;
    return (strcmp(method_name, "ML-DSA-44") == 0
            || strcmp(method_name, "ML-DSA-65") == 0
            || strcmp(method_name, "ML-DSA-87") == 0)
               ? 1
               : 0;
}

int QUDO_MLDSA_supports_ctx_str(const char *alg_name)
{

    return QUDO_MLDSA_alg_is_enabled(alg_name);
}

QUDO_MLDSA_security_level_t QUDO_MLDSA_get_security_level(const QUDO_MLDSA *sig)
{
    return sig ? get_level_from_mldsa(sig) : 0;
}

const char *QUDO_MLDSA_get_error_string(QUDO_MLDSA_status_t status)
{
    return QUDO_MLDSA_error_string(status);
}

QUDO_MLDSA_API QUDO_MLDSA_status_t
QUDO_MLDSA_keypair_internal(QUDO_MLDSA *sig, uint8_t *public_key,
                            uint8_t *secret_key, const uint8_t *seed)
{
    QUDO_FIPS_GATE(QUDO_MLDSA_ERROR);
    QUDO_FIPS_IND_CHECK(sig, QUDO_MLDSA_ERROR);
    if (!sig || !public_key || !secret_key || !seed) {
        return QUDO_MLDSA_ERROR_NULL_PTR;
    }

    int ret;
    switch (get_level_from_mldsa(sig)) {
    case QUDO_MLDSA_44:
        ret = mldsa44_keypair_internal_impl(public_key, secret_key, seed);
        break;
    case QUDO_MLDSA_65:
        ret = mldsa65_keypair_internal_impl(public_key, secret_key, seed);
        break;
    case QUDO_MLDSA_87:
        ret = mldsa87_keypair_internal_impl(public_key, secret_key, seed);
        break;
    default:
        return QUDO_MLDSA_ERROR_INVALID_ARG;
    }

    {
        QUDO_MLDSA_status_t rc = convert_mldsa_error(ret);
        if (rc != QUDO_MLDSA_SUCCESS)
            return rc;
#ifdef QUDO_FIPS_MODULE

        if (!qudo_pqc_is_self_testing()
            && !qudo_pqc_mldsa_pct(sig, public_key, secret_key)) {

            qudo_cleanse(public_key, sig->length_public_key);
            qudo_cleanse(secret_key, sig->length_secret_key);
            qudo_pqc_set_error_state(QUDO_ST_TYPE_PCT);
            return QUDO_MLDSA_ERROR_CRYPTO;
        }
#endif
        return QUDO_MLDSA_SUCCESS;
    }
}

QUDO_MLDSA_API QUDO_MLDSA_status_t QUDO_MLDSA_sign_internal(
    QUDO_MLDSA *sig, uint8_t *signature, size_t *signature_len,
    const uint8_t *message, size_t message_len, const uint8_t *prefix,
    size_t prefix_len, const uint8_t *rnd, const uint8_t *secret_key,
    int external_mu)
{
    QUDO_FIPS_GATE(QUDO_MLDSA_ERROR);
    if (!sig || !signature || !signature_len || !message || !rnd
        || !secret_key) {
        return QUDO_MLDSA_ERROR_NULL_PTR;
    }

    int ret;
    switch (get_level_from_mldsa(sig)) {
    case QUDO_MLDSA_44:
        ret = mldsa44_sign_internal_impl(signature, signature_len, message,
                                         message_len, prefix, prefix_len, rnd,
                                         secret_key, external_mu);
        break;
    case QUDO_MLDSA_65:
        ret = mldsa65_sign_internal_impl(signature, signature_len, message,
                                         message_len, prefix, prefix_len, rnd,
                                         secret_key, external_mu);
        break;
    case QUDO_MLDSA_87:
        ret = mldsa87_sign_internal_impl(signature, signature_len, message,
                                         message_len, prefix, prefix_len, rnd,
                                         secret_key, external_mu);
        break;
    default:
        return QUDO_MLDSA_ERROR_INVALID_ARG;
    }

    return convert_mldsa_error(ret);
}

QUDO_MLDSA_API QUDO_MLDSA_status_t QUDO_MLDSA_sign_extmu(
    QUDO_MLDSA *sig, uint8_t *signature, size_t *signature_len,
    const uint8_t *mu, const uint8_t *secret_key)
{
    QUDO_FIPS_GATE(QUDO_MLDSA_ERROR);
    QUDO_FIPS_IND_CHECK(sig, QUDO_MLDSA_ERROR);
    if (!sig || !signature || !signature_len || !mu || !secret_key) {
        return QUDO_MLDSA_ERROR_NULL_PTR;
    }

    int ret;
    switch (get_level_from_mldsa(sig)) {
    case QUDO_MLDSA_44:
        ret = mldsa44_sign_extmu_impl(signature, signature_len, mu, secret_key);
        break;
    case QUDO_MLDSA_65:
        ret = mldsa65_sign_extmu_impl(signature, signature_len, mu, secret_key);
        break;
    case QUDO_MLDSA_87:
        ret = mldsa87_sign_extmu_impl(signature, signature_len, mu, secret_key);
        break;
    default:
        return QUDO_MLDSA_ERROR_INVALID_ARG;
    }

    return convert_mldsa_error(ret);
}

QUDO_MLDSA_API QUDO_MLDSA_status_t QUDO_MLDSA_sign_concat(
    QUDO_MLDSA *sig, uint8_t *signed_message, size_t *signed_message_len,
    const uint8_t *message, size_t message_len, const uint8_t *context,
    size_t context_len, const uint8_t *secret_key)
{
    QUDO_FIPS_GATE(QUDO_MLDSA_ERROR);
    QUDO_FIPS_IND_CHECK(sig, QUDO_MLDSA_ERROR);
    if (!sig || !signed_message || !signed_message_len || !message
        || !secret_key) {
        return QUDO_MLDSA_ERROR_NULL_PTR;
    }

    int ret;
    switch (get_level_from_mldsa(sig)) {
    case QUDO_MLDSA_44:
        ret = mldsa44_sign_concat_impl(signed_message, signed_message_len,
                                       message, message_len, context,
                                       context_len, secret_key);
        break;
    case QUDO_MLDSA_65:
        ret = mldsa65_sign_concat_impl(signed_message, signed_message_len,
                                       message, message_len, context,
                                       context_len, secret_key);
        break;
    case QUDO_MLDSA_87:
        ret = mldsa87_sign_concat_impl(signed_message, signed_message_len,
                                       message, message_len, context,
                                       context_len, secret_key);
        break;
    default:
        return QUDO_MLDSA_ERROR_INVALID_ARG;
    }

    return convert_mldsa_error(ret);
}

QUDO_MLDSA_API QUDO_MLDSA_status_t QUDO_MLDSA_verify_internal(
    QUDO_MLDSA *sig, const uint8_t *signature, size_t signature_len,
    const uint8_t *message, size_t message_len, const uint8_t *prefix,
    size_t prefix_len, const uint8_t *public_key, int external_mu)
{
    QUDO_FIPS_GATE(QUDO_MLDSA_ERROR);
    if (!sig || !signature || !message || !public_key) {
        return QUDO_MLDSA_ERROR_NULL_PTR;
    }

    int ret;
    switch (get_level_from_mldsa(sig)) {
    case QUDO_MLDSA_44:
        ret = mldsa44_verify_internal_impl(signature, signature_len, message,
                                           message_len, prefix, prefix_len,
                                           public_key, external_mu);
        break;
    case QUDO_MLDSA_65:
        ret = mldsa65_verify_internal_impl(signature, signature_len, message,
                                           message_len, prefix, prefix_len,
                                           public_key, external_mu);
        break;
    case QUDO_MLDSA_87:
        ret = mldsa87_verify_internal_impl(signature, signature_len, message,
                                           message_len, prefix, prefix_len,
                                           public_key, external_mu);
        break;
    default:
        return QUDO_MLDSA_ERROR_INVALID_ARG;
    }

    return (ret == 0) ? QUDO_MLDSA_SUCCESS : QUDO_MLDSA_ERROR_VERIFY;
}

QUDO_MLDSA_API QUDO_MLDSA_status_t QUDO_MLDSA_verify_extmu(
    QUDO_MLDSA *sig, const uint8_t *signature, size_t signature_len,
    const uint8_t *mu, const uint8_t *public_key)
{
    QUDO_FIPS_GATE(QUDO_MLDSA_ERROR);
    if (!sig || !signature || !mu || !public_key) {
        return QUDO_MLDSA_ERROR_NULL_PTR;
    }

    int ret;
    switch (get_level_from_mldsa(sig)) {
    case QUDO_MLDSA_44:
        ret = mldsa44_verify_extmu_impl(signature, signature_len, mu,
                                        public_key);
        break;
    case QUDO_MLDSA_65:
        ret = mldsa65_verify_extmu_impl(signature, signature_len, mu,
                                        public_key);
        break;
    case QUDO_MLDSA_87:
        ret = mldsa87_verify_extmu_impl(signature, signature_len, mu,
                                        public_key);
        break;
    default:
        return QUDO_MLDSA_ERROR_INVALID_ARG;
    }

    return (ret == 0) ? QUDO_MLDSA_SUCCESS : QUDO_MLDSA_ERROR_VERIFY;
}

QUDO_MLDSA_API QUDO_MLDSA_status_t QUDO_MLDSA_open(
    QUDO_MLDSA *sig, uint8_t *message, size_t *message_len,
    const uint8_t *signed_message, size_t signed_message_len,
    const uint8_t *context, size_t context_len, const uint8_t *public_key)
{
    QUDO_FIPS_GATE(QUDO_MLDSA_ERROR);
    if (!sig || !message || !message_len || !signed_message || !public_key) {
        return QUDO_MLDSA_ERROR_NULL_PTR;
    }

    int ret;
    switch (get_level_from_mldsa(sig)) {
    case QUDO_MLDSA_44:
        ret = mldsa44_open_impl(message, message_len, signed_message,
                                signed_message_len, context, context_len,
                                public_key);
        break;
    case QUDO_MLDSA_65:
        ret = mldsa65_open_impl(message, message_len, signed_message,
                                signed_message_len, context, context_len,
                                public_key);
        break;
    case QUDO_MLDSA_87:
        ret = mldsa87_open_impl(message, message_len, signed_message,
                                signed_message_len, context, context_len,
                                public_key);
        break;
    default:
        return QUDO_MLDSA_ERROR_INVALID_ARG;
    }

    return (ret == 0) ? QUDO_MLDSA_SUCCESS : QUDO_MLDSA_ERROR_VERIFY;
}

QUDO_MLDSA_API QUDO_MLDSA_status_t QUDO_MLDSA_sign_pre_hash_internal(
    QUDO_MLDSA *sig, uint8_t *signature, size_t *signature_len,
    const uint8_t *pre_hash, size_t pre_hash_len, const uint8_t *context,
    size_t context_len, const uint8_t *rnd, const uint8_t *secret_key,
    int hash_alg)
{
    QUDO_FIPS_GATE(QUDO_MLDSA_ERROR);
    if (!sig || !signature || !signature_len || !pre_hash || !rnd
        || !secret_key) {
        return QUDO_MLDSA_ERROR_NULL_PTR;
    }

    int ret;
    switch (get_level_from_mldsa(sig)) {
    case QUDO_MLDSA_44:
        ret = mldsa44_sign_pre_hash_impl(signature, signature_len, pre_hash,
                                         pre_hash_len, context, context_len,
                                         rnd, secret_key, hash_alg);
        break;
    case QUDO_MLDSA_65:
        ret = mldsa65_sign_pre_hash_impl(signature, signature_len, pre_hash,
                                         pre_hash_len, context, context_len,
                                         rnd, secret_key, hash_alg);
        break;
    case QUDO_MLDSA_87:
        ret = mldsa87_sign_pre_hash_impl(signature, signature_len, pre_hash,
                                         pre_hash_len, context, context_len,
                                         rnd, secret_key, hash_alg);
        break;
    default:
        return QUDO_MLDSA_ERROR_INVALID_ARG;
    }

    return convert_mldsa_error(ret);
}

QUDO_MLDSA_API QUDO_MLDSA_status_t QUDO_MLDSA_verify_pre_hash_internal(
    QUDO_MLDSA *sig, const uint8_t *signature, size_t signature_len,
    const uint8_t *pre_hash, size_t pre_hash_len, const uint8_t *context,
    size_t context_len, const uint8_t *public_key, int hash_alg)
{
    QUDO_FIPS_GATE(QUDO_MLDSA_ERROR);
    if (!sig || !signature || !pre_hash || !public_key) {
        return QUDO_MLDSA_ERROR_NULL_PTR;
    }

    int ret;
    switch (get_level_from_mldsa(sig)) {
    case QUDO_MLDSA_44:
        ret = mldsa44_verify_pre_hash_impl(signature, signature_len, pre_hash,
                                           pre_hash_len, context, context_len,
                                           public_key, hash_alg);
        break;
    case QUDO_MLDSA_65:
        ret = mldsa65_verify_pre_hash_impl(signature, signature_len, pre_hash,
                                           pre_hash_len, context, context_len,
                                           public_key, hash_alg);
        break;
    case QUDO_MLDSA_87:
        ret = mldsa87_verify_pre_hash_impl(signature, signature_len, pre_hash,
                                           pre_hash_len, context, context_len,
                                           public_key, hash_alg);
        break;
    default:
        return QUDO_MLDSA_ERROR_INVALID_ARG;
    }

    return (ret == 0) ? QUDO_MLDSA_SUCCESS : QUDO_MLDSA_ERROR_VERIFY;
}

#include "sha2_api.h"
#include "sha3_api.h"

static size_t compute_pre_hash(uint8_t *digest, size_t digest_buf_len,
                               const uint8_t *message, size_t message_len,
                               int hash_alg)
{
    switch (hash_alg) {
    case QUDO_PREHASH_SHA2_224:
        if (digest_buf_len < 28)
            return 0;
        sha2_224(digest, message, message_len);
        return 28;
    case QUDO_PREHASH_SHA2_256:
        if (digest_buf_len < 32)
            return 0;
        sha2_256(digest, message, message_len);
        return 32;
    case QUDO_PREHASH_SHA2_384:
        if (digest_buf_len < 48)
            return 0;
        sha2_384(digest, message, message_len);
        return 48;
    case QUDO_PREHASH_SHA2_512:
        if (digest_buf_len < 64)
            return 0;
        sha2_512(digest, message, message_len);
        return 64;
    case QUDO_PREHASH_SHA2_512_224:
        if (digest_buf_len < 28)
            return 0;
        sha2_512_224(digest, message, message_len);
        return 28;
    case QUDO_PREHASH_SHA2_512_256:
        if (digest_buf_len < 32)
            return 0;
        sha2_512_256(digest, message, message_len);
        return 32;
    case QUDO_PREHASH_SHA3_224:
        if (digest_buf_len < 28)
            return 0;
        sha3(digest, 28, message, message_len);
        return 28;
    case QUDO_PREHASH_SHA3_256:
        if (digest_buf_len < 32)
            return 0;
        sha3(digest, 32, message, message_len);
        return 32;
    case QUDO_PREHASH_SHA3_384:
        if (digest_buf_len < 48)
            return 0;
        sha3(digest, 48, message, message_len);
        return 48;
    case QUDO_PREHASH_SHA3_512:
        if (digest_buf_len < 64)
            return 0;
        sha3(digest, 64, message, message_len);
        return 64;
    case QUDO_PREHASH_SHAKE_128:
        if (digest_buf_len < 32)
            return 0;
        shake128(digest, 32, message, message_len);
        return 32;
    case QUDO_PREHASH_SHAKE_256:
        if (digest_buf_len < 64)
            return 0;
        shake256(digest, 64, message, message_len);
        return 64;
    default:
        return 0;
    }
}

QUDO_MLDSA_API QUDO_MLDSA_status_t QUDO_MLDSA_sign_pre_hash(
    QUDO_MLDSA *sig, uint8_t *signature, size_t *signature_len,
    const uint8_t *message, size_t message_len, const uint8_t *context,
    size_t context_len, const uint8_t *rnd, const uint8_t *secret_key,
    int hash_alg)
{
    QUDO_FIPS_GATE(QUDO_MLDSA_ERROR);
    uint8_t digest[64];
    size_t digest_len;
    QUDO_MLDSA_status_t rc;

    if (!sig || !signature || !signature_len || !message || !rnd || !secret_key)
        return QUDO_MLDSA_ERROR_NULL_PTR;

    digest_len = compute_pre_hash(digest, sizeof(digest), message, message_len,
                                  hash_alg);
    if (digest_len == 0) {
        QUDO_MLDSA_secure_zero(digest, sizeof(digest));
        return QUDO_MLDSA_ERROR_INVALID_ARG;
    }

    rc = QUDO_MLDSA_sign_pre_hash_internal(
        sig, signature, signature_len, digest, digest_len, context, context_len,
        rnd, secret_key, hash_alg);
    QUDO_MLDSA_secure_zero(digest, sizeof(digest));
    return rc;
}

QUDO_MLDSA_API QUDO_MLDSA_status_t QUDO_MLDSA_verify_pre_hash(
    QUDO_MLDSA *sig, const uint8_t *signature, size_t signature_len,
    const uint8_t *message, size_t message_len, const uint8_t *context,
    size_t context_len, const uint8_t *public_key, int hash_alg)
{
    uint8_t digest[64];
    size_t digest_len;
    QUDO_MLDSA_status_t rc;

    if (!sig || !signature || !message || !public_key)
        return QUDO_MLDSA_ERROR_NULL_PTR;

    digest_len = compute_pre_hash(digest, sizeof(digest), message, message_len,
                                  hash_alg);
    if (digest_len == 0) {
        QUDO_MLDSA_secure_zero(digest, sizeof(digest));
        return QUDO_MLDSA_ERROR_INVALID_ARG;
    }

    rc = QUDO_MLDSA_verify_pre_hash_internal(sig, signature, signature_len,
                                             digest, digest_len, context,
                                             context_len, public_key, hash_alg);
    QUDO_MLDSA_secure_zero(digest, sizeof(digest));
    return rc;
}

QUDO_MLDSA_API QUDO_MLDSA_status_t QUDO_MLDSA_ML_DSA_44_keypair_internal(
    uint8_t public_key[ML_DSA_44_PUBLIC_KEY_BYTES],
    uint8_t secret_key[ML_DSA_44_SECRET_KEY_BYTES],
    const uint8_t seed[MLDSA_SEEDBYTES])
{
    QUDO_FIPS_GATE(QUDO_MLDSA_ERROR);
    if (!public_key || !secret_key || !seed) {
        return QUDO_MLDSA_ERROR_NULL_PTR;
    }

    int ret = mldsa44_keypair_internal_impl(public_key, secret_key, seed);
    return convert_mldsa_error(ret);
}

QUDO_MLDSA_API QUDO_MLDSA_status_t QUDO_MLDSA_ML_DSA_44_sign_internal(
    uint8_t *signature, size_t *signature_len, const uint8_t *message,
    size_t message_len, const uint8_t *prefix, size_t prefix_len,
    const uint8_t rnd[MLDSA_RNDBYTES],
    const uint8_t secret_key[ML_DSA_44_SECRET_KEY_BYTES], int external_mu)
{
    QUDO_FIPS_GATE(QUDO_MLDSA_ERROR);
    if (!signature || !signature_len || !message || !rnd || !secret_key) {
        return QUDO_MLDSA_ERROR_NULL_PTR;
    }

    int ret = mldsa44_sign_internal_impl(signature, signature_len, message,
                                         message_len, prefix, prefix_len, rnd,
                                         secret_key, external_mu);
    return convert_mldsa_error(ret);
}

QUDO_MLDSA_API QUDO_MLDSA_status_t QUDO_MLDSA_ML_DSA_44_sign_extmu(
    uint8_t *signature, size_t *signature_len, const uint8_t mu[MLDSA_CRHBYTES],
    const uint8_t secret_key[ML_DSA_44_SECRET_KEY_BYTES])
{
    QUDO_FIPS_GATE(QUDO_MLDSA_ERROR);
    if (!signature || !signature_len || !mu || !secret_key) {
        return QUDO_MLDSA_ERROR_NULL_PTR;
    }

    int ret = mldsa44_sign_extmu_impl(signature, signature_len, mu, secret_key);
    return convert_mldsa_error(ret);
}

QUDO_MLDSA_API QUDO_MLDSA_status_t QUDO_MLDSA_ML_DSA_44_sign_concat(
    uint8_t *signed_message, size_t *signed_message_len, const uint8_t *message,
    size_t message_len, const uint8_t *context, size_t context_len,
    const uint8_t secret_key[ML_DSA_44_SECRET_KEY_BYTES])
{
    QUDO_FIPS_GATE(QUDO_MLDSA_ERROR);
    if (!signed_message || !signed_message_len || !message || !secret_key) {
        return QUDO_MLDSA_ERROR_NULL_PTR;
    }

    int ret = mldsa44_sign_concat_impl(signed_message, signed_message_len,
                                       message, message_len, context,
                                       context_len, secret_key);
    return convert_mldsa_error(ret);
}

QUDO_MLDSA_API QUDO_MLDSA_status_t QUDO_MLDSA_ML_DSA_44_verify_internal(
    const uint8_t *signature, size_t signature_len, const uint8_t *message,
    size_t message_len, const uint8_t *prefix, size_t prefix_len,
    const uint8_t public_key[ML_DSA_44_PUBLIC_KEY_BYTES], int external_mu)
{
    QUDO_FIPS_GATE(QUDO_MLDSA_ERROR);
    if (!signature || !message || !public_key) {
        return QUDO_MLDSA_ERROR_NULL_PTR;
    }

    int ret = mldsa44_verify_internal_impl(signature, signature_len, message,
                                           message_len, prefix, prefix_len,
                                           public_key, external_mu);
    return (ret == 0) ? QUDO_MLDSA_SUCCESS : QUDO_MLDSA_ERROR_VERIFY;
}

QUDO_MLDSA_API QUDO_MLDSA_status_t QUDO_MLDSA_ML_DSA_44_verify_extmu(
    const uint8_t *signature, size_t signature_len,
    const uint8_t mu[MLDSA_CRHBYTES],
    const uint8_t public_key[ML_DSA_44_PUBLIC_KEY_BYTES])
{
    QUDO_FIPS_GATE(QUDO_MLDSA_ERROR);
    if (!signature || !mu || !public_key) {
        return QUDO_MLDSA_ERROR_NULL_PTR;
    }

    int ret
        = mldsa44_verify_extmu_impl(signature, signature_len, mu, public_key);
    return (ret == 0) ? QUDO_MLDSA_SUCCESS : QUDO_MLDSA_ERROR_VERIFY;
}

QUDO_MLDSA_API QUDO_MLDSA_status_t QUDO_MLDSA_ML_DSA_44_open(
    uint8_t *message, size_t *message_len, const uint8_t *signed_message,
    size_t signed_message_len, const uint8_t *context, size_t context_len,
    const uint8_t public_key[ML_DSA_44_PUBLIC_KEY_BYTES])
{
    QUDO_FIPS_GATE(QUDO_MLDSA_ERROR);
    if (!message || !message_len || !signed_message || !public_key) {
        return QUDO_MLDSA_ERROR_NULL_PTR;
    }

    int ret = mldsa44_open_impl(message, message_len, signed_message,
                                signed_message_len, context, context_len,
                                public_key);
    return (ret == 0) ? QUDO_MLDSA_SUCCESS : QUDO_MLDSA_ERROR_VERIFY;
}

QUDO_MLDSA_API QUDO_MLDSA_status_t QUDO_MLDSA_ML_DSA_44_sign_pre_hash(
    uint8_t *signature, size_t *signature_len, const uint8_t *pre_hash,
    size_t pre_hash_len, const uint8_t *context, size_t context_len,
    const uint8_t rnd[MLDSA_RNDBYTES],
    const uint8_t secret_key[ML_DSA_44_SECRET_KEY_BYTES], int hash_alg)
{
    QUDO_FIPS_GATE(QUDO_MLDSA_ERROR);
    if (!signature || !signature_len || !pre_hash || !rnd || !secret_key) {
        return QUDO_MLDSA_ERROR_NULL_PTR;
    }

    int ret = mldsa44_sign_pre_hash_impl(signature, signature_len, pre_hash,
                                         pre_hash_len, context, context_len,
                                         rnd, secret_key, hash_alg);
    return convert_mldsa_error(ret);
}

QUDO_MLDSA_API QUDO_MLDSA_status_t QUDO_MLDSA_ML_DSA_44_verify_pre_hash(
    const uint8_t *signature, size_t signature_len, const uint8_t *pre_hash,
    size_t pre_hash_len, const uint8_t *context, size_t context_len,
    const uint8_t public_key[ML_DSA_44_PUBLIC_KEY_BYTES], int hash_alg)
{
    QUDO_FIPS_GATE(QUDO_MLDSA_ERROR);
    if (!signature || !pre_hash || !public_key) {
        return QUDO_MLDSA_ERROR_NULL_PTR;
    }

    int ret = mldsa44_verify_pre_hash_impl(signature, signature_len, pre_hash,
                                           pre_hash_len, context, context_len,
                                           public_key, hash_alg);
    return (ret == 0) ? QUDO_MLDSA_SUCCESS : QUDO_MLDSA_ERROR_VERIFY;
}

QUDO_MLDSA_API QUDO_MLDSA_status_t QUDO_MLDSA_ML_DSA_65_keypair_internal(
    uint8_t public_key[ML_DSA_65_PUBLIC_KEY_BYTES],
    uint8_t secret_key[ML_DSA_65_SECRET_KEY_BYTES],
    const uint8_t seed[MLDSA_SEEDBYTES])
{
    QUDO_FIPS_GATE(QUDO_MLDSA_ERROR);
    if (!public_key || !secret_key || !seed) {
        return QUDO_MLDSA_ERROR_NULL_PTR;
    }

    int ret = mldsa65_keypair_internal_impl(public_key, secret_key, seed);
    return convert_mldsa_error(ret);
}

QUDO_MLDSA_API QUDO_MLDSA_status_t QUDO_MLDSA_ML_DSA_65_sign_internal(
    uint8_t *signature, size_t *signature_len, const uint8_t *message,
    size_t message_len, const uint8_t *prefix, size_t prefix_len,
    const uint8_t rnd[MLDSA_RNDBYTES],
    const uint8_t secret_key[ML_DSA_65_SECRET_KEY_BYTES], int external_mu)
{
    QUDO_FIPS_GATE(QUDO_MLDSA_ERROR);
    if (!signature || !signature_len || !message || !rnd || !secret_key) {
        return QUDO_MLDSA_ERROR_NULL_PTR;
    }

    int ret = mldsa65_sign_internal_impl(signature, signature_len, message,
                                         message_len, prefix, prefix_len, rnd,
                                         secret_key, external_mu);
    return convert_mldsa_error(ret);
}

QUDO_MLDSA_API QUDO_MLDSA_status_t QUDO_MLDSA_ML_DSA_65_sign_extmu(
    uint8_t *signature, size_t *signature_len, const uint8_t mu[MLDSA_CRHBYTES],
    const uint8_t secret_key[ML_DSA_65_SECRET_KEY_BYTES])
{
    QUDO_FIPS_GATE(QUDO_MLDSA_ERROR);
    if (!signature || !signature_len || !mu || !secret_key) {
        return QUDO_MLDSA_ERROR_NULL_PTR;
    }

    int ret = mldsa65_sign_extmu_impl(signature, signature_len, mu, secret_key);
    return convert_mldsa_error(ret);
}

QUDO_MLDSA_API QUDO_MLDSA_status_t QUDO_MLDSA_ML_DSA_65_sign_concat(
    uint8_t *signed_message, size_t *signed_message_len, const uint8_t *message,
    size_t message_len, const uint8_t *context, size_t context_len,
    const uint8_t secret_key[ML_DSA_65_SECRET_KEY_BYTES])
{
    QUDO_FIPS_GATE(QUDO_MLDSA_ERROR);
    if (!signed_message || !signed_message_len || !message || !secret_key) {
        return QUDO_MLDSA_ERROR_NULL_PTR;
    }

    int ret = mldsa65_sign_concat_impl(signed_message, signed_message_len,
                                       message, message_len, context,
                                       context_len, secret_key);
    return convert_mldsa_error(ret);
}

QUDO_MLDSA_API QUDO_MLDSA_status_t QUDO_MLDSA_ML_DSA_65_verify_internal(
    const uint8_t *signature, size_t signature_len, const uint8_t *message,
    size_t message_len, const uint8_t *prefix, size_t prefix_len,
    const uint8_t public_key[ML_DSA_65_PUBLIC_KEY_BYTES], int external_mu)
{
    QUDO_FIPS_GATE(QUDO_MLDSA_ERROR);
    if (!signature || !message || !public_key) {
        return QUDO_MLDSA_ERROR_NULL_PTR;
    }

    int ret = mldsa65_verify_internal_impl(signature, signature_len, message,
                                           message_len, prefix, prefix_len,
                                           public_key, external_mu);
    return (ret == 0) ? QUDO_MLDSA_SUCCESS : QUDO_MLDSA_ERROR_VERIFY;
}

QUDO_MLDSA_API QUDO_MLDSA_status_t QUDO_MLDSA_ML_DSA_65_verify_extmu(
    const uint8_t *signature, size_t signature_len,
    const uint8_t mu[MLDSA_CRHBYTES],
    const uint8_t public_key[ML_DSA_65_PUBLIC_KEY_BYTES])
{
    QUDO_FIPS_GATE(QUDO_MLDSA_ERROR);
    if (!signature || !mu || !public_key) {
        return QUDO_MLDSA_ERROR_NULL_PTR;
    }

    int ret
        = mldsa65_verify_extmu_impl(signature, signature_len, mu, public_key);
    return (ret == 0) ? QUDO_MLDSA_SUCCESS : QUDO_MLDSA_ERROR_VERIFY;
}

QUDO_MLDSA_API QUDO_MLDSA_status_t QUDO_MLDSA_ML_DSA_65_open(
    uint8_t *message, size_t *message_len, const uint8_t *signed_message,
    size_t signed_message_len, const uint8_t *context, size_t context_len,
    const uint8_t public_key[ML_DSA_65_PUBLIC_KEY_BYTES])
{
    QUDO_FIPS_GATE(QUDO_MLDSA_ERROR);
    if (!message || !message_len || !signed_message || !public_key) {
        return QUDO_MLDSA_ERROR_NULL_PTR;
    }

    int ret = mldsa65_open_impl(message, message_len, signed_message,
                                signed_message_len, context, context_len,
                                public_key);
    return (ret == 0) ? QUDO_MLDSA_SUCCESS : QUDO_MLDSA_ERROR_VERIFY;
}

QUDO_MLDSA_API QUDO_MLDSA_status_t QUDO_MLDSA_ML_DSA_65_sign_pre_hash(
    uint8_t *signature, size_t *signature_len, const uint8_t *pre_hash,
    size_t pre_hash_len, const uint8_t *context, size_t context_len,
    const uint8_t rnd[MLDSA_RNDBYTES],
    const uint8_t secret_key[ML_DSA_65_SECRET_KEY_BYTES], int hash_alg)
{
    QUDO_FIPS_GATE(QUDO_MLDSA_ERROR);
    if (!signature || !signature_len || !pre_hash || !rnd || !secret_key) {
        return QUDO_MLDSA_ERROR_NULL_PTR;
    }

    int ret = mldsa65_sign_pre_hash_impl(signature, signature_len, pre_hash,
                                         pre_hash_len, context, context_len,
                                         rnd, secret_key, hash_alg);
    return convert_mldsa_error(ret);
}

QUDO_MLDSA_API QUDO_MLDSA_status_t QUDO_MLDSA_ML_DSA_65_verify_pre_hash(
    const uint8_t *signature, size_t signature_len, const uint8_t *pre_hash,
    size_t pre_hash_len, const uint8_t *context, size_t context_len,
    const uint8_t public_key[ML_DSA_65_PUBLIC_KEY_BYTES], int hash_alg)
{
    QUDO_FIPS_GATE(QUDO_MLDSA_ERROR);
    if (!signature || !pre_hash || !public_key) {
        return QUDO_MLDSA_ERROR_NULL_PTR;
    }

    int ret = mldsa65_verify_pre_hash_impl(signature, signature_len, pre_hash,
                                           pre_hash_len, context, context_len,
                                           public_key, hash_alg);
    return (ret == 0) ? QUDO_MLDSA_SUCCESS : QUDO_MLDSA_ERROR_VERIFY;
}

QUDO_MLDSA_API QUDO_MLDSA_status_t QUDO_MLDSA_ML_DSA_87_keypair_internal(
    uint8_t public_key[ML_DSA_87_PUBLIC_KEY_BYTES],
    uint8_t secret_key[ML_DSA_87_SECRET_KEY_BYTES],
    const uint8_t seed[MLDSA_SEEDBYTES])
{
    QUDO_FIPS_GATE(QUDO_MLDSA_ERROR);
    if (!public_key || !secret_key || !seed) {
        return QUDO_MLDSA_ERROR_NULL_PTR;
    }

    int ret = mldsa87_keypair_internal_impl(public_key, secret_key, seed);
    return convert_mldsa_error(ret);
}

QUDO_MLDSA_API QUDO_MLDSA_status_t QUDO_MLDSA_ML_DSA_87_sign_internal(
    uint8_t *signature, size_t *signature_len, const uint8_t *message,
    size_t message_len, const uint8_t *prefix, size_t prefix_len,
    const uint8_t rnd[MLDSA_RNDBYTES],
    const uint8_t secret_key[ML_DSA_87_SECRET_KEY_BYTES], int external_mu)
{
    QUDO_FIPS_GATE(QUDO_MLDSA_ERROR);
    if (!signature || !signature_len || !message || !rnd || !secret_key) {
        return QUDO_MLDSA_ERROR_NULL_PTR;
    }

    int ret = mldsa87_sign_internal_impl(signature, signature_len, message,
                                         message_len, prefix, prefix_len, rnd,
                                         secret_key, external_mu);
    return convert_mldsa_error(ret);
}

QUDO_MLDSA_API QUDO_MLDSA_status_t QUDO_MLDSA_ML_DSA_87_sign_extmu(
    uint8_t *signature, size_t *signature_len, const uint8_t mu[MLDSA_CRHBYTES],
    const uint8_t secret_key[ML_DSA_87_SECRET_KEY_BYTES])
{
    QUDO_FIPS_GATE(QUDO_MLDSA_ERROR);
    if (!signature || !signature_len || !mu || !secret_key) {
        return QUDO_MLDSA_ERROR_NULL_PTR;
    }

    int ret = mldsa87_sign_extmu_impl(signature, signature_len, mu, secret_key);
    return convert_mldsa_error(ret);
}

QUDO_MLDSA_API QUDO_MLDSA_status_t QUDO_MLDSA_ML_DSA_87_sign_concat(
    uint8_t *signed_message, size_t *signed_message_len, const uint8_t *message,
    size_t message_len, const uint8_t *context, size_t context_len,
    const uint8_t secret_key[ML_DSA_87_SECRET_KEY_BYTES])
{
    QUDO_FIPS_GATE(QUDO_MLDSA_ERROR);
    if (!signed_message || !signed_message_len || !message || !secret_key) {
        return QUDO_MLDSA_ERROR_NULL_PTR;
    }

    int ret = mldsa87_sign_concat_impl(signed_message, signed_message_len,
                                       message, message_len, context,
                                       context_len, secret_key);
    return convert_mldsa_error(ret);
}

QUDO_MLDSA_API QUDO_MLDSA_status_t QUDO_MLDSA_ML_DSA_87_verify_internal(
    const uint8_t *signature, size_t signature_len, const uint8_t *message,
    size_t message_len, const uint8_t *prefix, size_t prefix_len,
    const uint8_t public_key[ML_DSA_87_PUBLIC_KEY_BYTES], int external_mu)
{
    QUDO_FIPS_GATE(QUDO_MLDSA_ERROR);
    if (!signature || !message || !public_key) {
        return QUDO_MLDSA_ERROR_NULL_PTR;
    }

    int ret = mldsa87_verify_internal_impl(signature, signature_len, message,
                                           message_len, prefix, prefix_len,
                                           public_key, external_mu);
    return (ret == 0) ? QUDO_MLDSA_SUCCESS : QUDO_MLDSA_ERROR_VERIFY;
}

QUDO_MLDSA_API QUDO_MLDSA_status_t QUDO_MLDSA_ML_DSA_87_verify_extmu(
    const uint8_t *signature, size_t signature_len,
    const uint8_t mu[MLDSA_CRHBYTES],
    const uint8_t public_key[ML_DSA_87_PUBLIC_KEY_BYTES])
{
    QUDO_FIPS_GATE(QUDO_MLDSA_ERROR);
    if (!signature || !mu || !public_key) {
        return QUDO_MLDSA_ERROR_NULL_PTR;
    }

    int ret
        = mldsa87_verify_extmu_impl(signature, signature_len, mu, public_key);
    return (ret == 0) ? QUDO_MLDSA_SUCCESS : QUDO_MLDSA_ERROR_VERIFY;
}

QUDO_MLDSA_API QUDO_MLDSA_status_t QUDO_MLDSA_ML_DSA_87_open(
    uint8_t *message, size_t *message_len, const uint8_t *signed_message,
    size_t signed_message_len, const uint8_t *context, size_t context_len,
    const uint8_t public_key[ML_DSA_87_PUBLIC_KEY_BYTES])
{
    QUDO_FIPS_GATE(QUDO_MLDSA_ERROR);
    if (!message || !message_len || !signed_message || !public_key) {
        return QUDO_MLDSA_ERROR_NULL_PTR;
    }

    int ret = mldsa87_open_impl(message, message_len, signed_message,
                                signed_message_len, context, context_len,
                                public_key);
    return (ret == 0) ? QUDO_MLDSA_SUCCESS : QUDO_MLDSA_ERROR_VERIFY;
}

QUDO_MLDSA_API QUDO_MLDSA_status_t QUDO_MLDSA_ML_DSA_87_sign_pre_hash(
    uint8_t *signature, size_t *signature_len, const uint8_t *pre_hash,
    size_t pre_hash_len, const uint8_t *context, size_t context_len,
    const uint8_t rnd[MLDSA_RNDBYTES],
    const uint8_t secret_key[ML_DSA_87_SECRET_KEY_BYTES], int hash_alg)
{
    QUDO_FIPS_GATE(QUDO_MLDSA_ERROR);
    if (!signature || !signature_len || !pre_hash || !rnd || !secret_key) {
        return QUDO_MLDSA_ERROR_NULL_PTR;
    }

    int ret = mldsa87_sign_pre_hash_impl(signature, signature_len, pre_hash,
                                         pre_hash_len, context, context_len,
                                         rnd, secret_key, hash_alg);
    return convert_mldsa_error(ret);
}

QUDO_MLDSA_API QUDO_MLDSA_status_t QUDO_MLDSA_ML_DSA_87_verify_pre_hash(
    const uint8_t *signature, size_t signature_len, const uint8_t *pre_hash,
    size_t pre_hash_len, const uint8_t *context, size_t context_len,
    const uint8_t public_key[ML_DSA_87_PUBLIC_KEY_BYTES], int hash_alg)
{
    QUDO_FIPS_GATE(QUDO_MLDSA_ERROR);
    if (!signature || !pre_hash || !public_key) {
        return QUDO_MLDSA_ERROR_NULL_PTR;
    }

    int ret = mldsa87_verify_pre_hash_impl(signature, signature_len, pre_hash,
                                           pre_hash_len, context, context_len,
                                           public_key, hash_alg);
    return (ret == 0) ? QUDO_MLDSA_SUCCESS : QUDO_MLDSA_ERROR_VERIFY;
}
