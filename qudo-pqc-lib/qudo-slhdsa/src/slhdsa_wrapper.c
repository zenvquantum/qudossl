/* SPDX-License-Identifier: Apache-2.0 AND MIT */

#include "slhdsa_wrapper.h"
#include "slh_dsa.h"
#include "slh_prehash.h"
#include "slhdsa_error.h"

#include <stdlib.h>
#include <string.h>

#ifdef QUDO_FIPS_MODULE

#    include "fips/qudo_fips_aes.h"
#    include "fips/qudo_fips_rand.h"
#    include "qudo_pqc.h"
#    include "qudo_pqc_audit.h"
#    include "qudo_pqc_platform.h"

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

#    ifdef QUDO_COMBINED_BUILD

#        include "fips/qudo_fips_rand.h"
#    endif
#    define QUDO_FIPS_GATE_PTR()              ((void)0)
#    define QUDO_FIPS_GATE(err)               ((void)0)
#    define QUDO_FIPS_IND_CHECK(sig_ptr, err) ((void)0)
#endif

static const slh_param_t *get_native_param(QUDO_SLHDSA_parameter_set_t ps)
{
    switch (ps) {
    case QUDO_SLHDSA_SHA2_128s:
        return &slh_dsa_sha2_128s;
    case QUDO_SLHDSA_SHA2_128f:
        return &slh_dsa_sha2_128f;
    case QUDO_SLHDSA_SHA2_192s:
        return &slh_dsa_sha2_192s;
    case QUDO_SLHDSA_SHA2_192f:
        return &slh_dsa_sha2_192f;
    case QUDO_SLHDSA_SHA2_256s:
        return &slh_dsa_sha2_256s;
    case QUDO_SLHDSA_SHA2_256f:
        return &slh_dsa_sha2_256f;
    case QUDO_SLHDSA_SHAKE_128s:
        return &slh_dsa_shake_128s;
    case QUDO_SLHDSA_SHAKE_128f:
        return &slh_dsa_shake_128f;
    case QUDO_SLHDSA_SHAKE_192s:
        return &slh_dsa_shake_192s;
    case QUDO_SLHDSA_SHAKE_192f:
        return &slh_dsa_shake_192f;
    case QUDO_SLHDSA_SHAKE_256s:
        return &slh_dsa_shake_256s;
    case QUDO_SLHDSA_SHAKE_256f:
        return &slh_dsa_shake_256f;
    default:
        return NULL;
    }
}

static int qudo_slhdsa_randombytes(uint8_t *x, size_t xlen)
{
#ifdef QUDO_COMBINED_BUILD
    if (qudo_fips_rand_bytes(x, xlen) != 0)
        return -1;
    return 0;
#else
    return (QUDO_SLHDSA_randombytes(x, xlen) == QUDO_SLHDSA_SUCCESS) ? 0 : -1;
#endif
}

static QUDO_SLHDSA_status_t internal_keypair(QUDO_SLHDSA_parameter_set_t ps,
                                             uint8_t *public_key,
                                             uint8_t *secret_key)
{

    const slh_param_t *prm = get_native_param(ps);
    if (!prm)
        return QUDO_SLHDSA_ERROR_INVALID_ARG;

    int ret = slh_keygen(secret_key, public_key, qudo_slhdsa_randombytes, prm);
    return (ret == 0) ? QUDO_SLHDSA_SUCCESS : QUDO_SLHDSA_ERROR_RNG;
}

static QUDO_SLHDSA_status_t
internal_sign(QUDO_SLHDSA_parameter_set_t ps, uint8_t *signature,
              size_t *signature_len, const uint8_t *message, size_t message_len,
              const uint8_t *secret_key)
{

    const slh_param_t *prm = get_native_param(ps);
    if (!prm)
        return QUDO_SLHDSA_ERROR_INVALID_ARG;

    size_t expected_sig_len = slh_sig_sz(prm);
    if (signature == NULL) {
        *signature_len = expected_sig_len;
        return QUDO_SLHDSA_SUCCESS;
    }
    if (*signature_len < expected_sig_len)
        return QUDO_SLHDSA_ERROR_BUFFER_TOO_SMALL;

    memset(signature, 0, expected_sig_len);

    size_t n = slh_pk_sz(prm) / 2;
    uint8_t addrnd[32];
    if (n > sizeof(addrnd))
        return QUDO_SLHDSA_ERROR_INVALID_ARG;
    if (qudo_slhdsa_randombytes(addrnd, n) != 0)
        return QUDO_SLHDSA_ERROR_RNG;

    static const uint8_t empty_ctx = 0;
    size_t sig_len = slh_sign(signature, message, message_len, &empty_ctx, 0,
                              secret_key, addrnd, prm);

    QUDO_SLHDSA_secure_zero(addrnd, sizeof(addrnd));

    if (sig_len == 0)
        return QUDO_SLHDSA_ERROR_CRYPTO;

    *signature_len = sig_len;
    return QUDO_SLHDSA_SUCCESS;
}

static QUDO_SLHDSA_status_t
internal_sign_with_ctx(QUDO_SLHDSA_parameter_set_t ps, uint8_t *signature,
                       size_t *signature_len, const uint8_t *message,
                       size_t message_len, const uint8_t *context,
                       size_t context_len, const uint8_t *secret_key)
{

    const slh_param_t *prm = get_native_param(ps);
    if (!prm)
        return QUDO_SLHDSA_ERROR_INVALID_ARG;

    if (context_len > SLHDSA_MAX_CONTEXT_BYTES)
        return QUDO_SLHDSA_ERROR_INVALID_ARG;

    size_t expected_sig_len = slh_sig_sz(prm);
    if (signature == NULL) {
        *signature_len = expected_sig_len;
        return QUDO_SLHDSA_SUCCESS;
    }
    if (*signature_len < expected_sig_len)
        return QUDO_SLHDSA_ERROR_BUFFER_TOO_SMALL;
    memset(signature, 0, expected_sig_len);

    size_t n = slh_pk_sz(prm) / 2;
    uint8_t addrnd[32];
    if (n > sizeof(addrnd))
        return QUDO_SLHDSA_ERROR_INVALID_ARG;
    if (qudo_slhdsa_randombytes(addrnd, n) != 0)
        return QUDO_SLHDSA_ERROR_RNG;

    size_t sig_len = slh_sign(signature, message, message_len, context,
                              context_len, secret_key, addrnd, prm);

    QUDO_SLHDSA_secure_zero(addrnd, sizeof(addrnd));

    if (sig_len == 0)
        return QUDO_SLHDSA_ERROR_CRYPTO;

    *signature_len = sig_len;
    return QUDO_SLHDSA_SUCCESS;
}

static QUDO_SLHDSA_status_t
internal_verify(QUDO_SLHDSA_parameter_set_t ps, const uint8_t *message,
                size_t message_len, const uint8_t *signature,
                size_t signature_len, const uint8_t *public_key)
{

    const slh_param_t *prm = get_native_param(ps);
    if (!prm)
        return QUDO_SLHDSA_ERROR_INVALID_ARG;

    size_t expected_sig_len = slhdsa_get_signature_bytes(ps);
    if (signature_len != expected_sig_len)
        return QUDO_SLHDSA_ERROR_VERIFY;

    static const uint8_t empty_ctx = 0;
    int ret = slh_verify(message, message_len, signature, signature_len,
                         &empty_ctx, 0, public_key, prm);

    return (ret == 1) ? QUDO_SLHDSA_SUCCESS : QUDO_SLHDSA_ERROR_VERIFY;
}

static QUDO_SLHDSA_status_t
internal_verify_with_ctx(QUDO_SLHDSA_parameter_set_t ps, const uint8_t *message,
                         size_t message_len, const uint8_t *signature,
                         size_t signature_len, const uint8_t *context,
                         size_t context_len, const uint8_t *public_key)
{

    const slh_param_t *prm = get_native_param(ps);
    if (!prm)
        return QUDO_SLHDSA_ERROR_INVALID_ARG;

    if (context_len > SLHDSA_MAX_CONTEXT_BYTES)
        return QUDO_SLHDSA_ERROR_INVALID_ARG;

    size_t expected_sig_len = slhdsa_get_signature_bytes(ps);
    if (signature_len != expected_sig_len)
        return QUDO_SLHDSA_ERROR_VERIFY;

    int ret = slh_verify(message, message_len, signature, signature_len,
                         context, context_len, public_key, prm);

    return (ret == 1) ? QUDO_SLHDSA_SUCCESS : QUDO_SLHDSA_ERROR_VERIFY;
}

#define DEFINE_VARIANT_WRAPPERS(VARIANT, PS_ENUM)                              \
    static QUDO_SLHDSA_status_t variant_keypair_##VARIANT(uint8_t *pk,         \
                                                          uint8_t *sk)         \
    {                                                                          \
        QUDO_FIPS_GATE(QUDO_SLHDSA_ERROR);                                     \
        return internal_keypair(PS_ENUM, pk, sk);                              \
    }                                                                          \
    static QUDO_SLHDSA_status_t variant_sign_##VARIANT(                        \
        uint8_t *sig, size_t *sig_len, const uint8_t *msg, size_t msg_len,     \
        const uint8_t *sk)                                                     \
    {                                                                          \
        QUDO_FIPS_GATE(QUDO_SLHDSA_ERROR);                                     \
        return internal_sign(PS_ENUM, sig, sig_len, msg, msg_len, sk);         \
    }                                                                          \
    static QUDO_SLHDSA_status_t variant_sign_ctx_##VARIANT(                    \
        uint8_t *sig, size_t *sig_len, const uint8_t *msg, size_t msg_len,     \
        const uint8_t *ctx, size_t ctx_len, const uint8_t *sk)                 \
    {                                                                          \
        QUDO_FIPS_GATE(QUDO_SLHDSA_ERROR);                                     \
        return internal_sign_with_ctx(PS_ENUM, sig, sig_len, msg, msg_len,     \
                                      ctx, ctx_len, sk);                       \
    }                                                                          \
    static QUDO_SLHDSA_status_t variant_verify_##VARIANT(                      \
        const uint8_t *msg, size_t msg_len, const uint8_t *sig,                \
        size_t sig_len, const uint8_t *pk)                                     \
    {                                                                          \
        QUDO_FIPS_GATE(QUDO_SLHDSA_ERROR);                                     \
        return internal_verify(PS_ENUM, msg, msg_len, sig, sig_len, pk);       \
    }                                                                          \
    static QUDO_SLHDSA_status_t variant_verify_ctx_##VARIANT(                  \
        const uint8_t *msg, size_t msg_len, const uint8_t *sig,                \
        size_t sig_len, const uint8_t *ctx, size_t ctx_len, const uint8_t *pk) \
    {                                                                          \
        QUDO_FIPS_GATE(QUDO_SLHDSA_ERROR);                                     \
        return internal_verify_with_ctx(PS_ENUM, msg, msg_len, sig, sig_len,   \
                                        ctx, ctx_len, pk);                     \
    }

DEFINE_VARIANT_WRAPPERS(sha2_128s, QUDO_SLHDSA_SHA2_128s)
DEFINE_VARIANT_WRAPPERS(sha2_128f, QUDO_SLHDSA_SHA2_128f)
DEFINE_VARIANT_WRAPPERS(sha2_192s, QUDO_SLHDSA_SHA2_192s)
DEFINE_VARIANT_WRAPPERS(sha2_192f, QUDO_SLHDSA_SHA2_192f)
DEFINE_VARIANT_WRAPPERS(sha2_256s, QUDO_SLHDSA_SHA2_256s)
DEFINE_VARIANT_WRAPPERS(sha2_256f, QUDO_SLHDSA_SHA2_256f)
DEFINE_VARIANT_WRAPPERS(shake_128s, QUDO_SLHDSA_SHAKE_128s)
DEFINE_VARIANT_WRAPPERS(shake_128f, QUDO_SLHDSA_SHAKE_128f)
DEFINE_VARIANT_WRAPPERS(shake_192s, QUDO_SLHDSA_SHAKE_192s)
DEFINE_VARIANT_WRAPPERS(shake_192f, QUDO_SLHDSA_SHAKE_192f)
DEFINE_VARIANT_WRAPPERS(shake_256s, QUDO_SLHDSA_SHAKE_256s)
DEFINE_VARIANT_WRAPPERS(shake_256f, QUDO_SLHDSA_SHAKE_256f)

#define POPULATE_SLHDSA(sig, VARIANT, NAME, LEVEL, SECBITS, PK, SK, SIG_SZ) \
    (sig)->method_name = NAME;                                              \
    (sig)->alg_version = "FIPS 205";                                        \
    (sig)->claimed_nist_level = LEVEL;                                      \
    (sig)->security_bits = SECBITS;                                         \
    (sig)->euf_cma = true;                                                  \
    (sig)->suf_cma = false;                                                 \
    (sig)->sig_with_ctx_support = true;                                     \
    (sig)->length_public_key = PK;                                          \
    (sig)->length_secret_key = SK;                                          \
    (sig)->length_signature = SIG_SZ;                                       \
    (sig)->keypair = variant_keypair_##VARIANT;                             \
    (sig)->sign = variant_sign_##VARIANT;                                   \
    (sig)->sign_with_ctx_str = variant_sign_ctx_##VARIANT;                  \
    (sig)->verify = variant_verify_##VARIANT;                               \
    (sig)->verify_with_ctx_str = variant_verify_ctx_##VARIANT;              \
    (sig)->param_set = ps;

QUDO_SLHDSA_API QUDO_SLHDSA *QUDO_SLHDSA_new(const char *algorithm)
{
    QUDO_FIPS_GATE_PTR();
    if (!algorithm)
        return NULL;

    QUDO_SLHDSA_parameter_set_t ps = slhdsa_get_parameter_set(algorithm);
    if (ps == 0)
        return NULL;

    QUDO_SLHDSA *sig = (QUDO_SLHDSA *)malloc(sizeof(QUDO_SLHDSA));
    if (!sig)
        return NULL;

    memset(sig, 0, sizeof(QUDO_SLHDSA));

    switch (ps) {
    case QUDO_SLHDSA_SHA2_128s:
        POPULATE_SLHDSA(sig, sha2_128s, QUDO_SLHDSA_alg_sha2_128s, 1, 128,
                        SLH_DSA_SHA2_128S_PUBLIC_KEY_BYTES,
                        SLH_DSA_SHA2_128S_SECRET_KEY_BYTES,
                        SLH_DSA_SHA2_128S_SIGNATURE_BYTES);
        break;
    case QUDO_SLHDSA_SHA2_128f:
        POPULATE_SLHDSA(sig, sha2_128f, QUDO_SLHDSA_alg_sha2_128f, 1, 128,
                        SLH_DSA_SHA2_128F_PUBLIC_KEY_BYTES,
                        SLH_DSA_SHA2_128F_SECRET_KEY_BYTES,
                        SLH_DSA_SHA2_128F_SIGNATURE_BYTES);
        break;
    case QUDO_SLHDSA_SHA2_192s:
        POPULATE_SLHDSA(sig, sha2_192s, QUDO_SLHDSA_alg_sha2_192s, 3, 192,
                        SLH_DSA_SHA2_192S_PUBLIC_KEY_BYTES,
                        SLH_DSA_SHA2_192S_SECRET_KEY_BYTES,
                        SLH_DSA_SHA2_192S_SIGNATURE_BYTES);
        break;
    case QUDO_SLHDSA_SHA2_192f:
        POPULATE_SLHDSA(sig, sha2_192f, QUDO_SLHDSA_alg_sha2_192f, 3, 192,
                        SLH_DSA_SHA2_192F_PUBLIC_KEY_BYTES,
                        SLH_DSA_SHA2_192F_SECRET_KEY_BYTES,
                        SLH_DSA_SHA2_192F_SIGNATURE_BYTES);
        break;
    case QUDO_SLHDSA_SHA2_256s:
        POPULATE_SLHDSA(sig, sha2_256s, QUDO_SLHDSA_alg_sha2_256s, 5, 256,
                        SLH_DSA_SHA2_256S_PUBLIC_KEY_BYTES,
                        SLH_DSA_SHA2_256S_SECRET_KEY_BYTES,
                        SLH_DSA_SHA2_256S_SIGNATURE_BYTES);
        break;
    case QUDO_SLHDSA_SHA2_256f:
        POPULATE_SLHDSA(sig, sha2_256f, QUDO_SLHDSA_alg_sha2_256f, 5, 256,
                        SLH_DSA_SHA2_256F_PUBLIC_KEY_BYTES,
                        SLH_DSA_SHA2_256F_SECRET_KEY_BYTES,
                        SLH_DSA_SHA2_256F_SIGNATURE_BYTES);
        break;
    case QUDO_SLHDSA_SHAKE_128s:
        POPULATE_SLHDSA(sig, shake_128s, QUDO_SLHDSA_alg_shake_128s, 1, 128,
                        SLH_DSA_SHAKE_128S_PUBLIC_KEY_BYTES,
                        SLH_DSA_SHAKE_128S_SECRET_KEY_BYTES,
                        SLH_DSA_SHAKE_128S_SIGNATURE_BYTES);
        break;
    case QUDO_SLHDSA_SHAKE_128f:
        POPULATE_SLHDSA(sig, shake_128f, QUDO_SLHDSA_alg_shake_128f, 1, 128,
                        SLH_DSA_SHAKE_128F_PUBLIC_KEY_BYTES,
                        SLH_DSA_SHAKE_128F_SECRET_KEY_BYTES,
                        SLH_DSA_SHAKE_128F_SIGNATURE_BYTES);
        break;
    case QUDO_SLHDSA_SHAKE_192s:
        POPULATE_SLHDSA(sig, shake_192s, QUDO_SLHDSA_alg_shake_192s, 3, 192,
                        SLH_DSA_SHAKE_192S_PUBLIC_KEY_BYTES,
                        SLH_DSA_SHAKE_192S_SECRET_KEY_BYTES,
                        SLH_DSA_SHAKE_192S_SIGNATURE_BYTES);
        break;
    case QUDO_SLHDSA_SHAKE_192f:
        POPULATE_SLHDSA(sig, shake_192f, QUDO_SLHDSA_alg_shake_192f, 3, 192,
                        SLH_DSA_SHAKE_192F_PUBLIC_KEY_BYTES,
                        SLH_DSA_SHAKE_192F_SECRET_KEY_BYTES,
                        SLH_DSA_SHAKE_192F_SIGNATURE_BYTES);
        break;
    case QUDO_SLHDSA_SHAKE_256s:
        POPULATE_SLHDSA(sig, shake_256s, QUDO_SLHDSA_alg_shake_256s, 5, 256,
                        SLH_DSA_SHAKE_256S_PUBLIC_KEY_BYTES,
                        SLH_DSA_SHAKE_256S_SECRET_KEY_BYTES,
                        SLH_DSA_SHAKE_256S_SIGNATURE_BYTES);
        break;
    case QUDO_SLHDSA_SHAKE_256f:
        POPULATE_SLHDSA(sig, shake_256f, QUDO_SLHDSA_alg_shake_256f, 5, 256,
                        SLH_DSA_SHAKE_256F_PUBLIC_KEY_BYTES,
                        SLH_DSA_SHAKE_256F_SECRET_KEY_BYTES,
                        SLH_DSA_SHAKE_256F_SIGNATURE_BYTES);
        break;
    default:
        free(sig);
        return NULL;
    }

#ifdef QUDO_FIPS_MODULE
    qudo_fips_ind_init(&sig->fips_ind, qudo_fips_ind_get_default_strict());
#endif

    return sig;
}

QUDO_SLHDSA_API void QUDO_SLHDSA_free(QUDO_SLHDSA *sig)
{

    if (sig) {
        QUDO_SLHDSA_secure_zero(sig, sizeof(QUDO_SLHDSA));
        free(sig);
    }
}

QUDO_SLHDSA_API QUDO_SLHDSA_status_t QUDO_SLHDSA_keypair(const QUDO_SLHDSA *sig,
                                                         uint8_t *public_key,
                                                         uint8_t *secret_key)
{
    QUDO_FIPS_GATE(QUDO_SLHDSA_ERROR);
    QUDO_FIPS_IND_CHECK(sig, QUDO_SLHDSA_ERROR);
    if (!sig || !public_key || !secret_key)
        return QUDO_SLHDSA_ERROR_NULL_PTR;
    {
        QUDO_SLHDSA_status_t rc = sig->keypair(public_key, secret_key);
        if (rc != QUDO_SLHDSA_SUCCESS)
            return rc;
#ifdef QUDO_FIPS_MODULE

        if (!qudo_pqc_is_self_testing()
            && !qudo_pqc_slhdsa_pct(sig, public_key, secret_key)) {

            qudo_cleanse(public_key, sig->length_public_key);
            qudo_cleanse(secret_key, sig->length_secret_key);
            qudo_pqc_set_error_state(QUDO_ST_TYPE_PCT);
            return QUDO_SLHDSA_ERROR_CRYPTO;
        }
#endif
        return QUDO_SLHDSA_SUCCESS;
    }
}

QUDO_SLHDSA_API QUDO_SLHDSA_status_t QUDO_SLHDSA_keypair_internal(
    const QUDO_SLHDSA *sig, uint8_t *public_key, uint8_t *secret_key,
    const uint8_t *sk_seed, const uint8_t *sk_prf, const uint8_t *pk_seed)
{
    QUDO_FIPS_GATE(QUDO_SLHDSA_ERROR);
    QUDO_FIPS_IND_CHECK(sig, QUDO_SLHDSA_ERROR);
    if (!sig || !public_key || !secret_key || !sk_seed || !sk_prf || !pk_seed)
        return QUDO_SLHDSA_ERROR_NULL_PTR;

    const slh_param_t *prm = get_native_param(sig->param_set);
    if (!prm)
        return QUDO_SLHDSA_ERROR_INVALID_ARG;

    int ret = slh_keygen_internal(secret_key, public_key, sk_seed, sk_prf,
                                  pk_seed, prm);
    if (ret != 0)
        return QUDO_SLHDSA_ERROR_CRYPTO;
#ifdef QUDO_FIPS_MODULE

    if (!qudo_pqc_is_self_testing()
        && !qudo_pqc_slhdsa_pct(sig, public_key, secret_key)) {

        qudo_cleanse(public_key, sig->length_public_key);
        qudo_cleanse(secret_key, sig->length_secret_key);
        qudo_pqc_set_error_state(QUDO_ST_TYPE_PCT);
        return QUDO_SLHDSA_ERROR_CRYPTO;
    }
#endif
    return QUDO_SLHDSA_SUCCESS;
}

QUDO_SLHDSA_API QUDO_SLHDSA_status_t QUDO_SLHDSA_sign(
    const QUDO_SLHDSA *sig, uint8_t *signature, size_t *signature_len,
    const uint8_t *message, size_t message_len, const uint8_t *secret_key)
{
    QUDO_FIPS_GATE(QUDO_SLHDSA_ERROR);
    QUDO_FIPS_IND_CHECK(sig, QUDO_SLHDSA_ERROR);

    if (!sig || !signature_len || !secret_key)
        return QUDO_SLHDSA_ERROR_NULL_PTR;
    if (!message && message_len > 0)
        return QUDO_SLHDSA_ERROR_NULL_PTR;
    return sig->sign(signature, signature_len, message, message_len,
                     secret_key);
}

QUDO_SLHDSA_API QUDO_SLHDSA_status_t QUDO_SLHDSA_sign_ex(
    const QUDO_SLHDSA *sig, uint8_t *signature, size_t *signature_len,
    const uint8_t *message, size_t message_len, const uint8_t *context,
    size_t context_len, const uint8_t *addrnd, const uint8_t *secret_key)
{
    QUDO_FIPS_GATE(QUDO_SLHDSA_ERROR);
    if (!sig || !signature_len || !secret_key)
        return QUDO_SLHDSA_ERROR_NULL_PTR;
    if (!message && message_len > 0)
        return QUDO_SLHDSA_ERROR_NULL_PTR;
    if (context_len > SLHDSA_MAX_CONTEXT_BYTES)
        return QUDO_SLHDSA_ERROR_INVALID_ARG;

    const slh_param_t *prm = get_native_param(sig->param_set);
    if (!prm)
        return QUDO_SLHDSA_ERROR_INVALID_ARG;

    size_t expected_sig_len = slh_sig_sz(prm);
    if (signature == NULL) {
        *signature_len = expected_sig_len;
        return QUDO_SLHDSA_SUCCESS;
    }
    if (*signature_len < expected_sig_len)
        return QUDO_SLHDSA_ERROR_BUFFER_TOO_SMALL;
    memset(signature, 0, expected_sig_len);

    const uint8_t *ctx = context;
    size_t ctx_len = context_len;
    static const uint8_t empty_ctx = 0;
    if (ctx == NULL) {
        ctx = &empty_ctx;
        ctx_len = 0;
    }

    size_t sig_len = slh_sign(signature, message, message_len, ctx, ctx_len,
                              secret_key, addrnd, prm);

    if (sig_len == 0)
        return QUDO_SLHDSA_ERROR_CRYPTO;

    *signature_len = sig_len;
    return QUDO_SLHDSA_SUCCESS;
}

QUDO_SLHDSA_API QUDO_SLHDSA_status_t QUDO_SLHDSA_sign_internal(
    const QUDO_SLHDSA *sig, uint8_t *signature, size_t *signature_len,
    const uint8_t *message, size_t message_len, const uint8_t *addrnd,
    const uint8_t *secret_key)
{
    QUDO_FIPS_GATE(QUDO_SLHDSA_ERROR);
    if (!sig || !signature_len || !secret_key)
        return QUDO_SLHDSA_ERROR_NULL_PTR;
    if (!message && message_len > 0)
        return QUDO_SLHDSA_ERROR_NULL_PTR;

    const slh_param_t *prm = get_native_param(sig->param_set);
    if (!prm)
        return QUDO_SLHDSA_ERROR_INVALID_ARG;

    size_t expected_sig_len = slh_sig_sz(prm);
    if (signature == NULL) {
        *signature_len = expected_sig_len;
        return QUDO_SLHDSA_SUCCESS;
    }
    if (*signature_len < expected_sig_len)
        return QUDO_SLHDSA_ERROR_BUFFER_TOO_SMALL;
    memset(signature, 0, expected_sig_len);

    size_t sig_len = slh_sign_internal(signature, message, message_len,
                                       secret_key, addrnd, prm);
    if (sig_len == 0)
        return QUDO_SLHDSA_ERROR_CRYPTO;

    *signature_len = sig_len;
    return QUDO_SLHDSA_SUCCESS;
}

QUDO_SLHDSA_API QUDO_SLHDSA_status_t
QUDO_SLHDSA_verify_internal(const QUDO_SLHDSA *sig, const uint8_t *message,
                            size_t message_len, const uint8_t *signature_buf,
                            size_t signature_len, const uint8_t *public_key)
{
    QUDO_FIPS_GATE(QUDO_SLHDSA_ERROR);
    if (!sig || !signature_buf || !public_key)
        return QUDO_SLHDSA_ERROR_NULL_PTR;
    if (!message && message_len > 0)
        return QUDO_SLHDSA_ERROR_NULL_PTR;

    const slh_param_t *prm = get_native_param(sig->param_set);
    if (!prm)
        return QUDO_SLHDSA_ERROR_INVALID_ARG;

    if (signature_len != slh_sig_sz(prm))
        return QUDO_SLHDSA_ERROR_VERIFY;

    int rc = slh_verify_internal(message, message_len, signature_buf,
                                 signature_len, public_key, prm);
    return (rc == 1) ? QUDO_SLHDSA_SUCCESS : QUDO_SLHDSA_ERROR_VERIFY;
}

QUDO_SLHDSA_API QUDO_SLHDSA_status_t QUDO_SLHDSA_sign_pre_hash(
    const QUDO_SLHDSA *sig, uint8_t *signature, size_t *signature_len,
    const uint8_t *message, size_t message_len, const uint8_t *context,
    size_t context_len, const char *hash_alg, const uint8_t *addrnd,
    const uint8_t *secret_key)
{
    QUDO_FIPS_GATE(QUDO_SLHDSA_ERROR);
    if (!sig || !signature_len || !secret_key || !hash_alg)
        return QUDO_SLHDSA_ERROR_NULL_PTR;
    if (!message && message_len > 0)
        return QUDO_SLHDSA_ERROR_NULL_PTR;
    if (context_len > SLHDSA_MAX_CONTEXT_BYTES)
        return QUDO_SLHDSA_ERROR_INVALID_ARG;

    const slh_param_t *prm = get_native_param(sig->param_set);
    if (!prm)
        return QUDO_SLHDSA_ERROR_INVALID_ARG;

    size_t expected_sig_len = slh_sig_sz(prm);
    if (signature == NULL) {
        *signature_len = expected_sig_len;
        return QUDO_SLHDSA_SUCCESS;
    }
    if (*signature_len < expected_sig_len)
        return QUDO_SLHDSA_ERROR_BUFFER_TOO_SMALL;
    memset(signature, 0, expected_sig_len);

    const uint8_t *ctx = context;
    size_t ctx_len = context_len;
    static const uint8_t empty_ctx = 0;
    if (ctx == NULL) {
        ctx = &empty_ctx;
        ctx_len = 0;
    }

    size_t sig_len = hash_slh_sign(signature, message, message_len, ctx,
                                   ctx_len, hash_alg, secret_key, addrnd, prm);
    if (sig_len == 0)
        return QUDO_SLHDSA_ERROR_CRYPTO;

    *signature_len = sig_len;
    return QUDO_SLHDSA_SUCCESS;
}

QUDO_SLHDSA_API QUDO_SLHDSA_status_t QUDO_SLHDSA_verify_pre_hash(
    const QUDO_SLHDSA *sig, const uint8_t *message, size_t message_len,
    const uint8_t *signature_buf, size_t signature_len, const uint8_t *context,
    size_t context_len, const char *hash_alg, const uint8_t *public_key)
{
    QUDO_FIPS_GATE(QUDO_SLHDSA_ERROR);
    if (!sig || !signature_buf || !public_key || !hash_alg)
        return QUDO_SLHDSA_ERROR_NULL_PTR;
    if (!message && message_len > 0)
        return QUDO_SLHDSA_ERROR_NULL_PTR;
    if (context_len > SLHDSA_MAX_CONTEXT_BYTES)
        return QUDO_SLHDSA_ERROR_INVALID_ARG;

    const slh_param_t *prm = get_native_param(sig->param_set);
    if (!prm)
        return QUDO_SLHDSA_ERROR_INVALID_ARG;

    if (signature_len != slh_sig_sz(prm))
        return QUDO_SLHDSA_ERROR_VERIFY;

    const uint8_t *ctx = context;
    size_t ctx_len = context_len;
    static const uint8_t empty_ctx = 0;
    if (ctx == NULL) {
        ctx = &empty_ctx;
        ctx_len = 0;
    }

    int rc = hash_slh_verify(message, message_len, signature_buf, signature_len,
                             ctx, ctx_len, hash_alg, public_key, prm);
    return (rc == 1) ? QUDO_SLHDSA_SUCCESS : QUDO_SLHDSA_ERROR_VERIFY;
}

QUDO_SLHDSA_API QUDO_SLHDSA_status_t QUDO_SLHDSA_sign_with_ctx_str(
    const QUDO_SLHDSA *sig, uint8_t *signature, size_t *signature_len,
    const uint8_t *message, size_t message_len, const uint8_t *context,
    size_t context_len, const uint8_t *secret_key)
{
    QUDO_FIPS_GATE(QUDO_SLHDSA_ERROR);
    QUDO_FIPS_IND_CHECK(sig, QUDO_SLHDSA_ERROR);

    if (!sig || !signature_len || !secret_key)
        return QUDO_SLHDSA_ERROR_NULL_PTR;
    if (!message && message_len > 0)
        return QUDO_SLHDSA_ERROR_NULL_PTR;
    if (!context && context_len > 0)
        return QUDO_SLHDSA_ERROR_NULL_PTR;
    return sig->sign_with_ctx_str(signature, signature_len, message,
                                  message_len, context, context_len,
                                  secret_key);
}

QUDO_SLHDSA_API QUDO_SLHDSA_status_t QUDO_SLHDSA_verify(
    const QUDO_SLHDSA *sig, const uint8_t *message, size_t message_len,
    const uint8_t *signature, size_t signature_len, const uint8_t *public_key)
{
    QUDO_FIPS_GATE(QUDO_SLHDSA_ERROR);
    QUDO_FIPS_IND_CHECK(sig, QUDO_SLHDSA_ERROR);
    if (!sig || !signature || !public_key)
        return QUDO_SLHDSA_ERROR_NULL_PTR;
    if (!message && message_len > 0)
        return QUDO_SLHDSA_ERROR_NULL_PTR;
    return sig->verify(message, message_len, signature, signature_len,
                       public_key);
}

QUDO_SLHDSA_API QUDO_SLHDSA_status_t QUDO_SLHDSA_verify_with_ctx_str(
    const QUDO_SLHDSA *sig, const uint8_t *message, size_t message_len,
    const uint8_t *signature, size_t signature_len, const uint8_t *context,
    size_t context_len, const uint8_t *public_key)
{
    QUDO_FIPS_GATE(QUDO_SLHDSA_ERROR);
    QUDO_FIPS_IND_CHECK(sig, QUDO_SLHDSA_ERROR);
    if (!sig || !signature || !public_key)
        return QUDO_SLHDSA_ERROR_NULL_PTR;
    if (!message && message_len > 0)
        return QUDO_SLHDSA_ERROR_NULL_PTR;
    if (!context && context_len > 0)
        return QUDO_SLHDSA_ERROR_NULL_PTR;
    return sig->verify_with_ctx_str(message, message_len, signature,
                                    signature_len, context, context_len,
                                    public_key);
}

#define IMPLEMENT_DIRECT_API(SUFFIX, PS_ENUM)                              \
    QUDO_SLHDSA_API QUDO_SLHDSA_status_t QUDO_SLHDSA_##SUFFIX##_keypair(   \
        uint8_t *pk, uint8_t *sk)                                          \
    {                                                                      \
        QUDO_FIPS_GATE(QUDO_SLHDSA_ERROR);                                 \
        if (!pk || !sk)                                                    \
            return QUDO_SLHDSA_ERROR_NULL_PTR;                             \
        return internal_keypair(PS_ENUM, pk, sk);                          \
    }                                                                      \
    QUDO_SLHDSA_API QUDO_SLHDSA_status_t QUDO_SLHDSA_##SUFFIX##_sign(      \
        uint8_t *sig, size_t *sig_len, const uint8_t *msg, size_t msg_len, \
        const uint8_t *sk)                                                 \
    {                                                                      \
        QUDO_FIPS_GATE(QUDO_SLHDSA_ERROR);                                 \
        if (!sig || !sig_len || !sk)                                       \
            return QUDO_SLHDSA_ERROR_NULL_PTR;                             \
        if (!msg && msg_len > 0)                                           \
            return QUDO_SLHDSA_ERROR_NULL_PTR;                             \
        return internal_sign(PS_ENUM, sig, sig_len, msg, msg_len, sk);     \
    }                                                                      \
    QUDO_SLHDSA_API QUDO_SLHDSA_status_t QUDO_SLHDSA_##SUFFIX##_verify(    \
        const uint8_t *msg, size_t msg_len, const uint8_t *sig,            \
        size_t sig_len, const uint8_t *pk)                                 \
    {                                                                      \
        QUDO_FIPS_GATE(QUDO_SLHDSA_ERROR);                                 \
        if (!sig || !pk)                                                   \
            return QUDO_SLHDSA_ERROR_NULL_PTR;                             \
        if (!msg && msg_len > 0)                                           \
            return QUDO_SLHDSA_ERROR_NULL_PTR;                             \
        return internal_verify(PS_ENUM, msg, msg_len, sig, sig_len, pk);   \
    }

IMPLEMENT_DIRECT_API(SHA2_128s, QUDO_SLHDSA_SHA2_128s)
IMPLEMENT_DIRECT_API(SHA2_128f, QUDO_SLHDSA_SHA2_128f)
IMPLEMENT_DIRECT_API(SHA2_192s, QUDO_SLHDSA_SHA2_192s)
IMPLEMENT_DIRECT_API(SHA2_192f, QUDO_SLHDSA_SHA2_192f)
IMPLEMENT_DIRECT_API(SHA2_256s, QUDO_SLHDSA_SHA2_256s)
IMPLEMENT_DIRECT_API(SHA2_256f, QUDO_SLHDSA_SHA2_256f)
IMPLEMENT_DIRECT_API(SHAKE_128s, QUDO_SLHDSA_SHAKE_128s)
IMPLEMENT_DIRECT_API(SHAKE_128f, QUDO_SLHDSA_SHAKE_128f)
IMPLEMENT_DIRECT_API(SHAKE_192s, QUDO_SLHDSA_SHAKE_192s)
IMPLEMENT_DIRECT_API(SHAKE_192f, QUDO_SLHDSA_SHAKE_192f)
IMPLEMENT_DIRECT_API(SHAKE_256s, QUDO_SLHDSA_SHAKE_256s)
IMPLEMENT_DIRECT_API(SHAKE_256f, QUDO_SLHDSA_SHAKE_256f)

#if defined(_MSC_VER)
#    include <intrin.h>
#    pragma intrinsic(_InterlockedExchange)
static volatile long g_slhdsa_init_state = 0;
#    define SLHDSA_INIT_STORE(val) \
        (void)_InterlockedExchange(&g_slhdsa_init_state, (val))
#    define SLHDSA_INIT_LOAD() g_slhdsa_init_state
#elif defined(__GNUC__) || defined(__clang__)
static volatile int g_slhdsa_init_state = 0;
#    define SLHDSA_INIT_STORE(val) \
        __atomic_store_n(&g_slhdsa_init_state, (val), __ATOMIC_SEQ_CST)
#    define SLHDSA_INIT_LOAD() \
        __atomic_load_n(&g_slhdsa_init_state, __ATOMIC_SEQ_CST)
#else
static volatile int g_slhdsa_init_state = 0;
#    define SLHDSA_INIT_STORE(val) (g_slhdsa_init_state = (val))
#    define SLHDSA_INIT_LOAD()     g_slhdsa_init_state
#endif

#if defined(_WIN32)
#    ifndef WIN32_LEAN_AND_MEAN
#        define WIN32_LEAN_AND_MEAN
#    endif
#    include <windows.h>
static SRWLOCK g_slhdsa_init_lock = SRWLOCK_INIT;
#    define SLHDSA_INIT_LOCK()   AcquireSRWLockExclusive(&g_slhdsa_init_lock)
#    define SLHDSA_INIT_UNLOCK() ReleaseSRWLockExclusive(&g_slhdsa_init_lock)
#else
#    include <pthread.h>
static pthread_mutex_t g_slhdsa_init_lock = PTHREAD_MUTEX_INITIALIZER;
#    define SLHDSA_INIT_LOCK()   (void)pthread_mutex_lock(&g_slhdsa_init_lock)
#    define SLHDSA_INIT_UNLOCK() (void)pthread_mutex_unlock(&g_slhdsa_init_lock)
#endif

QUDO_SLHDSA_API QUDO_SLHDSA_status_t QUDO_SLHDSA_init(void)
{
    QUDO_SLHDSA_status_t rc = QUDO_SLHDSA_SUCCESS;

    if (SLHDSA_INIT_LOAD() == 2)
        return QUDO_SLHDSA_SUCCESS;

    SLHDSA_INIT_LOCK();
    if (SLHDSA_INIT_LOAD() == 2) {
        SLHDSA_INIT_UNLOCK();
        return QUDO_SLHDSA_SUCCESS;
    }

    if (QUDO_SLHDSA_randombytes_init() != QUDO_SLHDSA_SUCCESS) {
        rc = QUDO_SLHDSA_ERROR_RNG;
        goto out;
    }

    if (QUDO_SLHDSA_randombytes_test() != QUDO_SLHDSA_SUCCESS) {
        rc = QUDO_SLHDSA_ERROR_RNG;
        goto out;
    }

    SLHDSA_INIT_STORE(2);
out:
    SLHDSA_INIT_UNLOCK();
    return rc;
}

QUDO_SLHDSA_API void QUDO_SLHDSA_cleanup(void)
{
    SLHDSA_INIT_LOCK();
    if (SLHDSA_INIT_LOAD() == 2) {
        QUDO_SLHDSA_randombytes_cleanup();
        SLHDSA_INIT_STORE(0);
    }
    SLHDSA_INIT_UNLOCK();
}

QUDO_SLHDSA_API int QUDO_SLHDSA_is_initialized(void)
{
    return (SLHDSA_INIT_LOAD() == 2);
}

QUDO_SLHDSA_API const char *
QUDO_SLHDSA_get_error_string(QUDO_SLHDSA_status_t status)
{
    return QUDO_SLHDSA_error_string(status);
}

QUDO_SLHDSA_API int
QUDO_SLHDSA_get_security_level(QUDO_SLHDSA_parameter_set_t param_set)
{
    return slhdsa_get_nist_level(param_set);
}

static const char *slhdsa_alg_names[] = {
    QUDO_SLHDSA_alg_sha2_128s,  QUDO_SLHDSA_alg_sha2_128f,
    QUDO_SLHDSA_alg_sha2_192s,  QUDO_SLHDSA_alg_sha2_192f,
    QUDO_SLHDSA_alg_sha2_256s,  QUDO_SLHDSA_alg_sha2_256f,
    QUDO_SLHDSA_alg_shake_128s, QUDO_SLHDSA_alg_shake_128f,
    QUDO_SLHDSA_alg_shake_192s, QUDO_SLHDSA_alg_shake_192f,
    QUDO_SLHDSA_alg_shake_256s, QUDO_SLHDSA_alg_shake_256f,
};

QUDO_SLHDSA_API int QUDO_SLHDSA_alg_count(void)
{
    return SLHDSA_NUM_PARAMETER_SETS;
}

QUDO_SLHDSA_API const char *QUDO_SLHDSA_alg_identifier(size_t i)
{
    if (i >= SLHDSA_NUM_PARAMETER_SETS)
        return NULL;
    return slhdsa_alg_names[i];
}

QUDO_SLHDSA_API int QUDO_SLHDSA_alg_is_enabled(const char *method_name)
{
    if (!method_name)
        return 0;
    QUDO_SLHDSA_parameter_set_t ps = slhdsa_get_parameter_set(method_name);
    return (ps != 0) ? 1 : 0;
}
