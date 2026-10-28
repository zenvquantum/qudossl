// SPDX-License-Identifier: Apache-2.0 AND MIT

#include "fips/qudo_fips_aes.h"
#include "fips/qudo_fips_ctrdrbg.h"
#include "fips/qudo_fips_hmac.h"
#include "fips/qudo_fips_rand.h"
#include "qudo_pqc.h"
#include <stdlib.h>
#include <string.h>

int qudo_pqc_rand_bytes(uint8_t *out, size_t out_len)
{
    if (!qudo_pqc_is_running())
        return -1;

    return qudo_fips_rand_bytes(out, out_len);
}

int qudo_pqc_rand_seed_from_platform(void)
{
    return qudo_fips_rand_seed_from_platform();
}

#ifdef QUDO_FIPS_MODULE

#    include <string.h>

extern int qudo_fips_module_start(void);
extern int qudo_fips_module_end(void);
extern unsigned char qudo_fips_integrity_hmac[32];

int qudo_pqc_get_module_boundary(const void **start_addr, const void **end_addr)
{
    if (start_addr == NULL || end_addr == NULL)
        return -1;
    const void *s = (const void *)(void *)qudo_fips_module_start;
    const void *e = (const void *)(void *)qudo_fips_module_end;
    if ((const uint8_t *)s >= (const uint8_t *)e)
        return -1;
    *start_addr = s;
    *end_addr = e;
    return 0;
}

int qudo_pqc_get_integrity_hmac(const uint8_t **hmac, size_t *hmac_len)
{
    if (hmac == NULL || hmac_len == NULL)
        return -1;
    *hmac = (const uint8_t *)qudo_fips_integrity_hmac;
    *hmac_len = sizeof(qudo_fips_integrity_hmac);
    return 0;
}

int qudo_pqc_integrity_hmac_is_patched(void)
{
    static const unsigned char sentinel[24]
        = {'Q', 'U', 'D', 'O', '_', 'F', 'I', 'P', 'S', '_', 'N', 'O',
           'T', '_', 'P', 'A', 'T', 'C', 'H', 'E', 'D', '_', '_', '_'};
    return memcmp(qudo_fips_integrity_hmac, sentinel, sizeof(sentinel)) != 0
               ? 1
               : 0;
}

#else

int qudo_pqc_get_module_boundary(const void **start_addr, const void **end_addr)
{
    (void)start_addr;
    (void)end_addr;
    return -1;
}

int qudo_pqc_get_integrity_hmac(const uint8_t **hmac, size_t *hmac_len)
{
    (void)hmac;
    (void)hmac_len;
    return -1;
}

int qudo_pqc_integrity_hmac_is_patched(void)
{
    return -1;
}

#endif

void qudo_pqc_cleanse(void *ptr, size_t len)
{
    if (ptr != NULL && len > 0)
        qudo_secure_clear(ptr, len);
}

struct qudo_pqc_hmac_ctx_st {
    qudo_fips_hmac_ctx_t inner;
};

void qudo_pqc_hmac_sha256(const uint8_t *key, size_t key_len,
                          const uint8_t *data, size_t data_len, uint8_t out[32])
{
    qudo_fips_hmac_sha256(key, key_len, data, data_len, out);
}

qudo_pqc_hmac_ctx_t *qudo_pqc_hmac_ctx_new(void)
{
    qudo_pqc_hmac_ctx_t *ctx
        = (qudo_pqc_hmac_ctx_t *)malloc(sizeof(qudo_pqc_hmac_ctx_t));
    if (ctx == NULL)
        return NULL;
    qudo_secure_clear(ctx, sizeof(*ctx));
    return ctx;
}

void qudo_pqc_hmac_ctx_init(qudo_pqc_hmac_ctx_t *ctx, const uint8_t *key,
                            size_t key_len)
{
    if (ctx == NULL)
        return;
    qudo_fips_hmac_init(&ctx->inner, key, key_len);
}

void qudo_pqc_hmac_ctx_update(qudo_pqc_hmac_ctx_t *ctx, const uint8_t *data,
                              size_t data_len)
{
    if (ctx == NULL)
        return;
    qudo_fips_hmac_update(&ctx->inner, data, data_len);
}

void qudo_pqc_hmac_ctx_final(qudo_pqc_hmac_ctx_t *ctx, uint8_t out[32])
{
    if (ctx == NULL)
        return;
    qudo_fips_hmac_final(&ctx->inner, out);
}

void qudo_pqc_hmac_ctx_free(qudo_pqc_hmac_ctx_t *ctx)
{
    if (ctx == NULL)
        return;
    qudo_secure_clear(ctx, sizeof(*ctx));
    free(ctx);
}

struct qudo_pqc_ctrdrbg_ctx_st {
    qudo_ctrdrbg_ctx_t inner;
};

static void qudo_pqc_ctrdrbg_mark_unapproved(const char *op)
{
    qudo_audit_log(QUDO_SEV_INFO, QUDO_ERR_NONE, QUDO_AUDIT_COMP_INDICATOR, op);
}

qudo_pqc_ctrdrbg_ctx_t *qudo_pqc_ctrdrbg_new(void)
{
    qudo_pqc_ctrdrbg_ctx_t *ctx;

    if (!qudo_pqc_is_running())
        return NULL;
    qudo_pqc_ctrdrbg_mark_unapproved(
        "qudo_pqc_ctrdrbg_new: non-Approved service");

    ctx = (qudo_pqc_ctrdrbg_ctx_t *)malloc(sizeof(qudo_pqc_ctrdrbg_ctx_t));
    if (ctx == NULL)
        return NULL;
    memset(ctx, 0, sizeof(*ctx));
    return ctx;
}

int qudo_pqc_ctrdrbg_init(qudo_pqc_ctrdrbg_ctx_t *ctx, size_t keylen,
                          const uint8_t *seed, size_t seedlen)
{
    if (!qudo_pqc_is_running())
        return -1;
    qudo_pqc_ctrdrbg_mark_unapproved(
        "qudo_pqc_ctrdrbg_init: non-Approved service");
    if (ctx == NULL)
        return -1;
    return qudo_ctrdrbg_init(&ctx->inner, keylen, seed, seedlen);
}

int qudo_pqc_ctrdrbg_generate(qudo_pqc_ctrdrbg_ctx_t *ctx, uint8_t *out,
                              size_t out_len, const uint8_t *additional,
                              size_t additional_len)
{
    if (!qudo_pqc_is_running())
        return -1;
    qudo_pqc_ctrdrbg_mark_unapproved(
        "qudo_pqc_ctrdrbg_generate: non-Approved service");
    if (ctx == NULL)
        return -1;
    return qudo_ctrdrbg_generate(&ctx->inner, out, out_len, additional,
                                 additional_len);
}

int qudo_pqc_ctrdrbg_reseed(qudo_pqc_ctrdrbg_ctx_t *ctx, const uint8_t *seed,
                            size_t seedlen)
{
    if (!qudo_pqc_is_running())
        return -1;
    qudo_pqc_ctrdrbg_mark_unapproved(
        "qudo_pqc_ctrdrbg_reseed: non-Approved service");
    if (ctx == NULL)
        return -1;
    return qudo_ctrdrbg_reseed(&ctx->inner, seed, seedlen);
}

void qudo_pqc_ctrdrbg_uninit(qudo_pqc_ctrdrbg_ctx_t *ctx)
{
    if (!qudo_pqc_is_running())
        return;
    qudo_pqc_ctrdrbg_mark_unapproved(
        "qudo_pqc_ctrdrbg_uninit: non-Approved service");
    if (ctx == NULL)
        return;
    qudo_ctrdrbg_free(&ctx->inner);
}

void qudo_pqc_ctrdrbg_free(qudo_pqc_ctrdrbg_ctx_t *ctx)
{
    if (!qudo_pqc_is_running())
        return;
    qudo_pqc_ctrdrbg_mark_unapproved(
        "qudo_pqc_ctrdrbg_free: non-Approved service");
    if (ctx == NULL)
        return;
    qudo_ctrdrbg_free(&ctx->inner);
    qudo_secure_clear(ctx, sizeof(*ctx));
    free(ctx);
}

int qudo_pqc_ctrdrbg_is_zeroized(const qudo_pqc_ctrdrbg_ctx_t *ctx)
{
    size_t i;
    if (!qudo_pqc_is_running())
        return 0;
    qudo_pqc_ctrdrbg_mark_unapproved(
        "qudo_pqc_ctrdrbg_is_zeroized: non-Approved service");
    if (ctx == NULL)
        return 0;
    for (i = 0; i < sizeof(ctx->inner.K); i++)
        if (ctx->inner.K[i] != 0)
            return 0;
    for (i = 0; i < sizeof(ctx->inner.V); i++)
        if (ctx->inner.V[i] != 0)
            return 0;
    if (ctx->inner.initialized != 0)
        return 0;
    return 1;
}

int qudo_pqc_rand_init(const uint8_t *entropy, size_t entropy_len)
{
    if (!qudo_pqc_is_running_or_selftest())
        return -1;
    return qudo_fips_rand_init(entropy, entropy_len);
}

int qudo_pqc_rand_reseed(const uint8_t *entropy, size_t entropy_len)
{
    return qudo_fips_rand_reseed(entropy, entropy_len);
}

int qudo_pqc_rand_is_ready(void)
{
    return qudo_fips_rand_is_ready();
}

void qudo_pqc_rand_cleanup(void)
{
    qudo_fips_rand_cleanup();
}
