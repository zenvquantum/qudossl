/* SPDX-License-Identifier: Apache-2.0 AND MIT */

#include "mldsa_wrapper.h"
#include "sha3_api.h"
#include <stdlib.h>
#include <string.h>

struct QUDO_MLDSA_shake256_st {
    sha3_var_t state;
    int finalized;
};

QUDO_MLDSA_API QUDO_MLDSA_status_t
QUDO_MLDSA_shake256_init(QUDO_MLDSA_shake256_ctx **ctx)
{
    if (ctx == NULL)
        return QUDO_MLDSA_ERROR_NULL_PTR;

    QUDO_MLDSA_shake256_ctx *c
        = (QUDO_MLDSA_shake256_ctx *)calloc(1, sizeof(QUDO_MLDSA_shake256_ctx));
    if (c == NULL)
        return QUDO_MLDSA_ERROR_ALLOC;

    shake256_init(&c->state);
    c->finalized = 0;
    *ctx = c;
    return QUDO_MLDSA_SUCCESS;
}

QUDO_MLDSA_API QUDO_MLDSA_status_t QUDO_MLDSA_shake256_absorb(
    QUDO_MLDSA_shake256_ctx *ctx, const uint8_t *data, size_t len)
{
    if (ctx == NULL)
        return QUDO_MLDSA_ERROR_NULL_PTR;
    if (ctx->finalized)
        return QUDO_MLDSA_ERROR;
    if (data == NULL && len > 0)
        return QUDO_MLDSA_ERROR_NULL_PTR;

    if (len > 0)
        shake_update(&ctx->state, data, len);
    return QUDO_MLDSA_SUCCESS;
}

QUDO_MLDSA_API QUDO_MLDSA_status_t QUDO_MLDSA_shake256_squeeze(
    QUDO_MLDSA_shake256_ctx *ctx, uint8_t *out, size_t outlen)
{
    if (ctx == NULL || out == NULL)
        return QUDO_MLDSA_ERROR_NULL_PTR;

    if (!ctx->finalized) {

        ctx->finalized = 1;
    }

    shake_out(&ctx->state, out, outlen);
    return QUDO_MLDSA_SUCCESS;
}

QUDO_MLDSA_API QUDO_MLDSA_status_t QUDO_MLDSA_shake256_dup(
    QUDO_MLDSA_shake256_ctx **dst, const QUDO_MLDSA_shake256_ctx *src)
{
    if (dst == NULL || src == NULL)
        return QUDO_MLDSA_ERROR_NULL_PTR;

    QUDO_MLDSA_shake256_ctx *c
        = (QUDO_MLDSA_shake256_ctx *)calloc(1, sizeof(QUDO_MLDSA_shake256_ctx));
    if (c == NULL)
        return QUDO_MLDSA_ERROR_ALLOC;

    memcpy(c, src, sizeof(QUDO_MLDSA_shake256_ctx));
    *dst = c;
    return QUDO_MLDSA_SUCCESS;
}

QUDO_MLDSA_API void QUDO_MLDSA_shake256_free(QUDO_MLDSA_shake256_ctx *ctx)
{
    if (ctx != NULL) {
        QUDO_MLDSA_secure_zero(ctx, sizeof(*ctx));
        free(ctx);
    }
}

QUDO_MLDSA_API QUDO_MLDSA_status_t QUDO_MLDSA_shake256(uint8_t *out,
                                                       size_t outlen,
                                                       const uint8_t *in,
                                                       size_t inlen)
{
    if (out == NULL || (in == NULL && inlen > 0))
        return QUDO_MLDSA_ERROR_NULL_PTR;

    shake256(out, outlen, in, inlen);
    return QUDO_MLDSA_SUCCESS;
}
