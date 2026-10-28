// SPDX-License-Identifier: Apache-2.0 AND MIT

#include "qudo_fips_ctrdrbg.h"
#include "qudo_fips_aes.h"
#include <string.h>

static void inc_128(qudo_ctrdrbg_ctx_t *ctx)
{
    unsigned char *p = &ctx->V[0];
    uint32_t n = 16, c = 1;

    do {
        --n;
        c += p[n];
        p[n] = (uint8_t)c;
        c >>= 8;
    } while (n);
}

static void ctr_XOR(qudo_ctrdrbg_ctx_t *ctx, const uint8_t *in, size_t inlen)
{
    size_t i, n;

    if (in == NULL || inlen == 0)
        return;

    n = inlen < ctx->keylen ? inlen : ctx->keylen;
    for (i = 0; i < n; i++)
        ctx->K[i] ^= in[i];
    if (inlen <= ctx->keylen)
        return;

    n = inlen - ctx->keylen;
    if (n > QUDO_CTRDRBG_BLOCKLEN)
        n = QUDO_CTRDRBG_BLOCKLEN;
    for (i = 0; i < n; i++)
        ctx->V[i] ^= in[i + ctx->keylen];
}

static void ctr_update(qudo_ctrdrbg_ctx_t *ctx, const uint8_t *provided_data,
                       size_t provided_data_len)
{
    uint8_t V_tmp[QUDO_CTRDRBG_MAX_SEEDLEN];
    uint8_t out[QUDO_CTRDRBG_MAX_SEEDLEN];
    size_t len;

    memcpy(V_tmp, ctx->V, 16);

    inc_128(ctx);
    memcpy(V_tmp + 16, ctx->V, 16);

    if (ctx->keylen == 16) {
        len = 32;
    } else {
        inc_128(ctx);
        memcpy(V_tmp + 32, ctx->V, 16);
        len = 48;
    }

    qudo_aes_encrypt(V_tmp, out, &ctx->aes);
    qudo_aes_encrypt(V_tmp + 16, out + 16, &ctx->aes);
    if (len == 48)
        qudo_aes_encrypt(V_tmp + 32, out + 32, &ctx->aes);

    memcpy(ctx->K, out, ctx->keylen);
    memcpy(ctx->V, out + ctx->keylen, QUDO_CTRDRBG_BLOCKLEN);

    ctr_XOR(ctx, provided_data, provided_data_len);

    qudo_aes_set_encrypt_key(ctx->K, (int)(ctx->keylen * 8), &ctx->aes);

    qudo_secure_clear(V_tmp, sizeof(V_tmp));
    qudo_secure_clear(out, sizeof(out));
}

int qudo_ctrdrbg_init(qudo_ctrdrbg_ctx_t *ctx, size_t keylen,
                      const uint8_t *seed, size_t seedlen)
{
    if (seed == NULL || ctx == NULL)
        return -1;

    if (keylen != 16 && keylen != 24 && keylen != 32)
        return -1;

    if (seedlen != keylen + QUDO_CTRDRBG_BLOCKLEN)
        return -1;

    ctx->keylen = keylen;
    ctx->seedlen = seedlen;

    memset(ctx->K, 0, QUDO_CTRDRBG_MAX_KEYLEN);
    memset(ctx->V, 0, QUDO_CTRDRBG_BLOCKLEN);

    qudo_aes_set_encrypt_key(ctx->K, (int)(keylen * 8), &ctx->aes);

    inc_128(ctx);

    ctr_update(ctx, seed, seedlen);
    ctx->initialized = 1;

    return 0;
}

int qudo_ctrdrbg_generate(qudo_ctrdrbg_ctx_t *ctx, uint8_t *out, size_t out_len,
                          const uint8_t *additional, size_t additional_len)
{
    uint8_t add_buf[QUDO_CTRDRBG_MAX_SEEDLEN];
    const uint8_t *adin_ptr = NULL;
    size_t adin_len = 0;
    size_t off;

    if (ctx == NULL)
        return -1;

    if (!ctx->initialized || out_len > QUDO_CTRDRBG_MAX_REQUEST)
        return -1;
    if (out == NULL && out_len > 0)
        return -1;

    if (additional != NULL && additional_len != 0) {
        if (additional_len > ctx->seedlen)
            return -1;
        memset(add_buf, 0, sizeof(add_buf));
        memcpy(add_buf, additional, additional_len);

        inc_128(ctx);
        ctr_update(ctx, add_buf, ctx->seedlen);

        adin_ptr = add_buf;
        adin_len = ctx->seedlen;
    }

    if (out_len == 0) {
        inc_128(ctx);
        ctr_update(ctx, adin_ptr, adin_len);
        if (adin_ptr != NULL)
            qudo_secure_clear(add_buf, sizeof(add_buf));
        return 0;
    }

    off = 0;
    while (off < out_len) {
        uint8_t block[QUDO_CTRDRBG_BLOCKLEN];
        size_t chunk;

        inc_128(ctx);
        qudo_aes_encrypt(ctx->V, block, &ctx->aes);

        chunk = out_len - off;
        if (chunk > QUDO_CTRDRBG_BLOCKLEN)
            chunk = QUDO_CTRDRBG_BLOCKLEN;
        memcpy(out + off, block, chunk);
        off += chunk;

        qudo_secure_clear(block, sizeof(block));
    }

    inc_128(ctx);

    ctr_update(ctx, adin_ptr, adin_len);

    if (adin_ptr != NULL)
        qudo_secure_clear(add_buf, sizeof(add_buf));

    return 0;
}

int qudo_ctrdrbg_reseed(qudo_ctrdrbg_ctx_t *ctx, const uint8_t *seed,
                        size_t seedlen)
{
    if (ctx == NULL || seed == NULL)
        return -1;
    if (!ctx->initialized)
        return -1;
    if (seedlen != ctx->seedlen)
        return -1;

    inc_128(ctx);
    ctr_update(ctx, seed, seedlen);
    return 0;
}

void qudo_ctrdrbg_free(qudo_ctrdrbg_ctx_t *ctx)
{
    if (ctx != NULL) {
        qudo_secure_clear(ctx, sizeof(*ctx));
    }
}
