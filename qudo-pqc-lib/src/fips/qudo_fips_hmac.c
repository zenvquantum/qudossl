// SPDX-License-Identifier: Apache-2.0 AND MIT

#include "qudo_fips_hmac.h"
#include "qudo_fips_aes.h"
#include <string.h>

void qudo_fips_hmac_init(qudo_fips_hmac_ctx_t *ctx, const uint8_t *key,
                         size_t key_len)
{
    int i;
    unsigned int keytmp_length;
    uint8_t keytmp[QUDO_FIPS_HMAC_MAX_MD_CBLOCK_SIZE];
    uint8_t pad[QUDO_FIPS_HMAC_MAX_MD_CBLOCK_SIZE];

    if (ctx == NULL)
        return;
    ctx->initialized = 0;
    if (key == NULL)
        return;

    ctx->block_size = QUDO_FIPS_HMAC_SHA256_BLOCK_SIZE;
    ctx->digest_size = QUDO_FIPS_HMAC_SHA256_DIGEST_SIZE;

    if (key_len > (size_t)ctx->block_size) {
        sha2_256(keytmp, key, key_len);
        keytmp_length = (unsigned int)ctx->digest_size;
    } else {
        memcpy(keytmp, key, key_len);
        keytmp_length = (unsigned int)key_len;
    }

    if (keytmp_length != (unsigned int)ctx->block_size)
        memset(&keytmp[keytmp_length], 0,
               (size_t)ctx->block_size - keytmp_length);

    for (i = 0; i < ctx->block_size; i++)
        pad[i] = 0x36 ^ keytmp[i];

    sha2_256_init(&ctx->i_ctx);
    sha2_256_update(&ctx->i_ctx, pad, (size_t)ctx->block_size);

    for (i = 0; i < ctx->block_size; i++)
        pad[i] = 0x5c ^ keytmp[i];

    sha2_256_init(&ctx->o_ctx);
    sha2_256_update(&ctx->o_ctx, pad, (size_t)ctx->block_size);

    memcpy(&ctx->md_ctx, &ctx->i_ctx, sizeof(sha2_256_t));

    ctx->initialized = 1;

    qudo_secure_clear(keytmp, sizeof(keytmp));
    qudo_secure_clear(pad, sizeof(pad));
}

void qudo_fips_hmac_update(qudo_fips_hmac_ctx_t *ctx, const uint8_t *data,
                           size_t data_len)
{
    if (ctx == NULL || !ctx->initialized)
        return;
    sha2_256_update(&ctx->md_ctx, data, data_len);
}

void qudo_fips_hmac_final(qudo_fips_hmac_ctx_t *ctx, uint8_t out[32])
{
    uint8_t buf[QUDO_FIPS_HMAC_SHA256_DIGEST_SIZE];

    if (ctx == NULL || !ctx->initialized)
        return;

    sha2_256_final(&ctx->md_ctx, buf);

    memcpy(&ctx->md_ctx, &ctx->o_ctx, sizeof(sha2_256_t));

    sha2_256_update(&ctx->md_ctx, buf, (size_t)ctx->digest_size);

    sha2_256_final(&ctx->md_ctx, out);

    qudo_secure_clear(buf, sizeof(buf));
    qudo_secure_clear(ctx, sizeof(*ctx));
}

void qudo_fips_hmac_sha256(const uint8_t *key, size_t key_len,
                           const uint8_t *data, size_t data_len,
                           uint8_t out[32])
{
    qudo_fips_hmac_ctx_t ctx;

    qudo_fips_hmac_init(&ctx, key, key_len);
    qudo_fips_hmac_update(&ctx, data, data_len);
    qudo_fips_hmac_final(&ctx, out);
}
