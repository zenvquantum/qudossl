/* SPDX-License-Identifier: Apache-2.0 AND MIT */

#include <string.h>
#include <stdint.h>
#include <openssl/evp.h>
#include <openssl/aes.h>
#include "nist_drbg.h"

#define AES256_KEYLEN 32
#define AES_BLOCKLEN 16

typedef struct {
    uint8_t Key[AES256_KEYLEN];
    uint8_t V[AES_BLOCKLEN];
    int reseed_counter;
} NIST_DRBG_CTX;

static NIST_DRBG_CTX drbg_ctx;

static void AES256_ECB(const uint8_t *key, const uint8_t *in, uint8_t *out) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    int len;

    EVP_EncryptInit_ex(ctx, EVP_aes_256_ecb(), NULL, key, NULL);
    EVP_CIPHER_CTX_set_padding(ctx, 0);
    EVP_EncryptUpdate(ctx, out, &len, in, AES_BLOCKLEN);

    EVP_CIPHER_CTX_free(ctx);
}

static void increment_V(uint8_t *V) {
    for (int i = AES_BLOCKLEN - 1; i >= 0; i--) {
        if (++V[i] != 0) {
            break;
        }
    }
}

static void DRBG_Update(const uint8_t *provided_data, uint8_t *Key, uint8_t *V) {
    uint8_t temp[AES256_KEYLEN + AES_BLOCKLEN];

    for (int i = 0; i < (AES256_KEYLEN + AES_BLOCKLEN) / AES_BLOCKLEN; i++) {
        increment_V(V);
        AES256_ECB(Key, V, temp + i * AES_BLOCKLEN);
    }

    if (provided_data != NULL) {
        for (int i = 0; i < AES256_KEYLEN + AES_BLOCKLEN; i++) {
            temp[i] ^= provided_data[i];
        }
    }

    memcpy(Key, temp, AES256_KEYLEN);
    memcpy(V, temp + AES256_KEYLEN, AES_BLOCKLEN);
}

void nist_drbg_init(const uint8_t *entropy_input, const uint8_t *personalization_string) {
    uint8_t seed_material[48];

    memcpy(seed_material, entropy_input, 48);
    if (personalization_string) {
        for (int i = 0; i < 48; i++) {
            seed_material[i] ^= personalization_string[i];
        }
    }

    memset(drbg_ctx.Key, 0x00, AES256_KEYLEN);
    memset(drbg_ctx.V, 0x00, AES_BLOCKLEN);

    DRBG_Update(seed_material, drbg_ctx.Key, drbg_ctx.V);
    drbg_ctx.reseed_counter = 1;
}

int nist_drbg_generate(uint8_t *out, size_t outlen) {
    uint8_t block[AES_BLOCKLEN];

    while (outlen > 0) {
        increment_V(drbg_ctx.V);
        AES256_ECB(drbg_ctx.Key, drbg_ctx.V, block);

        size_t use_len = (outlen < AES_BLOCKLEN) ? outlen : AES_BLOCKLEN;
        memcpy(out, block, use_len);

        out += use_len;
        outlen -= use_len;
    }

    DRBG_Update(NULL, drbg_ctx.Key, drbg_ctx.V);
    drbg_ctx.reseed_counter++;

    return 0;
}
