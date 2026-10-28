// SPDX-License-Identifier: Apache-2.0 AND MIT

#ifndef QUDO_FIPS_HMAC_H
#define QUDO_FIPS_HMAC_H

#include "qudo_fips_sha2.h"
#include <stddef.h>
#include <stdint.h>

#ifndef QUDO_PQC_API
#    if defined(_WIN32) || defined(__CYGWIN__)
#        if defined(QUDO_PQC_STATIC_LINK)
#            define QUDO_PQC_API
#        elif defined(QUDO_PQC_BUILDING)
#            define QUDO_PQC_API __declspec(dllexport)
#        else
#            define QUDO_PQC_API __declspec(dllimport)
#        endif
#    elif defined(__GNUC__) && __GNUC__ >= 4
#        define QUDO_PQC_API __attribute__((visibility("default")))
#    else
#        define QUDO_PQC_API
#    endif
#endif

#ifdef __cplusplus
extern "C" {
#endif

#define QUDO_FIPS_HMAC_MAX_MD_CBLOCK_SIZE 144

#define QUDO_FIPS_HMAC_SHA256_BLOCK_SIZE  64
#define QUDO_FIPS_HMAC_SHA256_DIGEST_SIZE 32

typedef struct {
    sha2_256_t i_ctx;
    sha2_256_t o_ctx;
    sha2_256_t md_ctx;
    int block_size;
    int digest_size;
    int initialized;
} qudo_fips_hmac_ctx_t;

QUDO_PQC_API void qudo_fips_hmac_sha256(const uint8_t *key, size_t key_len,
                                        const uint8_t *data, size_t data_len,
                                        uint8_t out[32]);

QUDO_PQC_API void qudo_fips_hmac_init(qudo_fips_hmac_ctx_t *ctx,
                                      const uint8_t *key, size_t key_len);

QUDO_PQC_API void qudo_fips_hmac_update(qudo_fips_hmac_ctx_t *ctx,
                                        const uint8_t *data, size_t data_len);

QUDO_PQC_API void qudo_fips_hmac_final(qudo_fips_hmac_ctx_t *ctx,
                                       uint8_t out[32]);

#ifdef __cplusplus
}
#endif

#endif
