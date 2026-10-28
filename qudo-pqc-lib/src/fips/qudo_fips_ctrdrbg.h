// SPDX-License-Identifier: Apache-2.0 AND MIT

#ifndef QUDO_FIPS_CTRDRBG_H
#define QUDO_FIPS_CTRDRBG_H

#ifndef QUDO_PQC_API
#    if defined(__GNUC__) && __GNUC__ >= 4
#        define QUDO_PQC_API __attribute__((visibility("default")))
#    else
#        define QUDO_PQC_API
#    endif
#endif

#include "qudo_fips_aes.h"
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define QUDO_CTRDRBG_MAX_SEEDLEN 48
#define QUDO_CTRDRBG_MAX_KEYLEN  32
#define QUDO_CTRDRBG_BLOCKLEN    16
#define QUDO_CTRDRBG_MAX_REQUEST 65536

#define QUDO_CTRDRBG_SEEDLEN 48

typedef struct {
    qudo_aes_key_t aes;
    uint8_t V[QUDO_CTRDRBG_BLOCKLEN];
    uint8_t K[QUDO_CTRDRBG_MAX_KEYLEN];
    size_t keylen;
    size_t seedlen;
    int initialized;
} qudo_ctrdrbg_ctx_t;

QUDO_PQC_API int qudo_ctrdrbg_init(qudo_ctrdrbg_ctx_t *ctx, size_t keylen,
                                   const uint8_t *seed, size_t seedlen);

QUDO_PQC_API int qudo_ctrdrbg_generate(qudo_ctrdrbg_ctx_t *ctx, uint8_t *out,
                                       size_t out_len,
                                       const uint8_t *additional,
                                       size_t additional_len);

QUDO_PQC_API int qudo_ctrdrbg_reseed(qudo_ctrdrbg_ctx_t *ctx,
                                     const uint8_t *seed, size_t seedlen);

QUDO_PQC_API void qudo_ctrdrbg_free(qudo_ctrdrbg_ctx_t *ctx);

#ifdef __cplusplus
}
#endif

#endif
