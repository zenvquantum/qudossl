// SPDX-License-Identifier: Apache-2.0 AND MIT

#ifndef QUDO_FIPS_AES_H
#define QUDO_FIPS_AES_H

#ifndef QUDO_PQC_API
#    if defined(__GNUC__) && __GNUC__ >= 4
#        define QUDO_PQC_API __attribute__((visibility("default")))
#    else
#        define QUDO_PQC_API
#    endif
#endif

#include <stddef.h>
#include <stdint.h>

#include <string.h>
#if defined(_WIN32)
#    include <windows.h>
#    define qudo_secure_clear(ptr, len) SecureZeroMemory((ptr), (len))
#elif defined(__STDC_LIB_EXT1__)
#    define qudo_secure_clear(ptr, len) memset_s((ptr), (len), 0, (len))
#elif defined(__OpenBSD__) \
    || (defined(__GLIBC__) \
        && (__GLIBC__ > 2 || (__GLIBC__ == 2 && __GLIBC_MINOR__ >= 25)))
#    define qudo_secure_clear(ptr, len) explicit_bzero((ptr), (len))
#else
static inline void qudo_secure_clear(void *ptr, size_t len)
{
    typedef void *(*memset_fn)(void *, int, size_t);
    static volatile memset_fn secure_memset = memset;
    secure_memset(ptr, 0, len);
#    if defined(__GNUC__) || defined(__clang__)
    __asm__ __volatile__("" ::: "memory");
#    endif
}
#endif

#ifdef __cplusplus
extern "C" {
#endif

#define QUDO_AES_MAXNR      14
#define QUDO_AES_BLOCK_SIZE 16

#define QUDO_AES256_KEY_SIZE   32
#define QUDO_AES256_BLOCK_SIZE 16
#define QUDO_AES256_ROUNDS     14

typedef struct {
#if defined(__GNUC__) || defined(__clang__)
    uint32_t rd_key[4 * (QUDO_AES_MAXNR + 1)] __attribute__((aligned(16)));
#elif defined(_MSC_VER)
    __declspec(align(16)) uint32_t rd_key[4 * (QUDO_AES_MAXNR + 1)];
#else
    uint32_t rd_key[4 * (QUDO_AES_MAXNR + 1)];
#endif
    int rounds;
} qudo_aes_key_t;

typedef qudo_aes_key_t qudo_aes256_ctx_t;

QUDO_PQC_API int qudo_aes_set_encrypt_key(const uint8_t *key, int bits,
                                          qudo_aes_key_t *ctx);

QUDO_PQC_API void qudo_aes_encrypt(const uint8_t *in, uint8_t *out,
                                   const qudo_aes_key_t *ctx);

static inline void qudo_aes256_init(qudo_aes256_ctx_t *ctx,
                                    const uint8_t key[32])
{
    qudo_aes_set_encrypt_key(key, 256, ctx);
}

static inline void qudo_aes256_encrypt(const qudo_aes256_ctx_t *ctx,
                                       const uint8_t in[16], uint8_t out[16])
{
    qudo_aes_encrypt(in, out, ctx);
}

#ifdef __cplusplus
}
#endif

#endif
