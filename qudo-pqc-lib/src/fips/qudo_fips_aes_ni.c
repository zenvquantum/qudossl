// SPDX-License-Identifier: Apache-2.0 AND MIT

#include "qudo_fips_aes.h"

#if defined(__x86_64__) || defined(_M_X64) || defined(__i386__) \
    || defined(_M_IX86)

#    if defined(_MSC_VER)
#        include <intrin.h>
#    else
#        include <smmintrin.h>
#        include <wmmintrin.h>
#    endif

static inline __m128i aes_128_assist(__m128i temp1, __m128i temp2)
{
    temp2 = _mm_shuffle_epi32(temp2, 0xff);
    __m128i temp3 = _mm_slli_si128(temp1, 0x4);
    temp1 = _mm_xor_si128(temp1, temp3);
    temp3 = _mm_slli_si128(temp3, 0x4);
    temp1 = _mm_xor_si128(temp1, temp3);
    temp3 = _mm_slli_si128(temp3, 0x4);
    temp1 = _mm_xor_si128(temp1, temp3);
    temp1 = _mm_xor_si128(temp1, temp2);
    return temp1;
}

static inline void aes_192_assist(__m128i *temp1, __m128i *temp2,
                                  __m128i *temp3)
{
    __m128i temp4;
    *temp3 = _mm_shuffle_epi32(*temp3, 0x55);
    temp4 = _mm_slli_si128(*temp1, 0x4);
    *temp1 = _mm_xor_si128(*temp1, temp4);
    temp4 = _mm_slli_si128(temp4, 0x4);
    *temp1 = _mm_xor_si128(*temp1, temp4);
    temp4 = _mm_slli_si128(temp4, 0x4);
    *temp1 = _mm_xor_si128(*temp1, temp4);
    *temp1 = _mm_xor_si128(*temp1, *temp3);
    *temp3 = _mm_shuffle_epi32(*temp1, 0xff);
    temp4 = _mm_slli_si128(*temp2, 0x4);
    *temp2 = _mm_xor_si128(*temp2, temp4);
    *temp2 = _mm_xor_si128(*temp2, *temp3);
}

static inline void aes_256_assist_1(__m128i *temp1, __m128i *temp2)
{
    __m128i temp4;
    *temp2 = _mm_shuffle_epi32(*temp2, 0xff);
    temp4 = _mm_slli_si128(*temp1, 0x4);
    *temp1 = _mm_xor_si128(*temp1, temp4);
    temp4 = _mm_slli_si128(temp4, 0x4);
    *temp1 = _mm_xor_si128(*temp1, temp4);
    temp4 = _mm_slli_si128(temp4, 0x4);
    *temp1 = _mm_xor_si128(*temp1, temp4);
    *temp1 = _mm_xor_si128(*temp1, *temp2);
}

static inline void aes_256_assist_2(__m128i *temp1, __m128i *temp3)
{
    __m128i temp2, temp4;
    temp4 = _mm_aeskeygenassist_si128(*temp1, 0x0);
    temp2 = _mm_shuffle_epi32(temp4, 0xaa);
    temp4 = _mm_slli_si128(*temp3, 0x4);
    *temp3 = _mm_xor_si128(*temp3, temp4);
    temp4 = _mm_slli_si128(temp4, 0x4);
    *temp3 = _mm_xor_si128(*temp3, temp4);
    temp4 = _mm_slli_si128(temp4, 0x4);
    *temp3 = _mm_xor_si128(*temp3, temp4);
    *temp3 = _mm_xor_si128(*temp3, temp2);
}

int qudo_aes_ni_set_encrypt_key(const uint8_t *userKey, int bits,
                                qudo_aes_key_t *key)
{
    __m128i *rk;

    if (!userKey || !key)
        return -1;
    if (bits != 128 && bits != 192 && bits != 256)
        return -2;

    rk = (__m128i *)key->rd_key;

    if (bits == 128) {
        __m128i temp1 = _mm_loadu_si128((const __m128i *)userKey);
        key->rounds = 10;
        rk[0] = temp1;
        rk[1] = temp1
            = aes_128_assist(temp1, _mm_aeskeygenassist_si128(temp1, 0x01));
        rk[2] = temp1
            = aes_128_assist(temp1, _mm_aeskeygenassist_si128(temp1, 0x02));
        rk[3] = temp1
            = aes_128_assist(temp1, _mm_aeskeygenassist_si128(temp1, 0x04));
        rk[4] = temp1
            = aes_128_assist(temp1, _mm_aeskeygenassist_si128(temp1, 0x08));
        rk[5] = temp1
            = aes_128_assist(temp1, _mm_aeskeygenassist_si128(temp1, 0x10));
        rk[6] = temp1
            = aes_128_assist(temp1, _mm_aeskeygenassist_si128(temp1, 0x20));
        rk[7] = temp1
            = aes_128_assist(temp1, _mm_aeskeygenassist_si128(temp1, 0x40));
        rk[8] = temp1
            = aes_128_assist(temp1, _mm_aeskeygenassist_si128(temp1, 0x80));
        rk[9] = temp1
            = aes_128_assist(temp1, _mm_aeskeygenassist_si128(temp1, 0x1b));
        rk[10] = aes_128_assist(temp1, _mm_aeskeygenassist_si128(temp1, 0x36));
        return 0;
    }

    if (bits == 192) {
        __m128i temp1 = _mm_loadu_si128((const __m128i *)userKey);
        __m128i temp2 = _mm_loadu_si128((const __m128i *)(userKey + 16));
        __m128i temp3;
        key->rounds = 12;

        rk[0] = temp1;
        rk[1] = temp2;

        temp3 = _mm_aeskeygenassist_si128(temp2, 0x1);
        aes_192_assist(&temp1, &temp2, &temp3);
        rk[1] = _mm_castpd_si128(_mm_shuffle_pd(_mm_castsi128_pd(rk[1]),
                                                _mm_castsi128_pd(temp1), 0));
        rk[2] = _mm_castpd_si128(_mm_shuffle_pd(_mm_castsi128_pd(temp1),
                                                _mm_castsi128_pd(temp2), 1));

        temp3 = _mm_aeskeygenassist_si128(temp2, 0x2);
        aes_192_assist(&temp1, &temp2, &temp3);
        rk[3] = temp1;
        rk[4] = temp2;

        temp3 = _mm_aeskeygenassist_si128(temp2, 0x4);
        aes_192_assist(&temp1, &temp2, &temp3);
        rk[4] = _mm_castpd_si128(_mm_shuffle_pd(_mm_castsi128_pd(rk[4]),
                                                _mm_castsi128_pd(temp1), 0));
        rk[5] = _mm_castpd_si128(_mm_shuffle_pd(_mm_castsi128_pd(temp1),
                                                _mm_castsi128_pd(temp2), 1));

        temp3 = _mm_aeskeygenassist_si128(temp2, 0x8);
        aes_192_assist(&temp1, &temp2, &temp3);
        rk[6] = temp1;
        rk[7] = temp2;

        temp3 = _mm_aeskeygenassist_si128(temp2, 0x10);
        aes_192_assist(&temp1, &temp2, &temp3);
        rk[7] = _mm_castpd_si128(_mm_shuffle_pd(_mm_castsi128_pd(rk[7]),
                                                _mm_castsi128_pd(temp1), 0));
        rk[8] = _mm_castpd_si128(_mm_shuffle_pd(_mm_castsi128_pd(temp1),
                                                _mm_castsi128_pd(temp2), 1));

        temp3 = _mm_aeskeygenassist_si128(temp2, 0x20);
        aes_192_assist(&temp1, &temp2, &temp3);
        rk[9] = temp1;
        rk[10] = temp2;

        temp3 = _mm_aeskeygenassist_si128(temp2, 0x40);
        aes_192_assist(&temp1, &temp2, &temp3);
        rk[10] = _mm_castpd_si128(_mm_shuffle_pd(_mm_castsi128_pd(rk[10]),
                                                 _mm_castsi128_pd(temp1), 0));
        rk[11] = _mm_castpd_si128(_mm_shuffle_pd(_mm_castsi128_pd(temp1),
                                                 _mm_castsi128_pd(temp2), 1));

        temp3 = _mm_aeskeygenassist_si128(temp2, 0x80);
        aes_192_assist(&temp1, &temp2, &temp3);
        rk[12] = temp1;
        return 0;
    }

    {
        __m128i temp1 = _mm_loadu_si128((const __m128i *)userKey);
        __m128i temp3 = _mm_loadu_si128((const __m128i *)(userKey + 16));
        __m128i temp2;
        key->rounds = 14;

        rk[0] = temp1;
        rk[1] = temp3;

        temp2 = _mm_aeskeygenassist_si128(temp3, 0x01);
        aes_256_assist_1(&temp1, &temp2);
        rk[2] = temp1;
        aes_256_assist_2(&temp1, &temp3);
        rk[3] = temp3;

        temp2 = _mm_aeskeygenassist_si128(temp3, 0x02);
        aes_256_assist_1(&temp1, &temp2);
        rk[4] = temp1;
        aes_256_assist_2(&temp1, &temp3);
        rk[5] = temp3;

        temp2 = _mm_aeskeygenassist_si128(temp3, 0x04);
        aes_256_assist_1(&temp1, &temp2);
        rk[6] = temp1;
        aes_256_assist_2(&temp1, &temp3);
        rk[7] = temp3;

        temp2 = _mm_aeskeygenassist_si128(temp3, 0x08);
        aes_256_assist_1(&temp1, &temp2);
        rk[8] = temp1;
        aes_256_assist_2(&temp1, &temp3);
        rk[9] = temp3;

        temp2 = _mm_aeskeygenassist_si128(temp3, 0x10);
        aes_256_assist_1(&temp1, &temp2);
        rk[10] = temp1;
        aes_256_assist_2(&temp1, &temp3);
        rk[11] = temp3;

        temp2 = _mm_aeskeygenassist_si128(temp3, 0x20);
        aes_256_assist_1(&temp1, &temp2);
        rk[12] = temp1;
        aes_256_assist_2(&temp1, &temp3);
        rk[13] = temp3;

        temp2 = _mm_aeskeygenassist_si128(temp3, 0x40);
        aes_256_assist_1(&temp1, &temp2);
        rk[14] = temp1;
        return 0;
    }
}

void qudo_aes_ni_encrypt(const uint8_t *in, uint8_t *out,
                         const qudo_aes_key_t *key)
{
    const __m128i *rk = (const __m128i *)key->rd_key;
    int nr = key->rounds;

    __m128i block = _mm_loadu_si128((const __m128i *)in);

    block = _mm_xor_si128(block, rk[0]);

    block = _mm_aesenc_si128(block, rk[1]);
    block = _mm_aesenc_si128(block, rk[2]);
    block = _mm_aesenc_si128(block, rk[3]);
    block = _mm_aesenc_si128(block, rk[4]);
    block = _mm_aesenc_si128(block, rk[5]);
    block = _mm_aesenc_si128(block, rk[6]);
    block = _mm_aesenc_si128(block, rk[7]);
    block = _mm_aesenc_si128(block, rk[8]);
    block = _mm_aesenc_si128(block, rk[9]);

    if (nr > 10) {
        block = _mm_aesenc_si128(block, rk[10]);
        block = _mm_aesenc_si128(block, rk[11]);
    }
    if (nr > 12) {
        block = _mm_aesenc_si128(block, rk[12]);
        block = _mm_aesenc_si128(block, rk[13]);
    }

    block = _mm_aesenclast_si128(block, rk[nr]);

    _mm_storeu_si128((__m128i *)out, block);
}

#endif
