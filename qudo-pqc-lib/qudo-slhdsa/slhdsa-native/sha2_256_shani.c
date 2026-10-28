/*
 * Based on the noloader/SHA-Intrinsics reference implementation.
 *
 * SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT
 */

#if defined(__x86_64__) || defined(__i386__)

/* Global compile flags may not include -msha, so enable it for this unit. */
#pragma GCC target("sha,sse4.1,ssse3")

#include <immintrin.h>
#include <stdint.h>

static const uint32_t K256[64] __attribute__((aligned(16))) = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
    0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
    0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
    0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
    0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
    0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
};

void sha2_256_compress_shani(void *v)
{
    uint32_t *sp = (uint32_t *)v;

    const __m128i SHUF_MASK = _mm_set_epi64x(
        0x0c0d0e0f08090a0bULL, 0x0405060700010203ULL);

    __m128i STATE0, STATE1, MSG, TMP;
    __m128i MSG0, MSG1, MSG2, MSG3;
    __m128i ABEF_SAVE, CDGH_SAVE;

    TMP    = _mm_shuffle_epi8(_mm_loadu_si128((__m128i *)(sp + 0)), SHUF_MASK);
    STATE1 = _mm_shuffle_epi8(_mm_loadu_si128((__m128i *)(sp + 4)), SHUF_MASK);

    TMP    = _mm_shuffle_epi32(TMP, 0xB1);
    STATE1 = _mm_shuffle_epi32(STATE1, 0x1B);
    STATE0 = _mm_alignr_epi8(TMP, STATE1, 8);
    STATE1 = _mm_blend_epi16(STATE1, TMP, 0xF0);

    ABEF_SAVE = STATE0;
    CDGH_SAVE = STATE1;

    MSG0 = _mm_shuffle_epi8(_mm_loadu_si128((__m128i *)(sp + 8)),  SHUF_MASK);
    MSG1 = _mm_shuffle_epi8(_mm_loadu_si128((__m128i *)(sp + 12)), SHUF_MASK);
    MSG2 = _mm_shuffle_epi8(_mm_loadu_si128((__m128i *)(sp + 16)), SHUF_MASK);
    MSG3 = _mm_shuffle_epi8(_mm_loadu_si128((__m128i *)(sp + 20)), SHUF_MASK);

    MSG = _mm_add_epi32(MSG0, _mm_load_si128((__m128i *)&K256[0]));
    STATE1 = _mm_sha256rnds2_epu32(STATE1, STATE0, MSG);
    MSG = _mm_shuffle_epi32(MSG, 0x0E);
    STATE0 = _mm_sha256rnds2_epu32(STATE0, STATE1, MSG);

    /*
     * sha256msg1 is applied to the message block of the previous round group,
     * so alignr in the next group still reads unmodified values.
     */
    MSG = _mm_add_epi32(MSG1, _mm_load_si128((__m128i *)&K256[4]));
    STATE1 = _mm_sha256rnds2_epu32(STATE1, STATE0, MSG);
    MSG = _mm_shuffle_epi32(MSG, 0x0E);
    STATE0 = _mm_sha256rnds2_epu32(STATE0, STATE1, MSG);
    MSG0 = _mm_sha256msg1_epu32(MSG0, MSG1);

    MSG = _mm_add_epi32(MSG2, _mm_load_si128((__m128i *)&K256[8]));
    STATE1 = _mm_sha256rnds2_epu32(STATE1, STATE0, MSG);
    MSG = _mm_shuffle_epi32(MSG, 0x0E);
    STATE0 = _mm_sha256rnds2_epu32(STATE0, STATE1, MSG);
    MSG1 = _mm_sha256msg1_epu32(MSG1, MSG2);

    /* MSG3 is left unmodified here: alignr in rounds 16-19 still needs it. */
    MSG = _mm_add_epi32(MSG3, _mm_load_si128((__m128i *)&K256[12]));
    STATE1 = _mm_sha256rnds2_epu32(STATE1, STATE0, MSG);
    TMP = _mm_alignr_epi8(MSG3, MSG2, 4);
    MSG0 = _mm_add_epi32(MSG0, TMP);
    MSG0 = _mm_sha256msg2_epu32(MSG0, MSG3);
    MSG = _mm_shuffle_epi32(MSG, 0x0E);
    STATE0 = _mm_sha256rnds2_epu32(STATE0, STATE1, MSG);
    MSG2 = _mm_sha256msg1_epu32(MSG2, MSG3);

    /* The final pass skips sha256msg1: no further message words are needed. */
    for (int k = 16; k < 64; k += 16) {
        MSG = _mm_add_epi32(MSG0, _mm_load_si128((__m128i *)&K256[k]));
        STATE1 = _mm_sha256rnds2_epu32(STATE1, STATE0, MSG);
        TMP = _mm_alignr_epi8(MSG0, MSG3, 4);
        MSG1 = _mm_add_epi32(MSG1, TMP);
        MSG1 = _mm_sha256msg2_epu32(MSG1, MSG0);
        MSG = _mm_shuffle_epi32(MSG, 0x0E);
        STATE0 = _mm_sha256rnds2_epu32(STATE0, STATE1, MSG);
        MSG3 = _mm_sha256msg1_epu32(MSG3, MSG0);

        MSG = _mm_add_epi32(MSG1, _mm_load_si128((__m128i *)&K256[k + 4]));
        STATE1 = _mm_sha256rnds2_epu32(STATE1, STATE0, MSG);
        TMP = _mm_alignr_epi8(MSG1, MSG0, 4);
        MSG2 = _mm_add_epi32(MSG2, TMP);
        MSG2 = _mm_sha256msg2_epu32(MSG2, MSG1);
        MSG = _mm_shuffle_epi32(MSG, 0x0E);
        STATE0 = _mm_sha256rnds2_epu32(STATE0, STATE1, MSG);
        if (k < 48) MSG0 = _mm_sha256msg1_epu32(MSG0, MSG1);

        MSG = _mm_add_epi32(MSG2, _mm_load_si128((__m128i *)&K256[k + 8]));
        STATE1 = _mm_sha256rnds2_epu32(STATE1, STATE0, MSG);
        TMP = _mm_alignr_epi8(MSG2, MSG1, 4);
        MSG3 = _mm_add_epi32(MSG3, TMP);
        MSG3 = _mm_sha256msg2_epu32(MSG3, MSG2);
        MSG = _mm_shuffle_epi32(MSG, 0x0E);
        STATE0 = _mm_sha256rnds2_epu32(STATE0, STATE1, MSG);
        if (k < 48) MSG1 = _mm_sha256msg1_epu32(MSG1, MSG2);

        MSG = _mm_add_epi32(MSG3, _mm_load_si128((__m128i *)&K256[k + 12]));
        STATE1 = _mm_sha256rnds2_epu32(STATE1, STATE0, MSG);
        TMP = _mm_alignr_epi8(MSG3, MSG2, 4);
        MSG0 = _mm_add_epi32(MSG0, TMP);
        MSG0 = _mm_sha256msg2_epu32(MSG0, MSG3);
        MSG = _mm_shuffle_epi32(MSG, 0x0E);
        STATE0 = _mm_sha256rnds2_epu32(STATE0, STATE1, MSG);
        if (k < 48) MSG2 = _mm_sha256msg1_epu32(MSG2, MSG3);
    }

    STATE0 = _mm_add_epi32(STATE0, ABEF_SAVE);
    STATE1 = _mm_add_epi32(STATE1, CDGH_SAVE);

    TMP    = _mm_shuffle_epi32(STATE0, 0x1B);
    STATE1 = _mm_shuffle_epi32(STATE1, 0xB1);
    STATE0 = _mm_blend_epi16(TMP, STATE1, 0xF0);
    STATE1 = _mm_alignr_epi8(STATE1, TMP, 8);

    _mm_storeu_si128((__m128i *)(sp + 0), _mm_shuffle_epi8(STATE0, SHUF_MASK));
    _mm_storeu_si128((__m128i *)(sp + 4), _mm_shuffle_epi8(STATE1, SHUF_MASK));
}

#endif /* __x86_64__ || __i386__ */
