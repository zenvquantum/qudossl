// SPDX-License-Identifier: Apache-2.0 AND MIT

#include "qudo_fips_aes.h"
#include <string.h>

typedef uint32_t u32;
typedef uint8_t u8;

#define GETU32(pt)                                                     \
    (((u32)(pt)[0] << 24) ^ ((u32)(pt)[1] << 16) ^ ((u32)(pt)[2] << 8) \
     ^ ((u32)(pt)[3]))

#define PUTU32(ct, st)              \
    {                               \
        (ct)[0] = (u8)((st) >> 24); \
        (ct)[1] = (u8)((st) >> 16); \
        (ct)[2] = (u8)((st) >> 8);  \
        (ct)[3] = (u8)(st);         \
    }

static const u8 SBOX[256] = {
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b,
    0xfe, 0xd7, 0xab, 0x76, 0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0,
    0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0, 0xb7, 0xfd, 0x93, 0x26,
    0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2,
    0xeb, 0x27, 0xb2, 0x75, 0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0,
    0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84, 0x53, 0xd1, 0x00, 0xed,
    0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f,
    0x50, 0x3c, 0x9f, 0xa8, 0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5,
    0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2, 0xcd, 0x0c, 0x13, 0xec,
    0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14,
    0xde, 0x5e, 0x0b, 0xdb, 0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c,
    0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79, 0xe7, 0xc8, 0x37, 0x6d,
    0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f,
    0x4b, 0xbd, 0x8b, 0x8a, 0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e,
    0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e, 0xe1, 0xf8, 0x98, 0x11,
    0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f,
    0xb0, 0x54, 0xbb, 0x16,
};

static inline u8 ct_sbox(u8 x)
{
    u8 result = 0;
    unsigned i;
    for (i = 0; i < 256; i++) {
        unsigned diff = (unsigned)x ^ i;
        unsigned mask = ((diff - 1) >> 8) & 0xFF;
        result |= (u8)(SBOX[i] & mask);
    }
    return result;
}

static inline u32 ct_subword(u32 x)
{
    return ((u32)ct_sbox((u8)(x >> 24)) << 24)
           | ((u32)ct_sbox((u8)(x >> 16)) << 16)
           | ((u32)ct_sbox((u8)(x >> 8)) << 8) | ((u32)ct_sbox((u8)(x)));
}

static inline u32 ct_rotword(u32 x)
{
    return (x << 8) | (x >> 24);
}

static const u32 rcon[] = {
    0x01000000, 0x02000000, 0x04000000, 0x08000000, 0x10000000,
    0x20000000, 0x40000000, 0x80000000, 0x1B000000, 0x36000000,
};

int qudo_aes_ct_set_encrypt_key(const uint8_t *userKey, int bits,
                                qudo_aes_key_t *key)
{
    u32 *rk;
    int i = 0;
    u32 temp;

    if (!userKey || !key)
        return -1;
    if (bits != 128 && bits != 192 && bits != 256)
        return -2;

    rk = key->rd_key;

    if (bits == 128) {
        key->rounds = 10;
        rk[0] = GETU32(userKey);
        rk[1] = GETU32(userKey + 4);
        rk[2] = GETU32(userKey + 8);
        rk[3] = GETU32(userKey + 12);
        while (1) {
            temp = rk[3];
            rk[4] = rk[0] ^ ct_subword(ct_rotword(temp)) ^ rcon[i];
            rk[5] = rk[1] ^ rk[4];
            rk[6] = rk[2] ^ rk[5];
            rk[7] = rk[3] ^ rk[6];
            if (++i == 10)
                return 0;
            rk += 4;
        }
    }

    rk[0] = GETU32(userKey);
    rk[1] = GETU32(userKey + 4);
    rk[2] = GETU32(userKey + 8);
    rk[3] = GETU32(userKey + 12);

    if (bits == 192) {
        key->rounds = 12;
        rk[4] = GETU32(userKey + 16);
        rk[5] = GETU32(userKey + 20);
        while (1) {
            temp = rk[5];
            rk[6] = rk[0] ^ ct_subword(ct_rotword(temp)) ^ rcon[i];
            rk[7] = rk[1] ^ rk[6];
            rk[8] = rk[2] ^ rk[7];
            rk[9] = rk[3] ^ rk[8];
            if (++i == 8)
                return 0;
            rk[10] = rk[4] ^ rk[9];
            rk[11] = rk[5] ^ rk[10];
            rk += 6;
        }
    }

    key->rounds = 14;
    rk[4] = GETU32(userKey + 16);
    rk[5] = GETU32(userKey + 20);
    rk[6] = GETU32(userKey + 24);
    rk[7] = GETU32(userKey + 28);
    while (1) {
        temp = rk[7];
        rk[8] = rk[0] ^ ct_subword(ct_rotword(temp)) ^ rcon[i];
        rk[9] = rk[1] ^ rk[8];
        rk[10] = rk[2] ^ rk[9];
        rk[11] = rk[3] ^ rk[10];
        if (++i == 7)
            return 0;
        temp = rk[11];
        rk[12] = rk[4] ^ ct_subword(temp);
        rk[13] = rk[5] ^ rk[12];
        rk[14] = rk[6] ^ rk[13];
        rk[15] = rk[7] ^ rk[14];
        rk += 8;
    }
}

static inline u8 xtime(u8 x)
{
    return (u8)((x << 1) ^ (((x >> 7) & 1) * 0x1b));
}

void qudo_aes_ct_encrypt(const uint8_t *in, uint8_t *out,
                         const qudo_aes_key_t *key)
{
    u8 state[16];
    const u32 *rk = key->rd_key;
    int nr = key->rounds;
    int round;

    {
        u32 w0 = GETU32(in) ^ rk[0];
        u32 w1 = GETU32(in + 4) ^ rk[1];
        u32 w2 = GETU32(in + 8) ^ rk[2];
        u32 w3 = GETU32(in + 12) ^ rk[3];
        state[0] = (u8)(w0 >> 24);
        state[1] = (u8)(w0 >> 16);
        state[2] = (u8)(w0 >> 8);
        state[3] = (u8)(w0);
        state[4] = (u8)(w1 >> 24);
        state[5] = (u8)(w1 >> 16);
        state[6] = (u8)(w1 >> 8);
        state[7] = (u8)(w1);
        state[8] = (u8)(w2 >> 24);
        state[9] = (u8)(w2 >> 16);
        state[10] = (u8)(w2 >> 8);
        state[11] = (u8)(w2);
        state[12] = (u8)(w3 >> 24);
        state[13] = (u8)(w3 >> 16);
        state[14] = (u8)(w3 >> 8);
        state[15] = (u8)(w3);
    }

    for (round = 1; round <= nr; round++) {
        u8 tmp[16];
        u8 t;

        int i;
        for (i = 0; i < 16; i++)
            tmp[i] = ct_sbox(state[i]);

        state[0] = tmp[0];
        state[4] = tmp[4];
        state[8] = tmp[8];
        state[12] = tmp[12];
        state[1] = tmp[5];
        state[5] = tmp[9];
        state[9] = tmp[13];
        state[13] = tmp[1];
        state[2] = tmp[10];
        state[6] = tmp[14];
        state[10] = tmp[2];
        state[14] = tmp[6];
        state[3] = tmp[15];
        state[7] = tmp[3];
        state[11] = tmp[7];
        state[15] = tmp[11];

        if (round < nr) {
            int c;
            for (c = 0; c < 4; c++) {
                int off = c * 4;
                u8 s0 = state[off], s1 = state[off + 1], s2 = state[off + 2],
                   s3 = state[off + 3];
                t = s0 ^ s1 ^ s2 ^ s3;
                state[off] = s0 ^ xtime(s0 ^ s1) ^ t;
                state[off + 1] = s1 ^ xtime(s1 ^ s2) ^ t;
                state[off + 2] = s2 ^ xtime(s2 ^ s3) ^ t;
                state[off + 3] = s3 ^ xtime(s3 ^ s0) ^ t;
            }
        }

        {
            const u32 *rkr = rk + round * 4;
            u32 k0 = rkr[0], k1 = rkr[1], k2 = rkr[2], k3 = rkr[3];
            state[0] ^= (u8)(k0 >> 24);
            state[1] ^= (u8)(k0 >> 16);
            state[2] ^= (u8)(k0 >> 8);
            state[3] ^= (u8)(k0);
            state[4] ^= (u8)(k1 >> 24);
            state[5] ^= (u8)(k1 >> 16);
            state[6] ^= (u8)(k1 >> 8);
            state[7] ^= (u8)(k1);
            state[8] ^= (u8)(k2 >> 24);
            state[9] ^= (u8)(k2 >> 16);
            state[10] ^= (u8)(k2 >> 8);
            state[11] ^= (u8)(k2);
            state[12] ^= (u8)(k3 >> 24);
            state[13] ^= (u8)(k3 >> 16);
            state[14] ^= (u8)(k3 >> 8);
            state[15] ^= (u8)(k3);
        }
    }

    memcpy(out, state, 16);

    qudo_secure_clear(state, sizeof(state));
}
