/* SPDX-License-Identifier: Apache-2.0 AND MIT */

#include "../include/mldsa_wrapper.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef QUDO_MLDSA_USE_OPENSSL
#    include <openssl/bio.h>
#    include <openssl/buffer.h>
#    include <openssl/evp.h>
#    include <openssl/pem.h>
#endif

static const char mldsa_b64_alphabet[]
    = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

static int mldsa_b64_decode_char(char c)
{
    if (c >= 'A' && c <= 'Z')
        return c - 'A';
    if (c >= 'a' && c <= 'z')
        return c - 'a' + 26;
    if (c >= '0' && c <= '9')
        return c - '0' + 52;
    if (c == '+')
        return 62;
    if (c == '/')
        return 63;
    return -1;
}

#define MLDSA_PEM_LINE 64

static size_t mldsa_b64_encoded_len(size_t bin_len)
{
    size_t groups = (bin_len + 2) / 3;
    size_t b64 = groups * 4;
    size_t lines = (b64 + MLDSA_PEM_LINE - 1) / MLDSA_PEM_LINE;
    return b64 + lines;
}

static void mldsa_b64_encode_wrapped(const uint8_t *in, size_t in_len,
                                     char *out, size_t *out_pos)
{
    size_t col = 0;
    size_t i = 0;
    while (i + 3 <= in_len) {
        uint32_t v
            = ((uint32_t)in[i] << 16) | ((uint32_t)in[i + 1] << 8) | in[i + 2];
        out[(*out_pos)++] = mldsa_b64_alphabet[(v >> 18) & 0x3F];
        out[(*out_pos)++] = mldsa_b64_alphabet[(v >> 12) & 0x3F];
        out[(*out_pos)++] = mldsa_b64_alphabet[(v >> 6) & 0x3F];
        out[(*out_pos)++] = mldsa_b64_alphabet[v & 0x3F];
        col += 4;
        if (col >= MLDSA_PEM_LINE) {
            out[(*out_pos)++] = '\n';
            col = 0;
        }
        i += 3;
    }
    if (i < in_len) {
        uint32_t v = (uint32_t)in[i] << 16;
        if (i + 1 < in_len)
            v |= (uint32_t)in[i + 1] << 8;
        out[(*out_pos)++] = mldsa_b64_alphabet[(v >> 18) & 0x3F];
        out[(*out_pos)++] = mldsa_b64_alphabet[(v >> 12) & 0x3F];
        out[(*out_pos)++]
            = (i + 1 < in_len) ? mldsa_b64_alphabet[(v >> 6) & 0x3F] : '=';
        out[(*out_pos)++] = '=';
        col += 4;
    }
    if (col != 0)
        out[(*out_pos)++] = '\n';
}

static int mldsa_b64_decode(const char *in, size_t in_len, uint8_t *out,
                            size_t *out_len)
{
    size_t op = 0;
    unsigned int buf = 0;
    int buf_bits = 0;
    int pad = 0;
    for (size_t i = 0; i < in_len; i++) {
        char c = in[i];
        if (c == '\r' || c == '\n' || c == ' ' || c == '\t')
            continue;
        if (c == '=') {
            pad++;
            continue;
        }
        if (pad)
            return -1;
        int v = mldsa_b64_decode_char(c);
        if (v < 0)
            return -1;
        buf = (buf << 6) | (unsigned int)v;
        buf_bits += 6;
        if (buf_bits >= 8) {
            buf_bits -= 8;
            if (op >= *out_len)
                return -1;
            out[op++] = (uint8_t)((buf >> buf_bits) & 0xFF);
            buf &= (1u << buf_bits) - 1u;
        }
    }
    *out_len = op;
    return 0;
}

static const uint8_t OID_ML_DSA_44[]
    = {0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x11};

static const uint8_t OID_ML_DSA_65[]
    = {0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x12};

static const uint8_t OID_ML_DSA_87[]
    = {0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x13};

static const uint8_t *get_oid_for_public_key_size(size_t key_len,
                                                  size_t *oid_len)
{
    if (key_len == 1312) {
        *oid_len = sizeof(OID_ML_DSA_44);
        return OID_ML_DSA_44;
    } else if (key_len == 1952) {
        *oid_len = sizeof(OID_ML_DSA_65);
        return OID_ML_DSA_65;
    } else if (key_len == 2592) {
        *oid_len = sizeof(OID_ML_DSA_87);
        return OID_ML_DSA_87;
    }
    return NULL;
}

static size_t asn1_encode_length(uint8_t *out, size_t len)
{
    if (len < 128) {
        out[0] = (uint8_t)len;
        return 1;
    } else if (len <= 0xFF) {
        out[0] = 0x81;
        out[1] = (uint8_t)len;
        return 2;
    } else if (len <= 0xFFFF) {
        out[0] = 0x82;
        out[1] = (uint8_t)(len >> 8);
        out[2] = (uint8_t)(len & 0xFF);
        return 3;
    } else {
        out[0] = 0x83;
        out[1] = (uint8_t)(len >> 16);
        out[2] = (uint8_t)((len >> 8) & 0xFF);
        out[3] = (uint8_t)(len & 0xFF);
        return 4;
    }
}

static size_t asn1_decode_length(const uint8_t **p, const uint8_t *end,
                                 size_t *out_len)
{
    if (*p >= end)
        return 0;

    uint8_t first = *(*p)++;

    if (first < 128) {
        *out_len = first;
        return 1;
    } else {
        size_t num_bytes = first & 0x7F;
        if (num_bytes == 0 || num_bytes > 4 || num_bytes > (size_t)(end - *p)) {
            return 0;
        }

        *out_len = 0;
        for (size_t i = 0; i < num_bytes; i++) {
            *out_len = (*out_len << 8) | *(*p)++;
        }
        return 1 + num_bytes;
    }
}

static const uint8_t *get_oid_for_private_key_size(size_t key_len,
                                                   size_t *oid_len)
{

    if (key_len == ML_DSA_44_SECRET_KEY_BYTES
        || key_len == ML_DSA_44_SECRET_KEY_BYTES + ML_DSA_44_PUBLIC_KEY_BYTES
        || key_len == MLDSA_SEEDBYTES + ML_DSA_44_SECRET_KEY_BYTES) {
        *oid_len = sizeof(OID_ML_DSA_44);
        return OID_ML_DSA_44;
    } else if (key_len == ML_DSA_65_SECRET_KEY_BYTES
               || key_len
                      == ML_DSA_65_SECRET_KEY_BYTES + ML_DSA_65_PUBLIC_KEY_BYTES
               || key_len == MLDSA_SEEDBYTES + ML_DSA_65_SECRET_KEY_BYTES) {
        *oid_len = sizeof(OID_ML_DSA_65);
        return OID_ML_DSA_65;
    } else if (key_len == ML_DSA_87_SECRET_KEY_BYTES
               || key_len
                      == ML_DSA_87_SECRET_KEY_BYTES + ML_DSA_87_PUBLIC_KEY_BYTES
               || key_len == MLDSA_SEEDBYTES + ML_DSA_87_SECRET_KEY_BYTES) {
        *oid_len = sizeof(OID_ML_DSA_87);
        return OID_ML_DSA_87;
    }
    return NULL;
}

static QUDO_MLDSA_status_t build_seed_priv_inner(const uint8_t *seed,
                                                 const uint8_t *sk,
                                                 size_t sk_len, uint8_t *out,
                                                 size_t *out_len)
{
    size_t content_len = 34 + 4 + sk_len;
    size_t total_len = 4 + content_len;

    if (*out_len < total_len) {
        *out_len = total_len;
        return QUDO_MLDSA_ERROR_BUFFER_TOO_SMALL;
    }

    uint8_t *p = out;

    *p++ = 0x30;
    *p++ = 0x82;
    *p++ = (content_len >> 8) & 0xFF;
    *p++ = content_len & 0xFF;

    *p++ = 0x04;
    *p++ = 0x20;
    memcpy(p, seed, MLDSA_SEEDBYTES);
    p += MLDSA_SEEDBYTES;

    *p++ = 0x04;
    *p++ = 0x82;
    *p++ = (sk_len >> 8) & 0xFF;
    *p++ = sk_len & 0xFF;
    memcpy(p, sk, sk_len);

    *out_len = total_len;
    return QUDO_MLDSA_SUCCESS;
}

static size_t get_sk_len_from_seed_priv_inner_len(size_t inner_len)
{

    if (inner_len == 42 + ML_DSA_44_SECRET_KEY_BYTES)
        return ML_DSA_44_SECRET_KEY_BYTES;
    if (inner_len == 42 + ML_DSA_65_SECRET_KEY_BYTES)
        return ML_DSA_65_SECRET_KEY_BYTES;
    if (inner_len == 42 + ML_DSA_87_SECRET_KEY_BYTES)
        return ML_DSA_87_SECRET_KEY_BYTES;
    return 0;
}

QUDO_MLDSA_API QUDO_MLDSA_status_t QUDO_MLDSA_export_public_key_der(
    const uint8_t *public_key, size_t public_key_len, uint8_t *der_buffer,
    size_t *der_len)
{
    uint8_t *p = der_buffer;
    size_t oid_len;
    const uint8_t *oid;
    uint8_t len_buf[4];
    size_t len_size;

    if (!public_key || !der_buffer || !der_len) {
        return QUDO_MLDSA_ERROR_NULL_PTR;
    }

    oid = get_oid_for_public_key_size(public_key_len, &oid_len);
    if (!oid) {
        return QUDO_MLDSA_ERROR_INVALID_ARG;
    }

    size_t alg_id_content_len = 2 + oid_len;
    size_t alg_id_len_size = asn1_encode_length(len_buf, alg_id_content_len);
    size_t alg_id_total = 1 + alg_id_len_size + alg_id_content_len;

    size_t bit_string_content_len = 1 + public_key_len;
    size_t bit_string_len_size
        = asn1_encode_length(len_buf, bit_string_content_len);
    size_t bit_string_total = 1 + bit_string_len_size + bit_string_content_len;

    size_t spki_content_len = alg_id_total + bit_string_total;
    size_t spki_len_size = asn1_encode_length(len_buf, spki_content_len);
    size_t total_len = 1 + spki_len_size + spki_content_len;

    if (total_len > *der_len) {
        *der_len = total_len;
        return QUDO_MLDSA_ERROR_BUFFER_TOO_SMALL;
    }

    *p++ = 0x30;
    len_size = asn1_encode_length(p, spki_content_len);
    p += len_size;

    *p++ = 0x30;
    len_size = asn1_encode_length(p, alg_id_content_len);
    p += len_size;

    *p++ = 0x06;
    *p++ = (uint8_t)oid_len;
    memcpy(p, oid, oid_len);
    p += oid_len;

    *p++ = 0x03;
    len_size = asn1_encode_length(p, bit_string_content_len);
    p += len_size;

    *p++ = 0x00;
    memcpy(p, public_key, public_key_len);
    p += public_key_len;

    *der_len = (size_t)(p - der_buffer);
    return QUDO_MLDSA_SUCCESS;
}

QUDO_MLDSA_API QUDO_MLDSA_status_t
QUDO_MLDSA_import_public_key_der(const uint8_t *der_buffer, size_t der_len,
                                 uint8_t *public_key, size_t *public_key_len)
{
    const uint8_t *p = der_buffer;
    const uint8_t *end;
    size_t len;

    if (!der_buffer || !public_key || !public_key_len) {
        return QUDO_MLDSA_ERROR_NULL_PTR;
    }
    end = der_buffer + der_len;

    if (der_len < 10) {
        return QUDO_MLDSA_ERROR_DECODE;
    }

    if (*p++ != 0x30) {
        return QUDO_MLDSA_ERROR_DECODE;
    }

    if (!asn1_decode_length(&p, end, &len)) {
        return QUDO_MLDSA_ERROR_DECODE;
    }

    if (p >= end || *p++ != 0x30) {
        return QUDO_MLDSA_ERROR_DECODE;
    }

    if (!asn1_decode_length(&p, end, &len)) {
        return QUDO_MLDSA_ERROR_DECODE;
    }

    if (p >= end || *p++ != 0x06) {
        return QUDO_MLDSA_ERROR_DECODE;
    }

    if (p >= end) {
        return QUDO_MLDSA_ERROR_DECODE;
    }
    size_t oid_len = *p++;
    if (oid_len > (size_t)(end - p)) {
        return QUDO_MLDSA_ERROR_DECODE;
    }
    const uint8_t *oid = p;
    p += oid_len;

    {
        int oid_known = 0;
        if (oid_len == sizeof(OID_ML_DSA_44)
            && memcmp(oid, OID_ML_DSA_44, oid_len) == 0)
            oid_known = 1;
        else if (oid_len == sizeof(OID_ML_DSA_65)
                 && memcmp(oid, OID_ML_DSA_65, oid_len) == 0)
            oid_known = 1;
        else if (oid_len == sizeof(OID_ML_DSA_87)
                 && memcmp(oid, OID_ML_DSA_87, oid_len) == 0)
            oid_known = 1;
        if (!oid_known)
            return QUDO_MLDSA_ERROR_DECODE;
    }

    if (p < end && *p == 0x05) {
        p++;
        if (p >= end || *p++ != 0x00) {
            return QUDO_MLDSA_ERROR_DECODE;
        }
    }

    if (p >= end || *p++ != 0x03) {
        return QUDO_MLDSA_ERROR_DECODE;
    }

    if (!asn1_decode_length(&p, end, &len)) {
        return QUDO_MLDSA_ERROR_DECODE;
    }

    if (len == 0 || p >= end || *p++ != 0x00) {
        return QUDO_MLDSA_ERROR_DECODE;
    }
    len--;

    if (len != ML_DSA_44_PUBLIC_KEY_BYTES && len != ML_DSA_65_PUBLIC_KEY_BYTES
        && len != ML_DSA_87_PUBLIC_KEY_BYTES) {
        return QUDO_MLDSA_ERROR_DECODE;
    }

    if (len > (size_t)(end - p)) {
        return QUDO_MLDSA_ERROR_DECODE;
    }

    if (len > *public_key_len) {
        *public_key_len = len;
        return QUDO_MLDSA_ERROR_BUFFER_TOO_SMALL;
    }

    memcpy(public_key, p, len);
    *public_key_len = len;

    return QUDO_MLDSA_SUCCESS;
}

QUDO_MLDSA_API QUDO_MLDSA_status_t QUDO_MLDSA_export_public_key_pem(
    const uint8_t *public_key, size_t public_key_len, char *pem_buffer,
    size_t *pem_len)
{
    if (!public_key || !pem_len)
        return QUDO_MLDSA_ERROR_NULL_PTR;

    uint8_t der_buffer[4096];
    size_t der_len = sizeof(der_buffer);
    QUDO_MLDSA_status_t status = QUDO_MLDSA_export_public_key_der(
        public_key, public_key_len, der_buffer, &der_len);
    if (status != QUDO_MLDSA_SUCCESS)
        return status;

    const char *hdr = "-----BEGIN PUBLIC KEY-----\n";
    const char *ftr = "-----END PUBLIC KEY-----\n";
    size_t need
        = strlen(hdr) + mldsa_b64_encoded_len(der_len) + strlen(ftr) + 1;

    if (!pem_buffer) {
        *pem_len = need;
        return QUDO_MLDSA_SUCCESS;
    }
    if (*pem_len < need) {
        *pem_len = need;
        return QUDO_MLDSA_ERROR_BUFFER_TOO_SMALL;
    }

    size_t pos = 0;
    memcpy(pem_buffer + pos, hdr, strlen(hdr));
    pos += strlen(hdr);
    mldsa_b64_encode_wrapped(der_buffer, der_len, pem_buffer, &pos);
    memcpy(pem_buffer + pos, ftr, strlen(ftr));
    pos += strlen(ftr);
    pem_buffer[pos] = '\0';
    *pem_len = pos;
    return QUDO_MLDSA_SUCCESS;
}

QUDO_MLDSA_API QUDO_MLDSA_status_t QUDO_MLDSA_import_public_key_pem(
    const char *pem_buffer, uint8_t *public_key, size_t *public_key_len)
{
    if (!pem_buffer || !public_key_len)
        return QUDO_MLDSA_ERROR_NULL_PTR;

    const char *start_marker = "-----BEGIN PUBLIC KEY-----";
    const char *end_marker = "-----END PUBLIC KEY-----";
    const char *start_pos = strstr(pem_buffer, start_marker);
    const char *end_pos = strstr(pem_buffer, end_marker);
    if (!start_pos || !end_pos || start_pos >= end_pos)
        return QUDO_MLDSA_ERROR_DECODE;

    start_pos += strlen(start_marker);

    uint8_t der_buffer[4096];
    size_t der_len = sizeof(der_buffer);
    if (mldsa_b64_decode(start_pos, (size_t)(end_pos - start_pos), der_buffer,
                         &der_len)
        != 0)
        return QUDO_MLDSA_ERROR_DECODE;

    return QUDO_MLDSA_import_public_key_der(der_buffer, der_len, public_key,
                                            public_key_len);
}

QUDO_MLDSA_API QUDO_MLDSA_status_t QUDO_MLDSA_export_private_key_der(
    const uint8_t *private_key, size_t private_key_len, uint8_t *der_buffer,
    size_t *der_len)
{
    uint8_t *p = der_buffer;
    size_t oid_len;
    const uint8_t *oid;
    uint8_t len_buf[4];
    size_t len_size;

    if (!private_key || !der_buffer || !der_len) {
        return QUDO_MLDSA_ERROR_NULL_PTR;
    }

    oid = get_oid_for_private_key_size(private_key_len, &oid_len);
    if (!oid) {
        return QUDO_MLDSA_ERROR_INVALID_ARG;
    }

    size_t version_len = 3;

    size_t alg_id_content_len = 2 + oid_len;
    size_t alg_id_len_size = asn1_encode_length(len_buf, alg_id_content_len);
    size_t alg_id_total = 1 + alg_id_len_size + alg_id_content_len;

    /* priv-only encoding: the PKCS#8 privateKey OCTET STRING wraps a second
     * OCTET STRING holding the expanded private key. */
    size_t inner_oct_len_size = asn1_encode_length(len_buf, private_key_len);
    size_t inner_oct_total = 1 + inner_oct_len_size + private_key_len;
    size_t outer_oct_len_size = asn1_encode_length(len_buf, inner_oct_total);
    size_t outer_oct_total = 1 + outer_oct_len_size + inner_oct_total;

    size_t pki_content_len = version_len + alg_id_total + outer_oct_total;
    size_t pki_len_size = asn1_encode_length(len_buf, pki_content_len);
    size_t total_len = 1 + pki_len_size + pki_content_len;

    if (total_len > *der_len) {
        *der_len = total_len;
        return QUDO_MLDSA_ERROR_BUFFER_TOO_SMALL;
    }

    *p++ = 0x30;
    len_size = asn1_encode_length(p, pki_content_len);
    p += len_size;

    *p++ = 0x02;
    *p++ = 0x01;
    *p++ = 0x00;

    *p++ = 0x30;
    len_size = asn1_encode_length(p, alg_id_content_len);
    p += len_size;

    *p++ = 0x06;
    *p++ = (uint8_t)oid_len;
    memcpy(p, oid, oid_len);
    p += oid_len;

    *p++ = 0x04;
    len_size = asn1_encode_length(p, inner_oct_total);
    p += len_size;
    *p++ = 0x04;
    len_size = asn1_encode_length(p, private_key_len);
    p += len_size;

    memcpy(p, private_key, private_key_len);
    p += private_key_len;

    *der_len = (size_t)(p - der_buffer);
    return QUDO_MLDSA_SUCCESS;
}

QUDO_MLDSA_API QUDO_MLDSA_status_t
QUDO_MLDSA_import_private_key_der(const uint8_t *der_buffer, size_t der_len,
                                  uint8_t *private_key, size_t *private_key_len)
{
    const uint8_t *p = der_buffer;
    const uint8_t *end;
    size_t len;

    if (!der_buffer || !private_key || !private_key_len) {
        return QUDO_MLDSA_ERROR_NULL_PTR;
    }
    end = der_buffer + der_len;

    if (der_len < 10) {
        return QUDO_MLDSA_ERROR_DECODE;
    }

    if (p >= end || *p++ != 0x30) {
        return QUDO_MLDSA_ERROR_DECODE;
    }

    if (!asn1_decode_length(&p, end, &len)) {
        return QUDO_MLDSA_ERROR_DECODE;
    }

    if (p >= end || *p++ != 0x02) {
        return QUDO_MLDSA_ERROR_DECODE;
    }

    if (!asn1_decode_length(&p, end, &len)) {
        return QUDO_MLDSA_ERROR_DECODE;
    }

    if (len > (size_t)(end - p)) {
        return QUDO_MLDSA_ERROR_DECODE;
    }
    p += len;

    if (p >= end || *p++ != 0x30) {
        return QUDO_MLDSA_ERROR_DECODE;
    }

    if (!asn1_decode_length(&p, end, &len)) {
        return QUDO_MLDSA_ERROR_DECODE;
    }

    if (p >= end || *p++ != 0x06) {
        return QUDO_MLDSA_ERROR_DECODE;
    }

    if (p >= end) {
        return QUDO_MLDSA_ERROR_DECODE;
    }
    size_t oid_len = *p++;
    if (oid_len > (size_t)(end - p)) {
        return QUDO_MLDSA_ERROR_DECODE;
    }
    const uint8_t *oid = p;
    p += oid_len;

    {
        int oid_known = 0;
        if (oid_len == sizeof(OID_ML_DSA_44)
            && memcmp(oid, OID_ML_DSA_44, oid_len) == 0)
            oid_known = 1;
        else if (oid_len == sizeof(OID_ML_DSA_65)
                 && memcmp(oid, OID_ML_DSA_65, oid_len) == 0)
            oid_known = 1;
        else if (oid_len == sizeof(OID_ML_DSA_87)
                 && memcmp(oid, OID_ML_DSA_87, oid_len) == 0)
            oid_known = 1;
        if (!oid_known)
            return QUDO_MLDSA_ERROR_DECODE;
    }

    if (p >= end || *p++ != 0x04) {
        return QUDO_MLDSA_ERROR_DECODE;
    }

    if (!asn1_decode_length(&p, end, &len)) {
        return QUDO_MLDSA_ERROR_DECODE;
    }

    if (len > (size_t)(end - p)) {
        return QUDO_MLDSA_ERROR_DECODE;
    }

    size_t seed_priv_sk_len = get_sk_len_from_seed_priv_inner_len(len);
    if (seed_priv_sk_len > 0) {

        const uint8_t *inner = p;
        const uint8_t *inner_end = p + len;

        if (inner >= inner_end || *inner++ != 0x30)
            return QUDO_MLDSA_ERROR_DECODE;

        size_t seq_len;
        if (!asn1_decode_length(&inner, inner_end, &seq_len))
            return QUDO_MLDSA_ERROR_DECODE;

        if (inner >= inner_end || *inner++ != 0x04)
            return QUDO_MLDSA_ERROR_DECODE;
        if (inner >= inner_end || *inner != 0x20)
            return QUDO_MLDSA_ERROR_DECODE;
        inner++;
        if (MLDSA_SEEDBYTES > (size_t)(inner_end - inner))
            return QUDO_MLDSA_ERROR_DECODE;
        inner += MLDSA_SEEDBYTES;

        if (inner >= inner_end || *inner++ != 0x04)
            return QUDO_MLDSA_ERROR_DECODE;

        size_t sk_oct_len;
        if (!asn1_decode_length(&inner, inner_end, &sk_oct_len))
            return QUDO_MLDSA_ERROR_DECODE;

        if (sk_oct_len != seed_priv_sk_len
            || sk_oct_len > (size_t)(inner_end - inner))
            return QUDO_MLDSA_ERROR_DECODE;

        if (sk_oct_len > *private_key_len) {
            *private_key_len = sk_oct_len;
            return QUDO_MLDSA_ERROR_BUFFER_TOO_SMALL;
        }

        memcpy(private_key, inner, sk_oct_len);
        *private_key_len = sk_oct_len;
        return QUDO_MLDSA_SUCCESS;
    }

    /* A nested OCTET STRING is recognised only when its length is a valid
     * expanded private-key size; otherwise the content is a bare key. */
    if (len >= 4 && p[0] == 0x04) {
        const uint8_t *inner = p + 1;
        const uint8_t *inner_end = p + len;
        size_t inner_len;
        if (asn1_decode_length(&inner, inner_end, &inner_len)
            && inner + inner_len == inner_end
            && (inner_len == ML_DSA_44_SECRET_KEY_BYTES
                || inner_len == ML_DSA_65_SECRET_KEY_BYTES
                || inner_len == ML_DSA_87_SECRET_KEY_BYTES)) {
            if (inner_len > *private_key_len) {
                *private_key_len = inner_len;
                return QUDO_MLDSA_ERROR_BUFFER_TOO_SMALL;
            }
            memcpy(private_key, inner, inner_len);
            *private_key_len = inner_len;
            return QUDO_MLDSA_SUCCESS;
        }
    }

    if (len != ML_DSA_44_SECRET_KEY_BYTES && len != ML_DSA_65_SECRET_KEY_BYTES
        && len != ML_DSA_87_SECRET_KEY_BYTES
        && len != ML_DSA_44_SECRET_KEY_BYTES + ML_DSA_44_PUBLIC_KEY_BYTES
        && len != ML_DSA_65_SECRET_KEY_BYTES + ML_DSA_65_PUBLIC_KEY_BYTES
        && len != ML_DSA_87_SECRET_KEY_BYTES + ML_DSA_87_PUBLIC_KEY_BYTES) {
        return QUDO_MLDSA_ERROR_DECODE;
    }

    if (len > *private_key_len) {
        *private_key_len = len;
        return QUDO_MLDSA_ERROR_BUFFER_TOO_SMALL;
    }

    memcpy(private_key, p, len);
    *private_key_len = len;

    return QUDO_MLDSA_SUCCESS;
}

QUDO_MLDSA_API QUDO_MLDSA_status_t QUDO_MLDSA_export_private_key_pem(
    const uint8_t *private_key, size_t private_key_len, char *pem_buffer,
    size_t *pem_len)
{
    if (!private_key || !pem_len)
        return QUDO_MLDSA_ERROR_NULL_PTR;

    uint8_t der_buffer[8192];
    size_t der_len = sizeof(der_buffer);
    QUDO_MLDSA_status_t status = QUDO_MLDSA_export_private_key_der(
        private_key, private_key_len, der_buffer, &der_len);
    if (status != QUDO_MLDSA_SUCCESS) {
        QUDO_MLDSA_secure_zero(der_buffer, sizeof(der_buffer));
        return status;
    }

    const char *hdr = "-----BEGIN PRIVATE KEY-----\n";
    const char *ftr = "-----END PRIVATE KEY-----\n";
    size_t need
        = strlen(hdr) + mldsa_b64_encoded_len(der_len) + strlen(ftr) + 1;

    if (!pem_buffer) {
        *pem_len = need;
        QUDO_MLDSA_secure_zero(der_buffer, sizeof(der_buffer));
        return QUDO_MLDSA_SUCCESS;
    }
    if (*pem_len < need) {
        *pem_len = need;
        QUDO_MLDSA_secure_zero(der_buffer, sizeof(der_buffer));
        return QUDO_MLDSA_ERROR_BUFFER_TOO_SMALL;
    }

    size_t pos = 0;
    memcpy(pem_buffer + pos, hdr, strlen(hdr));
    pos += strlen(hdr);
    mldsa_b64_encode_wrapped(der_buffer, der_len, pem_buffer, &pos);
    memcpy(pem_buffer + pos, ftr, strlen(ftr));
    pos += strlen(ftr);
    pem_buffer[pos] = '\0';
    *pem_len = pos;

    QUDO_MLDSA_secure_zero(der_buffer, sizeof(der_buffer));
    return QUDO_MLDSA_SUCCESS;
}

QUDO_MLDSA_API QUDO_MLDSA_status_t QUDO_MLDSA_import_private_key_pem(
    const char *pem_buffer, uint8_t *private_key, size_t *private_key_len)
{
    if (!pem_buffer || !private_key_len)
        return QUDO_MLDSA_ERROR_NULL_PTR;

    const char *start_marker = "-----BEGIN PRIVATE KEY-----";
    const char *end_marker = "-----END PRIVATE KEY-----";
    const char *start_pos = strstr(pem_buffer, start_marker);
    const char *end_pos = strstr(pem_buffer, end_marker);
    if (!start_pos || !end_pos || start_pos >= end_pos)
        return QUDO_MLDSA_ERROR_DECODE;

    start_pos += strlen(start_marker);

    uint8_t der_buffer[8192];
    size_t der_len = sizeof(der_buffer);
    if (mldsa_b64_decode(start_pos, (size_t)(end_pos - start_pos), der_buffer,
                         &der_len)
        != 0) {
        QUDO_MLDSA_secure_zero(der_buffer, sizeof(der_buffer));
        return QUDO_MLDSA_ERROR_DECODE;
    }

    QUDO_MLDSA_status_t status = QUDO_MLDSA_import_private_key_der(
        der_buffer, der_len, private_key, private_key_len);
    QUDO_MLDSA_secure_zero(der_buffer, sizeof(der_buffer));
    return status;
}

QUDO_MLDSA_API QUDO_MLDSA_status_t QUDO_MLDSA_export_private_key_der_format(
    const uint8_t *private_key, size_t private_key_len, uint8_t *der_buffer,
    size_t *der_len, QUDO_MLDSA_pkcs8_format_t format)
{
#ifndef QUDO_MLDSA_USE_OPENSSL
    (void)private_key;
    (void)private_key_len;
    (void)der_buffer;
    (void)der_len;
    (void)format;
    return QUDO_MLDSA_ERROR_NOT_IMPL;
#else

    if (format != QUDO_MLDSA_PKCS8_FORMAT_SEED_PRIV
        && format != QUDO_MLDSA_PKCS8_FORMAT_PRIV_ONLY
        && format != QUDO_MLDSA_PKCS8_FORMAT_OQSKEYPAIR) {
        return QUDO_MLDSA_ERROR_INVALID_ARG;
    }

    if (format == QUDO_MLDSA_PKCS8_FORMAT_OQSKEYPAIR) {
        return QUDO_MLDSA_export_private_key_der(private_key, private_key_len,
                                                 der_buffer, der_len);
    }

    if (format == QUDO_MLDSA_PKCS8_FORMAT_SEED_PRIV) {

        size_t sk_len = 0;
        if (private_key_len == MLDSA_SEEDBYTES + ML_DSA_44_SECRET_KEY_BYTES)
            sk_len = ML_DSA_44_SECRET_KEY_BYTES;
        else if (private_key_len
                 == MLDSA_SEEDBYTES + ML_DSA_65_SECRET_KEY_BYTES)
            sk_len = ML_DSA_65_SECRET_KEY_BYTES;
        else if (private_key_len
                 == MLDSA_SEEDBYTES + ML_DSA_87_SECRET_KEY_BYTES)
            sk_len = ML_DSA_87_SECRET_KEY_BYTES;
        else
            return QUDO_MLDSA_ERROR_INVALID_ARG;

        const uint8_t *seed = private_key;
        const uint8_t *sk = private_key + MLDSA_SEEDBYTES;

        size_t inner_len = 42 + sk_len;
        uint8_t inner_buf[42 + ML_DSA_87_SECRET_KEY_BYTES];
        size_t inner_buf_len = sizeof(inner_buf);
        QUDO_MLDSA_status_t rc = build_seed_priv_inner(
            seed, sk, sk_len, inner_buf, &inner_buf_len);
        if (rc != QUDO_MLDSA_SUCCESS)
            return rc;

        size_t oid_len;
        const uint8_t *oid
            = get_oid_for_private_key_size(private_key_len, &oid_len);
        if (!oid)
            return QUDO_MLDSA_ERROR_INVALID_ARG;

        uint8_t len_buf[4];
        size_t version_len = 3;
        size_t alg_id_content_len = 2 + oid_len;
        size_t alg_id_len_size
            = asn1_encode_length(len_buf, alg_id_content_len);
        size_t alg_id_total = 1 + alg_id_len_size + alg_id_content_len;
        size_t octet_string_len_size = asn1_encode_length(len_buf, inner_len);
        size_t octet_string_total = 1 + octet_string_len_size + inner_len;
        size_t pki_content_len
            = version_len + alg_id_total + octet_string_total;
        size_t pki_len_size = asn1_encode_length(len_buf, pki_content_len);
        size_t total_len = 1 + pki_len_size + pki_content_len;

        if (total_len > *der_len) {
            *der_len = total_len;
            return QUDO_MLDSA_ERROR_BUFFER_TOO_SMALL;
        }

        uint8_t *p = der_buffer;
        size_t len_size;

        *p++ = 0x30;
        len_size = asn1_encode_length(p, pki_content_len);
        p += len_size;

        *p++ = 0x02;
        *p++ = 0x01;
        *p++ = 0x00;

        *p++ = 0x30;
        len_size = asn1_encode_length(p, alg_id_content_len);
        p += len_size;
        *p++ = 0x06;
        *p++ = (uint8_t)oid_len;
        memcpy(p, oid, oid_len);
        p += oid_len;

        *p++ = 0x04;
        len_size = asn1_encode_length(p, inner_len);
        p += len_size;
        memcpy(p, inner_buf, inner_len);
        p += inner_len;

        *der_len = (size_t)(p - der_buffer);
        return QUDO_MLDSA_SUCCESS;
    }

    if (format == QUDO_MLDSA_PKCS8_FORMAT_PRIV_ONLY) {
        size_t sk_only = private_key_len;
        if (private_key_len
            == ML_DSA_44_SECRET_KEY_BYTES + ML_DSA_44_PUBLIC_KEY_BYTES)
            sk_only = ML_DSA_44_SECRET_KEY_BYTES;
        else if (private_key_len
                 == ML_DSA_65_SECRET_KEY_BYTES + ML_DSA_65_PUBLIC_KEY_BYTES)
            sk_only = ML_DSA_65_SECRET_KEY_BYTES;
        else if (private_key_len
                 == ML_DSA_87_SECRET_KEY_BYTES + ML_DSA_87_PUBLIC_KEY_BYTES)
            sk_only = ML_DSA_87_SECRET_KEY_BYTES;
        return QUDO_MLDSA_export_private_key_der(private_key, sk_only,
                                                 der_buffer, der_len);
    }

    return QUDO_MLDSA_ERROR_INVALID_ARG;
#endif
}

QUDO_MLDSA_API QUDO_MLDSA_status_t QUDO_MLDSA_import_private_key_der_format(
    const uint8_t *der_buffer, size_t der_len, uint8_t *private_key,
    size_t *private_key_len, uint8_t *public_key, size_t *public_key_len)
{
#ifndef QUDO_MLDSA_USE_OPENSSL
    (void)der_buffer;
    (void)der_len;
    (void)private_key;
    (void)private_key_len;
    (void)public_key;
    (void)public_key_len;
    return QUDO_MLDSA_ERROR_NOT_IMPL;
#else
    QUDO_MLDSA_status_t status;

    status = QUDO_MLDSA_import_private_key_der(der_buffer, der_len, private_key,
                                               private_key_len);
    if (status != QUDO_MLDSA_SUCCESS) {
        return status;
    }

    if (public_key && public_key_len) {
        size_t sk_bytes = 0, pk_bytes = 0;

        if (*private_key_len
            == ML_DSA_44_SECRET_KEY_BYTES + ML_DSA_44_PUBLIC_KEY_BYTES) {
            sk_bytes = ML_DSA_44_SECRET_KEY_BYTES;
            pk_bytes = ML_DSA_44_PUBLIC_KEY_BYTES;
        } else if (*private_key_len
                   == ML_DSA_65_SECRET_KEY_BYTES + ML_DSA_65_PUBLIC_KEY_BYTES) {
            sk_bytes = ML_DSA_65_SECRET_KEY_BYTES;
            pk_bytes = ML_DSA_65_PUBLIC_KEY_BYTES;
        } else if (*private_key_len
                   == ML_DSA_87_SECRET_KEY_BYTES + ML_DSA_87_PUBLIC_KEY_BYTES) {
            sk_bytes = ML_DSA_87_SECRET_KEY_BYTES;
            pk_bytes = ML_DSA_87_PUBLIC_KEY_BYTES;
        }

        if (pk_bytes > 0 && sk_bytes > 0) {

            if (*public_key_len < pk_bytes) {
                *public_key_len = pk_bytes;
                return QUDO_MLDSA_ERROR_BUFFER_TOO_SMALL;
            }
            memcpy(public_key, private_key + sk_bytes, pk_bytes);
            *public_key_len = pk_bytes;

            *private_key_len = sk_bytes;
        } else {

            size_t regen_pk_bytes = 0;
            if (*private_key_len == ML_DSA_44_SECRET_KEY_BYTES)
                regen_pk_bytes = ML_DSA_44_PUBLIC_KEY_BYTES;
            else if (*private_key_len == ML_DSA_65_SECRET_KEY_BYTES)
                regen_pk_bytes = ML_DSA_65_PUBLIC_KEY_BYTES;
            else if (*private_key_len == ML_DSA_87_SECRET_KEY_BYTES)
                regen_pk_bytes = ML_DSA_87_PUBLIC_KEY_BYTES;

            int found_seed = 0;
            uint8_t seed_buf[MLDSA_SEEDBYTES];

            if (regen_pk_bytes > 0) {
                const uint8_t *rp = der_buffer;
                const uint8_t *rp_end = der_buffer + der_len;
                size_t rlen;

                if (rp < rp_end && *rp++ == 0x30
                    && asn1_decode_length(&rp, rp_end, &rlen)) {

                    if (rp < rp_end && *rp++ == 0x02
                        && asn1_decode_length(&rp, rp_end, &rlen))
                        rp += rlen;

                    if (rp < rp_end && *rp++ == 0x30
                        && asn1_decode_length(&rp, rp_end, &rlen))
                        rp += rlen;

                    if (rp < rp_end && *rp++ == 0x04
                        && asn1_decode_length(&rp, rp_end, &rlen)) {

                        if (get_sk_len_from_seed_priv_inner_len(rlen) > 0
                            && rp + rlen <= rp_end) {

                            const uint8_t *inner = rp;
                            if (*inner == 0x30) {
                                inner++;
                                size_t seq_len;
                                if (asn1_decode_length(&inner, rp_end, &seq_len)
                                    && inner < rp_end && *inner == 0x04) {
                                    inner++;
                                    if (inner < rp_end && *inner == 0x20) {
                                        inner++;
                                        if (MLDSA_SEEDBYTES
                                            <= (size_t)(rp_end - inner)) {
                                            memcpy(seed_buf, inner,
                                                   MLDSA_SEEDBYTES);
                                            found_seed = 1;
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }

            if (found_seed && regen_pk_bytes > 0) {

                if (*public_key_len < regen_pk_bytes) {
                    *public_key_len = regen_pk_bytes;
                    return QUDO_MLDSA_ERROR_BUFFER_TOO_SMALL;
                }

                QUDO_MLDSA_status_t regen_rc = QUDO_MLDSA_ERROR_INVALID_ARG;
                uint8_t *tmp_sk = NULL;

                if (*private_key_len == ML_DSA_44_SECRET_KEY_BYTES) {
                    tmp_sk
                        = QUDO_MLDSA_secure_alloc(ML_DSA_44_SECRET_KEY_BYTES);
                    if (tmp_sk) {
                        regen_rc = QUDO_MLDSA_ML_DSA_44_keypair_internal(
                            public_key, tmp_sk, seed_buf);
                        QUDO_MLDSA_secure_free(tmp_sk,
                                               ML_DSA_44_SECRET_KEY_BYTES);
                    }
                } else if (*private_key_len == ML_DSA_65_SECRET_KEY_BYTES) {
                    tmp_sk
                        = QUDO_MLDSA_secure_alloc(ML_DSA_65_SECRET_KEY_BYTES);
                    if (tmp_sk) {
                        regen_rc = QUDO_MLDSA_ML_DSA_65_keypair_internal(
                            public_key, tmp_sk, seed_buf);
                        QUDO_MLDSA_secure_free(tmp_sk,
                                               ML_DSA_65_SECRET_KEY_BYTES);
                    }
                } else if (*private_key_len == ML_DSA_87_SECRET_KEY_BYTES) {
                    tmp_sk
                        = QUDO_MLDSA_secure_alloc(ML_DSA_87_SECRET_KEY_BYTES);
                    if (tmp_sk) {
                        regen_rc = QUDO_MLDSA_ML_DSA_87_keypair_internal(
                            public_key, tmp_sk, seed_buf);
                        QUDO_MLDSA_secure_free(tmp_sk,
                                               ML_DSA_87_SECRET_KEY_BYTES);
                    }
                }

                QUDO_MLDSA_secure_zero(seed_buf, MLDSA_SEEDBYTES);

                if (!tmp_sk)
                    return QUDO_MLDSA_ERROR_ALLOC;
                if (regen_rc != QUDO_MLDSA_SUCCESS)
                    return regen_rc;

                *public_key_len = regen_pk_bytes;
            } else {

                *public_key_len = 0;
            }
        }
    }

    return QUDO_MLDSA_SUCCESS;
#endif
}

QUDO_MLDSA_API QUDO_MLDSA_status_t QUDO_MLDSA_export_private_key_pem_format(
    const uint8_t *private_key, size_t private_key_len, char *pem_buffer,
    size_t *pem_len, QUDO_MLDSA_pkcs8_format_t format)
{
#ifndef QUDO_MLDSA_USE_OPENSSL
    (void)private_key;
    (void)private_key_len;
    (void)pem_buffer;
    (void)pem_len;
    (void)format;
    return QUDO_MLDSA_ERROR_NOT_IMPL;
#else
    BIO *mem_bio = NULL;
    BIO *b64_bio = NULL;
    BUF_MEM *buf_mem;
    uint8_t der_buffer[8192];
    size_t der_len = sizeof(der_buffer);
    QUDO_MLDSA_status_t status;

    if (!private_key || !pem_buffer || !pem_len) {
        return QUDO_MLDSA_ERROR_NULL_PTR;
    }

    status = QUDO_MLDSA_export_private_key_der_format(
        private_key, private_key_len, der_buffer, &der_len, format);
    if (status != QUDO_MLDSA_SUCCESS) {
        QUDO_MLDSA_secure_zero(der_buffer, sizeof(der_buffer));
        return status;
    }

    mem_bio = BIO_new(BIO_s_mem());
    if (!mem_bio) {
        QUDO_MLDSA_secure_zero(der_buffer, sizeof(der_buffer));
        return QUDO_MLDSA_ERROR_ALLOC;
    }

    b64_bio = BIO_new(BIO_f_base64());
    if (!b64_bio) {
        BIO_free(mem_bio);
        QUDO_MLDSA_secure_zero(der_buffer, sizeof(der_buffer));
        return QUDO_MLDSA_ERROR_ALLOC;
    }

    BIO_push(b64_bio, mem_bio);

    BIO_puts(mem_bio, "-----BEGIN PRIVATE KEY-----\n");

    BIO_write(b64_bio, der_buffer, (int)der_len);
    BIO_flush(b64_bio);

    QUDO_MLDSA_secure_zero(der_buffer, sizeof(der_buffer));

    BIO_puts(mem_bio, "-----END PRIVATE KEY-----\n");

    BIO_get_mem_ptr(mem_bio, &buf_mem);

    if (buf_mem->length + 1 > *pem_len) {
        *pem_len = buf_mem->length + 1;
        BIO_free_all(b64_bio);
        return QUDO_MLDSA_ERROR_BUFFER_TOO_SMALL;
    }

    memcpy(pem_buffer, buf_mem->data, buf_mem->length);
    pem_buffer[buf_mem->length] = '\0';
    *pem_len = buf_mem->length;

    BIO_free_all(b64_bio);
    return QUDO_MLDSA_SUCCESS;
#endif
}

QUDO_MLDSA_API QUDO_MLDSA_status_t QUDO_MLDSA_import_private_key_pem_format(
    const char *pem_buffer, uint8_t *private_key, size_t *private_key_len,
    uint8_t *public_key, size_t *public_key_len)
{
#ifndef QUDO_MLDSA_USE_OPENSSL
    (void)pem_buffer;
    (void)private_key;
    (void)private_key_len;
    (void)public_key;
    (void)public_key_len;
    return QUDO_MLDSA_ERROR_NOT_IMPL;
#else
    BIO *mem_bio = NULL;
    BIO *b64_bio = NULL;
    uint8_t der_buffer[8192];
    int der_len;
    QUDO_MLDSA_status_t status;
    const char *start_marker = "-----BEGIN PRIVATE KEY-----";
    const char *end_marker = "-----END PRIVATE KEY-----";
    const char *start_pos, *end_pos;

    if (!pem_buffer || !private_key || !private_key_len) {
        return QUDO_MLDSA_ERROR_NULL_PTR;
    }

    start_pos = strstr(pem_buffer, start_marker);
    end_pos = strstr(pem_buffer, end_marker);

    if (!start_pos || !end_pos || start_pos >= end_pos) {
        return QUDO_MLDSA_ERROR_DECODE;
    }

    start_pos += strlen(start_marker);

    mem_bio = BIO_new_mem_buf(start_pos, (int)(end_pos - start_pos));
    if (!mem_bio) {
        return QUDO_MLDSA_ERROR_ALLOC;
    }

    b64_bio = BIO_new(BIO_f_base64());
    if (!b64_bio) {
        BIO_free(mem_bio);
        return QUDO_MLDSA_ERROR_ALLOC;
    }

    BIO_push(b64_bio, mem_bio);

    der_len = BIO_read(b64_bio, der_buffer, sizeof(der_buffer));
    BIO_free_all(b64_bio);

    if (der_len <= 0) {
        QUDO_MLDSA_secure_zero(der_buffer, sizeof(der_buffer));
        return QUDO_MLDSA_ERROR_DECODE;
    }

    status = QUDO_MLDSA_import_private_key_der_format(
        der_buffer, (size_t)der_len, private_key, private_key_len, public_key,
        public_key_len);

    QUDO_MLDSA_secure_zero(der_buffer, sizeof(der_buffer));

    return status;
#endif
}
