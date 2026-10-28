/* SPDX-License-Identifier: Apache-2.0 AND MIT */

#include "../include/mlkem_wrapper.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static const char mlkem_b64_alphabet[]
    = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

static int mlkem_b64_decode_char(char c)
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

#define MLKEM_PEM_LINE 64

static size_t mlkem_b64_encoded_len(size_t bin_len)
{
    size_t groups = (bin_len + 2) / 3;
    size_t b64 = groups * 4;
    size_t lines = (b64 + MLKEM_PEM_LINE - 1) / MLKEM_PEM_LINE;
    return b64 + lines;
}

static void mlkem_b64_encode_wrapped(const uint8_t *in, size_t in_len,
                                     char *out, size_t *out_pos)
{
    size_t col = 0;
    size_t i = 0;
    while (i + 3 <= in_len) {
        uint32_t v
            = ((uint32_t)in[i] << 16) | ((uint32_t)in[i + 1] << 8) | in[i + 2];
        out[(*out_pos)++] = mlkem_b64_alphabet[(v >> 18) & 0x3F];
        out[(*out_pos)++] = mlkem_b64_alphabet[(v >> 12) & 0x3F];
        out[(*out_pos)++] = mlkem_b64_alphabet[(v >> 6) & 0x3F];
        out[(*out_pos)++] = mlkem_b64_alphabet[v & 0x3F];
        col += 4;
        if (col >= MLKEM_PEM_LINE) {
            out[(*out_pos)++] = '\n';
            col = 0;
        }
        i += 3;
    }
    if (i < in_len) {
        uint32_t v = (uint32_t)in[i] << 16;
        if (i + 1 < in_len)
            v |= (uint32_t)in[i + 1] << 8;
        out[(*out_pos)++] = mlkem_b64_alphabet[(v >> 18) & 0x3F];
        out[(*out_pos)++] = mlkem_b64_alphabet[(v >> 12) & 0x3F];
        out[(*out_pos)++]
            = (i + 1 < in_len) ? mlkem_b64_alphabet[(v >> 6) & 0x3F] : '=';
        out[(*out_pos)++] = '=';
        col += 4;
    }
    if (col != 0)
        out[(*out_pos)++] = '\n';
}

static int mlkem_b64_decode(const char *in, size_t in_len, uint8_t *out,
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
        int v = mlkem_b64_decode_char(c);
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

static const uint8_t OID_ML_KEM_512[]
    = {0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x04, 0x01};

static const uint8_t OID_ML_KEM_768[]
    = {0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x04, 0x02};

static const uint8_t OID_ML_KEM_1024[]
    = {0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x04, 0x03};

static const uint8_t *get_oid_for_key_size(size_t key_len, size_t *oid_len)
{
    if (key_len == 800) {
        *oid_len = sizeof(OID_ML_KEM_512);
        return OID_ML_KEM_512;
    } else if (key_len == 1184) {
        *oid_len = sizeof(OID_ML_KEM_768);
        return OID_ML_KEM_768;
    } else if (key_len == 1568) {
        *oid_len = sizeof(OID_ML_KEM_1024);
        return OID_ML_KEM_1024;
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

QUDO_KEM_API QUDO_KEM_status_t
QUDO_KEM_export_public_key_der(const uint8_t *public_key, size_t public_key_len,
                               uint8_t *der_buffer, size_t *der_len)
{
    uint8_t *p = der_buffer;
    size_t oid_len;
    const uint8_t *oid;
    uint8_t len_buf[4];
    size_t len_size;

    if (!public_key || !der_buffer || !der_len) {
        return QUDO_KEM_ERROR_NULL_PTR;
    }

    oid = get_oid_for_key_size(public_key_len, &oid_len);
    if (!oid) {
        return QUDO_KEM_ERROR_INVALID_ARG;
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
        return QUDO_KEM_ERROR_BUFFER_TOO_SMALL;
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
    return QUDO_KEM_SUCCESS;
}

QUDO_KEM_API QUDO_KEM_status_t
QUDO_KEM_import_public_key_der(const uint8_t *der_buffer, size_t der_len,
                               uint8_t *public_key, size_t *public_key_len)
{
    const uint8_t *p = der_buffer;
    const uint8_t *end;
    size_t len;

    if (!der_buffer || !public_key || !public_key_len) {
        return QUDO_KEM_ERROR_NULL_PTR;
    }
    end = der_buffer + der_len;

    if (der_len < 10) {
        return QUDO_KEM_ERROR_DECODE;
    }

    if (*p++ != 0x30) {
        return QUDO_KEM_ERROR_DECODE;
    }

    if (!asn1_decode_length(&p, end, &len)) {
        return QUDO_KEM_ERROR_DECODE;
    }

    if (p >= end || *p++ != 0x30) {
        return QUDO_KEM_ERROR_DECODE;
    }

    if (!asn1_decode_length(&p, end, &len)) {
        return QUDO_KEM_ERROR_DECODE;
    }

    if (p >= end || *p++ != 0x06) {
        return QUDO_KEM_ERROR_DECODE;
    }

    if (p >= end) {
        return QUDO_KEM_ERROR_DECODE;
    }
    size_t oid_len = *p++;
    if (oid_len > (size_t)(end - p)) {
        return QUDO_KEM_ERROR_DECODE;
    }
    const uint8_t *oid = p;
    p += oid_len;

    {
        int oid_known = 0;
        if (oid_len == sizeof(OID_ML_KEM_512)
            && memcmp(oid, OID_ML_KEM_512, oid_len) == 0)
            oid_known = 1;
        else if (oid_len == sizeof(OID_ML_KEM_768)
                 && memcmp(oid, OID_ML_KEM_768, oid_len) == 0)
            oid_known = 1;
        else if (oid_len == sizeof(OID_ML_KEM_1024)
                 && memcmp(oid, OID_ML_KEM_1024, oid_len) == 0)
            oid_known = 1;
        if (!oid_known)
            return QUDO_KEM_ERROR_DECODE;
    }

    if (p < end && *p == 0x05) {
        p++;
        if (p >= end || *p++ != 0x00) {
            return QUDO_KEM_ERROR_DECODE;
        }
    }

    if (p >= end || *p++ != 0x03) {
        return QUDO_KEM_ERROR_DECODE;
    }

    if (!asn1_decode_length(&p, end, &len)) {
        return QUDO_KEM_ERROR_DECODE;
    }

    if (len == 0 || p >= end || *p++ != 0x00) {
        return QUDO_KEM_ERROR_DECODE;
    }
    len--;

    if (len != QUDO_KEM_mlkem_512_length_public_key
        && len != QUDO_KEM_mlkem_768_length_public_key
        && len != QUDO_KEM_mlkem_1024_length_public_key) {
        return QUDO_KEM_ERROR_DECODE;
    }

    if (len > (size_t)(end - p)) {
        return QUDO_KEM_ERROR_DECODE;
    }

    if (len > *public_key_len) {
        *public_key_len = len;
        return QUDO_KEM_ERROR_BUFFER_TOO_SMALL;
    }

    memcpy(public_key, p, len);
    *public_key_len = len;

    return QUDO_KEM_SUCCESS;
}

QUDO_KEM_API QUDO_KEM_status_t
QUDO_KEM_export_public_key_pem(const uint8_t *public_key, size_t public_key_len,
                               char *pem_buffer, size_t *pem_len)
{
    if (!public_key || !pem_len)
        return QUDO_KEM_ERROR_NULL_PTR;

    uint8_t der_buffer[4096];
    size_t der_len = sizeof(der_buffer);
    QUDO_KEM_status_t status = QUDO_KEM_export_public_key_der(
        public_key, public_key_len, der_buffer, &der_len);
    if (status != QUDO_KEM_SUCCESS)
        return status;

    const char *hdr = "-----BEGIN PUBLIC KEY-----\n";
    const char *ftr = "-----END PUBLIC KEY-----\n";
    size_t need
        = strlen(hdr) + mlkem_b64_encoded_len(der_len) + strlen(ftr) + 1;

    if (!pem_buffer) {
        *pem_len = need;
        return QUDO_KEM_SUCCESS;
    }
    if (*pem_len < need) {
        *pem_len = need;
        return QUDO_KEM_ERROR_BUFFER_TOO_SMALL;
    }

    size_t pos = 0;
    memcpy(pem_buffer + pos, hdr, strlen(hdr));
    pos += strlen(hdr);
    mlkem_b64_encode_wrapped(der_buffer, der_len, pem_buffer, &pos);
    memcpy(pem_buffer + pos, ftr, strlen(ftr));
    pos += strlen(ftr);
    pem_buffer[pos] = '\0';
    *pem_len = pos;
    return QUDO_KEM_SUCCESS;
}

QUDO_KEM_API QUDO_KEM_status_t QUDO_KEM_import_public_key_pem(
    const char *pem_buffer, uint8_t *public_key, size_t *public_key_len)
{
    if (!pem_buffer || !public_key_len)
        return QUDO_KEM_ERROR_NULL_PTR;

    const char *start_marker = "-----BEGIN PUBLIC KEY-----";
    const char *end_marker = "-----END PUBLIC KEY-----";
    const char *start_pos = strstr(pem_buffer, start_marker);
    const char *end_pos = strstr(pem_buffer, end_marker);

    if (!start_pos || !end_pos || start_pos >= end_pos)
        return QUDO_KEM_ERROR_DECODE;

    start_pos += strlen(start_marker);

    uint8_t der_buffer[4096];
    size_t der_len = sizeof(der_buffer);
    if (mlkem_b64_decode(start_pos, (size_t)(end_pos - start_pos), der_buffer,
                         &der_len)
        != 0)
        return QUDO_KEM_ERROR_DECODE;

    return QUDO_KEM_import_public_key_der(der_buffer, der_len, public_key,
                                          public_key_len);
}
