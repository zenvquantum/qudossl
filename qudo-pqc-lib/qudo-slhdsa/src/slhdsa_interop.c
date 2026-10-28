/* SPDX-License-Identifier: Apache-2.0 AND MIT */

#include "slhdsa_config.h"
#include "slhdsa_wrapper.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef QUDO_SLHDSA_USE_OPENSSL
#    include <openssl/bio.h>
#    include <openssl/crypto.h>
#    include <openssl/evp.h>
#    include <openssl/pem.h>
#endif

#define OID_BASE_LEN 8
static const uint8_t OID_BASE[]
    = {0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03};

#define OID_SUFFIX_SHA2_128S  0x14
#define OID_SUFFIX_SHA2_128F  0x15
#define OID_SUFFIX_SHA2_192S  0x16
#define OID_SUFFIX_SHA2_192F  0x17
#define OID_SUFFIX_SHA2_256S  0x18
#define OID_SUFFIX_SHA2_256F  0x19
#define OID_SUFFIX_SHAKE_128S 0x1A
#define OID_SUFFIX_SHAKE_128F 0x1B
#define OID_SUFFIX_SHAKE_192S 0x1C
#define OID_SUFFIX_SHAKE_192F 0x1D
#define OID_SUFFIX_SHAKE_256S 0x1E
#define OID_SUFFIX_SHAKE_256F 0x1F

#define OID_LEN (OID_BASE_LEN + 1)

static uint8_t get_oid_suffix_for_param_set(QUDO_SLHDSA_parameter_set_t ps)
{
    switch (ps) {
    case QUDO_SLHDSA_SHA2_128s:
        return OID_SUFFIX_SHA2_128S;
    case QUDO_SLHDSA_SHA2_128f:
        return OID_SUFFIX_SHA2_128F;
    case QUDO_SLHDSA_SHA2_192s:
        return OID_SUFFIX_SHA2_192S;
    case QUDO_SLHDSA_SHA2_192f:
        return OID_SUFFIX_SHA2_192F;
    case QUDO_SLHDSA_SHA2_256s:
        return OID_SUFFIX_SHA2_256S;
    case QUDO_SLHDSA_SHA2_256f:
        return OID_SUFFIX_SHA2_256F;
    case QUDO_SLHDSA_SHAKE_128s:
        return OID_SUFFIX_SHAKE_128S;
    case QUDO_SLHDSA_SHAKE_128f:
        return OID_SUFFIX_SHAKE_128F;
    case QUDO_SLHDSA_SHAKE_192s:
        return OID_SUFFIX_SHAKE_192S;
    case QUDO_SLHDSA_SHAKE_192f:
        return OID_SUFFIX_SHAKE_192F;
    case QUDO_SLHDSA_SHAKE_256s:
        return OID_SUFFIX_SHAKE_256S;
    case QUDO_SLHDSA_SHAKE_256f:
        return OID_SUFFIX_SHAKE_256F;
    default:
        return 0;
    }
}

static QUDO_SLHDSA_parameter_set_t get_param_set_from_oid_suffix(uint8_t suffix)
{
    switch (suffix) {
    case OID_SUFFIX_SHA2_128S:
        return QUDO_SLHDSA_SHA2_128s;
    case OID_SUFFIX_SHA2_128F:
        return QUDO_SLHDSA_SHA2_128f;
    case OID_SUFFIX_SHA2_192S:
        return QUDO_SLHDSA_SHA2_192s;
    case OID_SUFFIX_SHA2_192F:
        return QUDO_SLHDSA_SHA2_192f;
    case OID_SUFFIX_SHA2_256S:
        return QUDO_SLHDSA_SHA2_256s;
    case OID_SUFFIX_SHA2_256F:
        return QUDO_SLHDSA_SHA2_256f;
    case OID_SUFFIX_SHAKE_128S:
        return QUDO_SLHDSA_SHAKE_128s;
    case OID_SUFFIX_SHAKE_128F:
        return QUDO_SLHDSA_SHAKE_128f;
    case OID_SUFFIX_SHAKE_192S:
        return QUDO_SLHDSA_SHAKE_192s;
    case OID_SUFFIX_SHAKE_192F:
        return QUDO_SLHDSA_SHAKE_192f;
    case OID_SUFFIX_SHAKE_256S:
        return QUDO_SLHDSA_SHAKE_256s;
    case OID_SUFFIX_SHAKE_256F:
        return QUDO_SLHDSA_SHAKE_256f;
    default:
        return 0;
    }
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
        if (*out_len > (size_t)(end - *p))
            return 0;
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
        if (*out_len > (size_t)(end - *p))
            return 0;
        return 1 + num_bytes;
    }
}

QUDO_SLHDSA_API QUDO_SLHDSA_status_t QUDO_SLHDSA_export_public_key_der(
    const uint8_t *public_key, size_t public_key_len,
    QUDO_SLHDSA_parameter_set_t param_set, uint8_t *der_out,
    size_t *der_out_len)
{

    if (!public_key || !der_out_len)
        return QUDO_SLHDSA_ERROR_NULL_PTR;

    uint8_t oid_suffix = get_oid_suffix_for_param_set(param_set);
    if (oid_suffix == 0)
        return QUDO_SLHDSA_ERROR_INVALID_ARG;

    size_t algid_content_len = 2 + OID_LEN;
    size_t algid_total_len = 2 + algid_content_len;

    size_t bitstr_content_len = 1 + public_key_len;
    uint8_t bitstr_len_buf[4];
    size_t bitstr_len_bytes
        = asn1_encode_length(bitstr_len_buf, bitstr_content_len);
    size_t bitstr_total_len = 1 + bitstr_len_bytes + bitstr_content_len;

    size_t seq_content_len = algid_total_len + bitstr_total_len;
    uint8_t seq_len_buf[4];
    size_t seq_len_bytes = asn1_encode_length(seq_len_buf, seq_content_len);
    size_t total_len = 1 + seq_len_bytes + seq_content_len;

    if (!der_out) {
        *der_out_len = total_len;
        return QUDO_SLHDSA_SUCCESS;
    }

    if (*der_out_len < total_len)
        return QUDO_SLHDSA_ERROR_BUFFER_TOO_SMALL;

    uint8_t *p = der_out;

    *p++ = 0x30;
    memcpy(p, seq_len_buf, seq_len_bytes);
    p += seq_len_bytes;

    *p++ = 0x30;
    *p++ = (uint8_t)algid_content_len;
    *p++ = 0x06;
    *p++ = OID_LEN;
    memcpy(p, OID_BASE, OID_BASE_LEN);
    p += OID_BASE_LEN;
    *p++ = oid_suffix;

    *p++ = 0x03;
    memcpy(p, bitstr_len_buf, bitstr_len_bytes);
    p += bitstr_len_bytes;
    *p++ = 0x00;
    memcpy(p, public_key, public_key_len);
    p += public_key_len;

    *der_out_len = total_len;
    return QUDO_SLHDSA_SUCCESS;
}

QUDO_SLHDSA_API QUDO_SLHDSA_status_t
QUDO_SLHDSA_import_public_key_der(const uint8_t *der_in, size_t der_in_len,
                                  uint8_t *public_key, size_t *public_key_len)
{

    if (!der_in || !public_key_len)
        return QUDO_SLHDSA_ERROR_NULL_PTR;

    if (der_in_len < 10) {
        return QUDO_SLHDSA_ERROR_DECODE;
    }

    const uint8_t *p = der_in;
    const uint8_t *end = der_in + der_in_len;
    size_t len;

    if (*p++ != 0x30) {
        return QUDO_SLHDSA_ERROR_DECODE;
    }

    if (!asn1_decode_length(&p, end, &len)) {
        return QUDO_SLHDSA_ERROR_DECODE;
    }

    if (p >= end || *p++ != 0x30) {
        return QUDO_SLHDSA_ERROR_DECODE;
    }

    if (!asn1_decode_length(&p, end, &len)) {
        return QUDO_SLHDSA_ERROR_DECODE;
    }

    if (p >= end || *p++ != 0x06) {
        return QUDO_SLHDSA_ERROR_DECODE;
    }

    if (p >= end) {
        return QUDO_SLHDSA_ERROR_DECODE;
    }
    size_t oid_len = *p++;
    if (oid_len != OID_LEN || oid_len > (size_t)(end - p)) {
        return QUDO_SLHDSA_ERROR_DECODE;
    }

    if (memcmp(p, OID_BASE, OID_BASE_LEN) != 0) {
        return QUDO_SLHDSA_ERROR_DECODE;
    }
    uint8_t oid_suffix = p[OID_BASE_LEN];
    p += oid_len;

    QUDO_SLHDSA_parameter_set_t ps = get_param_set_from_oid_suffix(oid_suffix);
    if (ps == 0)
        return QUDO_SLHDSA_ERROR_DECODE;

    size_t expected_pk_len = slhdsa_get_public_key_bytes(ps);

    if (p >= end || *p++ != 0x03) {
        return QUDO_SLHDSA_ERROR_DECODE;
    }

    if (!asn1_decode_length(&p, end, &len)) {
        return QUDO_SLHDSA_ERROR_DECODE;
    }

    if (len == 0 || p >= end || *p++ != 0x00) {
        return QUDO_SLHDSA_ERROR_DECODE;
    }
    len--;

    if (len != expected_pk_len) {
        return QUDO_SLHDSA_ERROR_DECODE;
    }

    if (len > (size_t)(end - p)) {
        return QUDO_SLHDSA_ERROR_DECODE;
    }

    if (!public_key) {
        *public_key_len = expected_pk_len;
        return QUDO_SLHDSA_SUCCESS;
    }

    if (*public_key_len < expected_pk_len) {
        return QUDO_SLHDSA_ERROR_BUFFER_TOO_SMALL;
    }

    memcpy(public_key, p, len);
    *public_key_len = expected_pk_len;
    return QUDO_SLHDSA_SUCCESS;
}

QUDO_SLHDSA_API QUDO_SLHDSA_status_t QUDO_SLHDSA_export_private_key_der(
    const uint8_t *private_key, size_t private_key_len,
    QUDO_SLHDSA_parameter_set_t param_set, uint8_t *der_out,
    size_t *der_out_len)
{

    if (!private_key || !der_out_len)
        return QUDO_SLHDSA_ERROR_NULL_PTR;

    uint8_t oid_suffix = get_oid_suffix_for_param_set(param_set);
    if (oid_suffix == 0)
        return QUDO_SLHDSA_ERROR_INVALID_ARG;

    size_t version_len = 3;

    size_t algid_content_len = 2 + OID_LEN;
    size_t algid_total_len = 2 + algid_content_len;

    uint8_t oct_len_buf[4];
    size_t oct_len_bytes = asn1_encode_length(oct_len_buf, private_key_len);
    size_t oct_total_len = 1 + oct_len_bytes + private_key_len;

    size_t seq_content_len = version_len + algid_total_len + oct_total_len;
    uint8_t seq_len_buf[4];
    size_t seq_len_bytes = asn1_encode_length(seq_len_buf, seq_content_len);
    size_t total_len = 1 + seq_len_bytes + seq_content_len;

    if (!der_out) {
        *der_out_len = total_len;
        return QUDO_SLHDSA_SUCCESS;
    }

    if (*der_out_len < total_len)
        return QUDO_SLHDSA_ERROR_BUFFER_TOO_SMALL;

    uint8_t *p = der_out;

    *p++ = 0x30;
    memcpy(p, seq_len_buf, seq_len_bytes);
    p += seq_len_bytes;

    *p++ = 0x02;
    *p++ = 0x01;
    *p++ = 0x00;

    *p++ = 0x30;
    *p++ = (uint8_t)algid_content_len;
    *p++ = 0x06;
    *p++ = OID_LEN;
    memcpy(p, OID_BASE, OID_BASE_LEN);
    p += OID_BASE_LEN;
    *p++ = oid_suffix;

    *p++ = 0x04;
    memcpy(p, oct_len_buf, oct_len_bytes);
    p += oct_len_bytes;
    memcpy(p, private_key, private_key_len);
    p += private_key_len;

    *der_out_len = total_len;
    return QUDO_SLHDSA_SUCCESS;
}

QUDO_SLHDSA_API QUDO_SLHDSA_status_t QUDO_SLHDSA_import_private_key_der(
    const uint8_t *der_in, size_t der_in_len, uint8_t *private_key,
    size_t *private_key_len)
{

    if (!der_in || !private_key_len)
        return QUDO_SLHDSA_ERROR_NULL_PTR;

    if (der_in_len < 10) {
        return QUDO_SLHDSA_ERROR_DECODE;
    }

    const uint8_t *p = der_in;
    const uint8_t *end = der_in + der_in_len;
    size_t len;

    if (*p++ != 0x30) {
        return QUDO_SLHDSA_ERROR_DECODE;
    }

    if (!asn1_decode_length(&p, end, &len)) {
        return QUDO_SLHDSA_ERROR_DECODE;
    }

    if (p >= end || *p++ != 0x02) {
        return QUDO_SLHDSA_ERROR_DECODE;
    }

    if (!asn1_decode_length(&p, end, &len)) {
        return QUDO_SLHDSA_ERROR_DECODE;
    }

    if (len > (size_t)(end - p)) {
        return QUDO_SLHDSA_ERROR_DECODE;
    }
    p += len;

    if (p >= end || *p++ != 0x30) {
        return QUDO_SLHDSA_ERROR_DECODE;
    }

    if (!asn1_decode_length(&p, end, &len)) {
        return QUDO_SLHDSA_ERROR_DECODE;
    }

    if (p >= end || *p++ != 0x06) {
        return QUDO_SLHDSA_ERROR_DECODE;
    }

    if (p >= end) {
        return QUDO_SLHDSA_ERROR_DECODE;
    }
    size_t oid_len = *p++;
    if (oid_len != OID_LEN || oid_len > (size_t)(end - p)) {
        return QUDO_SLHDSA_ERROR_DECODE;
    }

    if (memcmp(p, OID_BASE, OID_BASE_LEN) != 0) {
        return QUDO_SLHDSA_ERROR_DECODE;
    }
    uint8_t oid_suffix = p[OID_BASE_LEN];
    p += oid_len;

    QUDO_SLHDSA_parameter_set_t ps = get_param_set_from_oid_suffix(oid_suffix);
    if (ps == 0)
        return QUDO_SLHDSA_ERROR_DECODE;

    size_t expected_sk_len = slhdsa_get_secret_key_bytes(ps);

    if (p >= end || *p++ != 0x04) {
        return QUDO_SLHDSA_ERROR_DECODE;
    }

    if (!asn1_decode_length(&p, end, &len)) {
        return QUDO_SLHDSA_ERROR_DECODE;
    }

    if (len != expected_sk_len) {
        return QUDO_SLHDSA_ERROR_DECODE;
    }

    if (len > (size_t)(end - p)) {
        return QUDO_SLHDSA_ERROR_DECODE;
    }

    if (!private_key) {
        *private_key_len = expected_sk_len;
        return QUDO_SLHDSA_SUCCESS;
    }

    if (*private_key_len < expected_sk_len) {
        return QUDO_SLHDSA_ERROR_BUFFER_TOO_SMALL;
    }

    memcpy(private_key, p, len);
    *private_key_len = expected_sk_len;
    return QUDO_SLHDSA_SUCCESS;
}

#ifdef QUDO_SLHDSA_USE_OPENSSL

static const char PEM_HEADER_PUBLIC[] = "-----BEGIN PUBLIC KEY-----\n";
static const char PEM_FOOTER_PUBLIC[] = "-----END PUBLIC KEY-----\n";
static const char PEM_HEADER_PRIVATE[] = "-----BEGIN PRIVATE KEY-----\n";
static const char PEM_FOOTER_PRIVATE[] = "-----END PRIVATE KEY-----\n";

QUDO_SLHDSA_API QUDO_SLHDSA_status_t QUDO_SLHDSA_export_public_key_pem(
    const uint8_t *public_key, size_t public_key_len,
    QUDO_SLHDSA_parameter_set_t param_set, char *pem_out, size_t *pem_out_len)
{

    size_t der_len = 0;
    QUDO_SLHDSA_status_t rc = QUDO_SLHDSA_export_public_key_der(
        public_key, public_key_len, param_set, NULL, &der_len);
    if (rc != QUDO_SLHDSA_SUCCESS)
        return rc;

    uint8_t *der = (uint8_t *)malloc(der_len);
    if (!der)
        return QUDO_SLHDSA_ERROR_ALLOC;

    rc = QUDO_SLHDSA_export_public_key_der(public_key, public_key_len,
                                           param_set, der, &der_len);
    if (rc != QUDO_SLHDSA_SUCCESS) {
        free(der);
        return rc;
    }

    BIO *b64 = BIO_new(BIO_f_base64());
    BIO *mem = BIO_new(BIO_s_mem());
    if (!b64 || !mem) {
        free(der);
        BIO_free(b64);
        BIO_free(mem);
        return QUDO_SLHDSA_ERROR_ALLOC;
    }
    BIO_push(b64, mem);
    BIO_write(b64, der, (int)der_len);
    BIO_flush(b64);
    free(der);

    BUF_MEM *bptr;
    BIO_get_mem_ptr(b64, &bptr);

    size_t needed = strlen(PEM_HEADER_PUBLIC) + bptr->length
                    + strlen(PEM_FOOTER_PUBLIC) + 1;

    if (!pem_out) {
        *pem_out_len = needed;
        BIO_free_all(b64);
        return QUDO_SLHDSA_SUCCESS;
    }

    if (*pem_out_len < needed) {
        BIO_free_all(b64);
        return QUDO_SLHDSA_ERROR_BUFFER_TOO_SMALL;
    }

    char *p = pem_out;
    memcpy(p, PEM_HEADER_PUBLIC, strlen(PEM_HEADER_PUBLIC));
    p += strlen(PEM_HEADER_PUBLIC);
    memcpy(p, bptr->data, bptr->length);
    p += bptr->length;
    memcpy(p, PEM_FOOTER_PUBLIC, strlen(PEM_FOOTER_PUBLIC));
    p += strlen(PEM_FOOTER_PUBLIC);
    *p = '\0';
    *pem_out_len = (size_t)(p - pem_out);

    BIO_free_all(b64);
    return QUDO_SLHDSA_SUCCESS;
}

QUDO_SLHDSA_API QUDO_SLHDSA_status_t
QUDO_SLHDSA_import_public_key_pem(const char *pem_in, size_t pem_in_len,
                                  uint8_t *public_key, size_t *public_key_len)
{

    (void)pem_in_len;

    if (!pem_in || !public_key_len)
        return QUDO_SLHDSA_ERROR_NULL_PTR;

    const char *start = strstr(pem_in, "-----BEGIN PUBLIC KEY-----");
    if (!start)
        return QUDO_SLHDSA_ERROR_DECODE;
    start = strchr(start, '\n');
    if (!start)
        return QUDO_SLHDSA_ERROR_DECODE;
    start++;

    const char *end_marker = strstr(start, "-----END PUBLIC KEY-----");
    if (!end_marker)
        return QUDO_SLHDSA_ERROR_DECODE;

    size_t b64_len = (size_t)(end_marker - start);

    BIO *b64 = BIO_new(BIO_f_base64());
    BIO *mem = BIO_new_mem_buf(start, (int)b64_len);
    if (!b64 || !mem) {
        BIO_free(b64);
        BIO_free(mem);
        return QUDO_SLHDSA_ERROR_ALLOC;
    }
    BIO_push(b64, mem);

    uint8_t der[SLH_DSA_MAX_PUBLIC_KEY_BYTES + 64];
    int der_len = BIO_read(b64, der, sizeof(der));
    BIO_free_all(b64);

    if (der_len <= 0)
        return QUDO_SLHDSA_ERROR_DECODE;

    return QUDO_SLHDSA_import_public_key_der(der, (size_t)der_len, public_key,
                                             public_key_len);
}

QUDO_SLHDSA_API QUDO_SLHDSA_status_t QUDO_SLHDSA_export_private_key_pem(
    const uint8_t *private_key, size_t private_key_len,
    QUDO_SLHDSA_parameter_set_t param_set, char *pem_out, size_t *pem_out_len)
{

    size_t der_len = 0;
    QUDO_SLHDSA_status_t rc = QUDO_SLHDSA_export_private_key_der(
        private_key, private_key_len, param_set, NULL, &der_len);
    if (rc != QUDO_SLHDSA_SUCCESS)
        return rc;

    uint8_t *der = (uint8_t *)malloc(der_len);
    if (!der)
        return QUDO_SLHDSA_ERROR_ALLOC;

    rc = QUDO_SLHDSA_export_private_key_der(private_key, private_key_len,
                                            param_set, der, &der_len);
    if (rc != QUDO_SLHDSA_SUCCESS) {
        QUDO_SLHDSA_secure_zero(der, der_len);
        free(der);
        return rc;
    }

    BIO *b64 = BIO_new(BIO_f_base64());
    BIO *mem_bio = BIO_new(BIO_s_mem());
    if (!b64 || !mem_bio) {
        QUDO_SLHDSA_secure_zero(der, der_len);
        free(der);
        BIO_free(b64);
        BIO_free(mem_bio);
        return QUDO_SLHDSA_ERROR_ALLOC;
    }
    BIO_push(b64, mem_bio);
    BIO_write(b64, der, (int)der_len);
    BIO_flush(b64);
    QUDO_SLHDSA_secure_zero(der, der_len);
    free(der);

    BUF_MEM *bptr;
    BIO_get_mem_ptr(b64, &bptr);

    size_t needed = strlen(PEM_HEADER_PRIVATE) + bptr->length
                    + strlen(PEM_FOOTER_PRIVATE) + 1;

    if (!pem_out) {
        *pem_out_len = needed;
        BIO_free_all(b64);
        return QUDO_SLHDSA_SUCCESS;
    }

    if (*pem_out_len < needed) {
        BIO_free_all(b64);
        return QUDO_SLHDSA_ERROR_BUFFER_TOO_SMALL;
    }

    char *p = pem_out;
    memcpy(p, PEM_HEADER_PRIVATE, strlen(PEM_HEADER_PRIVATE));
    p += strlen(PEM_HEADER_PRIVATE);
    memcpy(p, bptr->data, bptr->length);
    p += bptr->length;
    memcpy(p, PEM_FOOTER_PRIVATE, strlen(PEM_FOOTER_PRIVATE));
    p += strlen(PEM_FOOTER_PRIVATE);
    *p = '\0';
    *pem_out_len = (size_t)(p - pem_out);

    BIO_free_all(b64);
    return QUDO_SLHDSA_SUCCESS;
}

QUDO_SLHDSA_API QUDO_SLHDSA_status_t QUDO_SLHDSA_import_private_key_pem(
    const char *pem_in, size_t pem_in_len, uint8_t *private_key,
    size_t *private_key_len)
{

    (void)pem_in_len;

    if (!pem_in || !private_key_len)
        return QUDO_SLHDSA_ERROR_NULL_PTR;

    const char *start = strstr(pem_in, "-----BEGIN PRIVATE KEY-----");
    if (!start)
        return QUDO_SLHDSA_ERROR_DECODE;
    start = strchr(start, '\n');
    if (!start)
        return QUDO_SLHDSA_ERROR_DECODE;
    start++;

    const char *end_marker = strstr(start, "-----END PRIVATE KEY-----");
    if (!end_marker)
        return QUDO_SLHDSA_ERROR_DECODE;

    size_t b64_len = (size_t)(end_marker - start);

    BIO *b64 = BIO_new(BIO_f_base64());
    BIO *mem = BIO_new_mem_buf(start, (int)b64_len);
    if (!b64 || !mem) {
        BIO_free(b64);
        BIO_free(mem);
        return QUDO_SLHDSA_ERROR_ALLOC;
    }
    BIO_push(b64, mem);

    uint8_t der[SLH_DSA_MAX_SECRET_KEY_BYTES + 64];
    int der_len = BIO_read(b64, der, sizeof(der));
    BIO_free_all(b64);

    if (der_len <= 0)
        return QUDO_SLHDSA_ERROR_DECODE;

    QUDO_SLHDSA_status_t rc = QUDO_SLHDSA_import_private_key_der(
        der, (size_t)der_len, private_key, private_key_len);

    QUDO_SLHDSA_secure_zero(der, sizeof(der));
    return rc;
}

#else

static const char b64_alphabet[]
    = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

static int b64_decode_char(char c)
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

#    define SLHDSA_PEM_LINE 64

static size_t slhdsa_b64_encoded_len(size_t bin_len)
{
    size_t groups = (bin_len + 2) / 3;
    size_t b64 = groups * 4;
    size_t lines = (b64 + SLHDSA_PEM_LINE - 1) / SLHDSA_PEM_LINE;
    return b64 + lines;
}

static void slhdsa_b64_encode_wrapped(const uint8_t *in, size_t in_len,
                                      char *out, size_t *out_pos)
{
    size_t col = 0;
    size_t i = 0;
    while (i + 3 <= in_len) {
        uint32_t v
            = ((uint32_t)in[i] << 16) | ((uint32_t)in[i + 1] << 8) | in[i + 2];
        out[(*out_pos)++] = b64_alphabet[(v >> 18) & 0x3F];
        out[(*out_pos)++] = b64_alphabet[(v >> 12) & 0x3F];
        out[(*out_pos)++] = b64_alphabet[(v >> 6) & 0x3F];
        out[(*out_pos)++] = b64_alphabet[v & 0x3F];
        col += 4;
        if (col >= SLHDSA_PEM_LINE) {
            out[(*out_pos)++] = '\n';
            col = 0;
        }
        i += 3;
    }
    if (i < in_len) {
        uint32_t v = (uint32_t)in[i] << 16;
        if (i + 1 < in_len)
            v |= (uint32_t)in[i + 1] << 8;
        out[(*out_pos)++] = b64_alphabet[(v >> 18) & 0x3F];
        out[(*out_pos)++] = b64_alphabet[(v >> 12) & 0x3F];
        out[(*out_pos)++]
            = (i + 1 < in_len) ? b64_alphabet[(v >> 6) & 0x3F] : '=';
        out[(*out_pos)++] = '=';
        col += 4;
    }
    if (col != 0)
        out[(*out_pos)++] = '\n';
}

static int slhdsa_b64_decode(const char *in, size_t in_len, uint8_t *out,
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
        int v = b64_decode_char(c);
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

static QUDO_SLHDSA_status_t slhdsa_pem_wrap(const char *label,
                                            const uint8_t *der, size_t der_len,
                                            char *out, size_t *out_len)
{
    size_t hdr_len = 11 + strlen(label) + 5 + 1;
    size_t ftr_len = 9 + strlen(label) + 5 + 1;
    size_t b64_len = slhdsa_b64_encoded_len(der_len);
    size_t need = hdr_len + b64_len + ftr_len + 1;

    if (!out) {
        *out_len = need;
        return QUDO_SLHDSA_SUCCESS;
    }
    if (*out_len < need)
        return QUDO_SLHDSA_ERROR_BUFFER_TOO_SMALL;

    size_t pos = 0;
    pos += (size_t)snprintf(out + pos, *out_len - pos, "-----BEGIN %s-----\n",
                            label);
    slhdsa_b64_encode_wrapped(der, der_len, out, &pos);
    pos += (size_t)snprintf(out + pos, *out_len - pos, "-----END %s-----\n",
                            label);
    out[pos] = '\0';
    *out_len = pos;
    return QUDO_SLHDSA_SUCCESS;
}

static QUDO_SLHDSA_status_t slhdsa_pem_unwrap(const char *label,
                                              const char *pem, size_t pem_len,
                                              uint8_t *der, size_t *der_len)
{
    char begin[64];
    char end[64];
    int n;
    n = snprintf(begin, sizeof(begin), "-----BEGIN %s-----", label);
    if (n <= 0 || (size_t)n >= sizeof(begin))
        return QUDO_SLHDSA_ERROR_DECODE;
    n = snprintf(end, sizeof(end), "-----END %s-----", label);
    if (n <= 0 || (size_t)n >= sizeof(end))
        return QUDO_SLHDSA_ERROR_DECODE;

    if (pem_len == 0)
        pem_len = strlen(pem);
    const char *p = strstr(pem, begin);
    if (!p)
        return QUDO_SLHDSA_ERROR_DECODE;
    p += strlen(begin);
    const char *q = strstr(p, end);
    if (!q || q <= p)
        return QUDO_SLHDSA_ERROR_DECODE;

    if (slhdsa_b64_decode(p, (size_t)(q - p), der, der_len) != 0)
        return QUDO_SLHDSA_ERROR_DECODE;
    return QUDO_SLHDSA_SUCCESS;
}

QUDO_SLHDSA_API QUDO_SLHDSA_status_t QUDO_SLHDSA_export_public_key_pem(
    const uint8_t *pk, size_t pk_len, QUDO_SLHDSA_parameter_set_t param_set,
    char *out, size_t *out_len)
{
    if (!pk || !out_len)
        return QUDO_SLHDSA_ERROR_NULL_PTR;

    size_t der_len = 0;
    QUDO_SLHDSA_status_t rc = QUDO_SLHDSA_export_public_key_der(
        pk, pk_len, param_set, NULL, &der_len);
    if (rc != QUDO_SLHDSA_SUCCESS)
        return rc;

    uint8_t *der = (uint8_t *)malloc(der_len);
    if (!der)
        return QUDO_SLHDSA_ERROR_ALLOC;

    rc = QUDO_SLHDSA_export_public_key_der(pk, pk_len, param_set, der,
                                           &der_len);
    if (rc != QUDO_SLHDSA_SUCCESS) {
        free(der);
        return rc;
    }

    rc = slhdsa_pem_wrap("PUBLIC KEY", der, der_len, out, out_len);
    free(der);
    return rc;
}

QUDO_SLHDSA_API QUDO_SLHDSA_status_t
QUDO_SLHDSA_import_public_key_pem(const char *pem_in, size_t pem_in_len,
                                  uint8_t *public_key, size_t *public_key_len)
{
    if (!pem_in || !public_key_len)
        return QUDO_SLHDSA_ERROR_NULL_PTR;

    uint8_t der[8192];
    size_t der_len = sizeof(der);
    QUDO_SLHDSA_status_t rc
        = slhdsa_pem_unwrap("PUBLIC KEY", pem_in, pem_in_len, der, &der_len);
    if (rc != QUDO_SLHDSA_SUCCESS)
        return rc;

    return QUDO_SLHDSA_import_public_key_der(der, der_len, public_key,
                                             public_key_len);
}

QUDO_SLHDSA_API QUDO_SLHDSA_status_t QUDO_SLHDSA_export_private_key_pem(
    const uint8_t *sk, size_t sk_len, QUDO_SLHDSA_parameter_set_t param_set,
    char *out, size_t *out_len)
{
    if (!sk || !out_len)
        return QUDO_SLHDSA_ERROR_NULL_PTR;

    size_t der_len = 0;
    QUDO_SLHDSA_status_t rc = QUDO_SLHDSA_export_private_key_der(
        sk, sk_len, param_set, NULL, &der_len);
    if (rc != QUDO_SLHDSA_SUCCESS)
        return rc;

    uint8_t *der = (uint8_t *)malloc(der_len);
    if (!der)
        return QUDO_SLHDSA_ERROR_ALLOC;

    rc = QUDO_SLHDSA_export_private_key_der(sk, sk_len, param_set, der,
                                            &der_len);
    if (rc != QUDO_SLHDSA_SUCCESS) {
        QUDO_SLHDSA_secure_zero(der, der_len);
        free(der);
        return rc;
    }

    rc = slhdsa_pem_wrap("PRIVATE KEY", der, der_len, out, out_len);
    QUDO_SLHDSA_secure_zero(der, der_len);
    free(der);
    return rc;
}

QUDO_SLHDSA_API QUDO_SLHDSA_status_t QUDO_SLHDSA_import_private_key_pem(
    const char *pem_in, size_t pem_in_len, uint8_t *private_key,
    size_t *private_key_len)
{
    if (!pem_in || !private_key_len)
        return QUDO_SLHDSA_ERROR_NULL_PTR;

    uint8_t der[16384];
    size_t der_len = sizeof(der);
    QUDO_SLHDSA_status_t rc
        = slhdsa_pem_unwrap("PRIVATE KEY", pem_in, pem_in_len, der, &der_len);
    if (rc != QUDO_SLHDSA_SUCCESS)
        return rc;

    rc = QUDO_SLHDSA_import_private_key_der(der, der_len, private_key,
                                            private_key_len);
    QUDO_SLHDSA_secure_zero(der, sizeof(der));
    return rc;
}

#endif
