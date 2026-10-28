/* SPDX-License-Identifier: Apache-2.0 AND MIT */

#include "qudo_pqc.h"

#ifdef QUDO_FIPS_MODULE

#    include "fips/qudo_fips_hmac.h"
#    include "qudo_fipskey.h"
#    include "qudo_pqc_platform.h"
#    include "qudo_pqc_selftest.h"
#    include <stdio.h>
#    include <string.h>

#    define INTEGRITY_BUF_SIZE 4096

static const unsigned char fixed_key[32] = {QUDO_FIPS_KEY_ELEMENTS};

static const unsigned char hmac_kat_pt[]
    = {0x51, 0x55, 0x44, 0x4f, 0x20, 0x46, 0x49, 0x50,
       0x53, 0x20, 0x49, 0x4e, 0x54, 0x45, 0x47, 0x21};

static const unsigned char hmac_kat_digest[]
    = {0x45, 0x4e, 0xad, 0x3e, 0xb8, 0x7c, 0xad, 0xa1, 0x61, 0x79, 0x98,
       0x1a, 0xb0, 0x34, 0xbb, 0x6b, 0x5d, 0x57, 0x07, 0xad, 0x0b, 0xcf,
       0xf3, 0x36, 0xd3, 0xdc, 0x74, 0x34, 0x45, 0xed, 0xe3, 0x1d};

static int qudo_pqc_integrity_kat(qudo_st_ctx_t *st)
{
    int ok = 0;
    unsigned char out[QUDO_FIPS_HMAC_SHA256_DIGEST_SIZE];

    qudo_st_begin(st, QUDO_ST_TYPE_KAT_INTEGRITY, QUDO_ST_DESC_INTEGRITY_HMAC);

    qudo_fips_hmac_sha256(fixed_key, sizeof(fixed_key), hmac_kat_pt,
                          sizeof(hmac_kat_pt), out);

    qudo_st_corrupt(st, out);

    if (qudo_memcmp_ct(out, hmac_kat_digest, sizeof(hmac_kat_digest)) != 0)
        goto err;

    ok = 1;
err:
    qudo_st_end(st, ok);
    qudo_cleanse(out, sizeof(out));
    return ok;
}

static void *default_io_open(const char *path, const char *mode)
{
    return (void *)fopen(path, mode);
}

static int default_io_read(void *handle, void *buf, size_t len,
                           size_t *bytes_read)
{
    size_t n;

    if (handle == NULL)
        return -1;
    n = fread(buf, 1, len, (FILE *)handle);
    if (bytes_read != NULL)
        *bytes_read = n;
    if (ferror((FILE *)handle))
        return -1;
    if (n == 0)
        return 0;
    return 1;
}

static void default_io_close(void *handle)
{
    if (handle != NULL)
        fclose((FILE *)handle);
}

static size_t hex_to_bin(const char *hex, unsigned char *bin, size_t bin_len)
{
    size_t out = 0;
    const char *p;

    if (hex == NULL || bin == NULL)
        return 0;

    p = hex;
    while (*p != '\0') {
        unsigned char hi, lo;

        if (*p == ':') {
            p++;
            continue;
        }

        if (p[1] == '\0')
            return 0;

        hi = (unsigned char)p[0];
        lo = (unsigned char)p[1];

        if (hi >= '0' && hi <= '9')
            hi -= '0';
        else if (hi >= 'a' && hi <= 'f')
            hi = hi - 'a' + 10;
        else if (hi >= 'A' && hi <= 'F')
            hi = hi - 'A' + 10;
        else
            return 0;

        if (lo >= '0' && lo <= '9')
            lo -= '0';
        else if (lo >= 'a' && lo <= 'f')
            lo = lo - 'a' + 10;
        else if (lo >= 'A' && lo <= 'F')
            lo = lo - 'A' + 10;
        else
            return 0;

        if (out >= bin_len)
            return 0;

        bin[out++] = (unsigned char)((hi << 4) | lo);
        p += 2;
    }
    return out;
}

QUDO_PQC_API int qudo_pqc_verify_integrity(const qudo_pqc_config_t *config,
                                           qudo_st_ctx_t *st)
{
    int ret = 0;
    unsigned char computed[QUDO_FIPS_HMAC_SHA256_DIGEST_SIZE];
    unsigned char expected[QUDO_FIPS_HMAC_SHA256_DIGEST_SIZE];
    unsigned char buf[INTEGRITY_BUF_SIZE];
    size_t bytes_read = 0;
    size_t expected_len;
    qudo_fips_hmac_ctx_t hmac_ctx;
    void *handle = NULL;

    qudo_io_open_fn io_open
        = config->io_open ? config->io_open : default_io_open;
    qudo_io_read_fn io_read
        = config->io_read ? config->io_read : default_io_read;
    qudo_io_close_fn io_close
        = config->io_close ? config->io_close : default_io_close;

    if (!qudo_pqc_integrity_kat(st))
        return 0;

    if (config->module_path == NULL || config->module_checksum_hex == NULL)
        return 0;

    expected_len
        = hex_to_bin(config->module_checksum_hex, expected, sizeof(expected));
    if (expected_len != QUDO_FIPS_HMAC_SHA256_DIGEST_SIZE)
        return 0;

    qudo_st_begin(st, QUDO_ST_TYPE_MODULE_INTEGRITY,
                  QUDO_ST_DESC_INTEGRITY_HMAC);

    handle = io_open(config->module_path, "rb");
    if (handle == NULL)
        goto err;

    qudo_fips_hmac_init(&hmac_ctx, fixed_key, sizeof(fixed_key));

    {
        int rd;
        while ((rd = io_read(handle, buf, sizeof(buf), &bytes_read)) > 0) {
            if (bytes_read > 0)
                qudo_fips_hmac_update(&hmac_ctx, buf, bytes_read);
        }
        if (rd < 0)
            goto err;
    }

    qudo_fips_hmac_final(&hmac_ctx, computed);

    qudo_st_corrupt(st, computed);

    if (qudo_memcmp_ct(computed, expected, QUDO_FIPS_HMAC_SHA256_DIGEST_SIZE)
        != 0)
        goto err;

    ret = 1;
err:
    qudo_st_end(st, ret);
    if (handle != NULL)
        io_close(handle);
    qudo_cleanse(computed, sizeof(computed));
    qudo_cleanse(buf, sizeof(buf));
    qudo_cleanse(&hmac_ctx, sizeof(hmac_ctx));
    return ret;
}

extern int qudo_fips_module_start(void);
extern int qudo_fips_module_end(void);

extern unsigned char qudo_fips_integrity_hmac[32];

QUDO_PQC_API int qudo_pqc_verify_integrity_embedded(qudo_st_ctx_t *st)
{
    unsigned char computed[QUDO_FIPS_HMAC_SHA256_DIGEST_SIZE];
    const unsigned char *region_start;
    const unsigned char *region_end;
    size_t region_size;
    int ret = 0;

    if (!qudo_pqc_integrity_kat(st))
        return 0;

    {
        static const unsigned char sentinel[24]
            = {'Q', 'U', 'D', 'O', '_', 'F', 'I', 'P', 'S', '_', 'N', 'O',
               'T', '_', 'P', 'A', 'T', 'C', 'H', 'E', 'D', '_', '_', '_'};
        if (memcmp(qudo_fips_integrity_hmac, sentinel, sizeof(sentinel)) == 0)
            return -1;
    }

    qudo_st_begin(st, QUDO_ST_TYPE_MODULE_INTEGRITY,
                  QUDO_ST_DESC_INTEGRITY_HMAC);

    region_start = (const unsigned char *)(void *)qudo_fips_module_start;
    region_end = (const unsigned char *)(void *)qudo_fips_module_end;

    if (region_end <= region_start)
        goto err;

    region_size = (size_t)(region_end - region_start);

    if (region_size < 1024)
        goto err;

    qudo_fips_hmac_sha256(fixed_key, sizeof(fixed_key), region_start,
                          region_size, computed);

    qudo_st_corrupt(st, computed);

    if (qudo_memcmp_ct(computed, qudo_fips_integrity_hmac,
                       QUDO_FIPS_HMAC_SHA256_DIGEST_SIZE)
        != 0)
        goto err;

    ret = 1;
err:
    qudo_st_end(st, ret);
    qudo_cleanse(computed, sizeof(computed));
    return ret;
}

#endif
