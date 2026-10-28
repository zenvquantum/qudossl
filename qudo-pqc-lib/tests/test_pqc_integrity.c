/* SPDX-License-Identifier: Apache-2.0 AND MIT */

#include "qudo_pqc.h"
#include "qudo_pqc_platform.h"
#include "test_fips_init.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef QUDO_FIPS_MODULE
#    include "qudo_fipskey.h"
#    include "qudo_pqc_selftest.h"

extern int qudo_pqc_verify_integrity(const qudo_pqc_config_t *config,
                                     qudo_st_ctx_t *st);
#endif

static int g_pass = 0;
static int g_fail = 0;
static int g_skip = 0;
static int g_verbose = 0;

#ifdef QUDO_FIPS_MODULE
static const char *state_name(int state)
{
    switch (state) {
    case QUDO_PQC_STATE_INIT:
        return "INIT";
    case QUDO_PQC_STATE_SELFTEST:
        return "SELFTEST";
    case QUDO_PQC_STATE_RUNNING:
        return "RUNNING";
    case QUDO_PQC_STATE_ERROR:
        return "ERROR";
    default:
        return "UNKNOWN";
    }
}
#endif

#define VLOG(...)                       \
    do {                                \
        if (g_verbose)                  \
            printf("    " __VA_ARGS__); \
    } while (0)

#define RUN_TEST(fn)                       \
    do {                                   \
        if (g_verbose)                     \
            printf("  %s:\n", #fn);        \
        int _r = fn();                     \
        if (_r > 0) {                      \
            g_pass++;                      \
            printf("  %-55s PASS\n", #fn); \
        } else if (_r == 0) {              \
            g_fail++;                      \
            printf("  %-55s FAIL\n", #fn); \
        } else {                           \
            g_skip++;                      \
            printf("  %-55s SKIP\n", #fn); \
        }                                  \
    } while (0)

static int test_is_fips(void)
{
    int fips = qudo_pqc_is_fips();
#ifdef QUDO_FIPS_MODULE
    if (fips != 1) {
        fprintf(stderr, "    expected 1 in FIPS build\n");
        return 0;
    }
#else
    if (fips != 0) {
        fprintf(stderr, "    expected 0 in standard build\n");
        return 0;
    }
#endif
    return 1;
}

#ifdef QUDO_FIPS_MODULE

static int null_st_cb(qudo_st_phase_t phase, const char *type, const char *desc,
                      int result, unsigned char *data, void **event,
                      void *cb_arg)
{
    (void)phase;
    (void)type;
    (void)desc;
    (void)result;
    (void)data;
    (void)event;
    (void)cb_arg;
    return 1;
}

static const unsigned char fips_key[32] = {QUDO_FIPS_KEY_ELEMENTS};

#    if defined(_WIN32)
#        define TEST_FILE_PATH "qudo_test_integrity_tmp.bin"
#        define TEST_CNF_PATH  "qudo_test_fips_tmp.cnf"
#    else
#        define TEST_FILE_PATH "/tmp/qudo_test_integrity_tmp.bin"
#        define TEST_CNF_PATH  "/tmp/qudo_test_fips_tmp.cnf"
#    endif

static char *create_test_file(const char *path, const unsigned char *content,
                              size_t content_len)
{
    FILE *f;
    unsigned char digest[32];
    char *hex;
    size_t i;

    f = fopen(path, "wb");
    if (f == NULL)
        return NULL;
    fwrite(content, 1, content_len, f);
    fclose(f);

    qudo_pqc_hmac_sha256(fips_key, sizeof(fips_key), content, content_len,
                         digest);

    hex = (char *)malloc(32 * 2 + 1);
    if (hex == NULL)
        return NULL;

    for (i = 0; i < 32; i++)
        sprintf(hex + i * 2, "%02x", digest[i]);
    hex[32 * 2] = '\0';

    return hex;
}

static void cleanup_test_file(const char *path)
{
    if (path != NULL)
        remove(path);
}

#    define FILE_BUF_SIZE 4096

static char *compute_file_hmac_hex(const char *path)
{
    FILE *f;
    qudo_pqc_hmac_ctx_t *ctx;
    unsigned char buf[FILE_BUF_SIZE];
    unsigned char digest[32];
    char *hex;
    size_t n, i;

    f = fopen(path, "rb");
    if (f == NULL)
        return NULL;

    ctx = qudo_pqc_hmac_ctx_new();
    if (ctx == NULL) {
        fclose(f);
        return NULL;
    }
    qudo_pqc_hmac_ctx_init(ctx, fips_key, sizeof(fips_key));

    while ((n = fread(buf, 1, sizeof(buf), f)) > 0)
        qudo_pqc_hmac_ctx_update(ctx, buf, n);

    if (ferror(f)) {
        qudo_pqc_hmac_ctx_free(ctx);
        fclose(f);
        return NULL;
    }
    fclose(f);

    qudo_pqc_hmac_ctx_final(ctx, digest);
    qudo_pqc_hmac_ctx_free(ctx);
    qudo_cleanse(buf, sizeof(buf));

    hex = (char *)malloc(32 * 2 + 1);
    if (hex == NULL)
        return NULL;

    for (i = 0; i < 32; i++)
        sprintf(hex + i * 2, "%02x", digest[i]);
    hex[32 * 2] = '\0';

    return hex;
}

static char *parse_module_mac_from_cnf(const char *cnf_path)
{
    FILE *f;
    char line[1024];
    char *mac_start, *hex, *dst;
    const char *src;

    f = fopen(cnf_path, "r");
    if (f == NULL)
        return NULL;

    while (fgets(line, sizeof(line), f) != NULL) {

        mac_start = strstr(line, "module-mac");
        if (mac_start == NULL)
            continue;

        mac_start = strchr(mac_start, '=');
        if (mac_start == NULL)
            continue;
        mac_start++;

        while (*mac_start == ' ' || *mac_start == '\t')
            mac_start++;

        {
            size_t len = strlen(mac_start);
            while (len > 0
                   && (mac_start[len - 1] == '\n' || mac_start[len - 1] == '\r'
                       || mac_start[len - 1] == ' '))
                mac_start[--len] = '\0';
        }

        hex = (char *)malloc(strlen(mac_start) + 1);
        if (hex == NULL) {
            fclose(f);
            return NULL;
        }

        dst = hex;
        for (src = mac_start; *src != '\0'; src++) {
            if (*src != ':')
                *dst++ = *src;
        }
        *dst = '\0';

        fclose(f);
        return hex;
    }

    fclose(f);
    return NULL;
}

#    if defined(_WIN32)
#        define LIB_NAME "..\\lib\\qudo-pqc.dll"
#    else
#        define LIB_NAME "../lib/libqudo-pqc.a"
#    endif

#    if defined(_WIN32)
#        define FIPSINSTALL_NAME "..\\tools\\qudo_fipsinstall.exe"
#    else
#        define FIPSINSTALL_NAME "../tools/qudo_fipsinstall"
#    endif

static int fipsinstall_available(void)
{
    FILE *f = fopen(FIPSINSTALL_NAME, "rb");
    if (f != NULL) {
        fclose(f);
        return 1;
    }
    VLOG("Tool not found: %s (run from build-fips/tests/)\n", FIPSINSTALL_NAME);
    return 0;
}

static int module_available(void)
{
    FILE *f = fopen(LIB_NAME, "rb");
    if (f != NULL) {
        fclose(f);
        return 1;
    }
    VLOG("Module not found: %s (run from build-fips/tests/)\n", LIB_NAME);
    return 0;
}

static const unsigned char hmac_kat_pt[]
    = {0x51, 0x55, 0x44, 0x4f, 0x20, 0x46, 0x49, 0x50,
       0x53, 0x20, 0x49, 0x4e, 0x54, 0x45, 0x47, 0x21};
static const unsigned char hmac_kat_expected[]
    = {0x45, 0x4e, 0xad, 0x3e, 0xb8, 0x7c, 0xad, 0xa1, 0x61, 0x79, 0x98,
       0x1a, 0xb0, 0x34, 0xbb, 0x6b, 0x5d, 0x57, 0x07, 0xad, 0x0b, 0xcf,
       0xf3, 0x36, 0xd3, 0xdc, 0x74, 0x34, 0x45, 0xed, 0xe3, 0x1d};

static int test_hmac_kat_exact(void)
{
    unsigned char out[32];

    VLOG("Computing HMAC-SHA-256(FIPS_KEY, \"QUDO FIPS INTEG!\") — 16 bytes\n");
    qudo_pqc_hmac_sha256(fips_key, sizeof(fips_key), hmac_kat_pt,
                         sizeof(hmac_kat_pt), out);

    VLOG("Comparing against hardcoded expected value (32 bytes)\n");
    VLOG("Expected: 454ead3eb87cada1...ed e31d\n");
    VLOG("Got:      %02x%02x%02x%02x%02x%02x%02x%02x...%02x%02x\n", out[0],
         out[1], out[2], out[3], out[4], out[5], out[6], out[7], out[30],
         out[31]);
    if (memcmp(out, hmac_kat_expected, sizeof(hmac_kat_expected)) != 0) {
        fprintf(stderr, "    HMAC output does not match expected KAT value\n");
        return 0;
    }
    return 1;
}

static int test_hmac_kat(void)
{
    unsigned char msg[] = {'Q', 'U', 'D', 'O'};
    unsigned char out1[32];
    unsigned char out2[32];
    int i, all_zero;

    VLOG("Computing HMAC-SHA-256(FIPS_KEY, \"QUDO\") twice\n");
    qudo_pqc_hmac_sha256(fips_key, sizeof(fips_key), msg, sizeof(msg), out1);
    qudo_pqc_hmac_sha256(fips_key, sizeof(fips_key), msg, sizeof(msg), out2);

    VLOG("Expected: non-zero output\n");
    all_zero = 1;
    for (i = 0; i < 32; i++) {
        if (out1[i] != 0) {
            all_zero = 0;
            break;
        }
    }
    VLOG("Got:      %s\n", all_zero ? "all zeros" : "non-zero");
    if (all_zero) {
        fprintf(stderr, "    HMAC output is all zeros\n");
        return 0;
    }

    VLOG("Expected: both outputs identical\n");
    VLOG("Got:      %s\n",
         memcmp(out1, out2, 32) == 0 ? "identical" : "different");
    if (memcmp(out1, out2, 32) != 0) {
        fprintf(stderr, "    HMAC not deterministic\n");
        return 0;
    }

    return 1;
}

static int test_hmac_different_inputs(void)
{
    unsigned char msg1[] = {'A', 'B', 'C'};
    unsigned char msg2[] = {'D', 'E', 'F'};
    unsigned char out1[32];
    unsigned char out2[32];

    VLOG("Computing HMAC(\"ABC\") and HMAC(\"DEF\")\n");
    qudo_pqc_hmac_sha256(fips_key, sizeof(fips_key), msg1, sizeof(msg1), out1);
    qudo_pqc_hmac_sha256(fips_key, sizeof(fips_key), msg2, sizeof(msg2), out2);

    VLOG("Expected: outputs differ\n");
    VLOG("Got:      %s\n",
         memcmp(out1, out2, 32) == 0 ? "identical" : "different");
    if (memcmp(out1, out2, 32) == 0) {
        fprintf(stderr, "    different inputs produced same HMAC\n");
        return 0;
    }

    return 1;
}

static int test_integrity_synthetic_valid(void)
{
    unsigned char content[] = "QUDO PQC FIPS 140-3 Integrity Test Content";
    char *checksum_hex;
    qudo_pqc_config_t config;
    qudo_st_ctx_t st;
    int ret;

    VLOG("Creating temp file with %zu bytes of known content\n",
         sizeof(content) - 1);
    checksum_hex
        = create_test_file(TEST_FILE_PATH, content, sizeof(content) - 1);
    if (checksum_hex == NULL) {
        fprintf(stderr, "    failed to create test file\n");
        return 0;
    }

    VLOG("Computing HMAC and verifying against file\n");
    memset(&config, 0, sizeof(config));
    config.self_test_cb = null_st_cb;
    config.module_path = TEST_FILE_PATH;
    config.module_checksum_hex = checksum_hex;
    config.conditional_errors = 1;

    st.cb = null_st_cb;
    st.cb_arg = NULL;
    st.current_type = NULL;
    st.current_desc = NULL;

    ret = qudo_pqc_verify_integrity(&config, &st);

    free(checksum_hex);
    cleanup_test_file(TEST_FILE_PATH);

    VLOG("Expected: accepted (return 1)\n");
    VLOG("Got:      %s (return %d)\n", ret ? "accepted" : "rejected", ret);
    if (!ret) {
        fprintf(stderr, "    integrity verification failed for valid file\n");
        return 0;
    }
    return 1;
}

static int test_integrity_synthetic_empty(void)
{
    unsigned char empty = 0;
    char *checksum_hex;
    qudo_pqc_config_t config;
    qudo_st_ctx_t st;
    int ret;

    VLOG("Creating empty temp file (0 bytes)\n");
    checksum_hex = create_test_file(TEST_FILE_PATH, &empty, 0);
    if (checksum_hex == NULL)
        return 0;

    VLOG("Verifying HMAC of empty file\n");
    memset(&config, 0, sizeof(config));
    config.self_test_cb = null_st_cb;
    config.module_path = TEST_FILE_PATH;
    config.module_checksum_hex = checksum_hex;
    config.conditional_errors = 1;

    st.cb = null_st_cb;
    st.cb_arg = NULL;
    st.current_type = NULL;
    st.current_desc = NULL;

    ret = qudo_pqc_verify_integrity(&config, &st);

    free(checksum_hex);
    cleanup_test_file(TEST_FILE_PATH);

    VLOG("Expected: accepted (return 1)\n");
    VLOG("Got:      %s (return %d)\n", ret ? "accepted" : "rejected", ret);
    if (!ret) {
        fprintf(stderr, "    empty file integrity verification failed\n");
        return 0;
    }
    return 1;
}

typedef struct {
    int kat_begin;
    int kat_end;
    int integrity_begin;
    int integrity_end;
} integrity_cb_data_t;

static int integrity_counting_cb(qudo_st_phase_t phase, const char *type,
                                 const char *desc, int result,
                                 unsigned char *data, void **event,
                                 void *cb_arg)
{
    integrity_cb_data_t *d = (integrity_cb_data_t *)cb_arg;
    (void)desc;
    (void)result;
    (void)data;
    (void)event;

    if (phase == QUDO_ST_PHASE_BEGIN) {
        if (strcmp(type, QUDO_ST_TYPE_KAT_INTEGRITY) == 0)
            d->kat_begin++;
        else if (strcmp(type, QUDO_ST_TYPE_MODULE_INTEGRITY) == 0)
            d->integrity_begin++;
    } else if (phase == QUDO_ST_PHASE_END) {
        if (strcmp(type, QUDO_ST_TYPE_KAT_INTEGRITY) == 0)
            d->kat_end++;
        else if (strcmp(type, QUDO_ST_TYPE_MODULE_INTEGRITY) == 0)
            d->integrity_end++;
    }
    return 1;
}

static int test_integrity_callback_events(void)
{
    unsigned char content[] = "Callback test content";
    char *checksum_hex;
    qudo_pqc_config_t config;
    qudo_st_ctx_t st;
    integrity_cb_data_t data;

    VLOG("Creating temp file and registering event-counting callback\n");
    checksum_hex
        = create_test_file(TEST_FILE_PATH, content, sizeof(content) - 1);
    if (checksum_hex == NULL)
        return 0;

    memset(&data, 0, sizeof(data));
    memset(&config, 0, sizeof(config));
    config.self_test_cb = integrity_counting_cb;
    config.self_test_cb_arg = &data;
    config.module_path = TEST_FILE_PATH;
    config.module_checksum_hex = checksum_hex;
    config.conditional_errors = 1;

    st.cb = integrity_counting_cb;
    st.cb_arg = &data;
    st.current_type = NULL;
    st.current_desc = NULL;

    qudo_pqc_verify_integrity(&config, &st);

    free(checksum_hex);
    cleanup_test_file(TEST_FILE_PATH);

    VLOG("Expected: KAT begin=1 end=1, integrity begin=1 end=1\n");
    VLOG("Got:      KAT begin=%d end=%d, integrity begin=%d end=%d\n",
         data.kat_begin, data.kat_end, data.integrity_begin,
         data.integrity_end);
    if (data.kat_begin != 1 || data.kat_end != 1) {
        fprintf(stderr, "    KAT events: begin=%d end=%d (expected 1/1)\n",
                data.kat_begin, data.kat_end);
        return 0;
    }
    if (data.integrity_begin != 1 || data.integrity_end != 1) {
        fprintf(stderr,
                "    integrity events: begin=%d end=%d (expected 1/1)\n",
                data.integrity_begin, data.integrity_end);
        return 0;
    }

    return 1;
}

static int test_integrity_real_binary_fipsinstall(void)
{
    char cmd[512];
    char *mac_hex = NULL;
    qudo_pqc_config_t config;
    qudo_st_ctx_t st;
    int ret;

    if (!fipsinstall_available() || !module_available())
        return -1;

    VLOG("Running: %s -module %s -out %s\n", FIPSINSTALL_NAME, LIB_NAME,
         TEST_CNF_PATH);

    snprintf(cmd, sizeof(cmd), "%s -module %s -out %s -quiet", FIPSINSTALL_NAME,
             LIB_NAME, TEST_CNF_PATH);

    if (system(cmd) != 0) {
        fprintf(stderr, "    qudo_fipsinstall failed\n");
        return 0;
    }

    VLOG("Parsing module-mac from %s\n", TEST_CNF_PATH);
    mac_hex = parse_module_mac_from_cnf(TEST_CNF_PATH);
    if (mac_hex == NULL) {
        fprintf(stderr, "    failed to parse module-mac from %s\n",
                TEST_CNF_PATH);
        cleanup_test_file(TEST_CNF_PATH);
        return 0;
    }

    VLOG("Verifying %s against parsed checksum (%zu hex chars)\n", LIB_NAME,
         mac_hex ? strlen(mac_hex) : 0);
    memset(&config, 0, sizeof(config));
    config.self_test_cb = null_st_cb;
    config.module_path = LIB_NAME;
    config.module_checksum_hex = mac_hex;
    config.conditional_errors = 1;

    st.cb = null_st_cb;
    st.cb_arg = NULL;
    st.current_type = NULL;
    st.current_desc = NULL;

    ret = qudo_pqc_verify_integrity(&config, &st);

    free(mac_hex);
    cleanup_test_file(TEST_CNF_PATH);

    VLOG("Expected: accepted (return 1)\n");
    VLOG("Got:      %s (return %d)\n", ret ? "accepted" : "rejected", ret);
    if (!ret) {
        fprintf(stderr, "    real binary integrity verification failed\n");
        return 0;
    }
    return 1;
}

static int test_integrity_real_binary_self_computed(void)
{
    char *mac_hex = NULL;
    qudo_pqc_config_t config;
    qudo_st_ctx_t st;
    int ret;

    if (!module_available())
        return -1;

    VLOG("Computing HMAC-SHA-256 of %s using internal FIPS HMAC\n", LIB_NAME);
    mac_hex = compute_file_hmac_hex(LIB_NAME);
    if (mac_hex == NULL) {
        fprintf(stderr, "    failed to compute HMAC of %s\n", LIB_NAME);
        return 0;
    }

    VLOG("Verifying %s against self-computed checksum\n", LIB_NAME);
    memset(&config, 0, sizeof(config));
    config.self_test_cb = null_st_cb;
    config.module_path = LIB_NAME;
    config.module_checksum_hex = mac_hex;
    config.conditional_errors = 1;

    st.cb = null_st_cb;
    st.cb_arg = NULL;
    st.current_type = NULL;
    st.current_desc = NULL;

    ret = qudo_pqc_verify_integrity(&config, &st);

    free(mac_hex);

    VLOG("Expected: accepted (return 1)\n");
    VLOG("Got:      %s (return %d)\n", ret ? "accepted" : "rejected", ret);
    if (!ret) {
        fprintf(stderr, "    real binary self-computed integrity failed\n");
        return 0;
    }
    return 1;
}

static int test_integrity_real_binary_tampered(void)
{
    char *mac_hex = NULL;
    qudo_pqc_config_t config;
    qudo_st_ctx_t st;
    int ret;

    if (!module_available())
        return -1;

    mac_hex = compute_file_hmac_hex(LIB_NAME);
    if (mac_hex == NULL)
        return 0;

    VLOG("Tampering first byte of checksum\n");
    if (mac_hex[0] == 'a')
        mac_hex[0] = 'b';
    else
        mac_hex[0] = 'a';

    VLOG("Verifying %s against tampered checksum\n", LIB_NAME);
    memset(&config, 0, sizeof(config));
    config.self_test_cb = null_st_cb;
    config.module_path = LIB_NAME;
    config.module_checksum_hex = mac_hex;
    config.conditional_errors = 1;

    st.cb = null_st_cb;
    st.cb_arg = NULL;
    st.current_type = NULL;
    st.current_desc = NULL;

    ret = qudo_pqc_verify_integrity(&config, &st);

    free(mac_hex);

    VLOG("Expected: rejected (return 0)\n");
    VLOG("Got:      %s (return %d)\n", ret == 0 ? "rejected" : "accepted", ret);
    if (ret != 0) {
        fprintf(stderr, "    tampered checksum should fail\n");
        return 0;
    }
    return 1;
}

static int test_fipsinstall_verify_pass(void)
{
    char cmd_gen[512];
    char cmd_verify[512];
    int ret;

    if (!fipsinstall_available() || !module_available())
        return -1;

    VLOG("Generating: %s -module %s -out %s\n", FIPSINSTALL_NAME, LIB_NAME,
         TEST_CNF_PATH);
    snprintf(cmd_gen, sizeof(cmd_gen), "%s -module %s -out %s -quiet",
             FIPSINSTALL_NAME, LIB_NAME, TEST_CNF_PATH);
    if (system(cmd_gen) != 0) {
        fprintf(stderr, "    fipsinstall generate failed\n");
        return 0;
    }

    VLOG("Verifying: %s -verify -module %s -in %s\n", FIPSINSTALL_NAME,
         LIB_NAME, TEST_CNF_PATH);
    snprintf(cmd_verify, sizeof(cmd_verify),
             "%s -verify -module %s -in %s -quiet", FIPSINSTALL_NAME, LIB_NAME,
             TEST_CNF_PATH);
    ret = system(cmd_verify);
    cleanup_test_file(TEST_CNF_PATH);

    VLOG("Expected: accepted\n");
    VLOG("Got:      %s (exit %d)\n", ret == 0 ? "accepted" : "rejected", ret);
    if (ret != 0) {
        fprintf(stderr, "    fipsinstall verify failed (expected pass)\n");
        return 0;
    }
    return 1;
}

static int test_fipsinstall_verify_tampered(void)
{
    char cmd[512];
    FILE *fp;
    int ret;

    if (!fipsinstall_available() || !module_available())
        return -1;

    VLOG("Creating tampered config with wrong MAC\n");
    fp = fopen(TEST_CNF_PATH, "w");
    if (fp == NULL)
        return 0;
    fprintf(fp, "[qudo_pqc_sect]\n");
    fprintf(fp, "activate = 1\n");
    fprintf(fp, "module-mac = 00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF:"
                "00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF\n");
    fclose(fp);

    VLOG("Running verify with tampered config — expecting rejection\n");
#    if defined(_WIN32)
    snprintf(cmd, sizeof(cmd), "%s -verify -module %s -in %s -quiet 2>nul",
             FIPSINSTALL_NAME, LIB_NAME, TEST_CNF_PATH);
#    else
    snprintf(cmd, sizeof(cmd),
             "%s -verify -module %s -in %s -quiet 2>/dev/null",
             FIPSINSTALL_NAME, LIB_NAME, TEST_CNF_PATH);
#    endif

    ret = system(cmd);
    cleanup_test_file(TEST_CNF_PATH);

    VLOG("Expected: rejected\n");
    VLOG("Got:      %s (exit %d)\n", ret != 0 ? "rejected" : "accepted", ret);
    if (ret == 0) {
        fprintf(stderr, "    fipsinstall should reject tampered config\n");
        return 0;
    }
    return 1;
}

static int test_fipsinstall_verify_missing(void)
{
    char cmd[512];
    int ret;

    if (!fipsinstall_available() || !module_available())
        return -1;

    VLOG("Running verify with nonexistent config — expecting rejection\n");
#    if defined(_WIN32)
    snprintf(cmd, sizeof(cmd),
             "%s -verify -module %s -in /nonexistent/config.cnf -quiet 2>nul",
             FIPSINSTALL_NAME, LIB_NAME);
#    else
    snprintf(
        cmd, sizeof(cmd),
        "%s -verify -module %s -in /nonexistent/config.cnf -quiet 2>/dev/null",
        FIPSINSTALL_NAME, LIB_NAME);
#    endif

    ret = system(cmd);

    VLOG("Expected: rejected\n");
    VLOG("Got:      %s (exit %d)\n", ret != 0 ? "rejected" : "accepted", ret);
    if (ret == 0) {
        fprintf(stderr, "    fipsinstall should fail with missing config\n");
        return 0;
    }
    return 1;
}

static int test_fipsinstall_deterministic(void)
{
    char cmd[512];
    FILE *fp1, *fp2;
    char line1[1024], line2[1024];
    int ok = 0;

#    if defined(_WIN32)
    const char *cnf1 = "qudo_test_det1.cnf";
    const char *cnf2 = "qudo_test_det2.cnf";
#    else
    const char *cnf1 = "/tmp/qudo_test_det1.cnf";
    const char *cnf2 = "/tmp/qudo_test_det2.cnf";
#    endif

    if (!fipsinstall_available() || !module_available())
        return -1;

    VLOG("Generating config twice and comparing byte-for-byte\n");
    snprintf(cmd, sizeof(cmd), "%s -module %s -out %s -quiet", FIPSINSTALL_NAME,
             LIB_NAME, cnf1);
    if (system(cmd) != 0)
        goto done;

    snprintf(cmd, sizeof(cmd), "%s -module %s -out %s -quiet", FIPSINSTALL_NAME,
             LIB_NAME, cnf2);
    if (system(cmd) != 0)
        goto done;

    fp1 = fopen(cnf1, "r");
    fp2 = fopen(cnf2, "r");
    if (fp1 == NULL || fp2 == NULL) {
        if (fp1)
            fclose(fp1);
        if (fp2)
            fclose(fp2);
        goto done;
    }

    ok = 1;
    while (fgets(line1, sizeof(line1), fp1) != NULL) {
        if (fgets(line2, sizeof(line2), fp2) == NULL) {
            ok = 0;
            break;
        }
        if (strcmp(line1, line2) != 0) {
            ok = 0;
            break;
        }
    }
    if (ok && fgets(line2, sizeof(line2), fp2) != NULL)
        ok = 0;

    fclose(fp1);
    fclose(fp2);

    VLOG("Expected: both configs identical\n");
    VLOG("Got:      %s\n", ok ? "identical" : "different");
    if (!ok)
        fprintf(stderr, "    fipsinstall outputs differ across runs\n");

done:
    cleanup_test_file(cnf1);
    cleanup_test_file(cnf2);
    return ok ? 1 : 0;
}

static int test_fipsinstall_config_fields(void)
{
    char cmd[512];
    FILE *fp;
    char line[1024];
    int has_module_mac = 0, has_activate = 0, has_section = 0;

    if (!fipsinstall_available() || !module_available())
        return -1;

    VLOG("Generating config and checking required fields\n");
    snprintf(cmd, sizeof(cmd), "%s -module %s -out %s -quiet", FIPSINSTALL_NAME,
             LIB_NAME, TEST_CNF_PATH);
    if (system(cmd) != 0) {
        fprintf(stderr, "    fipsinstall generate failed\n");
        return 0;
    }

    fp = fopen(TEST_CNF_PATH, "r");
    if (fp == NULL)
        return 0;

    while (fgets(line, sizeof(line), fp) != NULL) {
        if (strstr(line, "[qudo_pqc_sect]") != NULL)
            has_section = 1;
        if (strstr(line, "module-mac") != NULL)
            has_module_mac = 1;
        if (strstr(line, "activate") != NULL)
            has_activate = 1;
    }
    fclose(fp);
    cleanup_test_file(TEST_CNF_PATH);

    VLOG("Expected: [qudo_pqc_sect]=1, module-mac=1, activate=1\n");
    VLOG("Got:      [qudo_pqc_sect]=%d, module-mac=%d, activate=%d\n",
         has_section, has_module_mac, has_activate);
    if (!has_section || !has_module_mac || !has_activate) {
        fprintf(stderr,
                "    missing fields: section=%d module-mac=%d activate=%d\n",
                has_section, has_module_mac, has_activate);
        return 0;
    }
    return 1;
}

static int test_full_fips_init(void)
{
    int ret, state;

    VLOG("Calling qudo_pqc_init — embedded HMAC or cnf path per platform\n");
    ret = test_fips_init();

    VLOG("Expected: init returns 1, state = RUNNING\n");
    VLOG("Got:      init returns %d, state = %s\n", ret,
         state_name(qudo_pqc_get_state()));
    if (!ret) {
        fprintf(stderr, "    qudo_pqc_init failed (expected RUNNING)\n");
        fprintf(stderr, "    state = %d\n", qudo_pqc_get_state());
        return 0;
    }

    state = qudo_pqc_get_state();
    if (state != QUDO_PQC_STATE_RUNNING) {
        fprintf(stderr, "    expected RUNNING(%d), got %d\n",
                QUDO_PQC_STATE_RUNNING, state);
        return 0;
    }

    if (!qudo_pqc_is_running()) {
        fprintf(stderr, "    is_running returned 0 after successful init\n");
        return 0;
    }

    return 1;
}

static int test_integrity_bad_checksum(void)
{
    unsigned char content[] = "QUDO PQC Bad Checksum Test";
    char *checksum_hex;
    VLOG("Creating file and corrupting first byte of checksum\n");
    qudo_pqc_config_t config;
    qudo_st_ctx_t st;
    int ret;

    checksum_hex
        = create_test_file(TEST_FILE_PATH, content, sizeof(content) - 1);
    if (checksum_hex == NULL)
        return 0;

    if (checksum_hex[0] == 'a')
        checksum_hex[0] = 'b';
    else
        checksum_hex[0] = 'a';

    memset(&config, 0, sizeof(config));
    config.self_test_cb = null_st_cb;
    config.module_path = TEST_FILE_PATH;
    config.module_checksum_hex = checksum_hex;
    config.conditional_errors = 1;

    st.cb = null_st_cb;
    st.cb_arg = NULL;
    st.current_type = NULL;
    st.current_desc = NULL;

    ret = qudo_pqc_verify_integrity(&config, &st);

    free(checksum_hex);
    cleanup_test_file(TEST_FILE_PATH);

    VLOG("Expected: rejected (return 0)\n");
    VLOG("Got:      %s (return %d)\n", ret == 0 ? "rejected" : "accepted", ret);
    if (ret != 0) {
        fprintf(stderr, "    integrity should fail with bad checksum\n");
        return 0;
    }
    return 1;
}

static int test_integrity_missing_file(void)
{
    qudo_pqc_config_t config;
    qudo_st_ctx_t st;
    char fake[]
        = "0000000000000000000000000000000000000000000000000000000000000000";
    VLOG("Verifying nonexistent file — expecting rejection\n");

    memset(&config, 0, sizeof(config));
    config.self_test_cb = null_st_cb;
    config.module_path = "/nonexistent/path/to/module.so";
    config.module_checksum_hex = fake;
    config.conditional_errors = 1;

    st.cb = null_st_cb;
    st.cb_arg = NULL;
    st.current_type = NULL;
    st.current_desc = NULL;

    {
        int ret = qudo_pqc_verify_integrity(&config, &st);
        VLOG("Expected: rejected (return 0)\n");
        VLOG("Got:      %s (return %d)\n", ret == 0 ? "rejected" : "accepted",
             ret);
        if (ret != 0) {
            fprintf(stderr, "    integrity should fail for missing file\n");
            return 0;
        }
    }
    return 1;
}

static int test_integrity_null_path(void)
{
    qudo_pqc_config_t config;
    qudo_st_ctx_t st;

    VLOG("Passing NULL module_path — expecting rejection\n");
    memset(&config, 0, sizeof(config));
    config.self_test_cb = null_st_cb;
    config.module_path = NULL;
    config.module_checksum_hex
        = "0000000000000000000000000000000000000000000000000000000000000000";
    config.conditional_errors = 1;

    st.cb = null_st_cb;
    st.cb_arg = NULL;
    st.current_type = NULL;
    st.current_desc = NULL;

    {
        int ret = qudo_pqc_verify_integrity(&config, &st);
        VLOG("Expected: rejected (return 0)\n");
        VLOG("Got:      %s (return %d)\n", ret == 0 ? "rejected" : "accepted",
             ret);
        if (ret != 0) {
            fprintf(stderr, "    integrity should fail with NULL path\n");
            return 0;
        }
    }
    return 1;
}

static int test_integrity_null_checksum(void)
{
    qudo_pqc_config_t config;
    qudo_st_ctx_t st;

    VLOG("Passing NULL checksum — expecting rejection\n");
    memset(&config, 0, sizeof(config));
    config.self_test_cb = null_st_cb;
    config.module_path = "/some/path";
    config.module_checksum_hex = NULL;
    config.conditional_errors = 1;

    st.cb = null_st_cb;
    st.cb_arg = NULL;
    st.current_type = NULL;
    st.current_desc = NULL;

    {
        int ret = qudo_pqc_verify_integrity(&config, &st);
        VLOG("Expected: rejected (return 0)\n");
        VLOG("Got:      %s (return %d)\n", ret == 0 ? "rejected" : "accepted",
             ret);
        if (ret != 0) {
            fprintf(stderr, "    integrity should fail with NULL checksum\n");
            return 0;
        }
    }
    return 1;
}

static int test_integrity_invalid_hex(void)
{
    unsigned char content[] = "test";
    qudo_pqc_config_t config;
    qudo_st_ctx_t st;
    FILE *f;

    VLOG("Passing odd-length hex \"abc\" — expecting rejection\n");
    f = fopen(TEST_FILE_PATH, "wb");
    if (f == NULL)
        return 0;
    fwrite(content, 1, sizeof(content) - 1, f);
    fclose(f);

    memset(&config, 0, sizeof(config));
    config.self_test_cb = null_st_cb;
    config.module_path = TEST_FILE_PATH;
    config.module_checksum_hex = "abc";
    config.conditional_errors = 1;

    st.cb = null_st_cb;
    st.cb_arg = NULL;
    st.current_type = NULL;
    st.current_desc = NULL;

    {
        int ret = qudo_pqc_verify_integrity(&config, &st);
        cleanup_test_file(TEST_FILE_PATH);
        VLOG("Expected: rejected (return 0)\n");
        VLOG("Got:      %s (return %d)\n", ret == 0 ? "rejected" : "accepted",
             ret);
        if (ret != 0) {
            fprintf(stderr, "    integrity should fail with invalid hex\n");
            return 0;
        }
    }
    return 1;
}

#endif

#ifndef QUDO_FIPS_MODULE
static int test_hmac_kat_exact(void)
{
    return -1;
}
static int test_hmac_kat(void)
{
    return -1;
}
static int test_hmac_different_inputs(void)
{
    return -1;
}
static int test_integrity_synthetic_valid(void)
{
    return -1;
}
static int test_integrity_synthetic_empty(void)
{
    return -1;
}
static int test_integrity_callback_events(void)
{
    return -1;
}
static int test_integrity_real_binary_fipsinstall(void)
{
    return -1;
}
static int test_integrity_real_binary_self_computed(void)
{
    return -1;
}
static int test_integrity_real_binary_tampered(void)
{
    return -1;
}
static int test_fipsinstall_verify_pass(void)
{
    return -1;
}
static int test_fipsinstall_verify_tampered(void)
{
    return -1;
}
static int test_fipsinstall_verify_missing(void)
{
    return -1;
}
static int test_fipsinstall_deterministic(void)
{
    return -1;
}
static int test_fipsinstall_config_fields(void)
{
    return -1;
}
static int test_full_fips_init(void)
{
    return -1;
}
static int test_integrity_bad_checksum(void)
{
    return -1;
}
static int test_integrity_missing_file(void)
{
    return -1;
}
static int test_integrity_null_path(void)
{
    return -1;
}
static int test_integrity_null_checksum(void)
{
    return -1;
}
static int test_integrity_invalid_hex(void)
{
    return -1;
}
#endif

static int run_section(const char *filter, const char *name)
{
    if (filter == NULL)
        return 1;
    return (strcmp(filter, name) == 0);
}

static void print_usage(const char *prog)
{
    printf("Usage: %s [SECTION]\n\n", prog);
    printf("Sections:\n");
    printf("  --hmac         HMAC KAT tests\n");
    printf("  --synthetic    Synthetic file integrity tests\n");
    printf("  --real         Real binary integrity tests\n");
    printf("  --fipsinstall  fipsinstall tool tests\n");
    printf("  --init         Full FIPS init flow test\n");
    printf("  --negative     Negative tests\n");
    printf("  (no args)      Run all sections\n");
}

int main(int argc, char *argv[])
{
    test_fips_init_set_args(&argc, argv);
    const char *section = NULL;

    if (argc >= 2) {
        if (strcmp(argv[1], "--help") == 0 || strcmp(argv[1], "-h") == 0) {
            print_usage(argv[0]);
            return 0;
        }
        section = argv[1];
    }

    printf("=== QUDO PQC Integrity Tests ===\n");
#ifdef QUDO_FIPS_MODULE
    printf("Build mode: FIPS\n");
#else
    printf("Build mode: Standard (integrity tests will be skipped)\n");
#endif
    printf(
        "Sections: --hmac --synthetic --real --fipsinstall --init --negative\n\n");

    if (section != NULL)
        g_verbose = 1;

    if (section == NULL) {
        printf("[Build Mode]\n");
        RUN_TEST(test_is_fips);
    }

    if (run_section(section, "--hmac")) {
        printf("\n[HMAC KAT]\n");
        RUN_TEST(test_hmac_kat_exact);
        RUN_TEST(test_hmac_kat);
        RUN_TEST(test_hmac_different_inputs);
    }

    if (run_section(section, "--synthetic")) {
        printf("\n[Synthetic File Tests]\n");
        RUN_TEST(test_integrity_synthetic_valid);
        RUN_TEST(test_integrity_synthetic_empty);
        RUN_TEST(test_integrity_callback_events);
    }

    if (run_section(section, "--real")) {
        printf("\n[Real Binary Integrity]\n");
        RUN_TEST(test_integrity_real_binary_self_computed);
        RUN_TEST(test_integrity_real_binary_fipsinstall);
        RUN_TEST(test_integrity_real_binary_tampered);
    }

    if (run_section(section, "--fipsinstall")) {
        printf("\n[fipsinstall Tool]\n");
        RUN_TEST(test_fipsinstall_verify_pass);
        RUN_TEST(test_fipsinstall_verify_tampered);
        RUN_TEST(test_fipsinstall_verify_missing);
        RUN_TEST(test_fipsinstall_deterministic);
        RUN_TEST(test_fipsinstall_config_fields);
    }

    if (run_section(section, "--init")) {
        printf("\n[Full FIPS Init Flow]\n");
        RUN_TEST(test_full_fips_init);
    }

    if (run_section(section, "--negative")) {
        printf("\n[Negative Tests]\n");
        RUN_TEST(test_integrity_bad_checksum);
        RUN_TEST(test_integrity_missing_file);
        RUN_TEST(test_integrity_null_path);
        RUN_TEST(test_integrity_null_checksum);
        RUN_TEST(test_integrity_invalid_hex);
    }

    printf("\n=== Results: %d passed, %d failed, %d skipped ===\n", g_pass,
           g_fail, g_skip);

    return g_fail > 0 ? 1 : 0;
}
