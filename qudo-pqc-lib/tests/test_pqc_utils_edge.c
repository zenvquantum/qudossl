/* SPDX-License-Identifier: Apache-2.0 AND MIT */

#include "qudo_pqc.h"
#include "test_fips_init.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int g_pass = 0;
static int g_fail = 0;
static int g_verbose = 0;

#define CHECK(cond, msg)                                       \
    do {                                                       \
        if (!(cond)) {                                         \
            printf("    FAIL: %s (line %d)\n", msg, __LINE__); \
            return 0;                                          \
        }                                                      \
        if (g_verbose)                                         \
            printf("    OK: %s\n", msg);                       \
    } while (0)

#define RUN_TEST(fn)                       \
    do {                                   \
        int _r = fn();                     \
        if (_r) {                          \
            g_pass++;                      \
            printf("  %-55s PASS\n", #fn); \
        } else {                           \
            g_fail++;                      \
            printf("  %-55s FAIL\n", #fn); \
        }                                  \
    } while (0)

static int test_cleanse_edge(void)
{

    qudo_pqc_cleanse(NULL, 0);
    qudo_pqc_cleanse(NULL, 16);

    uint8_t buf[32];
    memset(buf, 0xAB, sizeof(buf));
    qudo_pqc_cleanse(buf, 0);
    size_t i;
    for (i = 0; i < sizeof(buf); i++)
        CHECK(buf[i] == 0xAB, "buf unchanged on len=0");

    qudo_pqc_cleanse(buf, sizeof(buf));
    for (i = 0; i < sizeof(buf); i++)
        CHECK(buf[i] == 0, "buf zero after cleanse");

    return 1;
}

static int test_hmac_sha256_oneshot(void)
{

    static const uint8_t key[20] = {
        0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
        0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
    };
    static const uint8_t data[] = "Hi There";
    static const uint8_t expected[32] = {
        0xb0, 0x34, 0x4c, 0x61, 0xd8, 0xdb, 0x38, 0x53, 0x5c, 0xa8, 0xaf,
        0xce, 0xaf, 0x0b, 0xf1, 0x2b, 0x88, 0x1d, 0xc2, 0x00, 0xc9, 0x83,
        0x3d, 0xa7, 0x26, 0xe9, 0x37, 0x6c, 0x2e, 0x32, 0xcf, 0xf7,
    };

    uint8_t out[32];
    qudo_pqc_hmac_sha256(key, sizeof(key), data, sizeof(data) - 1, out);
    CHECK(memcmp(out, expected, sizeof(expected)) == 0,
          "RFC 4231 TC1 one-shot digest");
    return 1;
}

static int test_hmac_sha256_ctx_lifecycle(void)
{
    static const uint8_t key[20] = {
        0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
        0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
    };
    static const uint8_t data[] = "Hi There";
    uint8_t expected[32];
    qudo_pqc_hmac_sha256(key, sizeof(key), data, sizeof(data) - 1, expected);

    qudo_pqc_hmac_ctx_t *ctx = qudo_pqc_hmac_ctx_new();
    CHECK(ctx != NULL, "ctx_new");

    qudo_pqc_hmac_ctx_init(ctx, key, sizeof(key));

    const size_t split = 3;
    qudo_pqc_hmac_ctx_update(ctx, data, split);
    qudo_pqc_hmac_ctx_update(ctx, data + split, sizeof(data) - 1 - split);

    uint8_t out[32];
    qudo_pqc_hmac_ctx_final(ctx, out);
    CHECK(memcmp(out, expected, 32) == 0, "chunked update matches one-shot");

    qudo_pqc_hmac_ctx_free(ctx);

    qudo_pqc_hmac_ctx_init(NULL, key, sizeof(key));
    qudo_pqc_hmac_ctx_update(NULL, data, sizeof(data) - 1);
    qudo_pqc_hmac_ctx_final(NULL, out);
    qudo_pqc_hmac_ctx_free(NULL);
    return 1;
}

static int test_ctrdrbg_lifecycle(void)
{
    qudo_pqc_ctrdrbg_ctx_t *ctx = qudo_pqc_ctrdrbg_new();
    CHECK(ctx != NULL, "ctrdrbg_new");

    uint8_t seed[48];
    size_t i;
    for (i = 0; i < sizeof(seed); i++)
        seed[i] = (uint8_t)(0x10 + i);

    CHECK(qudo_pqc_ctrdrbg_init(ctx, 32, seed, sizeof(seed)) == 0, "init");

    uint8_t out[64];
    CHECK(qudo_pqc_ctrdrbg_generate(ctx, out, sizeof(out), NULL, 0) == 0,
          "generate");

    int all_zero = 1;
    for (i = 0; i < sizeof(out); i++)
        if (out[i] != 0) {
            all_zero = 0;
            break;
        }
    CHECK(!all_zero, "output non-zero");

    uint8_t seed2[48];
    for (i = 0; i < sizeof(seed2); i++)
        seed2[i] = (uint8_t)(0xF0 ^ i);
    CHECK(qudo_pqc_ctrdrbg_reseed(ctx, seed2, sizeof(seed2)) == 0, "reseed");
    CHECK(qudo_pqc_ctrdrbg_generate(ctx, out, sizeof(out), NULL, 0) == 0,
          "post-reseed generate");

    CHECK(qudo_pqc_ctrdrbg_is_zeroized(ctx) == 0, "not zeroized while live");

    qudo_pqc_ctrdrbg_uninit(ctx);
    CHECK(qudo_pqc_ctrdrbg_is_zeroized(ctx) == 1, "zeroized after uninit");

    qudo_pqc_ctrdrbg_free(ctx);

    CHECK(qudo_pqc_ctrdrbg_init(NULL, 32, seed, sizeof(seed)) == -1,
          "init NULL ctx");
    CHECK(qudo_pqc_ctrdrbg_generate(NULL, out, sizeof(out), NULL, 0) == -1,
          "generate NULL ctx");
    CHECK(qudo_pqc_ctrdrbg_reseed(NULL, seed, sizeof(seed)) == -1,
          "reseed NULL ctx");
    CHECK(qudo_pqc_ctrdrbg_is_zeroized(NULL) == 0, "is_zeroized NULL");
    qudo_pqc_ctrdrbg_uninit(NULL);
    qudo_pqc_ctrdrbg_free(NULL);
    return 1;
}

static int test_module_boundary_getters(void)
{
    const void *start = NULL;
    const void *end = NULL;

    CHECK(qudo_pqc_get_module_boundary(NULL, NULL) == -1,
          "boundary NULL/NULL rejected");
    CHECK(qudo_pqc_get_module_boundary(&start, NULL) == -1,
          "boundary NULL end rejected");
    CHECK(qudo_pqc_get_module_boundary(NULL, &end) == -1,
          "boundary NULL start rejected");

    int ret = qudo_pqc_get_module_boundary(&start, &end);
    if (ret == 0) {
        CHECK(start != NULL && end != NULL, "boundary pointers set");
        CHECK((const uint8_t *)start < (const uint8_t *)end, "start < end");
    }

    const uint8_t *hmac = NULL;
    size_t hmac_len = 0;
    CHECK(qudo_pqc_get_integrity_hmac(NULL, NULL) == -1,
          "hmac NULL/NULL rejected");
    CHECK(qudo_pqc_get_integrity_hmac(&hmac, NULL) == -1,
          "hmac NULL len rejected");

    ret = qudo_pqc_get_integrity_hmac(&hmac, &hmac_len);
    if (ret == 0) {
        CHECK(hmac != NULL, "hmac non-null");
        CHECK(hmac_len == 32, "hmac len 32");
    }

    int patched1 = qudo_pqc_integrity_hmac_is_patched();
    int patched2 = qudo_pqc_integrity_hmac_is_patched();
    CHECK(patched1 == patched2, "is_patched idempotent");
    return 1;
}

static void usage(const char *prog)
{
    printf("Usage: %s [--all|--cleanse|--hmac|--hmac-ctx|--ctrdrbg|"
           "--boundary] [-v]\n",
           prog);
}

int main(int argc, char **argv)
{
    test_fips_init_set_args(&argc, argv);
    const char *section = "--all";
    int i;

    for (i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-v") == 0 || strcmp(argv[i], "--verbose") == 0)
            g_verbose = 1;
        else if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
            usage(argv[0]);
            return 0;
        } else if (argv[i][0] == '-')
            section = argv[i];
    }

    printf("=== Utility Wrapper Edge-Case Coverage Tests ===\n\n");

    if (!test_fips_init()) {
        fprintf(stderr, "FAIL: qudo_pqc_init returned error\n");
        return 1;
    }

    if (strcmp(section, "--all") == 0 || strcmp(section, "--cleanse") == 0) {
        printf("[qudo_pqc_cleanse edge cases]\n");
        RUN_TEST(test_cleanse_edge);
        printf("\n");
    }
    if (strcmp(section, "--all") == 0 || strcmp(section, "--hmac") == 0) {
        printf("[HMAC-SHA-256 one-shot]\n");
        RUN_TEST(test_hmac_sha256_oneshot);
        printf("\n");
    }
    if (strcmp(section, "--all") == 0 || strcmp(section, "--hmac-ctx") == 0) {
        printf("[HMAC-SHA-256 context lifecycle]\n");
        RUN_TEST(test_hmac_sha256_ctx_lifecycle);
        printf("\n");
    }
    if (strcmp(section, "--all") == 0 || strcmp(section, "--ctrdrbg") == 0) {
        printf("[CTR-DRBG public wrappers]\n");
        RUN_TEST(test_ctrdrbg_lifecycle);
        printf("\n");
    }
    if (strcmp(section, "--all") == 0 || strcmp(section, "--boundary") == 0) {
        printf("[module-boundary / integrity-HMAC getters]\n");
        RUN_TEST(test_module_boundary_getters);
        printf("\n");
    }

    printf("=== Results: %d passed, %d failed ===\n", g_pass, g_fail);
    return g_fail > 0 ? 1 : 0;
}
