/* SPDX-License-Identifier: Apache-2.0 AND MIT */

#include "qudo_fips_rand.h"
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

static int test_auto_reseed_interval(void)
{

    CHECK(test_fips_init() == 1, "qudo_pqc_init");

    const uint64_t N = (1ULL << 20) + 1024ULL;
    uint8_t prev[16] = {0};
    uint8_t buf[16];
    uint64_t i;
    for (i = 0; i < N; i++) {
        int r = qudo_pqc_rand_bytes(buf, sizeof(buf));
        if (r != 0) {
            printf("    rand_bytes failed at iteration %llu\n",
                   (unsigned long long)i);
            return 0;
        }

        if (i > 0 && memcmp(buf, prev, sizeof(buf)) == 0) {
            printf("    unexpected duplicate output at iteration %llu\n",
                   (unsigned long long)i);
            return 0;
        }
        memcpy(prev, buf, sizeof(buf));
    }
    CHECK(1, "1M+ requests including auto-reseed succeeded");
    return 1;
}

static int test_large_request_chunking(void)
{

    CHECK(test_fips_init() == 1, "qudo_pqc_init");

    const size_t len = 128 * 1024;
    uint8_t *buf = (uint8_t *)malloc(len);
    CHECK(buf != NULL, "malloc 128 KB");
    memset(buf, 0, len);

    CHECK(qudo_pqc_rand_bytes(buf, len) == 0, "rand_bytes 128 KB");

    int all_zero = 1;
    size_t j;
    for (j = 0; j < len; j++) {
        if (buf[j] != 0) {
            all_zero = 0;
            break;
        }
    }
    CHECK(!all_zero, "output not all-zero");

    free(buf);
    return 1;
}

static int test_explicit_reseed(void)
{

    CHECK(test_fips_init() == 1, "qudo_pqc_init");

    uint8_t entropy[48];
    size_t j;
    for (j = 0; j < sizeof(entropy); j++)
        entropy[j] = (uint8_t)(0xA0 + j);

    qudo_pqc_rand_cleanup();
    CHECK(qudo_pqc_rand_init(entropy, sizeof(entropy)) == 0, "rand_init");

    uint8_t before[32], after[32];
    CHECK(qudo_pqc_rand_bytes(before, sizeof(before)) == 0, "rand_bytes pre");

    uint8_t fresh[48];
    for (j = 0; j < sizeof(fresh); j++)
        fresh[j] = (uint8_t)(0x5A + j);
    CHECK(qudo_pqc_rand_reseed(fresh, sizeof(fresh)) == 0,
          "reseed valid entropy");

    CHECK(qudo_pqc_rand_bytes(after, sizeof(after)) == 0, "rand_bytes post");
    CHECK(memcmp(before, after, sizeof(before)) != 0,
          "post-reseed output differs");

    CHECK(qudo_pqc_rand_reseed(NULL, sizeof(fresh)) == -1, "reseed NULL");
    CHECK(qudo_pqc_rand_reseed(fresh, 16) == -1, "reseed short entropy");
    CHECK(qudo_pqc_rand_reseed(fresh, 0) == -1, "reseed zero entropy");

    qudo_pqc_rand_cleanup();
    CHECK(qudo_pqc_rand_bytes(after, sizeof(after)) == -1,
          "rand_bytes after cleanup");

    CHECK(qudo_pqc_rand_reseed(fresh, sizeof(fresh)) == -1, "reseed uninit");
    return 1;
}

static int test_adin_overlength_rejected(void)
{
    CHECK(test_fips_init() == 1, "qudo_pqc_init");

    uint8_t seed[48];
    size_t j;
    for (j = 0; j < sizeof(seed); j++)
        seed[j] = (uint8_t)(0x11 + j);

    qudo_pqc_ctrdrbg_ctx_t *ctx = qudo_pqc_ctrdrbg_new();
    CHECK(ctx != NULL, "ctrdrbg_new");
    CHECK(qudo_pqc_ctrdrbg_init(ctx, 32, seed, sizeof(seed)) == 0,
          "ctrdrbg_init AES-256 no-df");

    uint8_t out[32];
    uint8_t adin[64];
    memset(adin, 0x33, sizeof(adin));

    CHECK(qudo_pqc_ctrdrbg_generate(ctx, out, sizeof(out), adin, 48) == 0,
          "adin == seedlen accepted");
    CHECK(qudo_pqc_ctrdrbg_generate(ctx, out, sizeof(out), adin, sizeof(adin))
              == -1,
          "adin > seedlen rejected (not truncated)");

    qudo_pqc_ctrdrbg_free(ctx);
    return 1;
}

static int test_sequential_distinct(void)
{
    CHECK(test_fips_init() == 1, "qudo_pqc_init");

    enum {
        N = 256
    };
    uint8_t samples[N][32];
    int i, k;
    for (i = 0; i < N; i++)
        CHECK(qudo_pqc_rand_bytes(samples[i], 32) == 0, "rand_bytes");

    for (i = 0; i < N; i++)
        for (k = i + 1; k < N; k++)
            CHECK(memcmp(samples[i], samples[k], 32) != 0,
                  "samples pairwise distinct");
    return 1;
}

static int test_is_ready_transitions(void)
{
    qudo_pqc_rand_cleanup();
    CHECK(qudo_pqc_rand_is_ready() == 0, "not ready after cleanup");

    uint8_t entropy[48];
    size_t j;
    for (j = 0; j < sizeof(entropy); j++)
        entropy[j] = (uint8_t)j;

    CHECK(qudo_pqc_rand_init(entropy, sizeof(entropy)) == 0, "init");
    CHECK(qudo_pqc_rand_is_ready() == 1, "ready after init");

    qudo_pqc_rand_cleanup();
    CHECK(qudo_pqc_rand_is_ready() == 0, "not ready after re-cleanup");
    return 1;
}

static void usage(const char *prog)
{
    printf("Usage: %s [--all|--reseed-interval|--chunking|--explicit-reseed|"
           "--adin|--sequential|--is-ready] [-v]\n",
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

    printf("=== CTR-DRBG Limits & Reseed Coverage Tests ===\n\n");

    if (strcmp(section, "--all") == 0
        || strcmp(section, "--reseed-interval") == 0) {
        printf("[RESEED_INTERVAL auto-reseed]\n");
        RUN_TEST(test_auto_reseed_interval);
        printf("\n");
    }
    if (strcmp(section, "--all") == 0 || strcmp(section, "--chunking") == 0) {
        printf("[Large request chunking]\n");
        RUN_TEST(test_large_request_chunking);
        printf("\n");
    }
    if (strcmp(section, "--all") == 0
        || strcmp(section, "--explicit-reseed") == 0) {
        printf("[Explicit reseed API]\n");
        RUN_TEST(test_explicit_reseed);
        printf("\n");
    }
    if (strcmp(section, "--all") == 0 || strcmp(section, "--adin") == 0) {
        printf("[Additional-input length limit]\n");
        RUN_TEST(test_adin_overlength_rejected);
        printf("\n");
    }
    if (strcmp(section, "--all") == 0 || strcmp(section, "--sequential") == 0) {
        printf("[Sequential-output distinctness]\n");
        RUN_TEST(test_sequential_distinct);
        printf("\n");
    }
    if (strcmp(section, "--all") == 0 || strcmp(section, "--is-ready") == 0) {
        printf("[is_ready transitions]\n");
        RUN_TEST(test_is_ready_transitions);
        printf("\n");
    }

    printf("=== Results: %d passed, %d failed ===\n", g_pass, g_fail);
    return g_fail > 0 ? 1 : 0;
}
