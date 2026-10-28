/* SPDX-License-Identifier: Apache-2.0 AND MIT */

#include "qudo_pqc.h"
#include "test_fips_init.h"
#include <stdio.h>
#include <string.h>

static int g_pass = 0;
static int g_fail = 0;
static int g_skip = 0;

#define CHECK(cond, msg)                        \
    do {                                        \
        if (cond) {                             \
            g_pass++;                           \
            printf("  %-55s PASS\n", msg);      \
        } else {                                \
            g_fail++;                           \
            printf("  %-55s FAIL\n", msg);      \
        }                                       \
    } while (0)

#ifdef QUDO_PQC_USE_HOST_DRBG

static size_t g_host_calls = 0;
static int g_host_fail = 0;

static int host_rng(uint8_t *buf, size_t len)
{
    g_host_calls++;
    if (g_host_fail)
        return -1;
    memset(buf, 0xA5, len);
    return 0;
}

static void run_host_rand_tests(void)
{
    uint8_t buf[64];
    size_t i;
    int r;

    g_host_calls = 0;
    g_host_fail = 0;
    qudo_pqc_set_rand_provider(host_rng);
    memset(buf, 0x00, sizeof(buf));
    r = qudo_pqc_rand_bytes(buf, sizeof(buf));
    int all_a5 = 1;
    for (i = 0; i < sizeof(buf); i++)
        if (buf[i] != 0xA5)
            all_a5 = 0;
    CHECK(r == 0 && g_host_calls >= 1 && all_a5,
          "host provider routes qudo_pqc_rand_bytes");

    g_host_fail = 1;
    r = qudo_pqc_rand_bytes(buf, sizeof(buf));
    CHECK(r != 0, "host provider error fails closed");
    g_host_fail = 0;

    g_host_calls = 0;
    r = qudo_pqc_rand_bytes(buf, 0);
    CHECK(r == 0 && g_host_calls == 0, "zero-length request succeeds");

    qudo_pqc_set_rand_provider(NULL);
    g_host_calls = 0;
    r = qudo_pqc_rand_bytes(buf, sizeof(buf));
    CHECK(r == 0 && g_host_calls == 0,
          "clearing provider reverts to embedded DRBG");
}

#endif /* QUDO_PQC_USE_HOST_DRBG */

int main(int argc, char *argv[])
{
    test_fips_init_set_args(&argc, argv);
    (void)argc;
    (void)argv;

    printf("=== QUDO PQC Host-DRBG Hook Tests ===\n");

#ifdef QUDO_PQC_USE_HOST_DRBG
    if (!test_fips_init()) {
        fprintf(stderr, "FAIL: qudo_pqc_init returned error\n");
        return 1;
    }
    run_host_rand_tests();
#else
    g_skip++;
    printf("  %-55s SKIP (built without QUDO_PQC_USE_HOST_DRBG)\n",
           "host-drbg hook");
#endif

    printf("\n=== Results: %d passed, %d failed, %d skipped ===\n", g_pass,
           g_fail, g_skip);
    return g_fail > 0 ? 1 : 0;
}
