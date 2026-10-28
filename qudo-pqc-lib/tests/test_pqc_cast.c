/* SPDX-License-Identifier: Apache-2.0 AND MIT */

#include "qudo_pqc.h"
#include "qudo_pqc_platform.h"
#include "test_fips_init.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int g_pass = 0;
static int g_fail = 0;
static int g_skip = 0;
static int g_verbose = 0;

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

static const char *cast_name(int id)
{
    switch (id) {
    case QUDO_CAST_ML_KEM_512:
        return "ML-KEM-512";
    case QUDO_CAST_ML_KEM_768:
        return "ML-KEM-768";
    case QUDO_CAST_ML_KEM_1024:
        return "ML-KEM-1024";
    case QUDO_CAST_ML_DSA_44:
        return "ML-DSA-44";
    case QUDO_CAST_ML_DSA_65:
        return "ML-DSA-65";
    case QUDO_CAST_ML_DSA_87:
        return "ML-DSA-87";
    case QUDO_CAST_SLH_DSA_SHA2_128:
        return "SLH-DSA-SHA2-128";
    case QUDO_CAST_SLH_DSA_SHA2_192:
        return "SLH-DSA-SHA2-192";
    case QUDO_CAST_SLH_DSA_SHA2_256:
        return "SLH-DSA-SHA2-256";
    case QUDO_CAST_SLH_DSA_SHAKE_128:
        return "SLH-DSA-SHAKE-128";
    case QUDO_CAST_SLH_DSA_SHAKE_192:
        return "SLH-DSA-SHAKE-192";
    case QUDO_CAST_SLH_DSA_SHAKE_256:
        return "SLH-DSA-SHAKE-256";
    default:
        return "UNKNOWN";
    }
}

static const char *cast_state_name(int state)
{
    switch (state) {
    case QUDO_CAST_STATE_INIT:
        return "INIT";
    case QUDO_CAST_STATE_PROCESSING:
        return "PROCESSING";
    case QUDO_CAST_STATE_SUCCESS:
        return "SUCCESS";
    case QUDO_CAST_STATE_FAILURE:
        return "FAILURE";
    default:
        return "UNKNOWN";
    }
}

static int test_cast_status_after_init(void)
{
    int ok = 1;
    int id;

#ifdef QUDO_FIPS_MODULE

    int expected = QUDO_CAST_STATE_SUCCESS;
#else

    int expected = QUDO_CAST_STATE_INIT;
#endif

    for (id = 0; id < QUDO_CAST_COUNT; id++) {
        int status = qudo_pqc_get_cast_status(id);
        if (status != expected) {
            VLOG("CAST %s (%d): expected %s (%d), got %s (%d)\n", cast_name(id),
                 id, cast_state_name(expected), expected,
                 cast_state_name(status), status);
            ok = 0;
        }
    }

    return ok;
}

static int test_cast_individual_mlkem(void)
{

    qudo_pqc_run_all_casts();

    int ok = 1;

    if (qudo_pqc_get_cast_status(QUDO_CAST_ML_KEM_512)
        != QUDO_CAST_STATE_SUCCESS) {
        VLOG("ML-KEM-512 CAST not SUCCESS\n");
        ok = 0;
    }
    if (qudo_pqc_get_cast_status(QUDO_CAST_ML_KEM_768)
        != QUDO_CAST_STATE_SUCCESS) {
        VLOG("ML-KEM-768 CAST not SUCCESS\n");
        ok = 0;
    }
    if (qudo_pqc_get_cast_status(QUDO_CAST_ML_KEM_1024)
        != QUDO_CAST_STATE_SUCCESS) {
        VLOG("ML-KEM-1024 CAST not SUCCESS\n");
        ok = 0;
    }

    return ok;
}

static int test_cast_individual_mldsa(void)
{
    qudo_pqc_run_all_casts();

    int ok = 1;

    if (qudo_pqc_get_cast_status(QUDO_CAST_ML_DSA_44)
        != QUDO_CAST_STATE_SUCCESS) {
        VLOG("ML-DSA-44 CAST not SUCCESS\n");
        ok = 0;
    }
    if (qudo_pqc_get_cast_status(QUDO_CAST_ML_DSA_65)
        != QUDO_CAST_STATE_SUCCESS) {
        VLOG("ML-DSA-65 CAST not SUCCESS\n");
        ok = 0;
    }
    if (qudo_pqc_get_cast_status(QUDO_CAST_ML_DSA_87)
        != QUDO_CAST_STATE_SUCCESS) {
        VLOG("ML-DSA-87 CAST not SUCCESS\n");
        ok = 0;
    }

    return ok;
}

static int test_cast_individual_slhdsa(void)
{
    qudo_pqc_run_all_casts();

    int ok = 1;

    const qudo_cast_id_t slh_casts[] = {
        QUDO_CAST_SLH_DSA_SHA2_128,  QUDO_CAST_SLH_DSA_SHA2_192,
        QUDO_CAST_SLH_DSA_SHA2_256,  QUDO_CAST_SLH_DSA_SHAKE_128,
        QUDO_CAST_SLH_DSA_SHAKE_192, QUDO_CAST_SLH_DSA_SHAKE_256,
    };
    for (size_t i = 0; i < sizeof(slh_casts) / sizeof(slh_casts[0]); i++) {
        if (qudo_pqc_get_cast_status(slh_casts[i]) != QUDO_CAST_STATE_SUCCESS) {
            VLOG("%s CAST not SUCCESS\n", cast_name(slh_casts[i]));
            ok = 0;
        }
    }

    return ok;
}

static int test_run_all_casts(void)
{
    int result = qudo_pqc_run_all_casts();
    if (result != 1) {
        VLOG("run_all_casts returned %d, expected 1\n", result);
        return 0;
    }

    int ok = 1;
    int id;
    for (id = 0; id < QUDO_CAST_COUNT; id++) {
        int status = qudo_pqc_get_cast_status(id);
        if (status != QUDO_CAST_STATE_SUCCESS) {
            VLOG("CAST %s: expected SUCCESS after run_all_casts, got %s\n",
                 cast_name(id), cast_state_name(status));
            ok = 0;
        }
    }

    return ok;
}

static int test_run_all_casts_repeated(void)
{
    int ok = 1;
    int iter;

    for (iter = 0; iter < 3; iter++) {
        if (qudo_pqc_run_all_casts() != 1) {
            VLOG("run_all_casts failed on iteration %d\n", iter);
            ok = 0;
            break;
        }
    }

    return ok;
}

static int test_cast_invalid_id(void)
{
    int ok = 1;

    if (qudo_pqc_get_cast_status(-1) != -1) {
        VLOG("accepted negative CAST ID\n");
        ok = 0;
    }

    if (qudo_pqc_get_cast_status(QUDO_CAST_COUNT) != -1) {
        VLOG("accepted out-of-bounds CAST ID (%d)\n", QUDO_CAST_COUNT);
        ok = 0;
    }

    if (qudo_pqc_get_cast_status(999) != -1) {
        VLOG("accepted CAST ID 999\n");
        ok = 0;
    }

    return ok;
}

static int test_cast_count(void)
{
    if (QUDO_CAST_COUNT != 12) {
        VLOG("QUDO_CAST_COUNT = %d, expected 12\n", QUDO_CAST_COUNT);
        return 0;
    }
    return 1;
}

static void run_section_after_init(void)
{
    printf("\n--- Section 1: CAST Status After Init ---\n");
    RUN_TEST(test_cast_status_after_init);
}

static void run_section_individual(void)
{
    printf("\n--- Section 2: Per-Algorithm CAST ---\n");
    RUN_TEST(test_cast_individual_mlkem);
    RUN_TEST(test_cast_individual_mldsa);
    RUN_TEST(test_cast_individual_slhdsa);
}

static void run_section_run_all(void)
{
    printf("\n--- Section 3: Run All CASTs ---\n");
    RUN_TEST(test_run_all_casts);
    RUN_TEST(test_run_all_casts_repeated);
}

static void run_section_invalid(void)
{
    printf("\n--- Section 4: Invalid IDs ---\n");
    RUN_TEST(test_cast_invalid_id);
    RUN_TEST(test_cast_count);
}

int main(int argc, char *argv[])
{
    test_fips_init_set_args(&argc, argv);
    const char *section = NULL;
    int i;

    for (i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-v") == 0 || strcmp(argv[i], "--verbose") == 0)
            g_verbose = 1;
        else if (strncmp(argv[i], "--", 2) == 0)
            section = argv[i] + 2;
    }

    printf("=== QUDO PQC CAST Tests ===\n");

    if (test_fips_init() != 1) {
        printf("FATAL: module init failed\n");
        return 1;
    }

    if (section == NULL || strcmp(section, "init") == 0)
        run_section_after_init();
    if (section == NULL || strcmp(section, "individual") == 0)
        run_section_individual();
    if (section == NULL || strcmp(section, "runall") == 0)
        run_section_run_all();
    if (section == NULL || strcmp(section, "invalid") == 0)
        run_section_invalid();

    qudo_pqc_fini();

    printf("\n=== Results: %d passed, %d failed, %d skipped ===\n", g_pass,
           g_fail, g_skip);

    return g_fail > 0 ? 1 : 0;
}
