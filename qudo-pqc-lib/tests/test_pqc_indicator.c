/* SPDX-License-Identifier: Apache-2.0 AND MIT */

#include "qudo_pqc.h"
#include "qudo_pqc_indicator.h"
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

static int test_ind_init_approved(void)
{
    qudo_fips_ind_t ind;

    qudo_fips_ind_init(&ind, 0);
    if (ind.approved != 1) {
        VLOG("approved != 1 after init\n");
        return 0;
    }
    if (ind.strict != 0) {
        VLOG("strict != 0 in tolerant mode\n");
        return 0;
    }

    qudo_fips_ind_init(&ind, 1);
    if (ind.approved != 1) {
        VLOG("approved != 1 after strict init\n");
        return 0;
    }
    if (ind.strict != 1) {
        VLOG("strict != 1 in strict mode\n");
        return 0;
    }

    return 1;
}

static int test_ind_is_approved_default(void)
{
    qudo_fips_ind_t ind;

    qudo_fips_ind_init(&ind, 0);
    if (!qudo_fips_ind_is_approved(&ind)) {
        VLOG("not approved after init\n");
        return 0;
    }

    qudo_fips_ind_init(&ind, 1);
    if (!qudo_fips_ind_is_approved(&ind)) {
        VLOG("not approved after strict init\n");
        return 0;
    }

    return 1;
}

static int test_ind_unapproved_tolerant(void)
{
    qudo_fips_ind_t ind;

    qudo_fips_ind_init(&ind, 0);

    int may_continue = qudo_fips_ind_set_unapproved(&ind);
    if (!may_continue) {
        VLOG("tolerant mode returned abort (0)\n");
        return 0;
    }

    if (qudo_fips_ind_is_approved(&ind)) {
        VLOG("still approved after set_unapproved\n");
        return 0;
    }

    return 1;
}

static int test_ind_unapproved_strict(void)
{
    qudo_fips_ind_t ind;

    qudo_fips_ind_init(&ind, 1);

    int may_continue = qudo_fips_ind_set_unapproved(&ind);
    if (may_continue) {
        VLOG("strict mode returned continue (1)\n");
        return 0;
    }

    if (qudo_fips_ind_is_approved(&ind)) {
        VLOG("still approved after set_unapproved\n");
        return 0;
    }

    return 1;
}

static int test_ind_unapproved_sticky(void)
{
    qudo_fips_ind_t ind;

    qudo_fips_ind_init(&ind, 0);
    qudo_fips_ind_set_unapproved(&ind);

    if (qudo_fips_ind_is_approved(&ind)) {
        VLOG("unapproved status was not sticky\n");
        return 0;
    }

    qudo_fips_ind_init(&ind, 0);
    if (!qudo_fips_ind_is_approved(&ind)) {
        VLOG("not approved after re-init\n");
        return 0;
    }

    return 1;
}

static int test_ind_null_safety(void)
{

    qudo_fips_ind_init(NULL, 0);
    qudo_fips_ind_init(NULL, 1);

    int ret = qudo_fips_ind_set_unapproved(NULL);
    if (ret != 1) {
        VLOG("set_unapproved(NULL) returned %d, expected 1\n", ret);
        return 0;
    }

    int approved = qudo_fips_ind_is_approved(NULL);
    if (approved != 1) {
        VLOG("is_approved(NULL) returned %d, expected 1\n", approved);
        return 0;
    }

    return 1;
}

static int test_ind_default_strict(void)
{
    int strict = qudo_fips_ind_get_default_strict();

#ifdef QUDO_FIPS_MODULE
    if (strict != 1) {
        VLOG("FIPS build: default strict should be 1, got %d\n", strict);
        return 0;
    }
    VLOG("FIPS build: default strict = 1 (correct)\n");
#else
    if (strict != 0) {
        VLOG("Standard build: default strict should be 0, got %d\n", strict);
        return 0;
    }
    VLOG("Standard build: default strict = 0 (correct)\n");
#endif

    return 1;
}

static int test_algorithm_approved(void)
{
    static const char *approved_names[] = {

        "ML-KEM-512",
        "ML-KEM-768",
        "ML-KEM-1024",

        "ML-DSA-44",
        "ML-DSA-65",
        "ML-DSA-87",

        "SLH-DSA-SHA2-128s",
        "SLH-DSA-SHA2-128f",
        "SLH-DSA-SHA2-192s",
        "SLH-DSA-SHA2-192f",
        "SLH-DSA-SHA2-256s",
        "SLH-DSA-SHA2-256f",
        "SLH-DSA-SHAKE-128s",
        "SLH-DSA-SHAKE-128f",
        "SLH-DSA-SHAKE-192s",
        "SLH-DSA-SHAKE-192f",
        "SLH-DSA-SHAKE-256s",
        "SLH-DSA-SHAKE-256f",
        NULL};

    int ok = 1;
    int i;
    for (i = 0; approved_names[i] != NULL; i++) {
        if (!qudo_pqc_is_fips_approved(approved_names[i])) {
            VLOG("'%s' not approved\n", approved_names[i]);
            ok = 0;
        }
    }

    return ok;
}

static int test_algorithm_not_approved(void)
{
    static const char *unapproved_names[]
        = {"AES-256-CBC", "RSA-2048", "SHA-256", "UNKNOWN-ALG", "", NULL};

    int ok = 1;
    int i;
    for (i = 0; unapproved_names[i] != NULL; i++) {
        if (qudo_pqc_is_fips_approved(unapproved_names[i])) {
            VLOG("'%s' incorrectly approved\n", unapproved_names[i]);
            ok = 0;
        }
    }

    if (qudo_pqc_is_fips_approved(NULL)) {
        VLOG("NULL name incorrectly approved\n");
        ok = 0;
    }

    return ok;
}

static int test_check_operation_running(void)
{
    int ok = 1;

    if (!qudo_fips_ind_check_operation("ML-KEM-768")) {
        VLOG("ML-KEM-768 check_operation failed\n");
        ok = 0;
    }
    if (!qudo_fips_ind_check_operation("ML-DSA-65")) {
        VLOG("ML-DSA-65 check_operation failed\n");
        ok = 0;
    }
    if (!qudo_fips_ind_check_operation("SLH-DSA-SHA2-128f")) {
        VLOG("SLH-DSA-SHA2-128f check_operation failed\n");
        ok = 0;
    }

    if (qudo_fips_ind_check_operation("UNKNOWN")) {
        VLOG("UNKNOWN algorithm passed check_operation\n");
        ok = 0;
    }

    if (qudo_fips_ind_check_operation(NULL)) {
        VLOG("NULL name passed check_operation\n");
        ok = 0;
    }

    return ok;
}

static int test_security_level_indicator(void)
{

    qudo_fips_ind_t ind;
    qudo_fips_ind_init(&ind, 0);

    int ok = 1;

    if (!qudo_pqc_check_security_level("ML-KEM-512", &ind)) {
        VLOG("ML-KEM-512 failed level check at min=1\n");
        ok = 0;
    }
    if (!qudo_fips_ind_is_approved(&ind)) {
        VLOG("indicator unapproved after ML-KEM-512 at min=1\n");
        ok = 0;
    }

    qudo_pqc_set_min_security_level(3);
    qudo_fips_ind_init(&ind, 0);

    qudo_pqc_check_security_level("ML-KEM-512", &ind);
    if (qudo_fips_ind_is_approved(&ind)) {
        VLOG("indicator still approved after ML-KEM-512 at min=3 (tolerant)\n");
        ok = 0;
    }

    qudo_fips_ind_init(&ind, 1);
    int strict_result = qudo_pqc_check_security_level("ML-KEM-512", &ind);
    if (strict_result != 0) {
        VLOG("strict mode should abort (return 0) for below-minimum algo\n");
        ok = 0;
    }

    qudo_fips_ind_init(&ind, 0);
    if (!qudo_pqc_check_security_level("ML-KEM-1024", &ind)) {
        VLOG("ML-KEM-1024 failed level check at min=3\n");
        ok = 0;
    }

    qudo_pqc_set_min_security_level(1);

    return ok;
}

static int test_security_levels(void)
{
    struct {
        const char *name;
        int expected_level;
    } tests[] = {{"ML-KEM-512", 1},        {"ML-KEM-768", 3},
                 {"ML-KEM-1024", 5},       {"ML-DSA-44", 2},
                 {"ML-DSA-65", 3},         {"ML-DSA-87", 5},
                 {"SLH-DSA-SHA2-128s", 1}, {"SLH-DSA-SHA2-128f", 1},
                 {"SLH-DSA-SHA2-192s", 3}, {"SLH-DSA-SHA2-256s", 5},
                 {"UNKNOWN", 0},           {NULL, 0}};

    int ok = 1;
    int i;
    for (i = 0; tests[i].name != NULL; i++) {
        int level = qudo_pqc_get_security_level(tests[i].name);
        if (level != tests[i].expected_level) {
            VLOG("'%s': expected level %d, got %d\n", tests[i].name,
                 tests[i].expected_level, level);
            ok = 0;
        }
    }

    if (qudo_pqc_get_security_level(NULL) != 0) {
        VLOG("NULL name returned non-zero level\n");
        ok = 0;
    }

    return ok;
}

static void run_section_init(void)
{
    printf("\n--- Section 1: Indicator Init/Query ---\n");
    RUN_TEST(test_ind_init_approved);
    RUN_TEST(test_ind_is_approved_default);
}

static void run_section_unapproved(void)
{
    printf("\n--- Section 2: Set Unapproved ---\n");
    RUN_TEST(test_ind_unapproved_tolerant);
    RUN_TEST(test_ind_unapproved_strict);
    RUN_TEST(test_ind_unapproved_sticky);
}

static void run_section_null(void)
{
    printf("\n--- Section 3: NULL Safety ---\n");
    RUN_TEST(test_ind_null_safety);
}

static void run_section_default(void)
{
    printf("\n--- Section 4: Default Strict Mode ---\n");
    RUN_TEST(test_ind_default_strict);
}

static void run_section_approval(void)
{
    printf("\n--- Section 5: Algorithm Approval ---\n");
    RUN_TEST(test_algorithm_approved);
    RUN_TEST(test_algorithm_not_approved);
}

static void run_section_check_op(void)
{
    printf("\n--- Section 6: check_operation ---\n");
    RUN_TEST(test_check_operation_running);
}

static void run_section_security(void)
{
    printf("\n--- Section 7: Security Level ---\n");
    RUN_TEST(test_security_level_indicator);
    RUN_TEST(test_security_levels);
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

    printf("=== QUDO PQC FIPS Indicator Tests ===\n");

    if (test_fips_init() != 1) {
        printf("FATAL: module init failed\n");
        return 1;
    }

    if (section == NULL || strcmp(section, "init") == 0)
        run_section_init();
    if (section == NULL || strcmp(section, "unapproved") == 0)
        run_section_unapproved();
    if (section == NULL || strcmp(section, "null") == 0)
        run_section_null();
    if (section == NULL || strcmp(section, "default") == 0)
        run_section_default();
    if (section == NULL || strcmp(section, "approval") == 0)
        run_section_approval();
    if (section == NULL || strcmp(section, "check") == 0)
        run_section_check_op();
    if (section == NULL || strcmp(section, "security") == 0)
        run_section_security();

    qudo_pqc_fini();

    printf("\n=== Results: %d passed, %d failed, %d skipped ===\n", g_pass,
           g_fail, g_skip);

    return g_fail > 0 ? 1 : 0;
}
