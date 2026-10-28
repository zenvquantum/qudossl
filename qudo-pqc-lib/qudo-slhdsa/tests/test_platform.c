/* SPDX-License-Identifier: Apache-2.0 AND MIT */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../include/slhdsa_wrapper.h"
#include "../include/slhdsa_config.h"

static int tests_run = 0;
static int tests_passed = 0;

#define TEST(name) do { \
    tests_run++; \
    printf("  [%d] %-55s ", tests_run, name); \
    fflush(stdout); \
} while(0)

#define PASS() do { tests_passed++; printf("PASS\n"); } while(0)
#define FAIL(msg) do { printf("FAIL: %s\n", msg); } while(0)

static void test_get_platform(void) {
    TEST("QUDO_SLHDSA_get_platform()");
    const char *platform = QUDO_SLHDSA_get_platform();
    if (!platform) { FAIL("returned NULL"); return; }
    if (strlen(platform) == 0) { FAIL("empty string"); return; }
    printf("(%s) ", platform);
    PASS();
}

static void test_get_architecture(void) {
    TEST("QUDO_SLHDSA_get_architecture()");
    const char *arch = QUDO_SLHDSA_get_architecture();
    if (!arch) { FAIL("returned NULL"); return; }
    if (strlen(arch) == 0) { FAIL("empty string"); return; }
    printf("(%s) ", arch);
    PASS();
}

static void test_has_avx2(void) {
    TEST("QUDO_SLHDSA_has_avx2()");
    int result = QUDO_SLHDSA_has_avx2();
    if (result == 0 || result == 1) {
        printf("(%s) ", result ? "Yes" : "No");
        PASS();
    } else { FAIL("unexpected value"); }
}

static void test_has_neon(void) {
    TEST("QUDO_SLHDSA_has_neon()");
    int result = QUDO_SLHDSA_has_neon();
    if (result == 0 || result == 1) {
        printf("(%s) ", result ? "Yes" : "No");
        PASS();
    } else { FAIL("unexpected value"); }
}

static void test_get_cpu_count(void) {
    TEST("QUDO_SLHDSA_get_cpu_count()");
    int count = QUDO_SLHDSA_get_cpu_count();
    if (count >= 1) {
        printf("(%d) ", count);
        PASS();
    } else { FAIL("invalid count"); }
}

static void test_get_cache_line_size(void) {
    TEST("QUDO_SLHDSA_get_cache_line_size()");
    size_t size = QUDO_SLHDSA_get_cache_line_size();
    if (size >= 16 && size <= 256 && (size & (size - 1)) == 0) {
        printf("(%zu) ", size);
        PASS();
    } else {
        printf("(%zu) ", size);
        FAIL("unexpected cache line size");
    }
}

static void test_get_features(void) {
    TEST("QUDO_SLHDSA_get_features()");
    const char *features = QUDO_SLHDSA_get_features();
    if (!features) { FAIL("returned NULL"); return; }
    if (strlen(features) == 0) { FAIL("empty string"); return; }
    printf("(%s) ", features);
    PASS();

    TEST("QUDO_SLHDSA_get_features() idempotent");
    const char *features2 = QUDO_SLHDSA_get_features();
    if (features == features2) { PASS(); } else { FAIL("should return same pointer"); }
}

static void test_is_platform_supported(void) {
    TEST("QUDO_SLHDSA_is_platform_supported()");
    int supported = QUDO_SLHDSA_is_platform_supported();
    if (supported == 1) { PASS(); } else { FAIL("current platform should be supported"); }
}

static void test_print_system_info(void) {
    TEST("QUDO_SLHDSA_print_system_info()");
    printf("\n--- System Info Output ---\n");
    QUDO_SLHDSA_print_system_info();
    printf("--- End System Info ---\n");
    printf("  [%d] %-55s ", tests_run, "QUDO_SLHDSA_print_system_info()");
    PASS();
}

static void test_get_version(void) {
    TEST("QUDO_SLHDSA_get_version()");
    const char *ver = QUDO_SLHDSA_get_version();
    if (!ver) { FAIL("returned NULL"); return; }
    if (strlen(ver) == 0) { FAIL("empty string"); return; }
    if (strchr(ver, '.') != NULL) {
        printf("(%s) ", ver);
        PASS();
    } else { FAIL("not version format"); }
}

int main(void) {
    printf("=== QUDO SLH-DSA Platform Detection Tests ===\n\n");

    test_get_platform();
    test_get_architecture();
    test_has_avx2();
    test_has_neon();
    test_get_cpu_count();
    test_get_cache_line_size();
    test_get_features();
    test_is_platform_supported();
    test_print_system_info();
    test_get_version();

    printf("\n=== Results: %d/%d tests passed ===\n", tests_passed, tests_run);
    return (tests_passed == tests_run) ? 0 : 1;
}
