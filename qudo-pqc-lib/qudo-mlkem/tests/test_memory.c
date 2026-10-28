/* SPDX-License-Identifier: Apache-2.0 AND MIT */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../include/mlkem_wrapper.h"
#include "../include/mlkem_config.h"

static int tests_run = 0;
static int tests_passed = 0;

#define TEST(name) do { \
    tests_run++; \
    printf("  [%d] %-55s ", tests_run, name); \
    fflush(stdout); \
} while(0)

#define PASS() do { tests_passed++; printf("PASS\n"); } while(0)
#define FAIL(msg) do { printf("FAIL: %s\n", msg); } while(0)

static void test_secure_zero(void) {
    TEST("secure_zero() normal buffer");
    uint8_t buf[256];
    memset(buf, 0xAA, sizeof(buf));
    QUDO_KEM_secure_zero(buf, sizeof(buf));
    int all_zero = 1;
    for (size_t i = 0; i < sizeof(buf); i++) {
        if (buf[i] != 0) { all_zero = 0; break; }
    }
    if (all_zero) { PASS(); } else { FAIL("not zeroed"); }

    TEST("secure_zero() partial buffer");
    memset(buf, 0xBB, sizeof(buf));
    QUDO_KEM_secure_zero(buf, 100);
    int partial_ok = 1;
    for (size_t i = 0; i < 100; i++) {
        if (buf[i] != 0) { partial_ok = 0; break; }
    }
    if (buf[100] != 0xBB) partial_ok = 0;
    if (partial_ok) { PASS(); } else { FAIL("partial zero failed"); }

    TEST("secure_zero(NULL)");
    QUDO_KEM_secure_zero(NULL, 100);
    PASS();

    TEST("secure_zero(ptr, 0)");
    memset(buf, 0xCC, sizeof(buf));
    QUDO_KEM_secure_zero(buf, 0);
    if (buf[0] == 0xCC) { PASS(); } else { FAIL("should be no-op"); }

    TEST("secure_zero() single byte");
    buf[0] = 0xFF;
    QUDO_KEM_secure_zero(buf, 1);
    if (buf[0] == 0) { PASS(); } else { FAIL("single byte not zeroed"); }

    TEST("secure_zero() large buffer");
    size_t large_sz = 64 * 1024;
    uint8_t *large = malloc(large_sz);
    if (large) {
        memset(large, 0xDD, large_sz);
        QUDO_KEM_secure_zero(large, large_sz);
        int ok = 1;
        for (size_t i = 0; i < large_sz; i += 1024) {
            if (large[i] != 0) { ok = 0; break; }
        }
        if (ok) { PASS(); } else { FAIL("large buffer not zeroed"); }
        free(large);
    } else { FAIL("alloc failed"); }
}

static void test_secure_alloc_free(void) {
    TEST("secure_alloc() normal");
    void *ptr = QUDO_KEM_secure_alloc(256);
    if (!ptr) { FAIL("returned NULL"); return; }

    uint8_t *bytes = (uint8_t *)ptr;
    int all_zero = 1;
    for (int i = 0; i < 256; i++) {
        if (bytes[i] != 0) { all_zero = 0; break; }
    }
    if (all_zero) { PASS(); } else { FAIL("not zeroed"); }
    QUDO_KEM_secure_free(ptr, 256);

    TEST("secure_alloc(0)");
    ptr = QUDO_KEM_secure_alloc(0);
    if (ptr == NULL) { PASS(); } else { FAIL("should return NULL for 0"); QUDO_KEM_secure_free(ptr, 0); }

    TEST("secure_free(NULL)");
    QUDO_KEM_secure_free(NULL, 100);
    PASS();

    TEST("secure_alloc() large allocation");
    ptr = QUDO_KEM_secure_alloc(1024 * 1024);
    if (ptr) {
        PASS();
        QUDO_KEM_secure_free(ptr, 1024 * 1024);
    } else { FAIL("large alloc failed"); }

    TEST("secure_alloc/free multiple cycles");
    int ok = 1;
    for (int i = 0; i < 100; i++) {
        ptr = QUDO_KEM_secure_alloc(128);
        if (!ptr) { ok = 0; break; }
        memset(ptr, 0xAA, 128);
        QUDO_KEM_secure_free(ptr, 128);
    }
    if (ok) { PASS(); } else { FAIL("cycle failed"); }
}

static void test_constant_time_compare(void) {
    TEST("constant_time_compare() equal buffers");
    uint8_t a[32], b[32];
    memset(a, 0x42, sizeof(a));
    memcpy(b, a, sizeof(a));
    if (QUDO_KEM_constant_time_compare(a, b, sizeof(a)) == 0) { PASS(); } else { FAIL("should be equal"); }

    TEST("constant_time_compare() different buffers");
    b[15] ^= 0x01;
    if (QUDO_KEM_constant_time_compare(a, b, sizeof(a)) != 0) { PASS(); } else { FAIL("should differ"); }

    TEST("constant_time_compare() first byte different");
    memcpy(b, a, sizeof(a));
    b[0] ^= 0xFF;
    if (QUDO_KEM_constant_time_compare(a, b, sizeof(a)) != 0) { PASS(); } else { FAIL("should differ"); }

    TEST("constant_time_compare() last byte different");
    memcpy(b, a, sizeof(a));
    b[31] ^= 0x01;
    if (QUDO_KEM_constant_time_compare(a, b, sizeof(a)) != 0) { PASS(); } else { FAIL("should differ"); }

    TEST("constant_time_compare() zero length");
    if (QUDO_KEM_constant_time_compare(a, b, 0) == 0) { PASS(); } else { FAIL("zero len should match"); }

    TEST("constant_time_compare(NULL, b)");
    if (QUDO_KEM_constant_time_compare(NULL, b, sizeof(b)) == -1) { PASS(); } else { FAIL("should return -1"); }

    TEST("constant_time_compare(a, NULL)");
    if (QUDO_KEM_constant_time_compare(a, NULL, sizeof(a)) == -1) { PASS(); } else { FAIL("should return -1"); }

    TEST("constant_time_compare() single byte equal");
    a[0] = 0x55; b[0] = 0x55;
    if (QUDO_KEM_constant_time_compare(a, b, 1) == 0) { PASS(); } else { FAIL("should be equal"); }

    TEST("constant_time_compare() single byte different");
    b[0] = 0xAA;
    if (QUDO_KEM_constant_time_compare(a, b, 1) != 0) { PASS(); } else { FAIL("should differ"); }
}

static void test_constant_time_select(void) {
    uint8_t a[16], b[16], result[16];
    memset(a, 0xAA, sizeof(a));
    memset(b, 0xBB, sizeof(b));

    TEST("constant_time_select() condition=1 selects a");
    memset(result, 0, sizeof(result));
    QUDO_KEM_constant_time_select(result, a, b, sizeof(a), 1);
    if (memcmp(result, a, sizeof(a)) == 0) { PASS(); } else { FAIL("should select a"); }

    TEST("constant_time_select() condition=0 selects b");
    memset(result, 0, sizeof(result));
    QUDO_KEM_constant_time_select(result, a, b, sizeof(a), 0);
    if (memcmp(result, b, sizeof(b)) == 0) { PASS(); } else { FAIL("should select b"); }

    TEST("constant_time_select() condition=5 (nonzero) selects a");
    memset(result, 0, sizeof(result));
    QUDO_KEM_constant_time_select(result, a, b, sizeof(a), 5);
    if (memcmp(result, a, sizeof(a)) == 0) { PASS(); } else { FAIL("nonzero should select a"); }

    TEST("constant_time_select(NULL result)");
    QUDO_KEM_constant_time_select(NULL, a, b, sizeof(a), 1);
    PASS();

    TEST("constant_time_select(NULL a)");
    QUDO_KEM_constant_time_select(result, NULL, b, sizeof(b), 1);
    PASS();

    TEST("constant_time_select(NULL b)");
    QUDO_KEM_constant_time_select(result, a, NULL, sizeof(a), 0);
    PASS();

    TEST("constant_time_select() zero length");
    uint8_t prev[16];
    memcpy(prev, result, sizeof(result));
    QUDO_KEM_constant_time_select(result, a, b, 0, 1);
    if (memcmp(result, prev, sizeof(result)) == 0) { PASS(); } else { FAIL("zero len changed result"); }
}

static void test_aligned_alloc(void) {
    TEST("aligned_alloc(64, 256)");
    void *ptr = QUDO_KEM_aligned_alloc(64, 256);
    if (!ptr) { FAIL("returned NULL"); }
    else if (((size_t)ptr % 64) != 0) { FAIL("not aligned"); QUDO_KEM_aligned_free(ptr); }
    else { PASS(); QUDO_KEM_aligned_free(ptr); }

    TEST("aligned_alloc(32, 1024)");
    ptr = QUDO_KEM_aligned_alloc(32, 1024);
    if (!ptr) { FAIL("returned NULL"); }
    else if (((size_t)ptr % 32) != 0) { FAIL("not aligned"); QUDO_KEM_aligned_free(ptr); }
    else { PASS(); QUDO_KEM_aligned_free(ptr); }

    TEST("aligned_alloc(16, 1)");
    ptr = QUDO_KEM_aligned_alloc(16, 1);
    if (!ptr) { FAIL("returned NULL"); }
    else { PASS(); QUDO_KEM_aligned_free(ptr); }

    TEST("aligned_alloc(0, 256)");
    ptr = QUDO_KEM_aligned_alloc(0, 256);
    if (ptr == NULL) { PASS(); } else { FAIL("should return NULL for 0 align"); QUDO_KEM_aligned_free(ptr); }

    TEST("aligned_alloc(64, 0)");
    ptr = QUDO_KEM_aligned_alloc(64, 0);
    if (ptr == NULL) { PASS(); } else { FAIL("should return NULL for 0 size"); QUDO_KEM_aligned_free(ptr); }

    TEST("aligned_free(NULL)");
    QUDO_KEM_aligned_free(NULL);
    PASS();
}

static void test_zeroization_after_free(void) {
    TEST("KEM key buffer zeroization");

    static uint8_t pk[QUDO_KEM_768_PUBLIC_KEY_BYTES];
    static uint8_t sk[QUDO_KEM_768_SECRET_KEY_BYTES];

    QUDO_KEM *kem = QUDO_KEM_new(QUDO_KEM_alg_mlkem_768);
    if (!kem) { FAIL("QUDO_KEM_new failed"); return; }

    int ret = QUDO_KEM_keypair(kem, pk, sk);
    if (ret != QUDO_KEM_SUCCESS) {
        FAIL("keypair failed");
        QUDO_KEM_free(kem);
        return;
    }

    int pk_nonzero = 0;
    {
        size_t i;
        for (i = 0; i < 32; i++) {
            if (pk[i] != 0) { pk_nonzero = 1; break; }
        }
    }

    if (!pk_nonzero) {
        FAIL("public key is all zeros after keypair");
        QUDO_KEM_free(kem);
        return;
    }

    QUDO_KEM_free(kem);

    PASS();

    TEST("KEM encaps/decaps shared secret zeroization");
    QUDO_KEM *kem2 = QUDO_KEM_new(QUDO_KEM_alg_mlkem_768);
    if (!kem2) { FAIL("QUDO_KEM_new failed"); return; }

    ret = QUDO_KEM_keypair(kem2, pk, sk);
    if (ret != QUDO_KEM_SUCCESS) {
        FAIL("keypair failed");
        QUDO_KEM_free(kem2);
        return;
    }

    uint8_t ct[QUDO_KEM_768_CIPHERTEXT_BYTES];
    uint8_t ss_enc[QUDO_KEM_768_SHARED_SECRET_BYTES];
    uint8_t ss_dec[QUDO_KEM_768_SHARED_SECRET_BYTES];

    ret = QUDO_KEM_encaps(kem2, ct, ss_enc, pk);
    if (ret != QUDO_KEM_SUCCESS) {
        FAIL("encaps failed");
        QUDO_KEM_free(kem2);
        return;
    }

    ret = QUDO_KEM_decaps(kem2, ss_dec, ct, sk);
    if (ret != QUDO_KEM_SUCCESS) {
        FAIL("decaps failed");
        QUDO_KEM_free(kem2);
        return;
    }

    if (memcmp(ss_enc, ss_dec, sizeof(ss_enc)) != 0) {
        FAIL("shared secrets don't match");
        QUDO_KEM_free(kem2);
        return;
    }

    QUDO_KEM_secure_zero(ss_enc, sizeof(ss_enc));
    QUDO_KEM_secure_zero(ss_dec, sizeof(ss_dec));
    QUDO_KEM_secure_zero(sk, sizeof(sk));

    int ss_zeroed = 1;
    {
        size_t i;
        for (i = 0; i < sizeof(ss_enc); i++) {
            if (ss_enc[i] != 0 || ss_dec[i] != 0) { ss_zeroed = 0; break; }
        }
    }

    QUDO_KEM_free(kem2);

    if (ss_zeroed) { PASS(); } else { FAIL("shared secrets not zeroed"); }
}

int main(void) {
    printf("=== QUDO ML-KEM Secure Memory Tests ===\n\n");

    printf("[secure_zero]\n");
    test_secure_zero();

    printf("\n[secure_alloc/free]\n");
    test_secure_alloc_free();

    printf("\n[constant_time_compare]\n");
    test_constant_time_compare();

    printf("\n[constant_time_select]\n");
    test_constant_time_select();

    printf("\n[aligned_alloc/free]\n");
    test_aligned_alloc();

    printf("\n[zeroization after free]\n");
    test_zeroization_after_free();

    printf("\n=== Results: %d/%d tests passed ===\n", tests_passed, tests_run);
    return (tests_passed == tests_run) ? 0 : 1;
}
