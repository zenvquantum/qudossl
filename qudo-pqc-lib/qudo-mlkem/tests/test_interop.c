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

static void test_der_roundtrip(void) {
    QUDO_KEM_security_level_t levels[] = { QUDO_KEM_LEVEL_512, QUDO_KEM_LEVEL_768, QUDO_KEM_LEVEL_1024 };
    const char *names[] = { "ML-KEM-512", "ML-KEM-768", "ML-KEM-1024" };

    for (int i = 0; i < 3; i++) {
        char label[80];
        snprintf(label, sizeof(label), "DER export/import roundtrip %s", names[i]);
        TEST(label);

        QUDO_KEM *kem = QUDO_KEM_new_by_level(levels[i]);
        if (!kem) { FAIL("new failed"); continue; }

        uint8_t *pk = malloc(kem->length_public_key);
        uint8_t *sk = malloc(kem->length_secret_key);
        QUDO_KEM_keypair(kem, pk, sk);

        uint8_t der_buf[4096];
        size_t der_len = sizeof(der_buf);
        QUDO_KEM_status_t rc = QUDO_KEM_export_public_key_der(pk, kem->length_public_key, der_buf, &der_len);
        if (rc != QUDO_KEM_SUCCESS) { FAIL("export failed"); free(pk); free(sk); QUDO_KEM_free(kem); continue; }

        if (der_len <= kem->length_public_key) { FAIL("DER too small"); free(pk); free(sk); QUDO_KEM_free(kem); continue; }

        uint8_t *pk2 = malloc(kem->length_public_key);
        size_t pk2_len = kem->length_public_key;
        rc = QUDO_KEM_import_public_key_der(der_buf, der_len, pk2, &pk2_len);
        if (rc != QUDO_KEM_SUCCESS) { FAIL("import failed"); free(pk); free(sk); free(pk2); QUDO_KEM_free(kem); continue; }

        if (pk2_len != kem->length_public_key) { FAIL("wrong imported key size"); }
        else if (memcmp(pk, pk2, pk2_len) != 0) { FAIL("keys don't match"); }
        else { PASS(); }

        free(pk); free(sk); free(pk2);
        QUDO_KEM_free(kem);
    }
}

static void test_der_export_null_args(void) {
    TEST("DER export NULL public_key");
    uint8_t buf[4096];
    size_t len = sizeof(buf);
    QUDO_KEM_status_t rc = QUDO_KEM_export_public_key_der(NULL, 800, buf, &len);
    if (rc != QUDO_KEM_SUCCESS) { PASS(); } else { FAIL("should fail"); }

    TEST("DER export NULL buffer");
    uint8_t pk[800];
    memset(pk, 0x42, sizeof(pk));
    len = sizeof(buf);
    rc = QUDO_KEM_export_public_key_der(pk, sizeof(pk), NULL, &len);
    if (rc != QUDO_KEM_SUCCESS) { PASS(); } else { FAIL("should fail"); }

    TEST("DER export NULL len");
    rc = QUDO_KEM_export_public_key_der(pk, sizeof(pk), buf, NULL);
    if (rc != QUDO_KEM_SUCCESS) { PASS(); } else { FAIL("should fail"); }

    TEST("DER export buffer too small");
    len = 1;
    rc = QUDO_KEM_export_public_key_der(pk, QUDO_KEM_768_PUBLIC_KEY_BYTES, buf, &len);
    if (rc == QUDO_KEM_ERROR_BUFFER_TOO_SMALL || rc != QUDO_KEM_SUCCESS) { PASS(); } else { FAIL("should fail"); }
}

static void test_der_import_null_args(void) {
    TEST("DER import NULL der_buffer");
    uint8_t pk[2048];
    size_t pk_len = sizeof(pk);
    QUDO_KEM_status_t rc = QUDO_KEM_import_public_key_der(NULL, 100, pk, &pk_len);
    if (rc != QUDO_KEM_SUCCESS) { PASS(); } else { FAIL("should fail"); }

    TEST("DER import NULL public_key");
    uint8_t der[100];
    rc = QUDO_KEM_import_public_key_der(der, sizeof(der), NULL, &pk_len);
    if (rc != QUDO_KEM_SUCCESS) { PASS(); } else { FAIL("should fail"); }

    TEST("DER import NULL pk_len");
    rc = QUDO_KEM_import_public_key_der(der, sizeof(der), pk, NULL);
    if (rc != QUDO_KEM_SUCCESS) { PASS(); } else { FAIL("should fail"); }

    TEST("DER import invalid data");
    uint8_t garbage[50];
    memset(garbage, 0xFF, sizeof(garbage));
    pk_len = sizeof(pk);
    rc = QUDO_KEM_import_public_key_der(garbage, sizeof(garbage), pk, &pk_len);
    if (rc != QUDO_KEM_SUCCESS) { PASS(); } else { FAIL("should fail on garbage"); }

    TEST("DER import zero length");
    pk_len = sizeof(pk);
    rc = QUDO_KEM_import_public_key_der(der, 0, pk, &pk_len);
    if (rc != QUDO_KEM_SUCCESS) { PASS(); } else { FAIL("should fail on zero len"); }
}

static void test_der_import_invalid_key_size(void) {

    TEST("DER import buffer too small for key");
    QUDO_KEM *kem = QUDO_KEM_new("ML-KEM-512");
    if (!kem) { FAIL("new failed"); return; }

    uint8_t *pk = malloc(kem->length_public_key);
    uint8_t *sk = malloc(kem->length_secret_key);
    QUDO_KEM_keypair(kem, pk, sk);

    uint8_t der_buf[4096];
    size_t der_len = sizeof(der_buf);
    QUDO_KEM_export_public_key_der(pk, kem->length_public_key, der_buf, &der_len);

    uint8_t small_buf[10];
    size_t small_len = sizeof(small_buf);
    QUDO_KEM_status_t rc = QUDO_KEM_import_public_key_der(der_buf, der_len, small_buf, &small_len);
    if (rc != QUDO_KEM_SUCCESS) { PASS(); } else { FAIL("should fail with small buffer"); }

    free(pk); free(sk);
    QUDO_KEM_free(kem);
}

static void test_pem_roundtrip(void) {
    QUDO_KEM_security_level_t levels[] = { QUDO_KEM_LEVEL_512, QUDO_KEM_LEVEL_768, QUDO_KEM_LEVEL_1024 };
    const char *names[] = { "ML-KEM-512", "ML-KEM-768", "ML-KEM-1024" };

    for (int i = 0; i < 3; i++) {
        char label[80];
        snprintf(label, sizeof(label), "PEM export/import roundtrip %s", names[i]);
        TEST(label);

        QUDO_KEM *kem = QUDO_KEM_new_by_level(levels[i]);
        if (!kem) { FAIL("new failed"); continue; }

        uint8_t *pk = malloc(kem->length_public_key);
        uint8_t *sk = malloc(kem->length_secret_key);
        QUDO_KEM_keypair(kem, pk, sk);

        char pem_buf[8192];
        size_t pem_len = sizeof(pem_buf);
        QUDO_KEM_status_t rc = QUDO_KEM_export_public_key_pem(pk, kem->length_public_key, pem_buf, &pem_len);
        if (rc != QUDO_KEM_SUCCESS) { FAIL("export failed"); free(pk); free(sk); QUDO_KEM_free(kem); continue; }

        if (strstr(pem_buf, "-----BEGIN PUBLIC KEY-----") == NULL) {
            FAIL("missing PEM header");
            free(pk); free(sk); QUDO_KEM_free(kem); continue;
        }
        if (strstr(pem_buf, "-----END PUBLIC KEY-----") == NULL) {
            FAIL("missing PEM footer");
            free(pk); free(sk); QUDO_KEM_free(kem); continue;
        }

        uint8_t *pk2 = malloc(kem->length_public_key);
        size_t pk2_len = kem->length_public_key;
        rc = QUDO_KEM_import_public_key_pem(pem_buf, pk2, &pk2_len);
        if (rc != QUDO_KEM_SUCCESS) { FAIL("import failed"); free(pk); free(sk); free(pk2); QUDO_KEM_free(kem); continue; }

        if (pk2_len != kem->length_public_key) { FAIL("wrong imported key size"); }
        else if (memcmp(pk, pk2, pk2_len) != 0) { FAIL("keys don't match"); }
        else { PASS(); }

        free(pk); free(sk); free(pk2);
        QUDO_KEM_free(kem);
    }
}

static void test_pem_export_null_args(void) {
    TEST("PEM export NULL public_key");
    char buf[4096];
    size_t len = sizeof(buf);
    QUDO_KEM_status_t rc = QUDO_KEM_export_public_key_pem(NULL, 800, buf, &len);
    if (rc != QUDO_KEM_SUCCESS) { PASS(); } else { FAIL("should fail"); }

    TEST("PEM export NULL buffer (size query)");
    uint8_t pk[800];
    memset(pk, 0x42, sizeof(pk));
    len = 0;
    rc = QUDO_KEM_export_public_key_pem(pk, sizeof(pk), NULL, &len);
    if (rc == QUDO_KEM_SUCCESS && len > 0) { PASS(); } else { FAIL("size query failed"); }

    TEST("PEM export NULL len");
    rc = QUDO_KEM_export_public_key_pem(pk, sizeof(pk), buf, NULL);
    if (rc != QUDO_KEM_SUCCESS) { PASS(); } else { FAIL("should fail"); }

    TEST("PEM export buffer too small");
    len = 10;
    rc = QUDO_KEM_export_public_key_pem(pk, QUDO_KEM_768_PUBLIC_KEY_BYTES, buf, &len);
    if (rc != QUDO_KEM_SUCCESS) { PASS(); } else { FAIL("should fail"); }
}

static void test_pem_import_null_args(void) {
    TEST("PEM import NULL pem_buffer");
    uint8_t pk[2048];
    size_t pk_len = sizeof(pk);
    QUDO_KEM_status_t rc = QUDO_KEM_import_public_key_pem(NULL, pk, &pk_len);
    if (rc != QUDO_KEM_SUCCESS) { PASS(); } else { FAIL("should fail"); }

    TEST("PEM import NULL public_key");
    rc = QUDO_KEM_import_public_key_pem("dummy", NULL, &pk_len);
    if (rc != QUDO_KEM_SUCCESS) { PASS(); } else { FAIL("should fail"); }

    TEST("PEM import NULL pk_len");
    rc = QUDO_KEM_import_public_key_pem("dummy", pk, NULL);
    if (rc != QUDO_KEM_SUCCESS) { PASS(); } else { FAIL("should fail"); }

    TEST("PEM import invalid PEM data");
    pk_len = sizeof(pk);
    rc = QUDO_KEM_import_public_key_pem("not a PEM string", pk, &pk_len);
    if (rc != QUDO_KEM_SUCCESS) { PASS(); } else { FAIL("should fail on garbage"); }

    TEST("PEM import empty string");
    pk_len = sizeof(pk);
    rc = QUDO_KEM_import_public_key_pem("", pk, &pk_len);
    if (rc != QUDO_KEM_SUCCESS) { PASS(); } else { FAIL("should fail on empty"); }
}

static void test_der_pem_cross(void) {
    TEST("DER→PEM→DER roundtrip consistency");
    QUDO_KEM *kem = QUDO_KEM_new("ML-KEM-768");
    if (!kem) { FAIL("new failed"); return; }

    uint8_t *pk = malloc(kem->length_public_key);
    uint8_t *sk = malloc(kem->length_secret_key);
    QUDO_KEM_keypair(kem, pk, sk);

    uint8_t der[4096];
    size_t der_len = sizeof(der);
    QUDO_KEM_export_public_key_der(pk, kem->length_public_key, der, &der_len);

    char pem[8192];
    size_t pem_len = sizeof(pem);
    QUDO_KEM_export_public_key_pem(pk, kem->length_public_key, pem, &pem_len);

    uint8_t pk_from_der[2048], pk_from_pem[2048];
    size_t pk_der_len = sizeof(pk_from_der);
    size_t pk_pem_len = sizeof(pk_from_pem);

    QUDO_KEM_import_public_key_der(der, der_len, pk_from_der, &pk_der_len);
    QUDO_KEM_import_public_key_pem(pem, pk_from_pem, &pk_pem_len);

    if (pk_der_len != pk_pem_len) { FAIL("size mismatch"); }
    else if (memcmp(pk_from_der, pk_from_pem, pk_der_len) != 0) { FAIL("keys don't match"); }
    else { PASS(); }

    free(pk); free(sk);
    QUDO_KEM_free(kem);
}

int main(void) {
    printf("=== QUDO ML-KEM Interop (DER/PEM) Tests ===\n\n");

    printf("[DER Export/Import]\n");
    test_der_roundtrip();
    test_der_export_null_args();
    test_der_import_null_args();
    test_der_import_invalid_key_size();

    printf("\n[PEM Export/Import]\n");
    test_pem_roundtrip();
    test_pem_export_null_args();
    test_pem_import_null_args();

    printf("\n[Cross-Format]\n");
    test_der_pem_cross();

    printf("\n=== Results: %d/%d tests passed ===\n", tests_passed, tests_run);
    return (tests_passed == tests_run) ? 0 : 1;
}
