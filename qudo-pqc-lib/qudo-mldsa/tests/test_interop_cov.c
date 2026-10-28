/* SPDX-License-Identifier: Apache-2.0 AND MIT */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../include/mldsa_wrapper.h"
#include "../include/mldsa_config.h"

static int tests_run = 0;
static int tests_passed = 0;

#define TEST(name) do { \
    tests_run++; \
    printf("  [%d] %-55s ", tests_run, name); \
    fflush(stdout); \
} while(0)

#define PASS() do { tests_passed++; printf("PASS\n"); } while(0)
#define FAIL(msg) do { printf("FAIL: %s\n", msg); } while(0)

static void test_public_key_der(void) {
    const char *algs[] = { "ML-DSA-44", "ML-DSA-65", "ML-DSA-87" };
    const size_t pk_sizes[] = { ML_DSA_44_PUBLIC_KEY_BYTES, ML_DSA_65_PUBLIC_KEY_BYTES, ML_DSA_87_PUBLIC_KEY_BYTES };
    const size_t sk_sizes[] = { ML_DSA_44_SECRET_KEY_BYTES, ML_DSA_65_SECRET_KEY_BYTES, ML_DSA_87_SECRET_KEY_BYTES };

    for (int i = 0; i < 3; i++) {
        char label[64];
        QUDO_MLDSA *sig = QUDO_MLDSA_new(algs[i]);
        if (!sig) continue;

        uint8_t *pk = malloc(pk_sizes[i]);
        uint8_t *sk = malloc(sk_sizes[i]);
        if (!pk || !sk) { free(pk); free(sk); QUDO_MLDSA_free(sig); continue; }
        QUDO_MLDSA_keypair(sig, pk, sk);

        uint8_t der[16384];
        size_t der_len = sizeof(der);

        snprintf(label, sizeof(label), "%s public key DER export", algs[i]);
        TEST(label);
        QUDO_MLDSA_status_t rc = QUDO_MLDSA_export_public_key_der(pk, pk_sizes[i], der, &der_len);
        if (rc != QUDO_MLDSA_SUCCESS) { FAIL("export failed"); free(pk); free(sk); QUDO_MLDSA_free(sig); continue; }
        PASS();

        snprintf(label, sizeof(label), "%s public key DER import", algs[i]);
        TEST(label);
        uint8_t pk2[ML_DSA_87_PUBLIC_KEY_BYTES];
        size_t pk2_len = sizeof(pk2);
        rc = QUDO_MLDSA_import_public_key_der(der, der_len, pk2, &pk2_len);
        if (rc != QUDO_MLDSA_SUCCESS) { FAIL("import failed"); }
        else if (pk2_len != pk_sizes[i]) { FAIL("wrong size"); }
        else if (memcmp(pk, pk2, pk_sizes[i]) != 0) { FAIL("data mismatch"); }
        else { PASS(); }

        free(pk); free(sk);
        QUDO_MLDSA_free(sig);
    }
}

static void test_public_key_pem(void) {
    const char *algs[] = { "ML-DSA-44", "ML-DSA-65", "ML-DSA-87" };
    const size_t pk_sizes[] = { ML_DSA_44_PUBLIC_KEY_BYTES, ML_DSA_65_PUBLIC_KEY_BYTES, ML_DSA_87_PUBLIC_KEY_BYTES };
    const size_t sk_sizes[] = { ML_DSA_44_SECRET_KEY_BYTES, ML_DSA_65_SECRET_KEY_BYTES, ML_DSA_87_SECRET_KEY_BYTES };

    for (int i = 0; i < 3; i++) {
        char label[64];
        QUDO_MLDSA *sig = QUDO_MLDSA_new(algs[i]);
        if (!sig) continue;

        uint8_t *pk = malloc(pk_sizes[i]);
        uint8_t *sk = malloc(sk_sizes[i]);
        if (!pk || !sk) { free(pk); free(sk); QUDO_MLDSA_free(sig); continue; }
        QUDO_MLDSA_keypair(sig, pk, sk);

        char pem[32768];
        size_t pem_len = sizeof(pem);

        snprintf(label, sizeof(label), "%s public key PEM export", algs[i]);
        TEST(label);
        QUDO_MLDSA_status_t rc = QUDO_MLDSA_export_public_key_pem(pk, pk_sizes[i], pem, &pem_len);
        if (rc != QUDO_MLDSA_SUCCESS) { FAIL("export failed"); free(pk); free(sk); QUDO_MLDSA_free(sig); continue; }
        if (strstr(pem, "BEGIN PUBLIC KEY") == NULL) { FAIL("no PEM header"); free(pk); free(sk); QUDO_MLDSA_free(sig); continue; }
        PASS();

        snprintf(label, sizeof(label), "%s public key PEM import", algs[i]);
        TEST(label);
        uint8_t pk2[ML_DSA_87_PUBLIC_KEY_BYTES];
        size_t pk2_len = sizeof(pk2);
        rc = QUDO_MLDSA_import_public_key_pem(pem, pk2, &pk2_len);
        if (rc != QUDO_MLDSA_SUCCESS) { FAIL("import failed"); }
        else if (pk2_len != pk_sizes[i]) { FAIL("wrong size"); }
        else if (memcmp(pk, pk2, pk_sizes[i]) != 0) { FAIL("data mismatch"); }
        else { PASS(); }

        free(pk); free(sk);
        QUDO_MLDSA_free(sig);
    }
}

static void test_private_key_der(void) {
    const char *algs[] = { "ML-DSA-44", "ML-DSA-65", "ML-DSA-87" };
    const size_t pk_sizes[] = { ML_DSA_44_PUBLIC_KEY_BYTES, ML_DSA_65_PUBLIC_KEY_BYTES, ML_DSA_87_PUBLIC_KEY_BYTES };
    const size_t sk_sizes[] = { ML_DSA_44_SECRET_KEY_BYTES, ML_DSA_65_SECRET_KEY_BYTES, ML_DSA_87_SECRET_KEY_BYTES };

    for (int i = 0; i < 3; i++) {
        char label[64];
        QUDO_MLDSA *sig = QUDO_MLDSA_new(algs[i]);
        if (!sig) continue;

        uint8_t *pk = malloc(pk_sizes[i]);
        uint8_t *sk = malloc(sk_sizes[i]);
        if (!pk || !sk) { free(pk); free(sk); QUDO_MLDSA_free(sig); continue; }
        QUDO_MLDSA_keypair(sig, pk, sk);

        uint8_t der[16384];
        size_t der_len = sizeof(der);

        snprintf(label, sizeof(label), "%s private key DER export", algs[i]);
        TEST(label);
        QUDO_MLDSA_status_t rc = QUDO_MLDSA_export_private_key_der(sk, sk_sizes[i], der, &der_len);
        if (rc != QUDO_MLDSA_SUCCESS) { FAIL("export failed"); free(pk); free(sk); QUDO_MLDSA_free(sig); continue; }
        PASS();

        snprintf(label, sizeof(label), "%s private key DER import", algs[i]);
        TEST(label);
        uint8_t sk2[ML_DSA_87_SECRET_KEY_BYTES];
        size_t sk2_len = sizeof(sk2);
        rc = QUDO_MLDSA_import_private_key_der(der, der_len, sk2, &sk2_len);
        if (rc != QUDO_MLDSA_SUCCESS) { FAIL("import failed"); }
        else if (sk2_len != sk_sizes[i]) { FAIL("wrong size"); }
        else if (memcmp(sk, sk2, sk_sizes[i]) != 0) { FAIL("data mismatch"); }
        else { PASS(); }

        free(pk); free(sk);
        QUDO_MLDSA_free(sig);
    }
}

static void test_private_key_pem(void) {
    const char *algs[] = { "ML-DSA-44", "ML-DSA-65", "ML-DSA-87" };
    const size_t pk_sizes[] = { ML_DSA_44_PUBLIC_KEY_BYTES, ML_DSA_65_PUBLIC_KEY_BYTES, ML_DSA_87_PUBLIC_KEY_BYTES };
    const size_t sk_sizes[] = { ML_DSA_44_SECRET_KEY_BYTES, ML_DSA_65_SECRET_KEY_BYTES, ML_DSA_87_SECRET_KEY_BYTES };

    for (int i = 0; i < 3; i++) {
        char label[64];
        QUDO_MLDSA *sig = QUDO_MLDSA_new(algs[i]);
        if (!sig) continue;

        uint8_t *pk = malloc(pk_sizes[i]);
        uint8_t *sk = malloc(sk_sizes[i]);
        if (!pk || !sk) { free(pk); free(sk); QUDO_MLDSA_free(sig); continue; }
        QUDO_MLDSA_keypair(sig, pk, sk);

        char pem[32768];
        size_t pem_len = sizeof(pem);

        snprintf(label, sizeof(label), "%s private key PEM export", algs[i]);
        TEST(label);
        QUDO_MLDSA_status_t rc = QUDO_MLDSA_export_private_key_pem(sk, sk_sizes[i], pem, &pem_len);
        if (rc != QUDO_MLDSA_SUCCESS) { FAIL("export failed"); free(pk); free(sk); QUDO_MLDSA_free(sig); continue; }
        if (strstr(pem, "BEGIN PRIVATE KEY") == NULL) { FAIL("no PEM header"); free(pk); free(sk); QUDO_MLDSA_free(sig); continue; }
        PASS();

        snprintf(label, sizeof(label), "%s private key PEM import", algs[i]);
        TEST(label);
        uint8_t sk2[ML_DSA_87_SECRET_KEY_BYTES];
        size_t sk2_len = sizeof(sk2);
        rc = QUDO_MLDSA_import_private_key_pem(pem, sk2, &sk2_len);
        if (rc != QUDO_MLDSA_SUCCESS) { FAIL("import failed"); }
        else if (sk2_len != sk_sizes[i]) { FAIL("wrong size"); }
        else if (memcmp(sk, sk2, sk_sizes[i]) != 0) { FAIL("data mismatch"); }
        else { PASS(); }

        free(pk); free(sk);
        QUDO_MLDSA_free(sig);
    }
}

static void test_pkcs8_formats(void) {
    QUDO_MLDSA *sig = QUDO_MLDSA_new("ML-DSA-65");
    if (!sig) return;

    uint8_t pk[ML_DSA_65_PUBLIC_KEY_BYTES], sk[ML_DSA_65_SECRET_KEY_BYTES];
    QUDO_MLDSA_keypair(sig, pk, sk);

    QUDO_MLDSA_pkcs8_format_t formats[] = {
        QUDO_MLDSA_PKCS8_FORMAT_SEED_PRIV,
        QUDO_MLDSA_PKCS8_FORMAT_PRIV_ONLY,
        QUDO_MLDSA_PKCS8_FORMAT_OQSKEYPAIR
    };
    const char *format_names[] = { "SEED_PRIV", "PRIV_ONLY", "OQSKEYPAIR" };

    for (int i = 0; i < 3; i++) {
        char label[64];
        uint8_t der[16384];
        size_t der_len = sizeof(der);

        snprintf(label, sizeof(label), "export_private_key_der_format(%s)", format_names[i]);
        TEST(label);
        QUDO_MLDSA_status_t rc = QUDO_MLDSA_export_private_key_der_format(sk, sizeof(sk), der, &der_len, formats[i]);
        if (rc == QUDO_MLDSA_SUCCESS && der_len > 0) { printf("(%zu bytes) ", der_len); PASS(); }
        else if (formats[i] == QUDO_MLDSA_PKCS8_FORMAT_SEED_PRIV) { printf("(unsupported from full key) "); PASS(); }
        else { FAIL("export failed"); }
    }

    TEST("import_private_key_der_format(OQSKEYPAIR)");
    {
        uint8_t der[16384];
        size_t der_len = sizeof(der);
        QUDO_MLDSA_export_private_key_der_format(sk, sizeof(sk), der, &der_len, QUDO_MLDSA_PKCS8_FORMAT_OQSKEYPAIR);

        uint8_t sk2[ML_DSA_65_SECRET_KEY_BYTES], pk2[ML_DSA_65_PUBLIC_KEY_BYTES];
        size_t sk2_len = sizeof(sk2), pk2_len = sizeof(pk2);
        QUDO_MLDSA_status_t rc = QUDO_MLDSA_import_private_key_der_format(der, der_len, sk2, &sk2_len, pk2, &pk2_len);
        if (rc == QUDO_MLDSA_SUCCESS && sk2_len > 0) { PASS(); } else { FAIL("import failed"); }
    }

    TEST("import_private_key_der_format(NULL pk out)");
    {
        uint8_t der[16384];
        size_t der_len = sizeof(der);
        QUDO_MLDSA_export_private_key_der_format(sk, sizeof(sk), der, &der_len, QUDO_MLDSA_PKCS8_FORMAT_PRIV_ONLY);

        uint8_t sk2[ML_DSA_65_SECRET_KEY_BYTES];
        size_t sk2_len = sizeof(sk2);
        QUDO_MLDSA_status_t rc = QUDO_MLDSA_import_private_key_der_format(der, der_len, sk2, &sk2_len, NULL, NULL);
        if (rc == QUDO_MLDSA_SUCCESS) { PASS(); } else { FAIL("import failed"); }
    }

    TEST("import_private_key_der_format(truncated-prefix sweep, no OOB)");
    {
        uint8_t der[16384];
        size_t der_len = sizeof(der);
        int swept_ok = 1;

        if (QUDO_MLDSA_export_private_key_der_format(
                sk, sizeof(sk), der, &der_len,
                QUDO_MLDSA_PKCS8_FORMAT_OQSKEYPAIR)
                == QUDO_MLDSA_SUCCESS
            && der_len > 1) {
            for (size_t L = 1; L < der_len; L++) {
                uint8_t sk2[ML_DSA_65_SECRET_KEY_BYTES];
                uint8_t pk2[ML_DSA_65_PUBLIC_KEY_BYTES];
                size_t sk2_len = sizeof(sk2), pk2_len = sizeof(pk2);

                /* Every truncation must be rejected without reading past
                 * the buffer. */
                if (QUDO_MLDSA_import_private_key_der_format(
                        der, L, sk2, &sk2_len, pk2, &pk2_len)
                    == QUDO_MLDSA_SUCCESS)
                    swept_ok = 0;
            }
        }
        if (swept_ok) { PASS(); } else { FAIL("truncated prefix accepted"); }
    }

    TEST("export/import_private_key_pem_format(OQSKEYPAIR)");
    {
        char pem[32768];
        size_t pem_len = sizeof(pem);
        QUDO_MLDSA_status_t rc = QUDO_MLDSA_export_private_key_pem_format(sk, sizeof(sk), pem, &pem_len, QUDO_MLDSA_PKCS8_FORMAT_OQSKEYPAIR);
        if (rc != QUDO_MLDSA_SUCCESS) { FAIL("pem export failed"); }
        else {
            uint8_t sk2[ML_DSA_65_SECRET_KEY_BYTES];
            size_t sk2_len = sizeof(sk2);
            rc = QUDO_MLDSA_import_private_key_pem_format(pem, sk2, &sk2_len, NULL, NULL);
            if (rc == QUDO_MLDSA_SUCCESS) { PASS(); } else { FAIL("pem import failed"); }
        }
    }

    QUDO_MLDSA_free(sig);
}

static void test_null_args(void) {
    TEST("export_public_key_der(NULL pk)");
    uint8_t buf[4096]; size_t len = sizeof(buf);
    if (QUDO_MLDSA_export_public_key_der(NULL, 1952, buf, &len) != QUDO_MLDSA_SUCCESS) { PASS(); } else { FAIL("should fail"); }

    TEST("export_public_key_der(pk, NULL der)");
    uint8_t pk[ML_DSA_65_PUBLIC_KEY_BYTES] = {0};
    if (QUDO_MLDSA_export_public_key_der(pk, sizeof(pk), NULL, &len) != QUDO_MLDSA_SUCCESS) { PASS(); } else { FAIL("should fail"); }

    TEST("export_public_key_der(pk, der, NULL len)");
    if (QUDO_MLDSA_export_public_key_der(pk, sizeof(pk), buf, NULL) != QUDO_MLDSA_SUCCESS) { PASS(); } else { FAIL("should fail"); }

    TEST("import_public_key_der(NULL der)");
    if (QUDO_MLDSA_import_public_key_der(NULL, 100, pk, &len) != QUDO_MLDSA_SUCCESS) { PASS(); } else { FAIL("should fail"); }

    TEST("import_public_key_der(invalid data)");
    uint8_t garbage[] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05 };
    len = sizeof(pk);
    if (QUDO_MLDSA_import_public_key_der(garbage, sizeof(garbage), pk, &len) != QUDO_MLDSA_SUCCESS) { PASS(); } else { FAIL("should fail"); }

    TEST("export_private_key_der(NULL sk)");
    len = sizeof(buf);
    if (QUDO_MLDSA_export_private_key_der(NULL, 4032, buf, &len) != QUDO_MLDSA_SUCCESS) { PASS(); } else { FAIL("should fail"); }

    TEST("import_private_key_der(NULL der)");
    uint8_t sk[ML_DSA_65_SECRET_KEY_BYTES];
    len = sizeof(sk);
    if (QUDO_MLDSA_import_private_key_der(NULL, 100, sk, &len) != QUDO_MLDSA_SUCCESS) { PASS(); } else { FAIL("should fail"); }

    TEST("export_public_key_pem(NULL pk)");
    char pem[8192]; size_t pem_len = sizeof(pem);
    if (QUDO_MLDSA_export_public_key_pem(NULL, 1952, pem, &pem_len) != QUDO_MLDSA_SUCCESS) { PASS(); } else { FAIL("should fail"); }

    TEST("import_public_key_pem(NULL pem)");
    len = sizeof(pk);
    if (QUDO_MLDSA_import_public_key_pem(NULL, pk, &len) != QUDO_MLDSA_SUCCESS) { PASS(); } else { FAIL("should fail"); }

    TEST("export_private_key_pem(NULL sk)");
    pem_len = sizeof(pem);
    if (QUDO_MLDSA_export_private_key_pem(NULL, 4032, pem, &pem_len) != QUDO_MLDSA_SUCCESS) { PASS(); } else { FAIL("should fail"); }

    TEST("import_private_key_pem(NULL pem)");
    len = sizeof(sk);
    if (QUDO_MLDSA_import_private_key_pem(NULL, sk, &len) != QUDO_MLDSA_SUCCESS) { PASS(); } else { FAIL("should fail"); }
}

static void test_buffer_too_small(void) {
    QUDO_MLDSA *sig = QUDO_MLDSA_new("ML-DSA-44");
    if (!sig) return;
    uint8_t pk[ML_DSA_44_PUBLIC_KEY_BYTES], sk[ML_DSA_44_SECRET_KEY_BYTES];
    QUDO_MLDSA_keypair(sig, pk, sk);

    TEST("export_public_key_der() buffer too small");
    uint8_t tiny[4];
    size_t tiny_len = sizeof(tiny);
    QUDO_MLDSA_status_t rc = QUDO_MLDSA_export_public_key_der(pk, sizeof(pk), tiny, &tiny_len);
    if (rc != QUDO_MLDSA_SUCCESS) { PASS(); } else { FAIL("should fail"); }

    TEST("export_private_key_der() buffer too small");
    tiny_len = sizeof(tiny);
    rc = QUDO_MLDSA_export_private_key_der(sk, sizeof(sk), tiny, &tiny_len);
    if (rc != QUDO_MLDSA_SUCCESS) { PASS(); } else { FAIL("should fail"); }

    TEST("export_public_key_pem() buffer too small");
    char tiny_pem[4];
    size_t tiny_pem_len = sizeof(tiny_pem);
    rc = QUDO_MLDSA_export_public_key_pem(pk, sizeof(pk), tiny_pem, &tiny_pem_len);
    if (rc != QUDO_MLDSA_SUCCESS) { PASS(); } else { FAIL("should fail"); }

    TEST("export_private_key_pem() buffer too small");
    tiny_pem_len = sizeof(tiny_pem);
    rc = QUDO_MLDSA_export_private_key_pem(sk, sizeof(sk), tiny_pem, &tiny_pem_len);
    if (rc != QUDO_MLDSA_SUCCESS) { PASS(); } else { FAIL("should fail"); }

    QUDO_MLDSA_free(sig);
}

int main(void) {
    printf("=== QUDO ML-DSA DER/PEM Interop Tests ===\n\n");

    printf("[Public Key DER]\n");
    test_public_key_der();

    printf("\n[Public Key PEM]\n");
    test_public_key_pem();

    printf("\n[Private Key DER]\n");
    test_private_key_der();

    printf("\n[Private Key PEM]\n");
    test_private_key_pem();

    printf("\n[PKCS#8 Formats]\n");
    test_pkcs8_formats();

    printf("\n[NULL Arg Tests]\n");
    test_null_args();

    printf("\n[Buffer Too Small]\n");
    test_buffer_too_small();

    printf("\n=== Results: %d/%d tests passed ===\n", tests_passed, tests_run);
    return (tests_passed == tests_run) ? 0 : 1;
}
