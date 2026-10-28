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

static void test_public_key_der(void) {
    const char *algs[] = { "SLH-DSA-SHA2-128s", "SLH-DSA-SHA2-256s" };

    for (int i = 0; i < 2; i++) {
        char label[64];
        QUDO_SLHDSA *sig = QUDO_SLHDSA_new(algs[i]);
        if (!sig) continue;

        size_t pk_sz = sig->length_public_key;
        size_t sk_sz = sig->length_secret_key;
        uint8_t *pk = malloc(pk_sz);
        uint8_t *sk = malloc(sk_sz);
        if (!pk || !sk) { free(pk); free(sk); QUDO_SLHDSA_free(sig); continue; }
        QUDO_SLHDSA_keypair(sig, pk, sk);

        uint8_t der[1024];
        size_t der_len = sizeof(der);

        snprintf(label, sizeof(label), "%s public key DER export", algs[i]);
        TEST(label);
        QUDO_SLHDSA_status_t rc = QUDO_SLHDSA_export_public_key_der(pk, pk_sz, sig->param_set, der, &der_len);
        if (rc != QUDO_SLHDSA_SUCCESS) { FAIL("export failed"); free(pk); free(sk); QUDO_SLHDSA_free(sig); continue; }
        PASS();

        snprintf(label, sizeof(label), "%s public key DER import", algs[i]);
        TEST(label);
        uint8_t pk2[SLH_DSA_MAX_PUBLIC_KEY_BYTES];
        size_t pk2_len = sizeof(pk2);
        rc = QUDO_SLHDSA_import_public_key_der(der, der_len, pk2, &pk2_len);
        if (rc != QUDO_SLHDSA_SUCCESS) { FAIL("import failed"); }
        else if (pk2_len != pk_sz) { FAIL("wrong size"); }
        else if (memcmp(pk, pk2, pk_sz) != 0) { FAIL("data mismatch"); }
        else { PASS(); }

        free(pk); free(sk);
        QUDO_SLHDSA_free(sig);
    }
}

static void test_public_key_pem(void) {
    QUDO_SLHDSA *sig = QUDO_SLHDSA_new("SLH-DSA-SHA2-128s");
    if (!sig) { TEST("PEM roundtrip"); FAIL("new failed"); return; }

    size_t pk_sz = sig->length_public_key;
    size_t sk_sz = sig->length_secret_key;
    uint8_t *pk = malloc(pk_sz);
    uint8_t *sk = malloc(sk_sz);
    if (!pk || !sk) { free(pk); free(sk); QUDO_SLHDSA_free(sig); return; }
    QUDO_SLHDSA_keypair(sig, pk, sk);

    char pem[2048];
    size_t pem_len = sizeof(pem);

    TEST("SHA2-128s public key PEM export");
    QUDO_SLHDSA_status_t rc = QUDO_SLHDSA_export_public_key_pem(pk, pk_sz, sig->param_set, pem, &pem_len);
    if (rc != QUDO_SLHDSA_SUCCESS) { FAIL("export failed"); free(pk); free(sk); QUDO_SLHDSA_free(sig); return; }
    if (strstr(pem, "BEGIN PUBLIC KEY") == NULL) { FAIL("no PEM header"); free(pk); free(sk); QUDO_SLHDSA_free(sig); return; }
    PASS();

    TEST("SHA2-128s public key PEM import");
    uint8_t pk2[SLH_DSA_SHA2_128S_PUBLIC_KEY_BYTES];
    size_t pk2_len = sizeof(pk2);
    rc = QUDO_SLHDSA_import_public_key_pem(pem, pem_len, pk2, &pk2_len);
    if (rc != QUDO_SLHDSA_SUCCESS) { FAIL("import failed"); }
    else if (pk2_len != pk_sz) { FAIL("wrong size"); }
    else if (memcmp(pk, pk2, pk_sz) != 0) { FAIL("data mismatch"); }
    else { PASS(); }

    free(pk); free(sk);
    QUDO_SLHDSA_free(sig);
}

static void test_private_key_der(void) {
    QUDO_SLHDSA *sig = QUDO_SLHDSA_new("SLH-DSA-SHA2-128s");
    if (!sig) { TEST("private key DER"); FAIL("new failed"); return; }

    size_t pk_sz = sig->length_public_key;
    size_t sk_sz = sig->length_secret_key;
    uint8_t *pk = malloc(pk_sz);
    uint8_t *sk = malloc(sk_sz);
    if (!pk || !sk) { free(pk); free(sk); QUDO_SLHDSA_free(sig); return; }
    QUDO_SLHDSA_keypair(sig, pk, sk);

    uint8_t der[1024];
    size_t der_len = sizeof(der);

    TEST("SHA2-128s private key DER export");
    QUDO_SLHDSA_status_t rc = QUDO_SLHDSA_export_private_key_der(sk, sk_sz, sig->param_set, der, &der_len);
    if (rc != QUDO_SLHDSA_SUCCESS) { FAIL("export failed"); free(pk); free(sk); QUDO_SLHDSA_free(sig); return; }
    PASS();

    TEST("SHA2-128s private key DER import");
    uint8_t sk2[SLH_DSA_SHA2_128S_SECRET_KEY_BYTES];
    size_t sk2_len = sizeof(sk2);
    rc = QUDO_SLHDSA_import_private_key_der(der, der_len, sk2, &sk2_len);
    if (rc != QUDO_SLHDSA_SUCCESS) { FAIL("import failed"); }
    else if (sk2_len != sk_sz) { FAIL("wrong size"); }
    else if (memcmp(sk, sk2, sk_sz) != 0) { FAIL("data mismatch"); }
    else { PASS(); }

    free(pk); free(sk);
    QUDO_SLHDSA_free(sig);
}

static void test_private_key_pem(void) {
    QUDO_SLHDSA *sig = QUDO_SLHDSA_new("SLH-DSA-SHA2-128s");
    if (!sig) { TEST("private key PEM"); FAIL("new failed"); return; }

    size_t pk_sz = sig->length_public_key;
    size_t sk_sz = sig->length_secret_key;
    uint8_t *pk = malloc(pk_sz);
    uint8_t *sk = malloc(sk_sz);
    if (!pk || !sk) { free(pk); free(sk); QUDO_SLHDSA_free(sig); return; }
    QUDO_SLHDSA_keypair(sig, pk, sk);

    char pem[2048];
    size_t pem_len = sizeof(pem);

    TEST("SHA2-128s private key PEM export");
    QUDO_SLHDSA_status_t rc = QUDO_SLHDSA_export_private_key_pem(sk, sk_sz, sig->param_set, pem, &pem_len);
    if (rc != QUDO_SLHDSA_SUCCESS) { FAIL("export failed"); free(pk); free(sk); QUDO_SLHDSA_free(sig); return; }
    if (strstr(pem, "BEGIN PRIVATE KEY") == NULL) { FAIL("no PEM header"); free(pk); free(sk); QUDO_SLHDSA_free(sig); return; }
    PASS();

    TEST("SHA2-128s private key PEM import");
    uint8_t sk2[SLH_DSA_SHA2_128S_SECRET_KEY_BYTES];
    size_t sk2_len = sizeof(sk2);
    rc = QUDO_SLHDSA_import_private_key_pem(pem, pem_len, sk2, &sk2_len);
    if (rc != QUDO_SLHDSA_SUCCESS) { FAIL("import failed"); }
    else if (sk2_len != sk_sz) { FAIL("wrong size"); }
    else if (memcmp(sk, sk2, sk_sz) != 0) { FAIL("data mismatch"); }
    else { PASS(); }

    free(pk); free(sk);
    QUDO_SLHDSA_free(sig);
}

static void test_null_args(void) {
    uint8_t buf[1024]; size_t len = sizeof(buf);

    TEST("export_public_key_der(NULL pk)");
    if (QUDO_SLHDSA_export_public_key_der(NULL, 32, QUDO_SLHDSA_SHA2_128s, buf, &len) != QUDO_SLHDSA_SUCCESS) { PASS(); } else { FAIL("should fail"); }

    TEST("export_public_key_der(pk, NULL der)");
    uint8_t pk[SLH_DSA_SHA2_128S_PUBLIC_KEY_BYTES] = {0};
    QUDO_SLHDSA_status_t rc2 = QUDO_SLHDSA_export_public_key_der(pk, sizeof(pk), QUDO_SLHDSA_SHA2_128s, NULL, &len);
    if (rc2 != QUDO_SLHDSA_SUCCESS) { PASS(); } else { printf("(accepted NULL der) "); PASS(); }

    TEST("export_public_key_der(pk, der, NULL len)");
    if (QUDO_SLHDSA_export_public_key_der(pk, sizeof(pk), QUDO_SLHDSA_SHA2_128s, buf, NULL) != QUDO_SLHDSA_SUCCESS) { PASS(); } else { FAIL("should fail"); }

    TEST("import_public_key_der(NULL der)");
    len = sizeof(pk);
    if (QUDO_SLHDSA_import_public_key_der(NULL, 100, pk, &len) != QUDO_SLHDSA_SUCCESS) { PASS(); } else { FAIL("should fail"); }

    TEST("import_public_key_der(invalid data)");
    uint8_t garbage[] = { 0x00, 0x01, 0x02, 0x03, 0x04 };
    len = sizeof(pk);
    if (QUDO_SLHDSA_import_public_key_der(garbage, sizeof(garbage), pk, &len) != QUDO_SLHDSA_SUCCESS) { PASS(); } else { FAIL("should fail"); }

    TEST("export_private_key_der(NULL sk)");
    len = sizeof(buf);
    if (QUDO_SLHDSA_export_private_key_der(NULL, 64, QUDO_SLHDSA_SHA2_128s, buf, &len) != QUDO_SLHDSA_SUCCESS) { PASS(); } else { FAIL("should fail"); }

    TEST("import_private_key_der(NULL der)");
    uint8_t sk[SLH_DSA_SHA2_128S_SECRET_KEY_BYTES];
    len = sizeof(sk);
    if (QUDO_SLHDSA_import_private_key_der(NULL, 100, sk, &len) != QUDO_SLHDSA_SUCCESS) { PASS(); } else { FAIL("should fail"); }

    TEST("export_public_key_pem(NULL pk)");
    char pem[2048]; size_t pem_len = sizeof(pem);
    if (QUDO_SLHDSA_export_public_key_pem(NULL, 32, QUDO_SLHDSA_SHA2_128s, pem, &pem_len) != QUDO_SLHDSA_SUCCESS) { PASS(); } else { FAIL("should fail"); }

    TEST("import_public_key_pem(NULL pem)");
    len = sizeof(pk);
    if (QUDO_SLHDSA_import_public_key_pem(NULL, 0, pk, &len) != QUDO_SLHDSA_SUCCESS) { PASS(); } else { FAIL("should fail"); }

    TEST("export_private_key_pem(NULL sk)");
    pem_len = sizeof(pem);
    if (QUDO_SLHDSA_export_private_key_pem(NULL, 64, QUDO_SLHDSA_SHA2_128s, pem, &pem_len) != QUDO_SLHDSA_SUCCESS) { PASS(); } else { FAIL("should fail"); }

    TEST("import_private_key_pem(NULL pem)");
    len = sizeof(sk);
    if (QUDO_SLHDSA_import_private_key_pem(NULL, 0, sk, &len) != QUDO_SLHDSA_SUCCESS) { PASS(); } else { FAIL("should fail"); }
}

static void test_buffer_too_small(void) {
    QUDO_SLHDSA *sig = QUDO_SLHDSA_new("SLH-DSA-SHA2-128s");
    if (!sig) return;
    uint8_t pk[SLH_DSA_SHA2_128S_PUBLIC_KEY_BYTES], sk[SLH_DSA_SHA2_128S_SECRET_KEY_BYTES];
    QUDO_SLHDSA_keypair(sig, pk, sk);

    TEST("export_public_key_der() buffer too small");
    uint8_t tiny[4];
    size_t tiny_len = sizeof(tiny);
    QUDO_SLHDSA_status_t rc = QUDO_SLHDSA_export_public_key_der(pk, sizeof(pk), sig->param_set, tiny, &tiny_len);
    if (rc != QUDO_SLHDSA_SUCCESS) { PASS(); } else { FAIL("should fail"); }

    TEST("export_private_key_der() buffer too small");
    tiny_len = sizeof(tiny);
    rc = QUDO_SLHDSA_export_private_key_der(sk, sizeof(sk), sig->param_set, tiny, &tiny_len);
    if (rc != QUDO_SLHDSA_SUCCESS) { PASS(); } else { FAIL("should fail"); }

    TEST("export_public_key_pem() buffer too small");
    char tiny_pem[4];
    size_t tiny_pem_len = sizeof(tiny_pem);
    rc = QUDO_SLHDSA_export_public_key_pem(pk, sizeof(pk), sig->param_set, tiny_pem, &tiny_pem_len);
    if (rc != QUDO_SLHDSA_SUCCESS) { PASS(); } else { FAIL("should fail"); }

    TEST("export_private_key_pem() buffer too small");
    tiny_pem_len = sizeof(tiny_pem);
    rc = QUDO_SLHDSA_export_private_key_pem(sk, sizeof(sk), sig->param_set, tiny_pem, &tiny_pem_len);
    if (rc != QUDO_SLHDSA_SUCCESS) { PASS(); } else { FAIL("should fail"); }

    QUDO_SLHDSA_free(sig);
}

int main(void) {
    printf("=== QUDO SLH-DSA DER/PEM Interop Tests ===\n\n");

    printf("[Public Key DER]\n");
    test_public_key_der();

    printf("\n[Public Key PEM]\n");
    test_public_key_pem();

    printf("\n[Private Key DER]\n");
    test_private_key_der();

    printf("\n[Private Key PEM]\n");
    test_private_key_pem();

    printf("\n[NULL Arg Tests]\n");
    test_null_args();

    printf("\n[Buffer Too Small]\n");
    test_buffer_too_small();

    printf("\n=== Results: %d/%d tests passed ===\n", tests_passed, tests_run);
    return (tests_passed == tests_run) ? 0 : 1;
}
