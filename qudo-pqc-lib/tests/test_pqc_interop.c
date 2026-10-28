/* SPDX-License-Identifier: Apache-2.0 AND MIT */

#include "mldsa_wrapper.h"
#include "mlkem_wrapper.h"
#include "qudo_pqc.h"
#include "slhdsa_wrapper.h"
#include "test_fips_init.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int g_pass = 0;
static int g_fail = 0;

#define CHECK(expr, label)                          \
    do {                                            \
        if (expr) {                                 \
            g_pass++;                               \
        } else {                                    \
            g_fail++;                               \
            fprintf(stderr, "  FAIL: %s\n", label); \
        }                                           \
    } while (0)

/* PEM and some DER paths are NOT_IMPL stubs in builds without OpenSSL;
 * the round-trip step is skipped in that case. */
#define IS_OK_OR_NOTIMPL(rc, NOT_IMPL_VAL, SUCCESS_VAL) \
    ((rc) == (SUCCESS_VAL) || (rc) == (NOT_IMPL_VAL))

#define DER_BUF_SZ 16384
#define PEM_BUF_SZ 32768

static void test_slhdsa_one(const char *alg, QUDO_SLHDSA_parameter_set_t ps)
{
    QUDO_SLHDSA *sig = QUDO_SLHDSA_new(alg);
    if (!sig) {
        g_fail++;
        fprintf(stderr, "  FAIL: SLHDSA_new(%s)\n", alg);
        return;
    }

    uint8_t *pk = (uint8_t *)malloc(sig->length_public_key);
    uint8_t *sk = (uint8_t *)malloc(sig->length_secret_key);
    uint8_t *pk2 = (uint8_t *)malloc(sig->length_public_key);
    uint8_t *sk2 = (uint8_t *)malloc(sig->length_secret_key);
    uint8_t *der = (uint8_t *)malloc(DER_BUF_SZ);
    char *pem = (char *)malloc(PEM_BUF_SZ);

    if (!pk || !sk || !pk2 || !sk2 || !der || !pem)
        goto cleanup;

    CHECK(QUDO_SLHDSA_keypair(sig, pk, sk) == QUDO_SLHDSA_SUCCESS, "keypair");

    size_t der_len, pk2_len, sk2_len, pem_len;

    der_len = DER_BUF_SZ;
    CHECK(QUDO_SLHDSA_export_public_key_der(pk, sig->length_public_key, ps, der,
                                            &der_len)
              == QUDO_SLHDSA_SUCCESS,
          "export_public_key_der");
    pk2_len = sig->length_public_key;
    CHECK(QUDO_SLHDSA_import_public_key_der(der, der_len, pk2, &pk2_len)
              == QUDO_SLHDSA_SUCCESS,
          "import_public_key_der");
    CHECK(pk2_len == sig->length_public_key && memcmp(pk, pk2, pk2_len) == 0,
          "public_key_der_roundtrip");

    der_len = DER_BUF_SZ;
    CHECK(QUDO_SLHDSA_export_private_key_der(sk, sig->length_secret_key, ps,
                                             der, &der_len)
              == QUDO_SLHDSA_SUCCESS,
          "export_private_key_der");
    sk2_len = sig->length_secret_key;
    CHECK(QUDO_SLHDSA_import_private_key_der(der, der_len, sk2, &sk2_len)
              == QUDO_SLHDSA_SUCCESS,
          "import_private_key_der");
    CHECK(sk2_len == sig->length_secret_key && memcmp(sk, sk2, sk2_len) == 0,
          "private_key_der_roundtrip");

    pem_len = PEM_BUF_SZ;
    CHECK(QUDO_SLHDSA_export_public_key_pem(pk, sig->length_public_key, ps, pem,
                                            &pem_len)
              == QUDO_SLHDSA_SUCCESS,
          "export_public_key_pem");
    pk2_len = sig->length_public_key;
    CHECK(QUDO_SLHDSA_import_public_key_pem(pem, pem_len, pk2, &pk2_len)
              == QUDO_SLHDSA_SUCCESS,
          "import_public_key_pem");
    CHECK(pk2_len == sig->length_public_key && memcmp(pk, pk2, pk2_len) == 0,
          "public_key_pem_roundtrip");

    pem_len = PEM_BUF_SZ;
    CHECK(QUDO_SLHDSA_export_private_key_pem(sk, sig->length_secret_key, ps,
                                             pem, &pem_len)
              == QUDO_SLHDSA_SUCCESS,
          "export_private_key_pem");
    sk2_len = sig->length_secret_key;
    CHECK(QUDO_SLHDSA_import_private_key_pem(pem, pem_len, sk2, &sk2_len)
              == QUDO_SLHDSA_SUCCESS,
          "import_private_key_pem");
    CHECK(sk2_len == sig->length_secret_key && memcmp(sk, sk2, sk2_len) == 0,
          "private_key_pem_roundtrip");

    uint8_t tiny[4];
    size_t tiny_len = sizeof(tiny);
    CHECK(QUDO_SLHDSA_export_public_key_der(pk, sig->length_public_key, ps,
                                            tiny, &tiny_len)
              != QUDO_SLHDSA_SUCCESS,
          "export_pub_der_tiny");
    tiny_len = sizeof(tiny);
    CHECK(QUDO_SLHDSA_export_private_key_der(sk, sig->length_secret_key, ps,
                                             tiny, &tiny_len)
              != QUDO_SLHDSA_SUCCESS,
          "export_priv_der_tiny");
    char tiny_pem[4];
    size_t tiny_pem_len = sizeof(tiny_pem);
    CHECK(QUDO_SLHDSA_export_public_key_pem(pk, sig->length_public_key, ps,
                                            tiny_pem, &tiny_pem_len)
              != QUDO_SLHDSA_SUCCESS,
          "export_pub_pem_tiny");
    tiny_pem_len = sizeof(tiny_pem);
    CHECK(QUDO_SLHDSA_export_private_key_pem(sk, sig->length_secret_key, ps,
                                             tiny_pem, &tiny_pem_len)
              != QUDO_SLHDSA_SUCCESS,
          "export_priv_pem_tiny");

cleanup:
    free(pk);
    free(sk);
    free(pk2);
    free(sk2);
    free(der);
    free(pem);
    QUDO_SLHDSA_free(sig);
}

static void test_slhdsa_null_args(void)
{
    uint8_t buf[256];
    size_t len = sizeof(buf);
    uint8_t pk[64] = {0}, sk[128] = {0};
    char pem[256];
    size_t pem_len = sizeof(pem);

    CHECK(QUDO_SLHDSA_export_public_key_der(NULL, 32, QUDO_SLHDSA_SHA2_128s,
                                            buf, &len)
              != QUDO_SLHDSA_SUCCESS,
          "exp_pub_der NULL pk");
    CHECK(QUDO_SLHDSA_export_public_key_der(pk, sizeof(pk),
                                            QUDO_SLHDSA_SHA2_128s, buf, NULL)
              != QUDO_SLHDSA_SUCCESS,
          "exp_pub_der NULL len");
    len = sizeof(buf);
    CHECK(QUDO_SLHDSA_import_public_key_der(NULL, 100, pk, &len)
              != QUDO_SLHDSA_SUCCESS,
          "imp_pub_der NULL der");
    uint8_t garbage[8] = {0, 1, 2, 3, 4, 5, 6, 7};
    len = sizeof(pk);
    CHECK(QUDO_SLHDSA_import_public_key_der(garbage, sizeof(garbage), pk, &len)
              != QUDO_SLHDSA_SUCCESS,
          "imp_pub_der garbage");
    len = sizeof(buf);
    CHECK(QUDO_SLHDSA_export_private_key_der(NULL, 64, QUDO_SLHDSA_SHA2_128s,
                                             buf, &len)
              != QUDO_SLHDSA_SUCCESS,
          "exp_priv_der NULL sk");
    len = sizeof(sk);
    CHECK(QUDO_SLHDSA_import_private_key_der(NULL, 100, sk, &len)
              != QUDO_SLHDSA_SUCCESS,
          "imp_priv_der NULL der");
    pem_len = sizeof(pem);
    CHECK(QUDO_SLHDSA_export_public_key_pem(NULL, 32, QUDO_SLHDSA_SHA2_128s,
                                            pem, &pem_len)
              != QUDO_SLHDSA_SUCCESS,
          "exp_pub_pem NULL pk");
    len = sizeof(pk);
    CHECK(QUDO_SLHDSA_import_public_key_pem(NULL, 0, pk, &len)
              != QUDO_SLHDSA_SUCCESS,
          "imp_pub_pem NULL pem");
    pem_len = sizeof(pem);
    CHECK(QUDO_SLHDSA_export_private_key_pem(NULL, 64, QUDO_SLHDSA_SHA2_128s,
                                             pem, &pem_len)
              != QUDO_SLHDSA_SUCCESS,
          "exp_priv_pem NULL sk");
    len = sizeof(sk);
    CHECK(QUDO_SLHDSA_import_private_key_pem(NULL, 0, sk, &len)
              != QUDO_SLHDSA_SUCCESS,
          "imp_priv_pem NULL pem");
}

static void test_mldsa_one(const char *alg)
{
    QUDO_MLDSA *sig = QUDO_MLDSA_new(alg);
    if (!sig) {
        g_fail++;
        fprintf(stderr, "  FAIL: MLDSA_new(%s)\n", alg);
        return;
    }

    uint8_t *pk = (uint8_t *)malloc(sig->length_public_key);
    uint8_t *sk = (uint8_t *)malloc(sig->length_secret_key);
    uint8_t *pk2 = (uint8_t *)malloc(sig->length_public_key);
    uint8_t *sk2 = (uint8_t *)malloc(sig->length_secret_key);
    uint8_t *der = (uint8_t *)malloc(DER_BUF_SZ);
    char *pem = (char *)malloc(PEM_BUF_SZ);

    if (!pk || !sk || !pk2 || !sk2 || !der || !pem)
        goto cleanup;

    CHECK(QUDO_MLDSA_keypair(sig, pk, sk) == QUDO_MLDSA_SUCCESS,
          "MLDSA keypair");

    size_t der_len = DER_BUF_SZ, pk2_len, sk2_len, pem_len = PEM_BUF_SZ;

    CHECK(QUDO_MLDSA_export_public_key_der(pk, sig->length_public_key, der,
                                           &der_len)
              == QUDO_MLDSA_SUCCESS,
          "MLDSA exp_pub_der");
    pk2_len = sig->length_public_key;
    CHECK(QUDO_MLDSA_import_public_key_der(der, der_len, pk2, &pk2_len)
              == QUDO_MLDSA_SUCCESS,
          "MLDSA imp_pub_der");
    CHECK(pk2_len == sig->length_public_key && memcmp(pk, pk2, pk2_len) == 0,
          "MLDSA pub_der_roundtrip");

    der_len = DER_BUF_SZ;
    CHECK(QUDO_MLDSA_export_private_key_der(sk, sig->length_secret_key, der,
                                            &der_len)
              == QUDO_MLDSA_SUCCESS,
          "MLDSA exp_priv_der");
    sk2_len = sig->length_secret_key;
    CHECK(QUDO_MLDSA_import_private_key_der(der, der_len, sk2, &sk2_len)
              == QUDO_MLDSA_SUCCESS,
          "MLDSA imp_priv_der");
    CHECK(sk2_len == sig->length_secret_key && memcmp(sk, sk2, sk2_len) == 0,
          "MLDSA priv_der_roundtrip");

    pem_len = PEM_BUF_SZ;
    CHECK(QUDO_MLDSA_export_public_key_pem(pk, sig->length_public_key, pem,
                                           &pem_len)
              == QUDO_MLDSA_SUCCESS,
          "MLDSA exp_pub_pem");
    pk2_len = sig->length_public_key;
    CHECK(QUDO_MLDSA_import_public_key_pem(pem, pk2, &pk2_len)
              == QUDO_MLDSA_SUCCESS,
          "MLDSA imp_pub_pem");
    CHECK(pk2_len == sig->length_public_key && memcmp(pk, pk2, pk2_len) == 0,
          "MLDSA pub_pem_roundtrip");

    pem_len = PEM_BUF_SZ;
    CHECK(QUDO_MLDSA_export_private_key_pem(sk, sig->length_secret_key, pem,
                                            &pem_len)
              == QUDO_MLDSA_SUCCESS,
          "MLDSA exp_priv_pem");
    sk2_len = sig->length_secret_key;
    CHECK(QUDO_MLDSA_import_private_key_pem(pem, sk2, &sk2_len)
              == QUDO_MLDSA_SUCCESS,
          "MLDSA imp_priv_pem");
    CHECK(sk2_len == sig->length_secret_key && memcmp(sk, sk2, sk2_len) == 0,
          "MLDSA priv_pem_roundtrip");

    uint8_t tiny[4];
    size_t tiny_len = sizeof(tiny);
    CHECK(QUDO_MLDSA_export_public_key_der(pk, sig->length_public_key, tiny,
                                           &tiny_len)
              != QUDO_MLDSA_SUCCESS,
          "MLDSA exp_pub_der tiny");
    tiny_len = sizeof(tiny);
    CHECK(QUDO_MLDSA_export_private_key_der(sk, sig->length_secret_key, tiny,
                                            &tiny_len)
              != QUDO_MLDSA_SUCCESS,
          "MLDSA exp_priv_der tiny");

cleanup:
    free(pk);
    free(sk);
    free(pk2);
    free(sk2);
    free(der);
    free(pem);
    QUDO_MLDSA_free(sig);
}

static void test_mldsa_null_args(void)
{
    uint8_t buf[8192];
    size_t len = sizeof(buf);
    uint8_t pk[1312] = {0}, sk[2560] = {0};
    char pem[16384];
    size_t pem_len = sizeof(pem);

    CHECK(QUDO_MLDSA_export_public_key_der(NULL, 1312, buf, &len)
              != QUDO_MLDSA_SUCCESS,
          "MLDSA exp_pub_der NULL");
    len = sizeof(buf);
    CHECK(QUDO_MLDSA_import_public_key_der(NULL, 100, pk, &len)
              != QUDO_MLDSA_SUCCESS,
          "MLDSA imp_pub_der NULL");
    uint8_t garbage[8] = {0, 1, 2, 3, 4, 5, 6, 7};
    len = sizeof(pk);
    CHECK(QUDO_MLDSA_import_public_key_der(garbage, sizeof(garbage), pk, &len)
              != QUDO_MLDSA_SUCCESS,
          "MLDSA imp_pub_der garbage");
    len = sizeof(buf);
    CHECK(QUDO_MLDSA_export_private_key_der(NULL, 2560, buf, &len)
              != QUDO_MLDSA_SUCCESS,
          "MLDSA exp_priv_der NULL");
    pem_len = sizeof(pem);
    CHECK(QUDO_MLDSA_export_public_key_pem(NULL, 1312, pem, &pem_len)
              != QUDO_MLDSA_SUCCESS,
          "MLDSA exp_pub_pem NULL");
    len = sizeof(pk);
    CHECK(QUDO_MLDSA_import_public_key_pem(NULL, pk, &len)
              != QUDO_MLDSA_SUCCESS,
          "MLDSA imp_pub_pem NULL");
    pem_len = sizeof(pem);
    CHECK(QUDO_MLDSA_export_private_key_pem(NULL, 2560, pem, &pem_len)
              != QUDO_MLDSA_SUCCESS,
          "MLDSA exp_priv_pem NULL");
}

static void test_mlkem_one(const char *alg)
{
    QUDO_KEM *kem = QUDO_KEM_new(alg);
    if (!kem) {
        g_fail++;
        fprintf(stderr, "  FAIL: KEM_new(%s)\n", alg);
        return;
    }

    uint8_t *pk = (uint8_t *)malloc(kem->length_public_key);
    uint8_t *sk = (uint8_t *)malloc(kem->length_secret_key);
    uint8_t *pk2 = (uint8_t *)malloc(kem->length_public_key);
    uint8_t *der = (uint8_t *)malloc(DER_BUF_SZ);
    char *pem = (char *)malloc(PEM_BUF_SZ);

    if (!pk || !sk || !pk2 || !der || !pem)
        goto cleanup;

    CHECK(QUDO_KEM_keypair(kem, pk, sk) == QUDO_KEM_SUCCESS, "KEM keypair");

    size_t der_len = DER_BUF_SZ, pk2_len = kem->length_public_key,
           pem_len = PEM_BUF_SZ;
    CHECK(QUDO_KEM_export_public_key_der(pk, kem->length_public_key, der,
                                         &der_len)
              == QUDO_KEM_SUCCESS,
          "KEM exp_pub_der");
    CHECK(QUDO_KEM_import_public_key_der(der, der_len, pk2, &pk2_len)
              == QUDO_KEM_SUCCESS,
          "KEM imp_pub_der");
    CHECK(pk2_len == kem->length_public_key && memcmp(pk, pk2, pk2_len) == 0,
          "KEM pub_der_roundtrip");

    pem_len = PEM_BUF_SZ;
    CHECK(QUDO_KEM_export_public_key_pem(pk, kem->length_public_key, pem,
                                         &pem_len)
              == QUDO_KEM_SUCCESS,
          "KEM exp_pub_pem");
    pk2_len = kem->length_public_key;
    CHECK(QUDO_KEM_import_public_key_pem(pem, pk2, &pk2_len)
              == QUDO_KEM_SUCCESS,
          "KEM imp_pub_pem");
    CHECK(pk2_len == kem->length_public_key && memcmp(pk, pk2, pk2_len) == 0,
          "KEM pub_pem_roundtrip");

    uint8_t tiny[4];
    size_t tiny_len = sizeof(tiny);
    CHECK(QUDO_KEM_export_public_key_der(pk, kem->length_public_key, tiny,
                                         &tiny_len)
              != QUDO_KEM_SUCCESS,
          "KEM exp_pub_der tiny");

cleanup:
    free(pk);
    free(sk);
    free(pk2);
    free(der);
    free(pem);
    QUDO_KEM_free(kem);
}

int main(int argc, char **argv)
{
    test_fips_init_set_args(&argc, argv);
    if (test_fips_init() != 1) {
        fprintf(stderr, "FIPS init failed\n");
        return 1;
    }

    static const char *slhdsa_algs[]
        = {"SLH-DSA-SHA2-128s",  "SLH-DSA-SHA2-128f",  "SLH-DSA-SHA2-192s",
           "SLH-DSA-SHA2-192f",  "SLH-DSA-SHA2-256s",  "SLH-DSA-SHA2-256f",
           "SLH-DSA-SHAKE-128s", "SLH-DSA-SHAKE-128f", "SLH-DSA-SHAKE-192s",
           "SLH-DSA-SHAKE-192f", "SLH-DSA-SHAKE-256s", "SLH-DSA-SHAKE-256f"};
    static const QUDO_SLHDSA_parameter_set_t slhdsa_ps[] = {
        QUDO_SLHDSA_SHA2_128s,  QUDO_SLHDSA_SHA2_128f,  QUDO_SLHDSA_SHA2_192s,
        QUDO_SLHDSA_SHA2_192f,  QUDO_SLHDSA_SHA2_256s,  QUDO_SLHDSA_SHA2_256f,
        QUDO_SLHDSA_SHAKE_128s, QUDO_SLHDSA_SHAKE_128f, QUDO_SLHDSA_SHAKE_192s,
        QUDO_SLHDSA_SHAKE_192f, QUDO_SLHDSA_SHAKE_256s, QUDO_SLHDSA_SHAKE_256f};
    for (size_t i = 0; i < sizeof(slhdsa_algs) / sizeof(slhdsa_algs[0]); i++) {
        fprintf(stderr, "[%s]\n", slhdsa_algs[i]);
        test_slhdsa_one(slhdsa_algs[i], slhdsa_ps[i]);
    }
    fprintf(stderr, "[SLH-DSA NULL args]\n");
    test_slhdsa_null_args();

    static const char *mldsa_algs[] = {"ML-DSA-44", "ML-DSA-65", "ML-DSA-87"};
    for (size_t i = 0; i < 3; i++) {
        fprintf(stderr, "[%s]\n", mldsa_algs[i]);
        test_mldsa_one(mldsa_algs[i]);
    }
    fprintf(stderr, "[ML-DSA NULL args]\n");
    test_mldsa_null_args();

    static const char *mlkem_algs[]
        = {"ML-KEM-512", "ML-KEM-768", "ML-KEM-1024"};
    for (size_t i = 0; i < 3; i++) {
        fprintf(stderr, "[%s]\n", mlkem_algs[i]);
        test_mlkem_one(mlkem_algs[i]);
    }

    qudo_pqc_fini();

    fprintf(stderr, "\n=== Interop: %d pass, %d fail ===\n", g_pass, g_fail);
    return g_fail == 0 ? 0 : 1;
}
