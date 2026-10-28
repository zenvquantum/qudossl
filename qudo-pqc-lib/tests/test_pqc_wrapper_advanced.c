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

#define CHECK(cond, label)                          \
    do {                                            \
        if (cond) {                                 \
            g_pass++;                               \
        } else {                                    \
            g_fail++;                               \
            fprintf(stderr, "  FAIL: %s\n", label); \
        }                                           \
    } while (0)

static void test_init_cleanup_is_initialized(void)
{
    QUDO_MLDSA_init();
    QUDO_KEM_init();
    QUDO_SLHDSA_init();

    CHECK(QUDO_MLDSA_is_initialized() == 1,
          "MLDSA is_initialized after explicit init");
    CHECK(QUDO_KEM_is_initialized() == 1, "KEM is_initialized");
    CHECK(QUDO_SLHDSA_is_initialized() == 1, "SLHDSA is_initialized");

    QUDO_MLDSA_cleanup();
    CHECK(QUDO_MLDSA_is_initialized() == 0,
          "MLDSA not initialized after cleanup");
    QUDO_KEM_cleanup();
    CHECK(QUDO_KEM_is_initialized() == 0, "KEM not initialized after cleanup");
    QUDO_SLHDSA_cleanup();
    CHECK(QUDO_SLHDSA_is_initialized() == 0,
          "SLHDSA not initialized after cleanup");

    CHECK(QUDO_MLDSA_init() == QUDO_MLDSA_SUCCESS, "MLDSA re-init");
    CHECK(QUDO_KEM_init() == QUDO_KEM_SUCCESS, "KEM re-init");
    CHECK(QUDO_SLHDSA_init() == QUDO_SLHDSA_SUCCESS, "SLHDSA re-init");

    CHECK(QUDO_MLDSA_is_initialized() == 1, "MLDSA re-initialized");
    CHECK(QUDO_KEM_is_initialized() == 1, "KEM re-initialized");
    CHECK(QUDO_SLHDSA_is_initialized() == 1, "SLHDSA re-initialized");
}

static void test_mldsa_advanced(const char *alg)
{
    QUDO_MLDSA *sig = QUDO_MLDSA_new(alg);
    if (!sig) {
        g_fail++;
        fprintf(stderr, "  FAIL: MLDSA_new(%s)\n", alg);
        return;
    }

    uint8_t *pk = (uint8_t *)malloc(sig->length_public_key);
    uint8_t *sk = (uint8_t *)malloc(sig->length_secret_key);
    uint8_t *signature = (uint8_t *)malloc(sig->length_signature);
    uint8_t seed[MLDSA_SEEDBYTES] = {0x42};
    uint8_t rnd[MLDSA_RNDBYTES] = {0x77};
    uint8_t mu[MLDSA_CRHBYTES];
    memset(mu, 0xAB, sizeof(mu));
    const uint8_t msg[] = "test message";
    size_t msg_len = sizeof(msg) - 1;
    const uint8_t ctx[] = "context";
    size_t ctx_len = sizeof(ctx) - 1;

    if (!pk || !sk || !signature)
        goto cleanup;

    CHECK(QUDO_MLDSA_keypair_internal(sig, pk, sk, seed) == QUDO_MLDSA_SUCCESS,
          "MLDSA keypair_internal");

    size_t sig_len = sig->length_signature;
    CHECK(QUDO_MLDSA_sign_with_context(sig, signature, &sig_len, msg, msg_len,
                                       ctx, ctx_len, sk)
              == QUDO_MLDSA_SUCCESS,
          "MLDSA sign_with_context");
    CHECK(QUDO_MLDSA_verify_with_context(sig, signature, sig_len, msg, msg_len,
                                         ctx, ctx_len, pk)
              == QUDO_MLDSA_SUCCESS,
          "MLDSA verify_with_context");

    sig_len = sig->length_signature;
    CHECK(QUDO_MLDSA_sign_internal(sig, signature, &sig_len, msg, msg_len, NULL,
                                   0, rnd, sk, 0)
              == QUDO_MLDSA_SUCCESS,
          "MLDSA sign_internal");
    CHECK(QUDO_MLDSA_verify_internal(sig, signature, sig_len, msg, msg_len,
                                     NULL, 0, pk, 0)
              == QUDO_MLDSA_SUCCESS,
          "MLDSA verify_internal");

    sig_len = sig->length_signature;
    QUDO_MLDSA_status_t emu
        = QUDO_MLDSA_sign_extmu(sig, signature, &sig_len, mu, sk);
    if (emu == QUDO_MLDSA_SUCCESS) {
        CHECK(QUDO_MLDSA_verify_extmu(sig, signature, sig_len, mu, pk)
                  == QUDO_MLDSA_SUCCESS,
              "MLDSA verify_extmu");
    } else {
        CHECK(0, "MLDSA sign_extmu");
    }

    size_t signed_len = sig_len + msg_len + 1024;
    uint8_t *signed_msg = (uint8_t *)malloc(signed_len);
    uint8_t *opened = (uint8_t *)malloc(signed_len);
    if (signed_msg && opened) {
        QUDO_MLDSA_status_t sc = QUDO_MLDSA_sign_concat(
            sig, signed_msg, &signed_len, msg, msg_len, ctx, ctx_len, sk);
        if (sc == QUDO_MLDSA_SUCCESS) {
            size_t opened_len = signed_len;
            CHECK(QUDO_MLDSA_open(sig, opened, &opened_len, signed_msg,
                                  signed_len, ctx, ctx_len, pk)
                      == QUDO_MLDSA_SUCCESS,
                  "MLDSA open");
        } else {
            CHECK(0, "MLDSA sign_concat");
        }
    }
    free(signed_msg);
    free(opened);

    sig_len = sig->length_signature;
    QUDO_MLDSA_status_t ph
        = QUDO_MLDSA_sign_pre_hash(sig, signature, &sig_len, msg, msg_len, ctx,
                                   ctx_len, rnd, sk, QUDO_PREHASH_SHA2_256);
    if (ph == QUDO_MLDSA_SUCCESS) {
        CHECK(QUDO_MLDSA_verify_pre_hash(sig, signature, sig_len, msg, msg_len,
                                         ctx, ctx_len, pk,
                                         QUDO_PREHASH_SHA2_256)
                  == QUDO_MLDSA_SUCCESS,
              "MLDSA verify_pre_hash");
    } else {
        CHECK(0, "MLDSA sign_pre_hash");
    }

cleanup:
    free(pk);
    free(sk);
    free(signature);
    QUDO_MLDSA_free(sig);
}

static void test_mldsa_perset_internal(void)
{
    uint8_t seed[MLDSA_SEEDBYTES] = {0x77};
    uint8_t rnd[MLDSA_RNDBYTES] = {0x11};
    uint8_t mu[MLDSA_CRHBYTES];
    memset(mu, 0x99, sizeof(mu));
    const uint8_t msg[] = "perset";
    size_t msg_len = sizeof(msg) - 1;

    {
        uint8_t pk[ML_DSA_44_PUBLIC_KEY_BYTES];
        uint8_t sk[ML_DSA_44_SECRET_KEY_BYTES];
        uint8_t s[ML_DSA_44_SIGNATURE_BYTES];
        size_t sl = sizeof(s);

        CHECK(QUDO_MLDSA_ML_DSA_44_keypair_internal(pk, sk, seed)
                  == QUDO_MLDSA_SUCCESS,
              "44 keypair_internal");
        CHECK(QUDO_MLDSA_ML_DSA_44_sign_internal(s, &sl, msg, msg_len, NULL, 0,
                                                 rnd, sk, 0)
                  == QUDO_MLDSA_SUCCESS,
              "44 sign_internal");
        CHECK(QUDO_MLDSA_ML_DSA_44_verify_internal(s, sl, msg, msg_len, NULL, 0,
                                                   pk, 0)
                  == QUDO_MLDSA_SUCCESS,
              "44 verify_internal");

        sl = sizeof(s);
        QUDO_MLDSA_status_t r = QUDO_MLDSA_ML_DSA_44_sign_extmu(s, &sl, mu, sk);
        if (r == QUDO_MLDSA_SUCCESS) {
            CHECK(QUDO_MLDSA_ML_DSA_44_verify_extmu(s, sl, mu, pk)
                      == QUDO_MLDSA_SUCCESS,
                  "44 verify_extmu");
        } else
            CHECK(0, "44 sign_extmu");
    }
    {
        uint8_t pk[ML_DSA_65_PUBLIC_KEY_BYTES];
        uint8_t sk[ML_DSA_65_SECRET_KEY_BYTES];
        uint8_t s[ML_DSA_65_SIGNATURE_BYTES];
        size_t sl = sizeof(s);
        CHECK(QUDO_MLDSA_ML_DSA_65_keypair_internal(pk, sk, seed)
                  == QUDO_MLDSA_SUCCESS,
              "65 keypair_internal");
        CHECK(QUDO_MLDSA_ML_DSA_65_sign_internal(s, &sl, msg, msg_len, NULL, 0,
                                                 rnd, sk, 0)
                  == QUDO_MLDSA_SUCCESS,
              "65 sign_internal");
        CHECK(QUDO_MLDSA_ML_DSA_65_verify_internal(s, sl, msg, msg_len, NULL, 0,
                                                   pk, 0)
                  == QUDO_MLDSA_SUCCESS,
              "65 verify_internal");
    }
    {
        uint8_t pk[ML_DSA_87_PUBLIC_KEY_BYTES];
        uint8_t sk[ML_DSA_87_SECRET_KEY_BYTES];
        uint8_t s[ML_DSA_87_SIGNATURE_BYTES];
        size_t sl = sizeof(s);
        CHECK(QUDO_MLDSA_ML_DSA_87_keypair_internal(pk, sk, seed)
                  == QUDO_MLDSA_SUCCESS,
              "87 keypair_internal");
        CHECK(QUDO_MLDSA_ML_DSA_87_sign_internal(s, &sl, msg, msg_len, NULL, 0,
                                                 rnd, sk, 0)
                  == QUDO_MLDSA_SUCCESS,
              "87 sign_internal");
        CHECK(QUDO_MLDSA_ML_DSA_87_verify_internal(s, sl, msg, msg_len, NULL, 0,
                                                   pk, 0)
                  == QUDO_MLDSA_SUCCESS,
              "87 verify_internal");
    }
}

static void test_mlkem_derand_from_seed(const char *alg)
{
    QUDO_KEM *kem = QUDO_KEM_new(alg);
    if (!kem) {
        g_fail++;
        fprintf(stderr, "  FAIL: KEM_new(%s)\n", alg);
        return;
    }

    uint8_t *pk = (uint8_t *)malloc(kem->length_public_key);
    uint8_t *sk = (uint8_t *)malloc(kem->length_secret_key);
    uint8_t *ct = (uint8_t *)malloc(kem->length_ciphertext);
    uint8_t *ss1 = (uint8_t *)malloc(kem->length_shared_secret);
    uint8_t *ss2 = (uint8_t *)malloc(kem->length_shared_secret);
    uint8_t seed_out[QUDO_KEM_SEED_BYTES];
    uint8_t seed[QUDO_KEM_SEED_BYTES];
    memset(seed, 0xCC, sizeof(seed));

    if (!pk || !sk || !ct || !ss1 || !ss2)
        goto cleanup;

    QUDO_KEM_status_t r
        = QUDO_KEM_keypair_derand(kem, pk, sk, seed_out, sizeof(seed_out));
    if (r == QUDO_KEM_SUCCESS) {
        CHECK(QUDO_KEM_encaps(kem, ct, ss1, pk) == QUDO_KEM_SUCCESS,
              "KEM encaps after derand");
        CHECK(QUDO_KEM_decaps(kem, ss2, ct, sk) == QUDO_KEM_SUCCESS,
              "KEM decaps");
        CHECK(memcmp(ss1, ss2, kem->length_shared_secret) == 0,
              "KEM shared_secret matches");
    } else
        CHECK(0, "KEM keypair_derand");

    r = QUDO_KEM_keypair_from_seed(kem, pk, sk, seed);
    if (r == QUDO_KEM_SUCCESS) {
        CHECK(QUDO_KEM_encaps(kem, ct, ss1, pk) == QUDO_KEM_SUCCESS,
              "KEM encaps after from_seed");
    } else
        CHECK(0, "KEM keypair_from_seed");

cleanup:
    free(pk);
    free(sk);
    free(ct);
    free(ss1);
    free(ss2);
    QUDO_KEM_free(kem);
}

int main(int argc, char **argv)
{
    test_fips_init_set_args(&argc, argv);
    if (test_fips_init() != 1) {
        fprintf(stderr, "FIPS init failed\n");
        return 1;
    }

    fprintf(stderr, "[init/cleanup/is_initialized]\n");
    test_init_cleanup_is_initialized();

    fprintf(stderr, "[ML-DSA advanced API — ML-DSA-44]\n");
    test_mldsa_advanced("ML-DSA-44");
    fprintf(stderr, "[ML-DSA advanced API — ML-DSA-65]\n");
    test_mldsa_advanced("ML-DSA-65");
    fprintf(stderr, "[ML-DSA advanced API — ML-DSA-87]\n");
    test_mldsa_advanced("ML-DSA-87");

    fprintf(stderr, "[ML-DSA per-set internal API]\n");
    test_mldsa_perset_internal();

    fprintf(stderr, "[ML-KEM derand/from_seed — ML-KEM-512]\n");
    test_mlkem_derand_from_seed("ML-KEM-512");
    fprintf(stderr, "[ML-KEM derand/from_seed — ML-KEM-768]\n");
    test_mlkem_derand_from_seed("ML-KEM-768");
    fprintf(stderr, "[ML-KEM derand/from_seed — ML-KEM-1024]\n");
    test_mlkem_derand_from_seed("ML-KEM-1024");

    qudo_pqc_fini();
    fprintf(stderr, "\n=== Wrapper Advanced: %d pass, %d fail ===\n", g_pass,
            g_fail);
    return g_fail == 0 ? 0 : 1;
}
