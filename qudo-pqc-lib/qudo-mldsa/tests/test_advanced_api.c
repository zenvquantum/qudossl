/* SPDX-License-Identifier: Apache-2.0 AND MIT */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include "mldsa_wrapper.h"

#define TEST_PASS "\033[32mPASSED\033[0m"
#define TEST_FAIL "\033[31mFAILED\033[0m"

static int tests_run = 0;
static int tests_passed = 0;
static int tests_failed = 0;

#define RUN_TEST(test_func) do { \
    printf("  Running %s... ", #test_func); \
    fflush(stdout); \
    tests_run++; \
    if (test_func()) { \
        printf("%s\n", TEST_PASS); \
        tests_passed++; \
    } else { \
        printf("%s\n", TEST_FAIL); \
        tests_failed++; \
    } \
} while(0)

static int test_deterministic_keypair_44() {
    uint8_t seed[MLDSA_SEEDBYTES] = {0x42};
    uint8_t pk1[ML_DSA_44_PUBLIC_KEY_BYTES];
    uint8_t sk1[ML_DSA_44_SECRET_KEY_BYTES];
    uint8_t pk2[ML_DSA_44_PUBLIC_KEY_BYTES];
    uint8_t sk2[ML_DSA_44_SECRET_KEY_BYTES];

    QUDO_MLDSA_status_t ret1 = QUDO_MLDSA_ML_DSA_44_keypair_internal(pk1, sk1, seed);
    QUDO_MLDSA_status_t ret2 = QUDO_MLDSA_ML_DSA_44_keypair_internal(pk2, sk2, seed);

    return (ret1 == QUDO_MLDSA_SUCCESS && ret2 == QUDO_MLDSA_SUCCESS &&
            memcmp(pk1, pk2, ML_DSA_44_PUBLIC_KEY_BYTES) == 0 &&
            memcmp(sk1, sk2, ML_DSA_44_SECRET_KEY_BYTES) == 0);
}

static int test_deterministic_keypair_65() {
    uint8_t seed[MLDSA_SEEDBYTES] = {0x65};
    uint8_t pk1[ML_DSA_65_PUBLIC_KEY_BYTES];
    uint8_t sk1[ML_DSA_65_SECRET_KEY_BYTES];
    uint8_t pk2[ML_DSA_65_PUBLIC_KEY_BYTES];
    uint8_t sk2[ML_DSA_65_SECRET_KEY_BYTES];

    QUDO_MLDSA_status_t ret1 = QUDO_MLDSA_ML_DSA_65_keypair_internal(pk1, sk1, seed);
    QUDO_MLDSA_status_t ret2 = QUDO_MLDSA_ML_DSA_65_keypair_internal(pk2, sk2, seed);

    return (ret1 == QUDO_MLDSA_SUCCESS && ret2 == QUDO_MLDSA_SUCCESS &&
            memcmp(pk1, pk2, ML_DSA_65_PUBLIC_KEY_BYTES) == 0 &&
            memcmp(sk1, sk2, ML_DSA_65_SECRET_KEY_BYTES) == 0);
}

static int test_deterministic_keypair_87() {
    uint8_t seed[MLDSA_SEEDBYTES] = {0x87};
    uint8_t pk1[ML_DSA_87_PUBLIC_KEY_BYTES];
    uint8_t sk1[ML_DSA_87_SECRET_KEY_BYTES];
    uint8_t pk2[ML_DSA_87_PUBLIC_KEY_BYTES];
    uint8_t sk2[ML_DSA_87_SECRET_KEY_BYTES];

    QUDO_MLDSA_status_t ret1 = QUDO_MLDSA_ML_DSA_87_keypair_internal(pk1, sk1, seed);
    QUDO_MLDSA_status_t ret2 = QUDO_MLDSA_ML_DSA_87_keypair_internal(pk2, sk2, seed);

    return (ret1 == QUDO_MLDSA_SUCCESS && ret2 == QUDO_MLDSA_SUCCESS &&
            memcmp(pk1, pk2, ML_DSA_87_PUBLIC_KEY_BYTES) == 0 &&
            memcmp(sk1, sk2, ML_DSA_87_SECRET_KEY_BYTES) == 0);
}

static int test_deterministic_sign_65() {
    uint8_t seed[MLDSA_SEEDBYTES] = {0};
    uint8_t pk[ML_DSA_65_PUBLIC_KEY_BYTES];
    uint8_t sk[ML_DSA_65_SECRET_KEY_BYTES];
    uint8_t rnd[MLDSA_RNDBYTES] = {0xAB};
    const char *msg = "test message";
    size_t msglen = strlen(msg);

    uint8_t sig1[ML_DSA_65_SIGNATURE_BYTES];
    uint8_t sig2[ML_DSA_65_SIGNATURE_BYTES];
    size_t sig1len = ML_DSA_65_SIGNATURE_BYTES;
    size_t sig2len = ML_DSA_65_SIGNATURE_BYTES;

    QUDO_MLDSA_ML_DSA_65_keypair_internal(pk, sk, seed);

    QUDO_MLDSA_status_t ret1 = QUDO_MLDSA_ML_DSA_65_sign_internal(
        sig1, &sig1len, (const uint8_t*)msg, msglen, NULL, 0, rnd, sk, 0);
    QUDO_MLDSA_status_t ret2 = QUDO_MLDSA_ML_DSA_65_sign_internal(
        sig2, &sig2len, (const uint8_t*)msg, msglen, NULL, 0, rnd, sk, 0);

    return (ret1 == QUDO_MLDSA_SUCCESS && ret2 == QUDO_MLDSA_SUCCESS &&
            sig1len == sig2len && memcmp(sig1, sig2, sig1len) == 0);
}

static int test_external_mu_65() {
    uint8_t pk[ML_DSA_65_PUBLIC_KEY_BYTES];
    uint8_t sk[ML_DSA_65_SECRET_KEY_BYTES];
    uint8_t mu[MLDSA_CRHBYTES];
    uint8_t sig[ML_DSA_65_SIGNATURE_BYTES];
    size_t siglen = ML_DSA_65_SIGNATURE_BYTES;

    memset(mu, 0x42, MLDSA_CRHBYTES);

    QUDO_MLDSA_ML_DSA_65_keypair(pk, sk);

    QUDO_MLDSA_status_t sign_ret = QUDO_MLDSA_ML_DSA_65_sign_extmu(sig, &siglen, mu, sk);
    QUDO_MLDSA_status_t verify_ret = QUDO_MLDSA_ML_DSA_65_verify_extmu(sig, siglen, mu, pk);

    return (sign_ret == QUDO_MLDSA_SUCCESS && verify_ret == QUDO_MLDSA_SUCCESS);
}

static int test_concat_format_44() {
    uint8_t pk[ML_DSA_44_PUBLIC_KEY_BYTES];
    uint8_t sk[ML_DSA_44_SECRET_KEY_BYTES];
    const char *msg = "concat test";
    size_t msglen = strlen(msg);
    uint8_t sm[ML_DSA_44_SIGNATURE_BYTES + 200];
    size_t smlen = sizeof(sm);
    uint8_t msg_out[200];
    size_t msg_out_len = sizeof(msg_out);

    QUDO_MLDSA_ML_DSA_44_keypair(pk, sk);

    QUDO_MLDSA_status_t sign_ret = QUDO_MLDSA_ML_DSA_44_sign_concat(
        sm, &smlen, (const uint8_t*)msg, msglen, NULL, 0, sk);
    QUDO_MLDSA_status_t open_ret = QUDO_MLDSA_ML_DSA_44_open(
        msg_out, &msg_out_len, sm, smlen, NULL, 0, pk);

    return (sign_ret == QUDO_MLDSA_SUCCESS && open_ret == QUDO_MLDSA_SUCCESS &&
            msg_out_len == msglen && memcmp(msg, msg_out, msglen) == 0);
}

static int test_prehash_87() {
    uint8_t pk[ML_DSA_87_PUBLIC_KEY_BYTES];
    uint8_t sk[ML_DSA_87_SECRET_KEY_BYTES];
    uint8_t hash[32];
    uint8_t rnd[MLDSA_RNDBYTES] = {0};
    uint8_t sig[ML_DSA_87_SIGNATURE_BYTES];
    size_t siglen = ML_DSA_87_SIGNATURE_BYTES;

    memset(hash, 0x11, 32);

    QUDO_MLDSA_ML_DSA_87_keypair(pk, sk);

    QUDO_MLDSA_status_t sign_ret = QUDO_MLDSA_ML_DSA_87_sign_pre_hash(
        sig, &siglen, hash, 32, NULL, 0, rnd, sk, QUDO_PREHASH_SHA2_256);
    QUDO_MLDSA_status_t verify_ret = QUDO_MLDSA_ML_DSA_87_verify_pre_hash(
        sig, siglen, hash, 32, NULL, 0, pk, QUDO_PREHASH_SHA2_256);

    return (sign_ret == QUDO_MLDSA_SUCCESS && verify_ret == QUDO_MLDSA_SUCCESS);
}

static int test_object_api_keypair_internal() {
    QUDO_MLDSA *sig = QUDO_MLDSA_new("ML-DSA-65");
    if (!sig) return 0;

    uint8_t seed[MLDSA_SEEDBYTES] = {0x99};
    uint8_t pk1[ML_DSA_65_PUBLIC_KEY_BYTES];
    uint8_t sk1[ML_DSA_65_SECRET_KEY_BYTES];
    uint8_t pk2[ML_DSA_65_PUBLIC_KEY_BYTES];
    uint8_t sk2[ML_DSA_65_SECRET_KEY_BYTES];

    QUDO_MLDSA_status_t ret1 = QUDO_MLDSA_keypair_internal(sig, pk1, sk1, seed);
    QUDO_MLDSA_status_t ret2 = QUDO_MLDSA_keypair_internal(sig, pk2, sk2, seed);

    int result = (ret1 == QUDO_MLDSA_SUCCESS && ret2 == QUDO_MLDSA_SUCCESS &&
                  memcmp(pk1, pk2, ML_DSA_65_PUBLIC_KEY_BYTES) == 0);

    QUDO_MLDSA_free(sig);
    return result;
}

static int test_object_api_sign_internal() {
    QUDO_MLDSA *sig = QUDO_MLDSA_new("ML-DSA-44");
    if (!sig) return 0;

    uint8_t pk[ML_DSA_44_PUBLIC_KEY_BYTES];
    uint8_t sk[ML_DSA_44_SECRET_KEY_BYTES];
    uint8_t rnd[MLDSA_RNDBYTES] = {0xCD};
    const char *msg = "internal test";
    uint8_t signature[ML_DSA_44_SIGNATURE_BYTES];
    size_t siglen = ML_DSA_44_SIGNATURE_BYTES;

    QUDO_MLDSA_keypair(sig, pk, sk);

    QUDO_MLDSA_status_t ret = QUDO_MLDSA_sign_internal(
        sig, signature, &siglen, (const uint8_t*)msg, strlen(msg),
        NULL, 0, rnd, sk, 0);

    QUDO_MLDSA_free(sig);
    return (ret == QUDO_MLDSA_SUCCESS);
}

static int test_object_api_extmu() {
    QUDO_MLDSA *sig = QUDO_MLDSA_new("ML-DSA-87");
    if (!sig) return 0;

    uint8_t pk[ML_DSA_87_PUBLIC_KEY_BYTES];
    uint8_t sk[ML_DSA_87_SECRET_KEY_BYTES];
    uint8_t mu[MLDSA_CRHBYTES];
    uint8_t signature[ML_DSA_87_SIGNATURE_BYTES];
    size_t siglen = ML_DSA_87_SIGNATURE_BYTES;

    memset(mu, 0x77, MLDSA_CRHBYTES);
    QUDO_MLDSA_keypair(sig, pk, sk);

    QUDO_MLDSA_status_t sign_ret = QUDO_MLDSA_sign_extmu(sig, signature, &siglen, mu, sk);
    QUDO_MLDSA_status_t verify_ret = QUDO_MLDSA_verify_extmu(sig, signature, siglen, mu, pk);

    QUDO_MLDSA_free(sig);
    return (sign_ret == QUDO_MLDSA_SUCCESS && verify_ret == QUDO_MLDSA_SUCCESS);
}

static int test_object_api_concat() {
    QUDO_MLDSA *sig = QUDO_MLDSA_new("ML-DSA-65");
    if (!sig) return 0;

    uint8_t pk[ML_DSA_65_PUBLIC_KEY_BYTES];
    uint8_t sk[ML_DSA_65_SECRET_KEY_BYTES];
    const char *msg = "concat obj test";
    size_t msglen = strlen(msg);
    uint8_t sm[ML_DSA_65_SIGNATURE_BYTES + 200];
    size_t smlen = sizeof(sm);
    uint8_t msg_out[200];
    size_t msg_out_len = sizeof(msg_out);

    QUDO_MLDSA_keypair(sig, pk, sk);

    QUDO_MLDSA_status_t sign_ret = QUDO_MLDSA_sign_concat(
        sig, sm, &smlen, (const uint8_t*)msg, msglen, NULL, 0, sk);
    QUDO_MLDSA_status_t open_ret = QUDO_MLDSA_open(
        sig, msg_out, &msg_out_len, sm, smlen, NULL, 0, pk);

    int result = (sign_ret == QUDO_MLDSA_SUCCESS && open_ret == QUDO_MLDSA_SUCCESS &&
                  msg_out_len == msglen && memcmp(msg, msg_out, msglen) == 0);

    QUDO_MLDSA_free(sig);
    return result;
}

static int test_object_api_prehash() {
    QUDO_MLDSA *sig = QUDO_MLDSA_new("ML-DSA-44");
    if (!sig) return 0;

    uint8_t pk[ML_DSA_44_PUBLIC_KEY_BYTES];
    uint8_t sk[ML_DSA_44_SECRET_KEY_BYTES];
    uint8_t hash[32];
    uint8_t rnd[MLDSA_RNDBYTES] = {0xEF};
    uint8_t signature[ML_DSA_44_SIGNATURE_BYTES];
    size_t siglen = ML_DSA_44_SIGNATURE_BYTES;

    memset(hash, 0x22, 32);
    QUDO_MLDSA_keypair(sig, pk, sk);

    QUDO_MLDSA_status_t sign_ret = QUDO_MLDSA_sign_pre_hash_internal(
        sig, signature, &siglen, hash, 32, NULL, 0, rnd, sk, QUDO_PREHASH_SHA2_256);
    QUDO_MLDSA_status_t verify_ret = QUDO_MLDSA_verify_pre_hash_internal(
        sig, signature, siglen, hash, 32, NULL, 0, pk, QUDO_PREHASH_SHA2_256);

    QUDO_MLDSA_free(sig);
    return (sign_ret == QUDO_MLDSA_SUCCESS && verify_ret == QUDO_MLDSA_SUCCESS);
}

static int test_wrong_hash_rejected() {
    uint8_t pk[ML_DSA_65_PUBLIC_KEY_BYTES];
    uint8_t sk[ML_DSA_65_SECRET_KEY_BYTES];
    uint8_t hash1[32], hash2[32];
    uint8_t rnd[MLDSA_RNDBYTES] = {0};
    uint8_t sig[ML_DSA_65_SIGNATURE_BYTES];
    size_t siglen = ML_DSA_65_SIGNATURE_BYTES;

    memset(hash1, 0x11, 32);
    memset(hash2, 0x22, 32);

    QUDO_MLDSA_ML_DSA_65_keypair(pk, sk);
    QUDO_MLDSA_ML_DSA_65_sign_pre_hash(sig, &siglen, hash1, 32, NULL, 0, rnd, sk, QUDO_PREHASH_SHA2_256);

    QUDO_MLDSA_status_t ret = QUDO_MLDSA_ML_DSA_65_verify_pre_hash(
        sig, siglen, hash2, 32, NULL, 0, pk, QUDO_PREHASH_SHA2_256);

    return (ret != QUDO_MLDSA_SUCCESS);
}

static int test_object_api_verify_internal() {
    QUDO_MLDSA *sig = QUDO_MLDSA_new("ML-DSA-65");
    if (!sig) return 0;

    uint8_t pk[ML_DSA_65_PUBLIC_KEY_BYTES];
    uint8_t sk[ML_DSA_65_SECRET_KEY_BYTES];
    uint8_t rnd[MLDSA_RNDBYTES] = {0xAB};
    const char *msg = "verify_internal_test";
    uint8_t signature[ML_DSA_65_SIGNATURE_BYTES];
    size_t siglen = ML_DSA_65_SIGNATURE_BYTES;

    QUDO_MLDSA_keypair(sig, pk, sk);
    QUDO_MLDSA_sign_internal(sig, signature, &siglen,
        (const uint8_t*)msg, strlen(msg), NULL, 0, rnd, sk, 0);

    QUDO_MLDSA_status_t ret = QUDO_MLDSA_verify_internal(
        sig, signature, siglen, (const uint8_t*)msg, strlen(msg), NULL, 0, pk, 0);

    QUDO_MLDSA_free(sig);
    return (ret == QUDO_MLDSA_SUCCESS);
}

static int test_sign_verify_internal_44() {
    uint8_t pk[ML_DSA_44_PUBLIC_KEY_BYTES];
    uint8_t sk[ML_DSA_44_SECRET_KEY_BYTES];
    uint8_t rnd[MLDSA_RNDBYTES] = {0x11};
    const char *msg = "internal44";
    uint8_t sig[ML_DSA_44_SIGNATURE_BYTES];
    size_t siglen = ML_DSA_44_SIGNATURE_BYTES;

    QUDO_MLDSA_ML_DSA_44_keypair(pk, sk);
    QUDO_MLDSA_status_t s = QUDO_MLDSA_ML_DSA_44_sign_internal(
        sig, &siglen, (const uint8_t*)msg, strlen(msg), NULL, 0, rnd, sk, 0);
    QUDO_MLDSA_status_t v = QUDO_MLDSA_ML_DSA_44_verify_internal(
        sig, siglen, (const uint8_t*)msg, strlen(msg), NULL, 0, pk, 0);
    return (s == QUDO_MLDSA_SUCCESS && v == QUDO_MLDSA_SUCCESS);
}

static int test_prehash_44() {
    uint8_t pk[ML_DSA_44_PUBLIC_KEY_BYTES];
    uint8_t sk[ML_DSA_44_SECRET_KEY_BYTES];
    uint8_t hash[32];
    uint8_t rnd[MLDSA_RNDBYTES] = {0};
    uint8_t sig[ML_DSA_44_SIGNATURE_BYTES];
    size_t siglen = ML_DSA_44_SIGNATURE_BYTES;

    memset(hash, 0x55, 32);
    QUDO_MLDSA_ML_DSA_44_keypair(pk, sk);
    QUDO_MLDSA_status_t s = QUDO_MLDSA_ML_DSA_44_sign_pre_hash(
        sig, &siglen, hash, 32, NULL, 0, rnd, sk, QUDO_PREHASH_SHA2_256);
    QUDO_MLDSA_status_t v = QUDO_MLDSA_ML_DSA_44_verify_pre_hash(
        sig, siglen, hash, 32, NULL, 0, pk, QUDO_PREHASH_SHA2_256);
    return (s == QUDO_MLDSA_SUCCESS && v == QUDO_MLDSA_SUCCESS);
}

static int test_sign_verify_internal_65() {
    uint8_t pk[ML_DSA_65_PUBLIC_KEY_BYTES];
    uint8_t sk[ML_DSA_65_SECRET_KEY_BYTES];
    uint8_t rnd[MLDSA_RNDBYTES] = {0x22};
    const char *msg = "internal65";
    uint8_t sig[ML_DSA_65_SIGNATURE_BYTES];
    size_t siglen = ML_DSA_65_SIGNATURE_BYTES;

    QUDO_MLDSA_ML_DSA_65_keypair(pk, sk);
    QUDO_MLDSA_status_t s = QUDO_MLDSA_ML_DSA_65_sign_internal(
        sig, &siglen, (const uint8_t*)msg, strlen(msg), NULL, 0, rnd, sk, 0);
    QUDO_MLDSA_status_t v = QUDO_MLDSA_ML_DSA_65_verify_internal(
        sig, siglen, (const uint8_t*)msg, strlen(msg), NULL, 0, pk, 0);
    return (s == QUDO_MLDSA_SUCCESS && v == QUDO_MLDSA_SUCCESS);
}

static int test_concat_65() {
    uint8_t pk[ML_DSA_65_PUBLIC_KEY_BYTES];
    uint8_t sk[ML_DSA_65_SECRET_KEY_BYTES];
    const char *msg = "concat65";
    size_t msglen = strlen(msg);
    uint8_t sm[ML_DSA_65_SIGNATURE_BYTES + 100];
    size_t smlen = sizeof(sm);
    uint8_t mout[100];
    size_t mout_len = sizeof(mout);

    QUDO_MLDSA_ML_DSA_65_keypair(pk, sk);
    QUDO_MLDSA_status_t s = QUDO_MLDSA_ML_DSA_65_sign_concat(
        sm, &smlen, (const uint8_t*)msg, msglen, NULL, 0, sk);
    QUDO_MLDSA_status_t o = QUDO_MLDSA_ML_DSA_65_open(
        mout, &mout_len, sm, smlen, NULL, 0, pk);
    return (s == QUDO_MLDSA_SUCCESS && o == QUDO_MLDSA_SUCCESS &&
            mout_len == msglen && memcmp(msg, mout, msglen) == 0);
}

static int test_prehash_65() {
    uint8_t pk[ML_DSA_65_PUBLIC_KEY_BYTES];
    uint8_t sk[ML_DSA_65_SECRET_KEY_BYTES];
    uint8_t hash[32];
    uint8_t rnd[MLDSA_RNDBYTES] = {0};
    uint8_t sig[ML_DSA_65_SIGNATURE_BYTES];
    size_t siglen = ML_DSA_65_SIGNATURE_BYTES;

    memset(hash, 0x66, 32);
    QUDO_MLDSA_ML_DSA_65_keypair(pk, sk);
    QUDO_MLDSA_status_t s = QUDO_MLDSA_ML_DSA_65_sign_pre_hash(
        sig, &siglen, hash, 32, NULL, 0, rnd, sk, QUDO_PREHASH_SHA2_256);
    QUDO_MLDSA_status_t v = QUDO_MLDSA_ML_DSA_65_verify_pre_hash(
        sig, siglen, hash, 32, NULL, 0, pk, QUDO_PREHASH_SHA2_256);
    return (s == QUDO_MLDSA_SUCCESS && v == QUDO_MLDSA_SUCCESS);
}

static int test_extmu_87() {
    uint8_t pk[ML_DSA_87_PUBLIC_KEY_BYTES];
    uint8_t sk[ML_DSA_87_SECRET_KEY_BYTES];
    uint8_t mu[MLDSA_CRHBYTES];
    uint8_t sig[ML_DSA_87_SIGNATURE_BYTES];
    size_t siglen = ML_DSA_87_SIGNATURE_BYTES;

    memset(mu, 0x87, MLDSA_CRHBYTES);
    QUDO_MLDSA_ML_DSA_87_keypair(pk, sk);
    QUDO_MLDSA_status_t s = QUDO_MLDSA_ML_DSA_87_sign_extmu(sig, &siglen, mu, sk);
    QUDO_MLDSA_status_t v = QUDO_MLDSA_ML_DSA_87_verify_extmu(sig, siglen, mu, pk);
    return (s == QUDO_MLDSA_SUCCESS && v == QUDO_MLDSA_SUCCESS);
}

static int test_sign_verify_internal_87() {
    uint8_t pk[ML_DSA_87_PUBLIC_KEY_BYTES];
    uint8_t sk[ML_DSA_87_SECRET_KEY_BYTES];
    uint8_t rnd[MLDSA_RNDBYTES] = {0x33};
    const char *msg = "internal87";
    uint8_t sig[ML_DSA_87_SIGNATURE_BYTES];
    size_t siglen = ML_DSA_87_SIGNATURE_BYTES;

    QUDO_MLDSA_ML_DSA_87_keypair(pk, sk);
    QUDO_MLDSA_status_t s = QUDO_MLDSA_ML_DSA_87_sign_internal(
        sig, &siglen, (const uint8_t*)msg, strlen(msg), NULL, 0, rnd, sk, 0);
    QUDO_MLDSA_status_t v = QUDO_MLDSA_ML_DSA_87_verify_internal(
        sig, siglen, (const uint8_t*)msg, strlen(msg), NULL, 0, pk, 0);
    return (s == QUDO_MLDSA_SUCCESS && v == QUDO_MLDSA_SUCCESS);
}

static int test_concat_87() {
    uint8_t pk[ML_DSA_87_PUBLIC_KEY_BYTES];
    uint8_t sk[ML_DSA_87_SECRET_KEY_BYTES];
    const char *msg = "concat87";
    size_t msglen = strlen(msg);
    uint8_t sm[ML_DSA_87_SIGNATURE_BYTES + 100];
    size_t smlen = sizeof(sm);
    uint8_t mout[100];
    size_t mout_len = sizeof(mout);

    QUDO_MLDSA_ML_DSA_87_keypair(pk, sk);
    QUDO_MLDSA_status_t s = QUDO_MLDSA_ML_DSA_87_sign_concat(
        sm, &smlen, (const uint8_t*)msg, msglen, NULL, 0, sk);
    QUDO_MLDSA_status_t o = QUDO_MLDSA_ML_DSA_87_open(
        mout, &mout_len, sm, smlen, NULL, 0, pk);
    return (s == QUDO_MLDSA_SUCCESS && o == QUDO_MLDSA_SUCCESS &&
            mout_len == msglen && memcmp(msg, mout, msglen) == 0);
}

static int test_wrong_mu_rejected() {
    uint8_t pk[ML_DSA_44_PUBLIC_KEY_BYTES];
    uint8_t sk[ML_DSA_44_SECRET_KEY_BYTES];
    uint8_t mu1[MLDSA_CRHBYTES], mu2[MLDSA_CRHBYTES];
    uint8_t sig[ML_DSA_44_SIGNATURE_BYTES];
    size_t siglen = ML_DSA_44_SIGNATURE_BYTES;

    memset(mu1, 0xAA, MLDSA_CRHBYTES);
    memset(mu2, 0xBB, MLDSA_CRHBYTES);

    QUDO_MLDSA_ML_DSA_44_keypair(pk, sk);
    QUDO_MLDSA_ML_DSA_44_sign_extmu(sig, &siglen, mu1, sk);

    QUDO_MLDSA_status_t ret = QUDO_MLDSA_ML_DSA_44_verify_extmu(sig, siglen, mu2, pk);

    return (ret != QUDO_MLDSA_SUCCESS);
}

int main(void) {
    printf("\n=== Advanced ML-DSA API Test Suite ===\n\n");
    QUDO_MLDSA_init();

    printf("Deterministic Keypair Tests:\n");
    RUN_TEST(test_deterministic_keypair_44);
    RUN_TEST(test_deterministic_keypair_65);
    RUN_TEST(test_deterministic_keypair_87);

    printf("\nDeterministic Signing Tests:\n");
    RUN_TEST(test_deterministic_sign_65);

    printf("\nExternal Mu Tests:\n");
    RUN_TEST(test_external_mu_65);

    printf("\nConcatenated Format Tests:\n");
    RUN_TEST(test_concat_format_44);

    printf("\nPre-Hash Tests:\n");
    RUN_TEST(test_prehash_87);

    printf("\nObject API Advanced Tests:\n");
    RUN_TEST(test_object_api_keypair_internal);
    RUN_TEST(test_object_api_sign_internal);
    RUN_TEST(test_object_api_extmu);
    RUN_TEST(test_object_api_concat);
    RUN_TEST(test_object_api_prehash);

    printf("\nVerify Internal (Object API):\n");
    RUN_TEST(test_object_api_verify_internal);

    printf("\nML-DSA-44 Full Direct API:\n");
    RUN_TEST(test_sign_verify_internal_44);
    RUN_TEST(test_prehash_44);

    printf("\nML-DSA-65 Full Direct API:\n");
    RUN_TEST(test_sign_verify_internal_65);
    RUN_TEST(test_concat_65);
    RUN_TEST(test_prehash_65);

    printf("\nML-DSA-87 Full Direct API:\n");
    RUN_TEST(test_extmu_87);
    RUN_TEST(test_sign_verify_internal_87);
    RUN_TEST(test_concat_87);

    printf("\nNegative Tests:\n");
    RUN_TEST(test_wrong_hash_rejected);
    RUN_TEST(test_wrong_mu_rejected);

    printf("\n=== Test Results ===\n");
    printf("Tests run: %d\n", tests_run);
    printf("Tests passed: %d\n", tests_passed);
    printf("Tests failed: %d\n", tests_failed);

    if (tests_failed == 0) {
        printf("\n✓ ALL ADVANCED API TESTS PASSED\n\n");
        return 0;
    } else {
        printf("\n✗ SOME TESTS FAILED\n\n");
        return 1;
    }
}
