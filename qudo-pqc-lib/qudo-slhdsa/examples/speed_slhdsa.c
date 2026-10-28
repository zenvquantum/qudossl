/* SPDX-License-Identifier: Apache-2.0 AND MIT */
#include "slhdsa_wrapper.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

static double get_time_ms(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec * 1000.0 + ts.tv_nsec / 1000000.0;
}

static void benchmark_variant(const char *alg_name, int iterations)
{
    QUDO_SLHDSA *sig = QUDO_SLHDSA_new(alg_name);
    if (!sig) {
        fprintf(stderr, "Failed to create instance for %s\n", alg_name);
        return;
    }

    uint8_t *pk = malloc(sig->length_public_key);
    uint8_t *sk = malloc(sig->length_secret_key);
    uint8_t *signature = malloc(sig->length_signature);
    const uint8_t msg[]
        = "Benchmark test message for SLH-DSA performance measurement";
    size_t msg_len = sizeof(msg) - 1;
    size_t sig_len = sig->length_signature;

    double start = get_time_ms();
    for (int i = 0; i < iterations; i++) {
        QUDO_SLHDSA_keypair(sig, pk, sk);
    }
    double keygen_ms = (get_time_ms() - start) / iterations;

    start = get_time_ms();
    for (int i = 0; i < iterations; i++) {
        sig_len = sig->length_signature;
        QUDO_SLHDSA_sign(sig, signature, &sig_len, msg, msg_len, sk);
    }
    double sign_ms = (get_time_ms() - start) / iterations;

    sig_len = sig->length_signature;
    QUDO_SLHDSA_sign(sig, signature, &sig_len, msg, msg_len, sk);
    start = get_time_ms();
    for (int i = 0; i < iterations; i++) {
        QUDO_SLHDSA_verify(sig, msg, msg_len, signature, sig_len, pk);
    }
    double verify_ms = (get_time_ms() - start) / iterations;

    printf(
        "%-22s  pk=%3zu  sk=%3zu  sig=%5zu  keygen=%8.2f ms  sign=%8.2f ms  verify=%8.2f ms\n",
        alg_name, sig->length_public_key, sig->length_secret_key,
        sig->length_signature, keygen_ms, sign_ms, verify_ms);

    free(pk);
    free(sk);
    free(signature);
    QUDO_SLHDSA_free(sig);
}

int main(void)
{
    printf("\n=== QUDO SLH-DSA Performance Benchmark ===\n\n");
    printf("%-22s  %5s  %5s  %7s  %12s  %12s  %12s\n", "Algorithm", "PK", "SK",
           "Sig", "Keygen", "Sign", "Verify");
    printf("----------------------------------------------"
           "-------------------------------------------\n");

    const char *fast_algs[] = {
        "SLH-DSA-SHA2-128f",  "SLH-DSA-SHAKE-128f", "SLH-DSA-SHA2-192f",
        "SLH-DSA-SHAKE-192f", "SLH-DSA-SHA2-256f",  "SLH-DSA-SHAKE-256f",
    };

    for (int i = 0; i < 6; i++) {
        benchmark_variant(fast_algs[i], 3);
    }

    printf("\n");

    const char *small_algs[] = {
        "SLH-DSA-SHA2-128s",  "SLH-DSA-SHAKE-128s", "SLH-DSA-SHA2-192s",
        "SLH-DSA-SHAKE-192s", "SLH-DSA-SHA2-256s",  "SLH-DSA-SHAKE-256s",
    };

    for (int i = 0; i < 6; i++) {
        benchmark_variant(small_algs[i], 1);
    }

    printf("\n");
    return 0;
}
