/* SPDX-License-Identifier: Apache-2.0 AND MIT */
#include "mldsa_wrapper.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define NUM_ITERATIONS 100

static double get_time_ms(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec * 1000.0 + ts.tv_nsec / 1000000.0;
}

static void benchmark_algorithm(const char *alg_name, size_t pk_bytes,
                                size_t sk_bytes, size_t sig_bytes)
{
    printf("\n=== Benchmarking %s ===\n", alg_name);

    QUDO_MLDSA *sig = QUDO_MLDSA_new(alg_name);
    if (!sig) {
        fprintf(stderr, "ERROR: Failed to create %s instance\n", alg_name);
        return;
    }

    uint8_t *pk = malloc(pk_bytes);
    uint8_t *sk = malloc(sk_bytes);
    uint8_t *signature = malloc(sig_bytes);
    const char *msg = "Benchmark message";
    size_t msg_len = strlen(msg);
    size_t sig_len = sig_bytes;

    double start = get_time_ms();
    for (int i = 0; i < NUM_ITERATIONS; i++) {
        QUDO_MLDSA_keypair(sig, pk, sk);
    }
    double keypair_time = (get_time_ms() - start) / NUM_ITERATIONS;

    start = get_time_ms();
    for (int i = 0; i < NUM_ITERATIONS; i++) {
        QUDO_MLDSA_sign(sig, signature, &sig_len, (const uint8_t *)msg, msg_len,
                        sk);
    }
    double sign_time = (get_time_ms() - start) / NUM_ITERATIONS;

    start = get_time_ms();
    for (int i = 0; i < NUM_ITERATIONS; i++) {
        QUDO_MLDSA_verify(sig, signature, sig_len, (const uint8_t *)msg,
                          msg_len, pk);
    }
    double verify_time = (get_time_ms() - start) / NUM_ITERATIONS;

    printf("  Keypair:  %.3f ms\n", keypair_time);
    printf("  Sign:     %.3f ms\n", sign_time);
    printf("  Verify:   %.3f ms\n", verify_time);
    printf("  PK size:  %zu bytes\n", pk_bytes);
    printf("  SK size:  %zu bytes\n", sk_bytes);
    printf("  Sig size: %zu bytes\n", sig_bytes);

    free(pk);
    free(sk);
    free(signature);
    QUDO_MLDSA_free(sig);
}

int main()
{
    QUDO_MLDSA_init();

    printf("=== QUDO ML-DSA Performance Benchmark ===\n");
    printf("Iterations: %d\n", NUM_ITERATIONS);

    benchmark_algorithm("ML-DSA-44", ML_DSA_44_PUBLIC_KEY_BYTES,
                        ML_DSA_44_SECRET_KEY_BYTES, ML_DSA_44_SIGNATURE_BYTES);
    benchmark_algorithm("ML-DSA-65", ML_DSA_65_PUBLIC_KEY_BYTES,
                        ML_DSA_65_SECRET_KEY_BYTES, ML_DSA_65_SIGNATURE_BYTES);
    benchmark_algorithm("ML-DSA-87", ML_DSA_87_PUBLIC_KEY_BYTES,
                        ML_DSA_87_SECRET_KEY_BYTES, ML_DSA_87_SIGNATURE_BYTES);

    printf("\n=== Benchmark Complete ===\n");
    return 0;
}
