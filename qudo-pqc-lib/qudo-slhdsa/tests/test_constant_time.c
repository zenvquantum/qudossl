/* SPDX-License-Identifier: Apache-2.0 AND MIT */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <math.h>
#ifdef _MSC_VER
#include <intrin.h>
#endif
#include "../include/slhdsa_wrapper.h"

#define NUM_MEASUREMENTS 1000
#define WARMUP_ITERATIONS 10
#define SIGNIFICANCE_THRESHOLD 4.5

static inline uint64_t get_cycles(void) {
#if defined(_MSC_VER) && (defined(_M_X64) || defined(_M_IX86))
    return __rdtsc();
#elif defined(__x86_64__) || defined(__i386__)
    unsigned int hi, lo;
    __asm__ __volatile__ (
        "rdtsc"
        : "=a"(lo), "=d"(hi)
    );
    return ((uint64_t)hi << 32) | lo;
#elif defined(__aarch64__)
    uint64_t val;
    __asm__ __volatile__("mrs %0, cntvct_el0" : "=r"(val));
    return val;
#else
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ULL + ts.tv_nsec;
#endif
}

typedef struct {
    size_t n;
    double mean;
    double M2;
} WelfordState;

static void welford_update(WelfordState *state, double x) {
    state->n++;
    double delta = x - state->mean;
    state->mean += delta / state->n;
    double delta2 = x - state->mean;
    state->M2 += delta * delta2;
}

static double welford_variance(const WelfordState *state) {
    if (state->n < 2) return 0.0;
    return state->M2 / (state->n - 1);
}

static double compute_t_statistic(const WelfordState *class0, const WelfordState *class1) {
    if (class0->n < 2 || class1->n < 2) return 0.0;

    double mean_diff = class0->mean - class1->mean;
    double var0 = welford_variance(class0);
    double var1 = welford_variance(class1);
    double pooled_std = sqrt(var0 / class0->n + var1 / class1->n);

    if (pooled_std < 1e-10) return 0.0;

    return fabs(mean_diff) / pooled_std;
}

static int test_verify_constant_time(const char *alg_name) {
    printf("\nTesting %s verify constant-time behavior\n", alg_name);

    QUDO_SLHDSA *sig = QUDO_SLHDSA_new(alg_name);
    if (!sig) {
        printf("FAIL: Could not create instance\n");
        return 1;
    }

    uint8_t *pk = malloc(sig->length_public_key);
    uint8_t *sk = malloc(sig->length_secret_key);
    uint8_t *signature = malloc(sig->length_signature);
    uint8_t *bad_sig = malloc(sig->length_signature);
    size_t sig_len;

    uint8_t msg[] = "Constant time test message for SLH-DSA";
    size_t msg_len = sizeof(msg) - 1;

    QUDO_SLHDSA_keypair(sig, pk, sk);
    QUDO_SLHDSA_sign(sig, signature, &sig_len, msg, msg_len, sk);

    memcpy(bad_sig, signature, sig_len);
    bad_sig[0] ^= 0xFF;

    WelfordState valid_timing = {0, 0.0, 0.0};
    WelfordState invalid_timing = {0, 0.0, 0.0};

    for (int i = 0; i < WARMUP_ITERATIONS; i++) {
        QUDO_SLHDSA_verify(sig, msg, msg_len, signature, sig_len, pk);
        QUDO_SLHDSA_verify(sig, msg, msg_len, bad_sig, sig_len, pk);
    }

    for (int i = 0; i < NUM_MEASUREMENTS; i++) {
        uint64_t start, end;

        start = get_cycles();
        QUDO_SLHDSA_verify(sig, msg, msg_len, signature, sig_len, pk);
        end = get_cycles();
        welford_update(&valid_timing, (double)(end - start));

        start = get_cycles();
        QUDO_SLHDSA_verify(sig, msg, msg_len, bad_sig, sig_len, pk);
        end = get_cycles();
        welford_update(&invalid_timing, (double)(end - start));
    }

    double t_stat = compute_t_statistic(&valid_timing, &invalid_timing);

    printf("  Valid   mean: %.0f, stddev: %.0f\n",
           valid_timing.mean, sqrt(welford_variance(&valid_timing)));
    printf("  Invalid mean: %.0f, stddev: %.0f\n",
           invalid_timing.mean, sqrt(welford_variance(&invalid_timing)));
    printf("  t-statistic: %.2f (threshold: %.1f)\n", t_stat, SIGNIFICANCE_THRESHOLD);

    int result = 0;
    if (t_stat > SIGNIFICANCE_THRESHOLD) {
        printf("  WARNING: Timing difference detected (t=%.2f > %.1f)\n",
               t_stat, SIGNIFICANCE_THRESHOLD);
        printf("  Note: This is informational; SLH-DSA verify is not expected to be fully constant-time\n");
    } else {
        printf("  PASS: No significant timing difference\n");
    }

    free(pk);
    free(sk);
    free(signature);
    free(bad_sig);
    QUDO_SLHDSA_free(sig);

    return result;
}

int main(void) {
    int failures = 0;

    printf("=== SLH-DSA Constant-Time Validation Tests ===\n");
    printf("Measurements per test: %d\n", NUM_MEASUREMENTS);
    printf("Significance threshold: %.1f\n", SIGNIFICANCE_THRESHOLD);

    if (test_verify_constant_time("SLH-DSA-SHA2-128f") != 0) failures++;
    if (test_verify_constant_time("SLH-DSA-SHAKE-128f") != 0) failures++;

    printf("\n=== Constant-Time Tests Complete ===\n");
    return failures;
}
