/* SPDX-License-Identifier: Apache-2.0 AND MIT */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include <time.h>

#ifdef _WIN32
#include <windows.h>
#elif defined(__APPLE__)
#include <sys/time.h>
#include <mach/mach_time.h>
#else
#include <sys/time.h>
#endif

#include "mlkem_wrapper.h"

#define BENCHMARK_SECONDS 3

#define OUTLIER_THRESHOLD 3.0

#ifdef _WIN32
static int gettimeofday(struct timeval *tp, struct timezone *tzp) {
    SYSTEMTIME system_time;
    FILETIME file_time;
    uint64_t time;
    static const uint64_t EPOCH = ((uint64_t) 116444736000000000ULL);

    GetSystemTime(&system_time);
    SystemTimeToFileTime(&system_time, &file_time);
    time = ((uint64_t) file_time.dwLowDateTime);
    time += ((uint64_t) file_time.dwHighDateTime) << 32;
    tp->tv_sec = (long) ((time - EPOCH) / 10000000L);
    tp->tv_usec = (long) (system_time.wMilliseconds * 1000);
    return 0;
}
#endif

static uint64_t rdtsc(void) {
#if defined(_WIN32) || defined(_WIN64)
    LARGE_INTEGER li;
    QueryPerformanceCounter(&li);
    return li.QuadPart;
#elif defined(__i386__) || defined(__x86_64__)
    unsigned int lo, hi;
    __asm__ __volatile__ ("rdtsc" : "=a" (lo), "=d" (hi));
    return ((uint64_t)hi << 32) | lo;
#elif defined(__APPLE__)
    return mach_absolute_time();
#else
    struct timespec time;
    clock_gettime(CLOCK_MONOTONIC, &time);
    return (uint64_t)((double)time.tv_sec * 1e9 + (double)time.tv_nsec);
#endif
}

typedef struct {
    volatile uint64_t cycles_start, cycles_end;
    uint64_t cycles_cumulative;
    uint64_t cycles_diff;
    struct timeval timeval_start, timeval_end;
    uint64_t iterations;
    uint64_t iterations_valid;
    uint64_t time_cumulative;
    double cycles_mean, cycles_M2, cycles_stdev;
    double time_mean, time_M2, time_stdev;
    double cycles_median_estimate;
} bench_timer_t;

static void timer_init(bench_timer_t *t) {
    memset(t, 0, sizeof(bench_timer_t));
}

static void timer_start(bench_timer_t *t) {
    gettimeofday(&t->timeval_start, NULL);
    t->cycles_start = rdtsc();
}

static void timer_stop(bench_timer_t *t) {
    t->cycles_end = rdtsc();
    gettimeofday(&t->timeval_end, NULL);
    t->iterations += 1;

    if (t->cycles_end < t->cycles_start) {
        t->cycles_end += (uint64_t)1 << 32;
    }

    t->cycles_diff = t->cycles_end - t->cycles_start;
    t->cycles_cumulative += t->cycles_diff;

    double time_x = (double)(
        ((uint64_t)t->timeval_end.tv_sec * 1000000 + (uint64_t)t->timeval_end.tv_usec) -
        ((uint64_t)t->timeval_start.tv_sec * 1000000 + (uint64_t)t->timeval_start.tv_usec)
    );

    double cycles_x = (double)t->cycles_diff;
    if (t->iterations == 1) {
        t->cycles_median_estimate = cycles_x;
    } else {
        t->cycles_median_estimate += 0.1 * (cycles_x - t->cycles_median_estimate);
    }

    double expected_time_from_cycles = cycles_x * 0.0004;
    int is_outlier = (time_x > expected_time_from_cycles * OUTLIER_THRESHOLD);

    if (!is_outlier) {
        t->iterations_valid += 1;

        double cycles_delta = cycles_x - t->cycles_mean;
        t->cycles_mean += cycles_delta / (double)t->iterations_valid;
        t->cycles_M2 += cycles_delta * (cycles_x - t->cycles_mean);

        double time_delta = time_x - t->time_mean;
        t->time_mean += time_delta / (double)t->iterations_valid;
        t->time_M2 += time_delta * (time_x - t->time_mean);
    }

    t->time_cumulative += (uint64_t)time_x;
}

static void timer_finalize(bench_timer_t *t) {
    if (t->iterations_valid < 2) {
        t->cycles_stdev = 0.0;
        t->time_stdev = 0.0;
    } else {
        t->cycles_stdev = sqrt(t->cycles_M2 / (double)t->iterations_valid);
        t->time_stdev = sqrt(t->time_M2 / (double)t->iterations_valid);
    }
}

static const char* level_to_string(QUDO_KEM_security_level_t level) {
    switch (level) {
        case QUDO_KEM_512: return "ML-KEM-512";
        case QUDO_KEM_768: return "ML-KEM-768";
        case QUDO_KEM_1024: return "ML-KEM-1024";
        default: return NULL;
    }
}

static void benchmark_keypair_direct(QUDO_KEM_security_level_t level, const char *name) {
    bench_timer_t timer;
    timer_init(&timer);

    size_t pk_len = QUDO_KEM_get_public_key_size(level);
    size_t sk_len = QUDO_KEM_get_secret_key_size(level);

    uint8_t *pk = malloc(pk_len);
    uint8_t *sk = malloc(sk_len);

    if (!pk || !sk) {
        fprintf(stderr, "Memory allocation failed\n");
        free(pk); free(sk);
        return;
    }

    uint64_t time_goal_usecs = BENCHMARK_SECONDS * 1000000;

    while (timer.time_cumulative < time_goal_usecs) {
        timer_start(&timer);
        QUDO_KEM_keypair_generate(level, pk, sk);
        timer_stop(&timer);
    }

    timer_finalize(&timer);

    printf("%-30s | %10s | %12.2f ± %-8.2f | %12llu | %10llu (%llu valid)\n",
           name, "keypair",
           timer.time_mean, timer.time_stdev,
           (unsigned long long)timer.cycles_mean,
           (unsigned long long)timer.iterations_valid,
           (unsigned long long)timer.iterations);

    free(pk);
    free(sk);
}

static void benchmark_encaps_direct(QUDO_KEM_security_level_t level, const char *name) {
    bench_timer_t timer;
    timer_init(&timer);

    size_t pk_len = QUDO_KEM_get_public_key_size(level);
    size_t sk_len = QUDO_KEM_get_secret_key_size(level);
    size_t ct_len = QUDO_KEM_get_ciphertext_size(level);
    size_t ss_len = QUDO_KEM_get_shared_secret_size(level);

    uint8_t *pk = malloc(pk_len);
    uint8_t *sk = malloc(sk_len);
    uint8_t *ct = malloc(ct_len);
    uint8_t *ss = malloc(ss_len);

    if (!pk || !sk || !ct || !ss) {
        fprintf(stderr, "Memory allocation failed\n");
        free(pk); free(sk); free(ct); free(ss);
        return;
    }

    QUDO_KEM_keypair_generate(level, pk, sk);

    uint64_t time_goal_usecs = BENCHMARK_SECONDS * 1000000;

    while (timer.time_cumulative < time_goal_usecs) {
        timer_start(&timer);
        QUDO_KEM_encapsulate(level, ct, ss, pk);
        timer_stop(&timer);
    }

    timer_finalize(&timer);

    printf("%-30s | %10s | %12.2f ± %-8.2f | %12llu | %10llu (%llu valid)\n",
           name, "encaps",
           timer.time_mean, timer.time_stdev,
           (unsigned long long)timer.cycles_mean,
           (unsigned long long)timer.iterations_valid,
           (unsigned long long)timer.iterations);

    free(pk); free(sk); free(ct); free(ss);
}

static void benchmark_decaps_direct(QUDO_KEM_security_level_t level, const char *name) {
    bench_timer_t timer;
    timer_init(&timer);

    size_t pk_len = QUDO_KEM_get_public_key_size(level);
    size_t sk_len = QUDO_KEM_get_secret_key_size(level);
    size_t ct_len = QUDO_KEM_get_ciphertext_size(level);
    size_t ss_len = QUDO_KEM_get_shared_secret_size(level);

    uint8_t *pk = malloc(pk_len);
    uint8_t *sk = malloc(sk_len);
    uint8_t *ct = malloc(ct_len);
    uint8_t *ss = malloc(ss_len);

    if (!pk || !sk || !ct || !ss) {
        fprintf(stderr, "Memory allocation failed\n");
        free(pk); free(sk); free(ct); free(ss);
        return;
    }

    QUDO_KEM_keypair_generate(level, pk, sk);
    QUDO_KEM_encapsulate(level, ct, ss, pk);

    uint64_t time_goal_usecs = BENCHMARK_SECONDS * 1000000;

    while (timer.time_cumulative < time_goal_usecs) {
        timer_start(&timer);
        QUDO_KEM_decapsulate(level, ss, ct, sk);
        timer_stop(&timer);
    }

    timer_finalize(&timer);

    printf("%-30s | %10s | %12.2f ± %-8.2f | %12llu | %10llu (%llu valid)\n",
           name, "decaps",
           timer.time_mean, timer.time_stdev,
           (unsigned long long)timer.cycles_mean,
           (unsigned long long)timer.iterations_valid,
           (unsigned long long)timer.iterations);

    free(pk); free(sk); free(ct); free(ss);
}

static void benchmark_keypair_object(QUDO_KEM_security_level_t level, const char *name) {
    bench_timer_t timer;
    timer_init(&timer);

    QUDO_KEM *kem = QUDO_KEM_new(level_to_string(level));
    if (!kem) {
        fprintf(stderr, "QUDO_KEM_new failed\n");
        return;
    }

    size_t pk_len = QUDO_KEM_get_public_key_size(level);
    size_t sk_len = QUDO_KEM_get_secret_key_size(level);

    uint8_t *pk = malloc(pk_len);
    uint8_t *sk = malloc(sk_len);

    if (!pk || !sk) {
        fprintf(stderr, "Memory allocation failed\n");
        free(pk); free(sk);
        QUDO_KEM_free(kem);
        return;
    }

    uint64_t time_goal_usecs = BENCHMARK_SECONDS * 1000000;

    while (timer.time_cumulative < time_goal_usecs) {
        timer_start(&timer);
        kem->keypair( pk, sk);
        timer_stop(&timer);
    }

    timer_finalize(&timer);

    printf("%-30s | %10s | %12.2f ± %-8.2f | %12llu | %10llu (%llu valid)\n",
           name, "keypair",
           timer.time_mean, timer.time_stdev,
           (unsigned long long)timer.cycles_mean,
           (unsigned long long)timer.iterations_valid,
           (unsigned long long)timer.iterations);

    free(pk); free(sk);
    QUDO_KEM_free(kem);
}

static void benchmark_encaps_object(QUDO_KEM_security_level_t level, const char *name) {
    bench_timer_t timer;
    timer_init(&timer);

    QUDO_KEM *kem = QUDO_KEM_new(level_to_string(level));
    if (!kem) {
        fprintf(stderr, "QUDO_KEM_new failed\n");
        return;
    }

    size_t pk_len = QUDO_KEM_get_public_key_size(level);
    size_t sk_len = QUDO_KEM_get_secret_key_size(level);
    size_t ct_len = QUDO_KEM_get_ciphertext_size(level);
    size_t ss_len = QUDO_KEM_get_shared_secret_size(level);

    uint8_t *pk = malloc(pk_len);
    uint8_t *sk = malloc(sk_len);
    uint8_t *ct = malloc(ct_len);
    uint8_t *ss = malloc(ss_len);

    if (!pk || !sk || !ct || !ss) {
        fprintf(stderr, "Memory allocation failed\n");
        free(pk); free(sk); free(ct); free(ss);
        QUDO_KEM_free(kem);
        return;
    }

    kem->keypair( pk, sk);

    uint64_t time_goal_usecs = BENCHMARK_SECONDS * 1000000;

    while (timer.time_cumulative < time_goal_usecs) {
        timer_start(&timer);
        kem->encaps( ct, ss, pk);
        timer_stop(&timer);
    }

    timer_finalize(&timer);

    printf("%-30s | %10s | %12.2f ± %-8.2f | %12llu | %10llu (%llu valid)\n",
           name, "encaps",
           timer.time_mean, timer.time_stdev,
           (unsigned long long)timer.cycles_mean,
           (unsigned long long)timer.iterations_valid,
           (unsigned long long)timer.iterations);

    free(pk); free(sk); free(ct); free(ss);
    QUDO_KEM_free(kem);
}

static void benchmark_decaps_object(QUDO_KEM_security_level_t level, const char *name) {
    bench_timer_t timer;
    timer_init(&timer);

    QUDO_KEM *kem = QUDO_KEM_new(level_to_string(level));
    if (!kem) {
        fprintf(stderr, "QUDO_KEM_new failed\n");
        return;
    }

    size_t pk_len = QUDO_KEM_get_public_key_size(level);
    size_t sk_len = QUDO_KEM_get_secret_key_size(level);
    size_t ct_len = QUDO_KEM_get_ciphertext_size(level);
    size_t ss_len = QUDO_KEM_get_shared_secret_size(level);

    uint8_t *pk = malloc(pk_len);
    uint8_t *sk = malloc(sk_len);
    uint8_t *ct = malloc(ct_len);
    uint8_t *ss = malloc(ss_len);

    if (!pk || !sk || !ct || !ss) {
        fprintf(stderr, "Memory allocation failed\n");
        free(pk); free(sk); free(ct); free(ss);
        QUDO_KEM_free(kem);
        return;
    }

    kem->keypair( pk, sk);
    kem->encaps( ct, ss, pk);

    uint64_t time_goal_usecs = BENCHMARK_SECONDS * 1000000;

    while (timer.time_cumulative < time_goal_usecs) {
        timer_start(&timer);
        kem->decaps( ss, ct, sk);
        timer_stop(&timer);
    }

    timer_finalize(&timer);

    printf("%-30s | %10s | %12.2f ± %-8.2f | %12llu | %10llu (%llu valid)\n",
           name, "decaps",
           timer.time_mean, timer.time_stdev,
           (unsigned long long)timer.cycles_mean,
           (unsigned long long)timer.iterations_valid,
           (unsigned long long)timer.iterations);

    free(pk); free(sk); free(ct); free(ss);
    QUDO_KEM_free(kem);
}

int main(void) {
    if (QUDO_KEM_init() != QUDO_KEM_SUCCESS) {
        fprintf(stderr, "Failed to initialize QUDO KEM\n");
        return 1;
    }

    printf("╔════════════════════════════════════════════════════════════════════════════════╗\n");
    printf("║  ML-KEM Performance Benchmark - QUDO KEM Library                              ║\n");
    printf("║  %d seconds per operation | Mean ± Std Dev | CPU Cycles                      ║\n", BENCHMARK_SECONDS);
    printf("╚════════════════════════════════════════════════════════════════════════════════╝\n\n");

    printf("%-30s | %-10s | %-22s | %-12s | %-10s\n",
           "Algorithm", "Operation", "Time (μs)", "CPU Cycles", "Iterations");
    printf("─────────────────────────────────────────────────────────────────────────────────────────\n");

    benchmark_keypair_direct(QUDO_KEM_512, "ML-KEM-512 (Direct API)");
    benchmark_encaps_direct(QUDO_KEM_512, "ML-KEM-512 (Direct API)");
    benchmark_decaps_direct(QUDO_KEM_512, "ML-KEM-512 (Direct API)");

    benchmark_keypair_direct(QUDO_KEM_768, "ML-KEM-768 (Direct API)");
    benchmark_encaps_direct(QUDO_KEM_768, "ML-KEM-768 (Direct API)");
    benchmark_decaps_direct(QUDO_KEM_768, "ML-KEM-768 (Direct API)");

    benchmark_keypair_direct(QUDO_KEM_1024, "ML-KEM-1024 (Direct API)");
    benchmark_encaps_direct(QUDO_KEM_1024, "ML-KEM-1024 (Direct API)");
    benchmark_decaps_direct(QUDO_KEM_1024, "ML-KEM-1024 (Direct API)");

    printf("─────────────────────────────────────────────────────────────────────────────────────────\n");

    benchmark_keypair_object(QUDO_KEM_512, "ML-KEM-512 (Object API)");
    benchmark_encaps_object(QUDO_KEM_512, "ML-KEM-512 (Object API)");
    benchmark_decaps_object(QUDO_KEM_512, "ML-KEM-512 (Object API)");

    benchmark_keypair_object(QUDO_KEM_768, "ML-KEM-768 (Object API)");
    benchmark_encaps_object(QUDO_KEM_768, "ML-KEM-768 (Object API)");
    benchmark_decaps_object(QUDO_KEM_768, "ML-KEM-768 (Object API)");

    benchmark_keypair_object(QUDO_KEM_1024, "ML-KEM-1024 (Object API)");
    benchmark_encaps_object(QUDO_KEM_1024, "ML-KEM-1024 (Object API)");
    benchmark_decaps_object(QUDO_KEM_1024, "ML-KEM-1024 (Object API)");

    printf("─────────────────────────────────────────────────────────────────────────────────────────\n");
    printf("\nBenchmark completed!\n");

    return 0;
}
