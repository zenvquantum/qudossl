/* SPDX-License-Identifier: Apache-2.0 AND MIT */

#include "mldsa_wrapper.h"
#include "mlkem_wrapper.h"
#include "qudo_pqc.h"
#include "qudo_pqc_platform.h"
#include "slhdsa_wrapper.h"
#include "test_fips_init.h"
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#if defined(_MSC_VER)
#    include <intrin.h>
#    define QUDO_ATOMIC_INC(p) \
        ((void)_InterlockedIncrement((long volatile *)(p)))
#else
#    define QUDO_ATOMIC_INC(p) \
        ((void)__atomic_add_fetch((p), 1, __ATOMIC_RELAXED))
#endif

#if defined(_WIN32)
#    include <process.h>
#    include <windows.h>
typedef HANDLE thread_t;
static int thread_create(thread_t *t, unsigned(__stdcall *fn)(void *),
                         void *arg)
{
    *t = (HANDLE)_beginthreadex(NULL, 0, fn, arg, 0, NULL);
    return (*t != NULL) ? 0 : -1;
}
static void thread_join(thread_t t)
{
    WaitForSingleObject(t, INFINITE);
    CloseHandle(t);
}
#    define THREAD_RETURN     unsigned __stdcall
#    define THREAD_RETURN_VAL 0
typedef unsigned(__stdcall *worker_fn_t)(void *);
#elif defined(__unix__) || defined(__APPLE__)
#    include <pthread.h>
typedef pthread_t thread_t;
static int thread_create(thread_t *t, void *(*fn)(void *), void *arg)
{
    return pthread_create(t, NULL, fn, arg);
}
static void thread_join(thread_t t)
{
    pthread_join(t, NULL);
}
#    define THREAD_RETURN     void *
#    define THREAD_RETURN_VAL NULL
typedef void *(*worker_fn_t)(void *);
#else
#    define NO_THREADS 1
#endif

#define NUM_THREADS      8
#define ITERS_PER_THREAD 8

typedef struct {
    unsigned int begin_magic;
    int phase_count;
} shadow_event_t;

static volatile int g_begin_total = 0;
static volatile int g_end_total = 0;
static volatile int g_error = 0;

static int shadow_cb(qudo_st_phase_t phase, const char *type, const char *desc,
                     int result, unsigned char *data, void **event,
                     void *cb_arg)
{
    shadow_event_t *ev;

    (void)type;
    (void)desc;
    (void)result;
    (void)data;
    (void)cb_arg;

    if (event == NULL) {

        return 1;
    }

    switch (phase) {
    case QUDO_ST_PHASE_BEGIN:
        ev = (shadow_event_t *)malloc(sizeof(*ev));
        if (ev == NULL) {
            g_error = 1;
            return 0;
        }
        ev->begin_magic = 0xBEEFCAFEu;
        ev->phase_count = 1;
        *event = ev;
        QUDO_ATOMIC_INC(&g_begin_total);
        break;
    case QUDO_ST_PHASE_CORRUPT:
        ev = (shadow_event_t *)*event;
        if (ev == NULL || ev->begin_magic != 0xBEEFCAFEu) {
            g_error = 1;
            return 0;
        }
        ev->phase_count++;
        break;
    case QUDO_ST_PHASE_END:
        ev = (shadow_event_t *)*event;
        if (ev == NULL || ev->begin_magic != 0xBEEFCAFEu) {
            g_error = 1;
            return 1;
        }
        ev->begin_magic = 0;
        free(ev);
        *event = NULL;
        QUDO_ATOMIC_INC(&g_end_total);
        break;
    }
    return 1;
}

#ifndef NO_THREADS

static THREAD_RETURN worker_mlkem(void *arg)
{
    int i;
    QUDO_KEM *kem;
    uint8_t *pk, *sk;

    (void)arg;
    kem = QUDO_KEM_new("ML-KEM-512");
    if (kem == NULL) {
        g_error = 1;
        return THREAD_RETURN_VAL;
    }
    pk = (uint8_t *)malloc(kem->length_public_key);
    sk = (uint8_t *)malloc(kem->length_secret_key);
    if (pk == NULL || sk == NULL) {
        g_error = 1;
        goto done;
    }
    for (i = 0; i < ITERS_PER_THREAD; i++) {
        if (QUDO_KEM_keypair(kem, pk, sk) != QUDO_KEM_SUCCESS) {
            g_error = 1;
            break;
        }
    }
done:
    free(pk);
    if (sk != NULL) {
        qudo_cleanse(sk, kem->length_secret_key);
        free(sk);
    }
    QUDO_KEM_free(kem);
    return THREAD_RETURN_VAL;
}

static THREAD_RETURN worker_mldsa(void *arg)
{
    int i;
    QUDO_MLDSA *sig;
    uint8_t *pk, *sk;

    (void)arg;
    sig = QUDO_MLDSA_new("ML-DSA-44");
    if (sig == NULL) {
        g_error = 1;
        return THREAD_RETURN_VAL;
    }
    pk = (uint8_t *)malloc(sig->length_public_key);
    sk = (uint8_t *)malloc(sig->length_secret_key);
    if (pk == NULL || sk == NULL) {
        g_error = 1;
        goto done;
    }
    for (i = 0; i < ITERS_PER_THREAD; i++) {
        if (QUDO_MLDSA_keypair(sig, pk, sk) != QUDO_MLDSA_SUCCESS) {
            g_error = 1;
            break;
        }
    }
done:
    free(pk);
    if (sk != NULL) {
        qudo_cleanse(sk, sig->length_secret_key);
        free(sk);
    }
    QUDO_MLDSA_free(sig);
    return THREAD_RETURN_VAL;
}

static THREAD_RETURN worker_slhdsa(void *arg)
{
    int i;
    QUDO_SLHDSA *sig;
    uint8_t *pk, *sk;

    (void)arg;
    sig = QUDO_SLHDSA_new("SLH-DSA-SHA2-128f");
    if (sig == NULL) {
        g_error = 1;
        return THREAD_RETURN_VAL;
    }
    pk = (uint8_t *)malloc(sig->length_public_key);
    sk = (uint8_t *)malloc(sig->length_secret_key);
    if (pk == NULL || sk == NULL) {
        g_error = 1;
        goto done;
    }
    for (i = 0; i < ITERS_PER_THREAD; i++) {
        if (QUDO_SLHDSA_keypair(sig, pk, sk) != QUDO_SLHDSA_SUCCESS) {
            g_error = 1;
            break;
        }
    }
done:
    free(pk);
    if (sk != NULL) {
        qudo_cleanse(sk, sig->length_secret_key);
        free(sk);
    }
    QUDO_SLHDSA_free(sig);
    return THREAD_RETURN_VAL;
}

static int run_concurrent(worker_fn_t fn, const char *label)
{
    thread_t threads[NUM_THREADS];
    int i;
    int n_started = 0;

    g_error = 0;

    for (i = 0; i < NUM_THREADS; i++) {
        if (thread_create(&threads[i], fn, NULL) != 0) {
            fprintf(stderr, "    %s: thread_create %d failed\n", label, i);
            break;
        }
        n_started++;
    }
    for (i = 0; i < n_started; i++)
        thread_join(threads[i]);

    if (n_started != NUM_THREADS) {
        fprintf(stderr, "    %s: only %d/%d threads started\n", label,
                n_started, NUM_THREADS);
        return 0;
    }
    if (g_error) {
        fprintf(stderr, "    %s: worker reported failure\n", label);
        return 0;
    }
    printf("  %-16s %d threads x %d iterations OK\n", label, NUM_THREADS,
           ITERS_PER_THREAD);
    return 1;
}

#endif

int main(int argc, char **argv)
{
    qudo_pqc_config_t cfg;
    int pass = 0;
    int fail = 0;

    test_fips_init_set_args(&argc, argv);

    printf("=== QUDO PQC Concurrent PCT ===\n");
#ifdef NO_THREADS
    printf("Threading not available — SKIP\n");
    return 0;
#else
    memset(&cfg, 0, sizeof(cfg));
    cfg.self_test_cb = shadow_cb;
    cfg.self_test_cb_arg = NULL;
    cfg.conditional_errors = 1;
    if (test_fips_fill_config(&cfg) < 0) {
        fprintf(stderr, "failed to parse --fips-cnf\n");
        return 1;
    }

    if (qudo_pqc_init(&cfg) != 1) {
        fprintf(stderr, "qudo_pqc_init failed\n");
        return 1;
    }

    printf("Threads: %d, Iterations/thread: %d\n", NUM_THREADS,
           ITERS_PER_THREAD);

    if (run_concurrent(worker_mlkem, "ML-KEM-512"))
        pass++;
    else
        fail++;
    if (run_concurrent(worker_mldsa, "ML-DSA-44"))
        pass++;
    else
        fail++;
    if (run_concurrent(worker_slhdsa, "SLH-DSA-128f"))
        pass++;
    else
        fail++;

    printf("begin_total=%d end_total=%d\n", g_begin_total, g_end_total);
    if (g_begin_total != g_end_total) {
        fprintf(stderr, "begin/end mismatch: leaked per-call event slot\n");
        fail++;
    }

    qudo_pqc_fini();

    printf("=== Results: %d passed, %d failed ===\n", pass, fail);
    return fail > 0 ? 1 : 0;
#endif
}
