/* SPDX-License-Identifier: Apache-2.0 AND MIT */

#include "mldsa_wrapper.h"
#include "mlkem_wrapper.h"
#include "qudo_pqc.h"
#include "qudo_pqc_platform.h"
#include "slhdsa_wrapper.h"
#include "test_fips_init.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int g_pass = 0;
static int g_fail = 0;
static int g_skip = 0;
static int g_verbose = 0;

#define VLOG(...)                       \
    do {                                \
        if (g_verbose)                  \
            printf("    " __VA_ARGS__); \
    } while (0)

#define RUN_TEST(fn)                       \
    do {                                   \
        if (g_verbose)                     \
            printf("  %s:\n", #fn);        \
        int _r = fn();                     \
        if (_r > 0) {                      \
            g_pass++;                      \
            printf("  %-55s PASS\n", #fn); \
        } else if (_r == 0) {              \
            g_fail++;                      \
            printf("  %-55s FAIL\n", #fn); \
        } else {                           \
            g_skip++;                      \
            printf("  %-55s SKIP\n", #fn); \
        }                                  \
    } while (0)

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

#else

#    define NO_THREADS 1
#endif

#define NUM_THREADS      8
#define ITERS_PER_THREAD 100
#define CRYPTO_ITERS     10

#ifndef NO_THREADS

static volatile int g_thread_error = 0;

static void secure_clear(void *p, size_t n)
{
    volatile uint8_t *v = (volatile uint8_t *)p;
    while (n--)
        *v++ = 0;
}

static THREAD_RETURN worker_rand_bytes(void *arg)
{
    int id = *(int *)arg;
    uint8_t buf[64];
    int i;
    (void)id;

    for (i = 0; i < ITERS_PER_THREAD; i++) {
        if (qudo_pqc_rand_bytes(buf, sizeof(buf)) != 0) {
            g_thread_error = 1;
            break;
        }
    }

    return THREAD_RETURN_VAL;
}

static THREAD_RETURN worker_get_state(void *arg)
{
    int id = *(int *)arg;
    int i;
    (void)id;

    for (i = 0; i < ITERS_PER_THREAD; i++) {
        int state = qudo_pqc_get_state();
        if (state != QUDO_PQC_STATE_RUNNING) {
            g_thread_error = 1;
            break;
        }

        if (!qudo_pqc_is_running()) {
            g_thread_error = 1;
            break;
        }
    }

    return THREAD_RETURN_VAL;
}

static THREAD_RETURN worker_cast_status(void *arg)
{
    int id = *(int *)arg;
    int i, cast_id;
    (void)id;

    for (i = 0; i < ITERS_PER_THREAD; i++) {
        for (cast_id = 0; cast_id < QUDO_CAST_COUNT; cast_id++) {
            int status = qudo_pqc_get_cast_status(cast_id);

            if (status < 0 || status == QUDO_CAST_STATE_PROCESSING) {
                g_thread_error = 1;
                break;
            }
        }
        if (g_thread_error)
            break;
    }

    return THREAD_RETURN_VAL;
}

static THREAD_RETURN worker_is_approved(void *arg)
{
    int id = *(int *)arg;
    int i;
    (void)id;

    static const char *algos[]
        = {"ML-KEM-512", "ML-KEM-768", "ML-KEM-1024",       "ML-DSA-44",
           "ML-DSA-65",  "ML-DSA-87",  "SLH-DSA-SHA2-128f", NULL};

    for (i = 0; i < ITERS_PER_THREAD; i++) {
        int a;
        for (a = 0; algos[a] != NULL; a++) {
            if (!qudo_pqc_is_fips_approved(algos[a])) {
                g_thread_error = 1;
                break;
            }
        }
        if (g_thread_error)
            break;
    }

    return THREAD_RETURN_VAL;
}

static THREAD_RETURN worker_crypto(void *arg)
{
    int id = *(int *)arg;
    int i;
    uint8_t msg[32];
    QUDO_KEM *kem = QUDO_KEM_new("ML-KEM-768");
    QUDO_MLDSA *dsa = QUDO_MLDSA_new("ML-DSA-65");
    QUDO_SLHDSA *slh = QUDO_SLHDSA_new("SLH-DSA-SHA2-128f");
    uint8_t *kpk = NULL, *ksk = NULL, *kct = NULL, *kss1 = NULL, *kss2 = NULL;
    uint8_t *dpk = NULL, *dsk = NULL, *dsig = NULL;
    uint8_t *spk = NULL, *ssk = NULL, *ssig = NULL;
    size_t siglen;
    (void)id;

    if (kem == NULL || dsa == NULL || slh == NULL) {
        g_thread_error = 1;
        goto done;
    }

    memset(msg, 0xA5, sizeof(msg));
    kpk = malloc(kem->length_public_key);
    ksk = malloc(kem->length_secret_key);
    kct = malloc(kem->length_ciphertext);
    kss1 = malloc(kem->length_shared_secret);
    kss2 = malloc(kem->length_shared_secret);
    dpk = malloc(dsa->length_public_key);
    dsk = malloc(dsa->length_secret_key);
    dsig = malloc(dsa->length_signature);
    spk = malloc(slh->length_public_key);
    ssk = malloc(slh->length_secret_key);
    ssig = malloc(slh->length_signature);
    if (kpk == NULL || ksk == NULL || kct == NULL || kss1 == NULL
        || kss2 == NULL || dpk == NULL || dsk == NULL || dsig == NULL
        || spk == NULL || ssk == NULL || ssig == NULL) {
        g_thread_error = 1;
        goto done;
    }

    for (i = 0; i < CRYPTO_ITERS; i++) {
        if (QUDO_KEM_keypair(kem, kpk, ksk) != QUDO_KEM_SUCCESS
            || QUDO_KEM_encaps(kem, kct, kss1, kpk) != QUDO_KEM_SUCCESS
            || QUDO_KEM_decaps(kem, kss2, kct, ksk) != QUDO_KEM_SUCCESS
            || memcmp(kss1, kss2, kem->length_shared_secret) != 0) {
            g_thread_error = 1;
            break;
        }

        siglen = dsa->length_signature;
        if (QUDO_MLDSA_keypair(dsa, dpk, dsk) != QUDO_MLDSA_SUCCESS
            || QUDO_MLDSA_sign(dsa, dsig, &siglen, msg, sizeof(msg), dsk)
                   != QUDO_MLDSA_SUCCESS
            || QUDO_MLDSA_verify(dsa, dsig, siglen, msg, sizeof(msg), dpk)
                   != QUDO_MLDSA_SUCCESS) {
            g_thread_error = 1;
            break;
        }

        siglen = slh->length_signature;
        if (QUDO_SLHDSA_keypair(slh, spk, ssk) != QUDO_SLHDSA_SUCCESS
            || QUDO_SLHDSA_sign(slh, ssig, &siglen, msg, sizeof(msg), ssk)
                   != QUDO_SLHDSA_SUCCESS
            || QUDO_SLHDSA_verify(slh, msg, sizeof(msg), ssig, siglen, spk)
                   != QUDO_SLHDSA_SUCCESS) {
            g_thread_error = 1;
            break;
        }
    }

done:
    if (ksk != NULL)
        secure_clear(ksk, kem->length_secret_key);
    if (dsk != NULL)
        secure_clear(dsk, dsa->length_secret_key);
    if (ssk != NULL)
        secure_clear(ssk, slh->length_secret_key);
    free(kpk);
    free(ksk);
    free(kct);
    free(kss1);
    free(kss2);
    free(dpk);
    free(dsk);
    free(dsig);
    free(spk);
    free(ssk);
    free(ssig);
    QUDO_KEM_free(kem);
    QUDO_MLDSA_free(dsa);
    QUDO_SLHDSA_free(slh);
    return THREAD_RETURN_VAL;
}

#endif

#ifdef NO_THREADS

static int test_concurrent_rand(void)
{
    return -1;
}
static int test_concurrent_state(void)
{
    return -1;
}
static int test_concurrent_cast(void)
{
    return -1;
}
static int test_concurrent_approved(void)
{
    return -1;
}
static int test_concurrent_crypto(void)
{
    return -1;
}

#else

static int test_concurrent_rand(void)
{
    thread_t threads[NUM_THREADS];
    int ids[NUM_THREADS];
    int i;

    g_thread_error = 0;

    for (i = 0; i < NUM_THREADS; i++) {
        ids[i] = i;
        if (thread_create(&threads[i], worker_rand_bytes, &ids[i]) != 0) {
            VLOG("failed to create thread %d\n", i);
            return 0;
        }
    }

    for (i = 0; i < NUM_THREADS; i++)
        thread_join(threads[i]);

    if (g_thread_error) {
        VLOG("rand_bytes failed in at least one thread\n");
        return 0;
    }

    VLOG("%d threads x %d iterations = %d concurrent rand_bytes calls OK\n",
         NUM_THREADS, ITERS_PER_THREAD, NUM_THREADS * ITERS_PER_THREAD);
    return 1;
}

static int test_concurrent_state(void)
{
    thread_t threads[NUM_THREADS];
    int ids[NUM_THREADS];
    int i;

    g_thread_error = 0;

    for (i = 0; i < NUM_THREADS; i++) {
        ids[i] = i;
        if (thread_create(&threads[i], worker_get_state, &ids[i]) != 0) {
            VLOG("failed to create thread %d\n", i);
            return 0;
        }
    }

    for (i = 0; i < NUM_THREADS; i++)
        thread_join(threads[i]);

    if (g_thread_error) {
        VLOG("state query inconsistency detected\n");
        return 0;
    }

    return 1;
}

static int test_concurrent_cast(void)
{
    thread_t threads[NUM_THREADS];
    int ids[NUM_THREADS];
    int i;

    g_thread_error = 0;

    for (i = 0; i < NUM_THREADS; i++) {
        ids[i] = i;
        if (thread_create(&threads[i], worker_cast_status, &ids[i]) != 0) {
            VLOG("failed to create thread %d\n", i);
            return 0;
        }
    }

    for (i = 0; i < NUM_THREADS; i++)
        thread_join(threads[i]);

    if (g_thread_error) {
        VLOG("CAST status inconsistency detected\n");
        return 0;
    }

    return 1;
}

static int test_concurrent_approved(void)
{
    thread_t threads[NUM_THREADS];
    int ids[NUM_THREADS];
    int i;

    g_thread_error = 0;

    for (i = 0; i < NUM_THREADS; i++) {
        ids[i] = i;
        if (thread_create(&threads[i], worker_is_approved, &ids[i]) != 0) {
            VLOG("failed to create thread %d\n", i);
            return 0;
        }
    }

    for (i = 0; i < NUM_THREADS; i++)
        thread_join(threads[i]);

    if (g_thread_error) {
        VLOG("approval query inconsistency detected\n");
        return 0;
    }

    return 1;
}

static int test_concurrent_crypto(void)
{
    thread_t threads[NUM_THREADS];
    int ids[NUM_THREADS];
    int i;

#    if defined(__has_feature)
#        if __has_feature(memory_sanitizer)
    /* MSan cannot instrument the assembly backends, so fresh keygen output
     * reads as uninitialised. */
    return -1;
#        endif
#    endif

    g_thread_error = 0;

    for (i = 0; i < NUM_THREADS; i++) {
        ids[i] = i;
        if (thread_create(&threads[i], worker_crypto, &ids[i]) != 0) {
            VLOG("failed to create thread %d\n", i);
            return 0;
        }
    }

    for (i = 0; i < NUM_THREADS; i++)
        thread_join(threads[i]);

    if (g_thread_error) {
        VLOG("concurrent crypto roundtrip failed in at least one thread\n");
        return 0;
    }

    VLOG("%d threads x %d iterations: concurrent ML-KEM/ML-DSA/SLH-DSA "
         "keygen+op+verify OK\n",
         NUM_THREADS, CRYPTO_ITERS);
    return 1;
}

#endif

int main(int argc, char *argv[])
{
    test_fips_init_set_args(&argc, argv);
    int i;

    for (i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-v") == 0 || strcmp(argv[i], "--verbose") == 0)
            g_verbose = 1;
    }

    printf("=== QUDO PQC Threading Tests ===\n");

#ifdef NO_THREADS
    printf("Threading not available on this platform — all tests will SKIP\n");
#else
    printf("Threads: %d, Iterations/thread: %d\n", NUM_THREADS,
           ITERS_PER_THREAD);
#endif

    if (test_fips_init() != 1) {
        printf("Module init failed — cannot run threading tests\n");
        return 1;
    }

    printf("\n--- Concurrent Operations ---\n");
    RUN_TEST(test_concurrent_rand);
    RUN_TEST(test_concurrent_state);
    RUN_TEST(test_concurrent_cast);
    RUN_TEST(test_concurrent_approved);
    RUN_TEST(test_concurrent_crypto);

    qudo_pqc_fini();

    printf("\n=== Results: %d passed, %d failed, %d skipped ===\n", g_pass,
           g_fail, g_skip);

    return g_fail > 0 ? 1 : 0;
}
