/* SPDX-License-Identifier: Apache-2.0 AND MIT */

#include "qudo_pqc_platform.h"
#include <stdlib.h>
#include <string.h>

#if defined(_WIN32)

struct qudo_rwlock_st {
    SRWLOCK srw;
};

QUDO_RWLOCK *qudo_rwlock_new(void)
{
    QUDO_RWLOCK *lock = (QUDO_RWLOCK *)calloc(1, sizeof(QUDO_RWLOCK));
    if (lock != NULL)
        InitializeSRWLock(&lock->srw);
    return lock;
}

int qudo_rwlock_rdlock(QUDO_RWLOCK *lock)
{
    if (lock == NULL)
        return 0;
    AcquireSRWLockShared(&lock->srw);
    return 1;
}

void qudo_rwlock_rdunlock(QUDO_RWLOCK *lock)
{
    if (lock != NULL)
        ReleaseSRWLockShared(&lock->srw);
}

int qudo_rwlock_wrlock(QUDO_RWLOCK *lock)
{
    if (lock == NULL)
        return 0;
    AcquireSRWLockExclusive(&lock->srw);
    return 1;
}

void qudo_rwlock_unlock(QUDO_RWLOCK *lock)
{
    if (lock != NULL)
        ReleaseSRWLockExclusive(&lock->srw);
}

void qudo_rwlock_free(QUDO_RWLOCK *lock)
{
    free(lock);
}

#elif defined(__APPLE__) || defined(__linux__) || defined(__unix__)

struct qudo_rwlock_st {
    pthread_rwlock_t rwl;
};

QUDO_RWLOCK *qudo_rwlock_new(void)
{
    QUDO_RWLOCK *lock = (QUDO_RWLOCK *)calloc(1, sizeof(QUDO_RWLOCK));
    if (lock != NULL) {
        if (pthread_rwlock_init(&lock->rwl, NULL) != 0) {
            free(lock);
            return NULL;
        }
    }
    return lock;
}

int qudo_rwlock_rdlock(QUDO_RWLOCK *lock)
{
    if (lock == NULL)
        return 0;
    return (pthread_rwlock_rdlock(&lock->rwl) == 0) ? 1 : 0;
}

void qudo_rwlock_rdunlock(QUDO_RWLOCK *lock)
{
    if (lock != NULL)
        pthread_rwlock_unlock(&lock->rwl);
}

int qudo_rwlock_wrlock(QUDO_RWLOCK *lock)
{
    if (lock == NULL)
        return 0;
    return (pthread_rwlock_wrlock(&lock->rwl) == 0) ? 1 : 0;
}

void qudo_rwlock_unlock(QUDO_RWLOCK *lock)
{
    if (lock != NULL)
        pthread_rwlock_unlock(&lock->rwl);
}

void qudo_rwlock_free(QUDO_RWLOCK *lock)
{
    if (lock != NULL) {
        pthread_rwlock_destroy(&lock->rwl);
        free(lock);
    }
}

#else

struct qudo_rwlock_st {
    int dummy;
};

QUDO_RWLOCK *qudo_rwlock_new(void)
{
    return (QUDO_RWLOCK *)calloc(1, sizeof(QUDO_RWLOCK));
}

int qudo_rwlock_rdlock(QUDO_RWLOCK *lock)
{
    (void)lock;
    return 1;
}

void qudo_rwlock_rdunlock(QUDO_RWLOCK *lock)
{
    (void)lock;
}

int qudo_rwlock_wrlock(QUDO_RWLOCK *lock)
{
    (void)lock;
    return 1;
}

void qudo_rwlock_unlock(QUDO_RWLOCK *lock)
{
    (void)lock;
}

void qudo_rwlock_free(QUDO_RWLOCK *lock)
{
    free(lock);
}

#endif

#if defined(_WIN32)

static BOOL CALLBACK qudo_once_callback(PINIT_ONCE once, PVOID param,
                                        PVOID *context)
{
    void (*init_fn)(void) = (void (*)(void))param;
    (void)once;
    (void)context;
    init_fn();
    return TRUE;
}

int qudo_once(QUDO_ONCE *once, void (*init_fn)(void))
{
    if (once == NULL || init_fn == NULL)
        return 0;
    return InitOnceExecuteOnce(once, qudo_once_callback, (PVOID)init_fn, NULL)
               ? 1
               : 0;
}

#elif defined(__APPLE__) || defined(__linux__) || defined(__unix__)

int qudo_once(QUDO_ONCE *once, void (*init_fn)(void))
{
    if (once == NULL || init_fn == NULL)
        return 0;
    return (pthread_once(once, init_fn) == 0) ? 1 : 0;
}

#else

int qudo_once(QUDO_ONCE *once, void (*init_fn)(void))
{
    if (once == NULL || init_fn == NULL)
        return 0;
    if (*once == 0) {
        *once = 1;
        init_fn();
    }
    return 1;
}

#endif

void qudo_once_reset(QUDO_ONCE *once)
{
    QUDO_ONCE fresh = QUDO_ONCE_INIT;
    if (once != NULL)
        *once = fresh;
}

void *qudo_malloc(size_t size)
{
    if (size == 0)
        return NULL;
    return malloc(size);
}

void *qudo_zalloc(size_t size)
{
    void *ptr;

    if (size == 0)
        return NULL;
    ptr = malloc(size);
    if (ptr != NULL)
        memset(ptr, 0, size);
    return ptr;
}

void qudo_free(void *ptr)
{
    free(ptr);
}

#include "fips/qudo_fips_aes.h"

void qudo_cleanse(void *ptr, size_t len)
{
    if (ptr == NULL || len == 0)
        return;
    qudo_secure_clear(ptr, len);
}

int qudo_memcmp_ct(const void *a, const void *b, size_t len)
{
    const volatile unsigned char *pa = (const volatile unsigned char *)a;
    const volatile unsigned char *pb = (const volatile unsigned char *)b;
    volatile unsigned int diff = 0;
    size_t i;

    for (i = 0; i < len; i++)
        diff |= pa[i] ^ pb[i];

    return (diff != 0);
}
