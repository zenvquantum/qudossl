/* SPDX-License-Identifier: Apache-2.0 AND MIT */

#ifndef QUDO_PQC_PLATFORM_H
#define QUDO_PQC_PLATFORM_H

#include <stddef.h>
#include <stdint.h>

#ifndef QUDO_PQC_API
#    if defined(_WIN32) || defined(__CYGWIN__)
#        ifdef QUDO_PQC_BUILDING
#            define QUDO_PQC_API __declspec(dllexport)
#        else
#            define QUDO_PQC_API __declspec(dllimport)
#        endif
#    elif defined(__GNUC__) && __GNUC__ >= 4
#        define QUDO_PQC_API __attribute__((visibility("default")))
#    else
#        define QUDO_PQC_API
#    endif
#endif

#ifdef __cplusplus
extern "C" {
#endif

typedef struct qudo_rwlock_st QUDO_RWLOCK;

QUDO_PQC_API QUDO_RWLOCK *qudo_rwlock_new(void);

QUDO_PQC_API int qudo_rwlock_rdlock(QUDO_RWLOCK *lock);

QUDO_PQC_API void qudo_rwlock_rdunlock(QUDO_RWLOCK *lock);

QUDO_PQC_API int qudo_rwlock_wrlock(QUDO_RWLOCK *lock);

QUDO_PQC_API void qudo_rwlock_unlock(QUDO_RWLOCK *lock);

QUDO_PQC_API void qudo_rwlock_free(QUDO_RWLOCK *lock);

#if defined(_WIN32)
#    ifndef WIN32_LEAN_AND_MEAN
#        define WIN32_LEAN_AND_MEAN
#    endif
#    include <windows.h>
typedef INIT_ONCE QUDO_ONCE;
#    define QUDO_ONCE_INIT INIT_ONCE_STATIC_INIT
#elif defined(__APPLE__) || defined(__linux__) || defined(__unix__)
#    include <pthread.h>
typedef pthread_once_t QUDO_ONCE;
#    define QUDO_ONCE_INIT PTHREAD_ONCE_INIT
#else
typedef int QUDO_ONCE;
#    define QUDO_ONCE_INIT 0
#endif

QUDO_PQC_API int qudo_once(QUDO_ONCE *once, void (*init_fn)(void));

QUDO_PQC_API void qudo_once_reset(QUDO_ONCE *once);

QUDO_PQC_API void *qudo_malloc(size_t size);

QUDO_PQC_API void *qudo_zalloc(size_t size);

QUDO_PQC_API void qudo_free(void *ptr);

QUDO_PQC_API void qudo_cleanse(void *ptr, size_t len);

QUDO_PQC_API int qudo_memcmp_ct(const void *a, const void *b, size_t len);

#if defined(__STDC_VERSION__) && __STDC_VERSION__ >= 201112L \
    && !defined(__STDC_NO_ATOMICS__)
#    include <stdatomic.h>
#    if defined(ATOMIC_POINTER_LOCK_FREE) && ATOMIC_POINTER_LOCK_FREE >= 2
#        define QUDO_ATOMIC_QUALIFIER _Atomic
#        define qudo_atomic_load(ptr) \
            atomic_load_explicit((ptr), memory_order_relaxed)
#        define qudo_atomic_store(ptr, val) \
            atomic_store_explicit((ptr), (val), memory_order_relaxed)
#        define qudo_atomic_inc(ptr) \
            atomic_fetch_add_explicit((ptr), 1, memory_order_relaxed)
#    endif
#endif

#ifndef QUDO_ATOMIC_QUALIFIER
#    if defined(__GNUC__) && defined(__ATOMIC_RELAXED)
#        if defined(__GCC_ATOMIC_POINTER_LOCK_FREE) \
            && __GCC_ATOMIC_POINTER_LOCK_FREE >= 2
#            define QUDO_ATOMIC_QUALIFIER volatile
#            define qudo_atomic_load(ptr) \
                __atomic_load_n((ptr), __ATOMIC_RELAXED)
#            define qudo_atomic_store(ptr, val) \
                __atomic_store_n((ptr), (val), __ATOMIC_RELAXED)
#            define qudo_atomic_inc(ptr) \
                __atomic_fetch_add((ptr), 1, __ATOMIC_RELAXED)
#        endif
#    endif
#endif

#ifndef QUDO_ATOMIC_QUALIFIER
#    if defined(_MSC_VER) && _MSC_VER >= 1200                        \
        && (defined(_M_IX86) || defined(_M_AMD64) || defined(_M_X64) \
            || defined(_M_ARM64) || (defined(_M_ARM) && _M_ARM >= 7))
#        define QUDO_ATOMIC_QUALIFIER volatile
#        if defined(_M_ARM) || defined(_M_ARM64)
#            pragma intrinsic(__iso_volatile_load32, __iso_volatile_store32)
#            define qudo_atomic_load(ptr) \
                __iso_volatile_load32((const void *)(ptr))
#            define qudo_atomic_store(ptr, val) \
                __iso_volatile_store32((void *)(ptr), (val))
#            pragma intrinsic(_InterlockedExchangeAdd_nf)
#            define qudo_atomic_inc(ptr) \
                _InterlockedExchangeAdd_nf((volatile long *)(ptr), 1)
#        else
#            define qudo_atomic_load(ptr)       (*(ptr))
#            define qudo_atomic_store(ptr, val) (*(ptr) = (val))
#            pragma intrinsic(_InterlockedExchangeAdd)
#            define qudo_atomic_inc(ptr) \
                _InterlockedExchangeAdd((volatile long *)(ptr), 1)
#        endif
#    endif
#endif

#ifndef QUDO_ATOMIC_QUALIFIER
#    define QUDO_ATOMIC_QUALIFIER       volatile
#    define qudo_atomic_load(ptr)       (*(volatile int *)(ptr))
#    define qudo_atomic_store(ptr, val) (*(volatile int *)(ptr) = (val))
#    define qudo_atomic_inc(ptr)        (*(volatile int *)(ptr) += 1)
#endif

#ifndef QUDO_NELEM
#    define QUDO_NELEM(x) (sizeof(x) / sizeof((x)[0]))
#endif

#ifdef __cplusplus
}
#endif

#endif
