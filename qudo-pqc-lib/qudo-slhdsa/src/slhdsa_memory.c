/* SPDX-License-Identifier: Apache-2.0 AND MIT */

#include "../include/slhdsa_config.h"
#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
#    include <windows.h>
#elif defined(__unix__) || defined(__APPLE__)
#    include <sys/mman.h>
#endif

QUDO_SLHDSA_API void QUDO_SLHDSA_secure_zero(void *ptr, size_t len)
{
    if (ptr == NULL || len == 0) {
        return;
    }

#if defined(_WIN32)
    SecureZeroMemory(ptr, len);
#elif defined(__STDC_LIB_EXT1__)
    memset_s(ptr, len, 0, len);
#elif defined(__OpenBSD__)
    explicit_bzero(ptr, len);
#elif defined(__GLIBC__) && __GLIBC__ >= 2 && __GLIBC_MINOR__ >= 25
    extern void explicit_bzero(void *s, size_t n);
    explicit_bzero(ptr, len);
#else
    volatile unsigned char *volatile vptr
        = (volatile unsigned char *volatile)ptr;
    size_t i;
    for (i = 0; i < len; i++) {
        vptr[i] = 0;
    }
    __asm__ __volatile__("" ::: "memory");
#endif
}

QUDO_SLHDSA_API void *QUDO_SLHDSA_secure_alloc(size_t size)
{
    void *ptr;

    if (size == 0) {
        return NULL;
    }

    ptr = malloc(size);
    if (ptr == NULL) {
        return NULL;
    }

    QUDO_SLHDSA_secure_zero(ptr, size);

#if defined(_WIN32)
    VirtualLock(ptr, size);
#elif defined(__unix__) || defined(__APPLE__)

    if (mlock(ptr, size) != 0) {
    }
#endif

    return ptr;
}

QUDO_SLHDSA_API void QUDO_SLHDSA_secure_free(void *ptr, size_t size)
{
    if (ptr == NULL) {
        return;
    }

    QUDO_SLHDSA_secure_zero(ptr, size);

#if defined(_WIN32)
    VirtualUnlock(ptr, size);
#elif defined(__unix__) || defined(__APPLE__)
    munlock(ptr, size);
#endif

    free(ptr);
}

QUDO_SLHDSA_API int QUDO_SLHDSA_constant_time_compare(const void *a,
                                                      const void *b, size_t len)
{
    const unsigned char *pa = (const unsigned char *)a;
    const unsigned char *pb = (const unsigned char *)b;
    unsigned char diff = 0;
    size_t i;

    if (a == NULL || b == NULL) {
        return -1;
    }

    for (i = 0; i < len; i++) {
        diff |= pa[i] ^ pb[i];
    }

    return (diff == 0) ? 0 : 1;
}

QUDO_SLHDSA_API void *QUDO_SLHDSA_aligned_alloc(size_t alignment, size_t size)
{
    if (size == 0 || alignment == 0) {
        return NULL;
    }

#if defined(_WIN32)
    return _aligned_malloc(size, alignment);
#else
    void *ptr;
    if (posix_memalign(&ptr, alignment, size) != 0) {
        return NULL;
    }
    return ptr;
#endif
}

QUDO_SLHDSA_API void QUDO_SLHDSA_aligned_free(void *ptr)
{
    if (ptr == NULL) {
        return;
    }

#if defined(_WIN32)
    _aligned_free(ptr);
#else
    free(ptr);
#endif
}
