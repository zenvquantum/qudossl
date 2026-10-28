/* SPDX-License-Identifier: Apache-2.0 AND MIT */

#include "../include/mlkem_config.h"
#include <string.h>

#if defined(QUDO_COMBINED_BUILD)

#    include "fips/qudo_fips_rand.h"

#elif defined(QUDO_PQC_MATH_ONLY)

/* Math-only build: the caller supplies all randomness; no platform entropy
 * source is compiled in. */

#else

#    include <stdint.h>

#    if defined(_WIN32)

/* windows.h must precede bcrypt.h — bcrypt.h needs NTSTATUS, ULONG, etc. */
/* clang-format off */
#        include <windows.h>
#        include <bcrypt.h>
/* clang-format on */

#    elif defined(__APPLE__)
#        include <sys/random.h>
#    elif defined(__GLIBC__) && defined(__GLIBC_PREREQ)
#        if __GLIBC_PREREQ(2, 25)
#            include <sys/random.h>
#            define QUDO_MLKEM_HAS_GETENTROPY 1
#        endif
#        include <fcntl.h>
#        include <unistd.h>
#    else
#        include <fcntl.h>
#        include <unistd.h>
#    endif

static int mlkem_platform_rand(uint8_t *out, size_t len)
{
#    if defined(_WIN32)
    NTSTATUS status = BCryptGenRandom(NULL, out, (ULONG)len,
                                      BCRYPT_USE_SYSTEM_PREFERRED_RNG);
    return (status == 0) ? 0 : -1;
#    elif defined(__APPLE__) || defined(QUDO_MLKEM_HAS_GETENTROPY)
    while (len > 0) {
        size_t chunk = len < 256 ? len : 256;
        if (getentropy(out, chunk) != 0)
            return -1;
        out += chunk;
        len -= chunk;
    }
    return 0;
#    elif defined(__unix__)
    int fd = open("/dev/urandom", O_RDONLY);
    if (fd < 0)
        return -1;
    {
        size_t total = 0;
        while (total < len) {
            ssize_t n = read(fd, out + total, len - total);
            if (n <= 0) {
                close(fd);
                return -1;
            }
            total += (size_t)n;
        }
    }
    close(fd);
    return 0;
#    else
    (void)out;
    (void)len;
    return -1;
#    endif
}
#endif

QUDO_KEM_API int QUDO_KEM_randombytes_init(void)
{
    return QUDO_KEM_SUCCESS;
}

QUDO_KEM_API int QUDO_KEM_randombytes(uint8_t *out, size_t outlen)
{
    if (out == NULL || outlen == 0) {
        return QUDO_KEM_ERROR;
    }

#if defined(QUDO_COMBINED_BUILD)

    if (!qudo_fips_rand_is_ready()) {
        return QUDO_KEM_ERROR;
    }
    if (qudo_fips_rand_bytes(out, outlen) != 0) {
        return QUDO_KEM_ERROR;
    }
#elif defined(QUDO_PQC_MATH_ONLY)

    /* No entropy source in a math-only build; fail closed. */
    return QUDO_KEM_ERROR;
#else

    if (mlkem_platform_rand(out, outlen) != 0) {
        return QUDO_KEM_ERROR;
    }
#endif

    return QUDO_KEM_SUCCESS;
}

QUDO_KEM_API void QUDO_KEM_randombytes_cleanup(void)
{
}

QUDO_KEM_API int QUDO_KEM_randombytes_test(void)
{
    uint8_t test_buf[32];
    uint8_t zero_buf[32];

    memset(zero_buf, 0, sizeof(zero_buf));
    memset(test_buf, 0, sizeof(test_buf));

    if (QUDO_KEM_randombytes(test_buf, sizeof(test_buf)) != QUDO_KEM_SUCCESS) {
        return QUDO_KEM_ERROR;
    }

    if (memcmp(test_buf, zero_buf, sizeof(test_buf)) == 0) {
        QUDO_KEM_secure_zero(test_buf, sizeof(test_buf));
        return QUDO_KEM_ERROR;
    }

    QUDO_KEM_secure_zero(test_buf, sizeof(test_buf));
    return QUDO_KEM_SUCCESS;
}

int randombytes(uint8_t *out, size_t outlen)
{
    return QUDO_KEM_randombytes(out, outlen);
}
