// SPDX-License-Identifier: Apache-2.0 AND MIT

#include "qudo_fips_rand.h"
#include "qudo_fips_aes.h"
#include "qudo_fips_ctrdrbg.h"
#include "qudo_pqc.h"
#include "qudo_pqc_audit.h"
#include <errno.h>
#include <string.h>

#ifdef _WIN32
/* clang-format off */
/* windows.h must precede bcrypt.h — bcrypt.h needs NTSTATUS, ULONG, etc. */
#    include <windows.h>
#    include <bcrypt.h>
/* clang-format on */
#elif defined(__APPLE__)
#    include <sys/random.h>
#elif defined(__GLIBC__) && defined(__GLIBC_PREREQ)
#    if __GLIBC_PREREQ(2, 25)
#        include <sys/random.h>
#        define QUDO_HAS_GETENTROPY 1
#    endif
#    include <fcntl.h>
#    include <unistd.h>
#    if defined(__linux__) && !defined(QUDO_HAS_GETENTROPY)
#        include <sys/syscall.h>
#    endif
#else
#    include <fcntl.h>
#    include <unistd.h>
#endif

#include "qudo_pqc_platform.h"

#ifdef QUDO_PQC_USE_HOST_DRBG
static qudo_pqc_rand_fn g_host_rand_provider = NULL;

void qudo_pqc_set_rand_provider(qudo_pqc_rand_fn fn)
{
    g_host_rand_provider = fn;
}
#endif /* QUDO_PQC_USE_HOST_DRBG */

#define RESEED_INTERVAL (1U << 20)

#define FIPS_RAND_KEYLEN  32
#define FIPS_RAND_SEEDLEN (FIPS_RAND_KEYLEN + QUDO_CTRDRBG_BLOCKLEN)

static qudo_ctrdrbg_ctx_t g_fips_drbg;
static QUDO_ATOMIC_QUALIFIER int g_fips_rand_ready = 0;
static unsigned int g_fips_rand_gen_count = 0;

#define FIPS_ENTROPY_H 8

static const unsigned int rct_critical[9] = {41, 21, 11, 8, 6, 5, 5, 4, 4};

#define FIPS_APT_WINDOW 512
static const unsigned int apt_critical[9]
    = {410, 311, 177, 103, 62, 39, 25, 18, 13};

#define FIPS_ENTROPY_STARTUP_SAMPLES 1024
static QUDO_ATOMIC_QUALIFIER int g_startup_tested = 0;

static uint8_t g_rct_a = 0;
static unsigned int g_rct_b = 0;

static uint8_t g_apt_a = 0;
static unsigned int g_apt_b = 0;
static unsigned int g_apt_i = 0;

static QUDO_ATOMIC_QUALIFIER int g_health_failed = 0;

static QUDO_RWLOCK *g_fips_rand_lock = NULL;
static QUDO_ONCE g_fips_rand_lock_once = QUDO_ONCE_INIT;

static void do_fips_rand_lock_init(void)
{
    g_fips_rand_lock = qudo_rwlock_new();
}

static int raw_platform_entropy(uint8_t *out, size_t len)
{
#if defined(_WIN32)
    NTSTATUS status = BCryptGenRandom(NULL, out, (ULONG)len,
                                      BCRYPT_USE_SYSTEM_PREFERRED_RNG);
    return (status == 0) ? 0 : -1;

#elif defined(__APPLE__) || defined(QUDO_HAS_GETENTROPY)
    while (len > 0) {
        size_t chunk = len < 256 ? len : 256;
        if (getentropy(out, chunk) != 0)
            return -1;
        out += chunk;
        len -= chunk;
    }
    return 0;

#elif defined(__unix__)
#    if defined(__linux__) && defined(SYS_getrandom)
    {
        size_t total = 0;
        while (total < len) {
            long n = syscall(SYS_getrandom, out + total, len - total, 0);
            if (n < 0) {
                if (errno == ENOSYS)
                    break;
                if (errno == EINTR)
                    continue;
                return -1;
            }
            total += (size_t)n;
        }
        if (total == len)
            return 0;
    }
#    endif
    {
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
    }
    return 0;

#else
    (void)out;
    (void)len;
    return -1;
#endif
}

int qudo_fips_rand_init(const uint8_t *entropy, size_t entropy_len)
{
    if (entropy == NULL || entropy_len < FIPS_RAND_SEEDLEN)
        return -1;

    if (!qudo_once(&g_fips_rand_lock_once, do_fips_rand_lock_init))
        return -1;
    if (g_fips_rand_lock == NULL)
        return -1;

    if (!qudo_rwlock_wrlock(g_fips_rand_lock))
        return -1;

    if (qudo_ctrdrbg_init(&g_fips_drbg, FIPS_RAND_KEYLEN, entropy,
                          FIPS_RAND_SEEDLEN)
        != 0) {
        qudo_rwlock_unlock(g_fips_rand_lock);
        return -1;
    }

    g_fips_rand_gen_count = 0;
    qudo_atomic_store(&g_fips_rand_ready, 1);

    qudo_rwlock_unlock(g_fips_rand_lock);
    return 0;
}

static int rct_test(uint8_t next)
{
    if (g_rct_b != 0 && next == g_rct_a) {
        if (++g_rct_b >= rct_critical[FIPS_ENTROPY_H])
            return 0;
        return 1;
    }
    g_rct_a = next;
    g_rct_b = 1;
    return 1;
}

static int apt_test(uint8_t next)
{
    if (g_apt_b != 0) {
        if (next == g_apt_a) {
            if (++g_apt_b >= apt_critical[FIPS_ENTROPY_H]) {
                g_apt_b = 0;
                return 0;
            }
        }
        if (++g_apt_i >= FIPS_APT_WINDOW)
            g_apt_b = 0;
        return 1;
    }
    g_apt_a = next;
    g_apt_b = 1;
    g_apt_i = 1;
    return 1;
}

static int continuous_health_test(const uint8_t *buf, size_t len)
{
    size_t i;

    for (i = 0; i < len; i++) {
        if (!rct_test(buf[i]) || !apt_test(buf[i]))
            return 0;
    }
    return 1;
}

static void entropy_health_fail(const char *msg)
{
    qudo_atomic_store(&g_health_failed, 1);
    qudo_audit_log(QUDO_SEV_FATAL, QUDO_ERR_DRBG_HEALTH_FAIL,
                   QUDO_AUDIT_COMP_DRBG, msg);
    qudo_pqc_set_error_state(QUDO_ST_TYPE_DRBG_HEALTH);
}

static int startup_health_test(void)
{
    uint8_t buf[64];
    size_t remaining = FIPS_ENTROPY_STARTUP_SAMPLES;

    while (remaining > 0) {
        size_t chunk = remaining < sizeof(buf) ? remaining : sizeof(buf);
        if (raw_platform_entropy(buf, chunk) != 0) {
            entropy_health_fail("Startup entropy read failed");
            qudo_cleanse(buf, sizeof(buf));
            return -1;
        }
        if (!continuous_health_test(buf, chunk)) {
            entropy_health_fail(
                "Startup entropy health test failed (RCT or APT)");
            qudo_cleanse(buf, sizeof(buf));
            return -1;
        }
        remaining -= chunk;
    }
    qudo_cleanse(buf, sizeof(buf));
    return 0;
}

static int platform_entropy(uint8_t *out, size_t len)
{
    if (qudo_atomic_load(&g_health_failed))
        return -1;

    if (!qudo_atomic_load(&g_startup_tested)) {
        if (startup_health_test() != 0)
            return -1;
        qudo_atomic_store(&g_startup_tested, 1);
    }

    if (raw_platform_entropy(out, len) != 0)
        return -1;

    if (!continuous_health_test(out, len)) {
        entropy_health_fail("Raw entropy health test failed (RCT or APT)");
        qudo_cleanse(out, len);
        return -1;
    }
    return 0;
}

int qudo_fips_rand_bytes(uint8_t *out, size_t out_len)
{
    if (!qudo_pqc_is_running_or_selftest())
        return -1;

#ifdef QUDO_PQC_USE_HOST_DRBG
    if (g_host_rand_provider != NULL) {
        if (out == NULL)
            return -1;
        if (out_len == 0)
            return 0;
        /* Fail-closed: any host RNG error propagates as a failure. */
        return (g_host_rand_provider(out, out_len) == 0) ? 0 : -1;
    }
#endif

    if (!qudo_atomic_load(&g_fips_rand_ready) || out == NULL)
        return -1;

    if (out_len == 0)
        return 0;

    if (qudo_atomic_load(&g_health_failed))
        return -1;

    if (!qudo_rwlock_wrlock(g_fips_rand_lock))
        return -1;

    while (out_len > 0) {
        size_t chunk = out_len;
        if (chunk > QUDO_CTRDRBG_MAX_REQUEST)
            chunk = QUDO_CTRDRBG_MAX_REQUEST;

        if (++g_fips_rand_gen_count >= RESEED_INTERVAL) {
            uint8_t fresh[FIPS_RAND_SEEDLEN];
            if (platform_entropy(fresh, sizeof(fresh)) != 0) {
                qudo_rwlock_unlock(g_fips_rand_lock);
                return -1;
            }
            if (qudo_ctrdrbg_reseed(&g_fips_drbg, fresh, sizeof(fresh)) != 0) {
                qudo_cleanse(fresh, sizeof(fresh));
                qudo_rwlock_unlock(g_fips_rand_lock);
                qudo_pqc_set_error_state(QUDO_ST_TYPE_DRBG_HEALTH);
                return -1;
            }
            qudo_cleanse(fresh, sizeof(fresh));
            g_fips_rand_gen_count = 0;
        }

        if (qudo_ctrdrbg_generate(&g_fips_drbg, out, chunk, NULL, 0) != 0) {
            qudo_rwlock_unlock(g_fips_rand_lock);
            return -1;
        }

        out += chunk;
        out_len -= chunk;
    }

    qudo_rwlock_unlock(g_fips_rand_lock);
    return 0;
}

int qudo_fips_rand_reseed(const uint8_t *entropy, size_t entropy_len)
{
    if (!qudo_pqc_is_running_or_selftest())
        return -1;

    if (!qudo_atomic_load(&g_fips_rand_ready) || entropy == NULL)
        return -1;
    if (entropy_len < FIPS_RAND_SEEDLEN)
        return -1;

    if (!qudo_rwlock_wrlock(g_fips_rand_lock))
        return -1;

    if (qudo_ctrdrbg_reseed(&g_fips_drbg, entropy, FIPS_RAND_SEEDLEN) != 0) {
        qudo_rwlock_unlock(g_fips_rand_lock);
        qudo_pqc_set_error_state(QUDO_ST_TYPE_DRBG_HEALTH);
        return -1;
    }
    g_fips_rand_gen_count = 0;

    qudo_rwlock_unlock(g_fips_rand_lock);
    return 0;
}

void qudo_fips_rand_cleanup(void)
{
    if (qudo_atomic_load(&g_fips_rand_ready)) {
        if (g_fips_rand_lock != NULL)
            qudo_rwlock_wrlock(g_fips_rand_lock);

        qudo_atomic_store(&g_fips_rand_ready, 0);
        qudo_ctrdrbg_free(&g_fips_drbg);
        qudo_cleanse(&g_fips_drbg, sizeof(g_fips_drbg));
        g_fips_rand_gen_count = 0;

        g_rct_a = 0;
        g_rct_b = 0;
        g_apt_a = 0;
        g_apt_b = 0;
        g_apt_i = 0;
        qudo_atomic_store(&g_health_failed, 0);
        qudo_atomic_store(&g_startup_tested, 0);

        if (g_fips_rand_lock != NULL)
            qudo_rwlock_unlock(g_fips_rand_lock);
    }
}

void qudo_fips_rand_dep_cleanup(void)
{
    if (g_fips_rand_lock != NULL) {
        qudo_rwlock_free(g_fips_rand_lock);
        g_fips_rand_lock = NULL;
    }
    qudo_once_reset(&g_fips_rand_lock_once);
}

int qudo_fips_rand_seed_from_platform(void)
{
    uint8_t entropy[FIPS_RAND_SEEDLEN];

    if (platform_entropy(entropy, sizeof(entropy)) != 0)
        return -1;

    int ret = qudo_fips_rand_init(entropy, sizeof(entropy));
    qudo_secure_clear(entropy, sizeof(entropy));
    return ret;
}

int qudo_fips_rand_is_ready(void)
{
    return qudo_atomic_load(&g_fips_rand_ready);
}
