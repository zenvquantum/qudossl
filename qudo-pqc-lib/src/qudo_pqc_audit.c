/* SPDX-License-Identifier: Apache-2.0 AND MIT */

#include "qudo_pqc_audit.h"
#include "qudo_pqc_platform.h"

static qudo_audit_cb g_audit_cb = NULL;
static void *g_audit_cb_arg = NULL;

static QUDO_ATOMIC_QUALIFIER unsigned int g_audit_count[4] = {0, 0, 0, 0};

static QUDO_RWLOCK *g_audit_lock = NULL;
static QUDO_ONCE g_audit_lock_once = QUDO_ONCE_INIT;

static void do_audit_lock_init(void)
{
    g_audit_lock = qudo_rwlock_new();
}

void qudo_audit_cleanup(void)
{
    if (g_audit_lock != NULL) {
        qudo_rwlock_free(g_audit_lock);
        g_audit_lock = NULL;
    }
    qudo_once_reset(&g_audit_lock_once);
    g_audit_cb = NULL;
    g_audit_cb_arg = NULL;
}

void qudo_audit_set_callback(qudo_audit_cb cb, void *cb_arg)
{
    qudo_once(&g_audit_lock_once, do_audit_lock_init);

    if (g_audit_lock != NULL)
        qudo_rwlock_wrlock(g_audit_lock);
    g_audit_cb = cb;
    g_audit_cb_arg = cb_arg;
    if (g_audit_lock != NULL)
        qudo_rwlock_unlock(g_audit_lock);
}

void qudo_audit_log(qudo_sev_t severity, qudo_err_t code, const char *component,
                    const char *detail)
{
    qudo_audit_cb cb;
    void *cb_arg;
    unsigned int count;

    if ((unsigned int)severity > QUDO_SEV_FATAL)
        return;

    if (g_audit_lock != NULL) {
        qudo_rwlock_rdlock(g_audit_lock);
        cb = g_audit_cb;
        cb_arg = g_audit_cb_arg;
        qudo_rwlock_rdunlock(g_audit_lock);
    } else {
        cb = g_audit_cb;
        cb_arg = g_audit_cb_arg;
    }

    if (cb == NULL)
        return;

    count = qudo_atomic_load(&g_audit_count[(unsigned int)severity]);
    if (count >= QUDO_AUDIT_RATE_LIMIT)
        return;
    qudo_atomic_inc(&g_audit_count[(unsigned int)severity]);

    cb(severity, code, component, detail, cb_arg);
}

static const struct {
    qudo_err_t code;
    const char *msg;
} qudo_err_table[] = {
    {QUDO_ERR_NONE, "No error"},

    {QUDO_ERR_STATE_INVALID, "Invalid module state for operation"},
    {QUDO_ERR_MODULE_NOT_RUNNING, "Module not in RUNNING state"},
    {QUDO_ERR_MODULE_ERROR_STATE, "Module in ERROR state"},
    {QUDO_ERR_INIT_LOCK_FAIL, "Failed to acquire initialization lock"},
    {QUDO_ERR_INIT_ONCE_FAIL, "Once-initialization failed"},

    {QUDO_ERR_POST_INTEGRITY_FAIL, "Module integrity verification failed"},
    {QUDO_ERR_POST_KAT_FAIL, "Power-on self-test KAT failed"},
    {QUDO_ERR_POST_KEYGEN_KAT_FAIL, "POST keygen KAT failed"},
    {QUDO_ERR_POST_KEM_KAT_FAIL, "POST KEM KAT failed"},
    {QUDO_ERR_POST_SIG_KAT_FAIL, "POST signature KAT failed"},
    {QUDO_ERR_INTEGRITY_HMAC_FAIL, "HMAC integrity self-test failed"},
    {QUDO_ERR_INTEGRITY_MISMATCH, "Module HMAC does not match expected value"},
    {QUDO_ERR_INTEGRITY_NO_CONFIG,
     "No integrity configuration or embedded HMAC"},

    {QUDO_ERR_PCT_KEYGEN_FAIL, "Pairwise consistency test failed (keygen)"},
    {QUDO_ERR_PCT_IMPORT_FAIL, "Pairwise consistency test failed (import)"},
    {QUDO_ERR_PCT_ENCAPS_FAIL, "PCT encapsulation/decapsulation mismatch"},
    {QUDO_ERR_PCT_SIGN_FAIL, "PCT sign/verify mismatch"},

    {QUDO_ERR_CAST_NOT_RUN, "Conditional self-test not yet executed"},
    {QUDO_ERR_CAST_FAIL, "Conditional algorithm self-test failed"},
    {QUDO_ERR_CAST_KEYGEN_FAIL, "CAST temporary key generation failed"},

    {QUDO_ERR_DRBG_NOT_SEEDED, "DRBG not initialized/seeded"},
    {QUDO_ERR_DRBG_SEED_FAIL, "DRBG seeding from platform entropy failed"},
    {QUDO_ERR_DRBG_HEALTH_FAIL, "DRBG entropy health test failed"},
    {QUDO_ERR_DRBG_RESEED_FAIL, "DRBG reseed failed"},
    {QUDO_ERR_DRBG_GENERATE_FAIL, "DRBG generate failed"},

    {QUDO_ERR_KEY_INVALID, "Invalid key material"},
    {QUDO_ERR_KEY_SIZE_MISMATCH,
     "Key size does not match algorithm parameters"},
    {QUDO_ERR_KEY_ZEROIZE_FAIL, "Key zeroization verification failed"},

    {QUDO_ERR_ALLOC, "Memory allocation failed"},
    {QUDO_ERR_PARAM_INVALID, "Invalid parameter value"},
    {QUDO_ERR_PARAM_NULL, "NULL parameter"},
    {QUDO_ERR_NOT_SUPPORTED, "Operation not supported"},
    {QUDO_ERR_INTERNAL, "Internal error"},
};

const char *qudo_err_string(qudo_err_t err)
{
    size_t i;
    for (i = 0; i < sizeof(qudo_err_table) / sizeof(qudo_err_table[0]); i++) {
        if (qudo_err_table[i].code == err)
            return qudo_err_table[i].msg;
    }
    return "Unknown error";
}
