/* SPDX-License-Identifier: Apache-2.0 AND MIT */

#include "fips/qudo_fips_rand.h"
#include "mldsa_wrapper.h"
#include "mlkem_wrapper.h"
#include "qudo_pqc.h"
#include "qudo_pqc_audit.h"
#include "qudo_pqc_platform.h"
#include "qudo_pqc_selftest.h"
#include "slhdsa_wrapper.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#if defined(_WIN32) || defined(_MSC_VER)
#    define QUDO_STRCASECMP _stricmp
#else
#    include <strings.h>
#    define QUDO_STRCASECMP strcasecmp
#endif

extern int qudo_pqc_run_post(qudo_st_ctx_t *st);
extern int qudo_pqc_run_post_primitives(qudo_st_ctx_t *st);
extern int qudo_pqc_run_post_algorithms(qudo_st_ctx_t *st);
extern int qudo_pqc_verify_integrity(const qudo_pqc_config_t *config,
                                     qudo_st_ctx_t *st);
extern void qudo_pqc_post_mark_integrity_passed(void);
extern void qudo_pqc_post_reset_status(void);

extern int qudo_fips_rand_seed_from_platform(void);

#ifdef QUDO_FIPS_MODULE
extern int qudo_pqc_verify_integrity_embedded(qudo_st_ctx_t *st);
#endif

#define QUDO_DEP_INITIAL_STATE  QUDO_PQC_STATE_INIT
#define QUDO_DEP_INIT_ATTRIBUTE static
#define QUDO_DEP_FINI_ATTRIBUTE static

static void qudo_dep_init(void);
static void qudo_dep_cleanup(void);

#if defined(_WIN32) || defined(__CYGWIN__)
#    include <windows.h>

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved);
BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved)
{
    (void)hinstDLL;
    (void)lpvReserved;
    switch (fdwReason) {
    case DLL_PROCESS_ATTACH:
        qudo_dep_init();
        break;
    case DLL_PROCESS_DETACH:
        qudo_dep_cleanup();
        break;
    default:
        break;
    }
    return TRUE;
}

#elif defined(__GNUC__) && !defined(_AIX)
#    undef QUDO_DEP_INIT_ATTRIBUTE
#    undef QUDO_DEP_FINI_ATTRIBUTE
#    define QUDO_DEP_INIT_ATTRIBUTE static __attribute__((constructor))
#    define QUDO_DEP_FINI_ATTRIBUTE static __attribute__((destructor))

#elif defined(__sun)
#    pragma init(qudo_dep_init)
#    pragma fini(qudo_dep_cleanup)

#elif defined(_AIX) && !defined(__GNUC__)
void _init(void);
void _cleanup(void);
#    pragma init(_init)
#    pragma fini(_cleanup)
void _init(void)
{
    qudo_dep_init();
}
void _cleanup(void)
{
    qudo_dep_cleanup();
}

#elif defined(__hpux)
#    pragma init "qudo_dep_init"
#    pragma fini "qudo_dep_cleanup"

#elif defined(__TANDEM)
void __INIT__qudo_dep_init(void)
{
    qudo_dep_init();
}
void __TERM__qudo_dep_cleanup(void)
{
    qudo_dep_cleanup();
}

#else
#    undef QUDO_DEP_INIT_ATTRIBUTE
#    undef QUDO_DEP_FINI_ATTRIBUTE
#    undef QUDO_DEP_INITIAL_STATE
#    define QUDO_DEP_INITIAL_STATE QUDO_PQC_STATE_SELFTEST
#endif

static QUDO_ATOMIC_QUALIFIER int g_module_state = QUDO_DEP_INITIAL_STATE;

static QUDO_RWLOCK *g_self_test_lock = NULL;
static QUDO_ONCE g_self_test_once = QUDO_ONCE_INIT;

#define QUDO_ERROR_REPORT_LIMIT 10
static QUDO_ATOMIC_QUALIFIER unsigned int g_error_report_count = 0;

static QUDO_ATOMIC_QUALIFIER int g_conditional_error_check = 1;

static qudo_st_event_cb g_self_test_cb = NULL;
static void *g_self_test_cb_arg = NULL;

static qudo_error_cb g_error_cb = NULL;
static void *g_error_cb_arg = NULL;

static const char *g_error_reason = NULL;

static QUDO_ATOMIC_QUALIFIER int g_config_set = 0;

#ifdef QUDO_FIPS_MODULE
static char g_stored_module_path[1024];
static char g_stored_module_mac[256];
static int g_stored_used_cnf = 0;
#endif

QUDO_DEP_INIT_ATTRIBUTE void qudo_dep_init(void)
{
    qudo_atomic_store(&g_module_state, QUDO_PQC_STATE_SELFTEST);
}

QUDO_DEP_FINI_ATTRIBUTE void qudo_dep_cleanup(void)
{
    /* Module unload: no thread can still execute module code, so the
     * once-created locks are freed here — repeated load/unload must not
     * leak a lock set per cycle. */
    qudo_audit_cleanup();
    qudo_fips_rand_dep_cleanup();
    if (g_self_test_lock != NULL) {
        qudo_rwlock_free(g_self_test_lock);
        g_self_test_lock = NULL;
    }
    qudo_once_reset(&g_self_test_once);
}

static void do_self_test_lock_init(void)
{
    g_self_test_lock = qudo_rwlock_new();
}

static void report_error_state(void)
{
    unsigned int count = qudo_atomic_load(&g_error_report_count);
    if (count < QUDO_ERROR_REPORT_LIMIT) {
        qudo_error_cb cb = NULL;
        void *cb_arg = NULL;
        const char *reason = NULL;
        char msg[128];

        qudo_atomic_inc(&g_error_report_count);

        if (g_self_test_lock != NULL) {
            qudo_rwlock_rdlock(g_self_test_lock);
            cb = g_error_cb;
            cb_arg = g_error_cb_arg;
            reason = g_error_reason;
            qudo_rwlock_rdunlock(g_self_test_lock);
        }

        if (reason != NULL) {
            int n = snprintf(msg, sizeof(msg),
                             "Module in error state (cause: %s)", reason);
            if (n < 0 || (size_t)n >= sizeof(msg))
                msg[sizeof(msg) - 1] = '\0';
        } else {
            snprintf(msg, sizeof(msg),
                     "Module in error state (cause unspecified)");
        }

        if (cb != NULL)
            cb(1, msg, cb_arg);
        qudo_audit_log(QUDO_SEV_ERROR, QUDO_ERR_MODULE_ERROR_STATE,
                       QUDO_AUDIT_COMP_STATE, msg);
    }
}

int qudo_pqc_is_running(void)
{
    int state = qudo_atomic_load(&g_module_state);

    if (state == QUDO_PQC_STATE_ERROR)
        report_error_state();

    return (state == QUDO_PQC_STATE_RUNNING);
}

int qudo_pqc_is_running_or_selftest(void)
{
    int state = qudo_atomic_load(&g_module_state);

    if (state == QUDO_PQC_STATE_ERROR)
        report_error_state();

    return (state == QUDO_PQC_STATE_RUNNING
            || state == QUDO_PQC_STATE_SELFTEST);
}

int qudo_pqc_is_self_testing(void)
{
    return (qudo_atomic_load(&g_module_state) == QUDO_PQC_STATE_SELFTEST);
}

int qudo_pqc_get_state(void)
{
    return qudo_atomic_load(&g_module_state);
}

int qudo_pqc_is_fips(void)
{
#ifdef QUDO_FIPS_MODULE
    return 1;
#else
    return 0;
#endif
}

int qudo_pqc_is_fips_approved(const char *algorithm_name)
{
    static const char *approved[] = {"ML-KEM-512",         "ML-KEM-768",
                                     "ML-KEM-1024",        "ML-DSA-44",
                                     "ML-DSA-65",          "ML-DSA-87",
                                     "HashML-DSA-44",      "HashML-DSA-65",
                                     "HashML-DSA-87",      "SLH-DSA-SHA2-128s",
                                     "SLH-DSA-SHA2-128f",  "SLH-DSA-SHA2-192s",
                                     "SLH-DSA-SHA2-192f",  "SLH-DSA-SHA2-256s",
                                     "SLH-DSA-SHA2-256f",  "SLH-DSA-SHAKE-128s",
                                     "SLH-DSA-SHAKE-128f", "SLH-DSA-SHAKE-192s",
                                     "SLH-DSA-SHAKE-192f", "SLH-DSA-SHAKE-256s",
                                     "SLH-DSA-SHAKE-256f", NULL};
    size_t i;

    if (algorithm_name == NULL)
        return 0;

    for (i = 0; approved[i] != NULL; i++) {
        if (QUDO_STRCASECMP(algorithm_name, approved[i]) == 0)
            return 1;
    }
    return 0;
}

static QUDO_ATOMIC_QUALIFIER int g_cast_status[QUDO_CAST_COUNT] = {0};

int qudo_pqc_get_cast_status(int cast_id)
{
    if (cast_id < 0 || cast_id >= QUDO_CAST_COUNT)
        return -1;
    return qudo_atomic_load(&g_cast_status[cast_id]);
}

void qudo_pqc_set_cast_status(int cast_id, int status)
{
    if (cast_id >= 0 && cast_id < QUDO_CAST_COUNT)
        qudo_atomic_store(&g_cast_status[cast_id], status);
}

static int run_cast_mlkem(const char *alg_name, int cast_id)
{
    QUDO_KEM *kem = NULL;
    uint8_t *pk = NULL, *sk = NULL;
    int ret = 0;
    int err_code = QUDO_ERR_CAST_FAIL;

    qudo_pqc_set_cast_status(cast_id, QUDO_CAST_STATE_PROCESSING);

    kem = QUDO_KEM_new(alg_name);
    if (kem == NULL)
        goto done;

    pk = (uint8_t *)qudo_malloc(kem->length_public_key);
    sk = (uint8_t *)qudo_malloc(kem->length_secret_key);
    if (pk == NULL || sk == NULL)
        goto done;

    if (QUDO_KEM_keypair(kem, pk, sk) != QUDO_KEM_SUCCESS) {
        err_code = QUDO_ERR_CAST_KEYGEN_FAIL;
        goto done;
    }

    ret = qudo_pqc_mlkem_pct(kem, pk, sk, 0);

done:
    qudo_pqc_set_cast_status(cast_id, ret ? QUDO_CAST_STATE_SUCCESS
                                          : QUDO_CAST_STATE_FAILURE);
    if (!ret)
        qudo_audit_log(QUDO_SEV_ERROR, err_code, QUDO_AUDIT_COMP_CAST,
                       alg_name);
    if (sk != NULL) {
        qudo_cleanse(sk, kem ? kem->length_secret_key : 0);
        qudo_free(sk);
    }
    if (pk != NULL)
        qudo_free(pk);
    QUDO_KEM_free(kem);
    return ret;
}

static int run_cast_mldsa(const char *alg_name, int cast_id)
{
    QUDO_MLDSA *sig = NULL;
    uint8_t *pk = NULL, *sk = NULL;
    int ret = 0;
    int err_code = QUDO_ERR_CAST_FAIL;

    qudo_pqc_set_cast_status(cast_id, QUDO_CAST_STATE_PROCESSING);

    sig = QUDO_MLDSA_new(alg_name);
    if (sig == NULL)
        goto done;

    pk = (uint8_t *)qudo_malloc(sig->length_public_key);
    sk = (uint8_t *)qudo_malloc(sig->length_secret_key);
    if (pk == NULL || sk == NULL)
        goto done;

    if (QUDO_MLDSA_keypair(sig, pk, sk) != QUDO_MLDSA_SUCCESS) {
        err_code = QUDO_ERR_CAST_KEYGEN_FAIL;
        goto done;
    }

    ret = qudo_pqc_mldsa_pct(sig, pk, sk);

done:
    qudo_pqc_set_cast_status(cast_id, ret ? QUDO_CAST_STATE_SUCCESS
                                          : QUDO_CAST_STATE_FAILURE);
    if (!ret)
        qudo_audit_log(QUDO_SEV_ERROR, err_code, QUDO_AUDIT_COMP_CAST,
                       alg_name);
    if (sk != NULL) {
        qudo_cleanse(sk, sig ? sig->length_secret_key : 0);
        qudo_free(sk);
    }
    if (pk != NULL)
        qudo_free(pk);
    QUDO_MLDSA_free(sig);
    return ret;
}

static int run_cast_slhdsa(const char *param_set, int cast_id)
{
    QUDO_SLHDSA *sig = NULL;
    uint8_t *pk = NULL, *sk = NULL;
    int ret = 0;
    int err_code = QUDO_ERR_CAST_FAIL;

    qudo_pqc_set_cast_status(cast_id, QUDO_CAST_STATE_PROCESSING);

    sig = QUDO_SLHDSA_new(param_set);
    if (sig == NULL)
        goto done;

    pk = (uint8_t *)qudo_malloc(sig->length_public_key);
    sk = (uint8_t *)qudo_malloc(sig->length_secret_key);
    if (pk == NULL || sk == NULL)
        goto done;

    if (QUDO_SLHDSA_keypair(sig, pk, sk) != QUDO_SLHDSA_SUCCESS) {
        err_code = QUDO_ERR_CAST_KEYGEN_FAIL;
        goto done;
    }

    ret = qudo_pqc_slhdsa_pct(sig, pk, sk);

done:
    qudo_pqc_set_cast_status(cast_id, ret ? QUDO_CAST_STATE_SUCCESS
                                          : QUDO_CAST_STATE_FAILURE);
    if (!ret)
        qudo_audit_log(QUDO_SEV_ERROR, err_code, QUDO_AUDIT_COMP_CAST,
                       param_set);
    if (sk != NULL) {
        qudo_cleanse(sk, sig ? sig->length_secret_key : 0);
        qudo_free(sk);
    }
    if (pk != NULL)
        qudo_free(pk);
    QUDO_SLHDSA_free(sig);
    return ret;
}

int qudo_pqc_run_all_casts(void)
{
    int ok = 1;

    qudo_audit_log(QUDO_SEV_INFO, QUDO_ERR_NONE, QUDO_AUDIT_COMP_CAST,
                   "On-demand CAST starting");

    if (!run_cast_mlkem("ML-KEM-512", QUDO_CAST_ML_KEM_512))
        ok = 0;
    if (!run_cast_mlkem("ML-KEM-768", QUDO_CAST_ML_KEM_768))
        ok = 0;
    if (!run_cast_mlkem("ML-KEM-1024", QUDO_CAST_ML_KEM_1024))
        ok = 0;
    if (!run_cast_mldsa("ML-DSA-44", QUDO_CAST_ML_DSA_44))
        ok = 0;
    if (!run_cast_mldsa("ML-DSA-65", QUDO_CAST_ML_DSA_65))
        ok = 0;
    if (!run_cast_mldsa("ML-DSA-87", QUDO_CAST_ML_DSA_87))
        ok = 0;
    if (!run_cast_slhdsa("SLH-DSA-SHA2-128f", QUDO_CAST_SLH_DSA_SHA2_128))
        ok = 0;
    if (!run_cast_slhdsa("SLH-DSA-SHA2-192f", QUDO_CAST_SLH_DSA_SHA2_192))
        ok = 0;
    if (!run_cast_slhdsa("SLH-DSA-SHA2-256f", QUDO_CAST_SLH_DSA_SHA2_256))
        ok = 0;
    if (!run_cast_slhdsa("SLH-DSA-SHAKE-128f", QUDO_CAST_SLH_DSA_SHAKE_128))
        ok = 0;
    if (!run_cast_slhdsa("SLH-DSA-SHAKE-192f", QUDO_CAST_SLH_DSA_SHAKE_192))
        ok = 0;
    if (!run_cast_slhdsa("SLH-DSA-SHAKE-256f", QUDO_CAST_SLH_DSA_SHAKE_256))
        ok = 0;

    qudo_audit_log(ok ? QUDO_SEV_INFO : QUDO_SEV_ERROR,
                   ok ? QUDO_ERR_NONE : QUDO_ERR_CAST_FAIL,
                   QUDO_AUDIT_COMP_CAST,
                   ok ? "All CASTs passed" : "One or more CASTs failed");

    return ok;
}

void qudo_pqc_set_error_state(const char *type)
{
    int cond_test = 0;
    int import_pct = 0;
    qudo_error_cb cb = NULL;
    void *cb_arg = NULL;

    if (type != NULL) {
        cond_test = (strcmp(type, QUDO_ST_TYPE_PCT) == 0);
        import_pct = (strcmp(type, QUDO_ST_TYPE_PCT_IMPORT) == 0);
    }

    /* No lock: reachable while the self-test thread holds g_self_test_lock as
     * a writer, and that lock is not reentrant. The state store is atomic and
     * the callbacks are set once at init. */
    cb = g_error_cb;
    cb_arg = g_error_cb_arg;

    if (import_pct) {
        if (cb != NULL)
            cb(2, "Import PCT error (transient)", cb_arg);
        qudo_audit_log(QUDO_SEV_WARN, QUDO_ERR_PCT_IMPORT_FAIL,
                       QUDO_AUDIT_COMP_PCT,
                       "Import PCT failed (transient, no state change)");
    } else if (!cond_test || qudo_atomic_load(&g_conditional_error_check)) {
        qudo_atomic_store(&g_module_state, QUDO_PQC_STATE_ERROR);
        g_error_reason = type;
        if (cb != NULL)
            cb(3, "Module entering error state", cb_arg);
        qudo_audit_log(QUDO_SEV_FATAL, QUDO_ERR_MODULE_ERROR_STATE,
                       QUDO_AUDIT_COMP_STATE,
                       "Module entering ERROR state (fatal)");
    } else {
        if (cb != NULL)
            cb(4, "Conditional error (warning only)", cb_arg);
        qudo_audit_log(QUDO_SEV_WARN, QUDO_ERR_PCT_KEYGEN_FAIL,
                       QUDO_AUDIT_COMP_PCT,
                       "Conditional PCT error (warning, check disabled)");
    }
}

void qudo_pqc_get_st_ctx(qudo_st_ctx_t *st)
{
    if (st != NULL) {
        if (g_self_test_lock != NULL) {
            qudo_rwlock_rdlock(g_self_test_lock);
            st->cb = g_self_test_cb;
            st->cb_arg = g_self_test_cb_arg;
            qudo_rwlock_rdunlock(g_self_test_lock);
        } else {
            st->cb = NULL;
            st->cb_arg = NULL;
        }
        st->current_type = NULL;
        st->current_desc = NULL;
        st->event = NULL;
    }
}

static int qudo_pqc_run_self_tests(const qudo_pqc_config_t *config)
{
    qudo_st_ctx_t st;
    void *event = NULL;
    int ok = 1;

    st.cb = config->self_test_cb;
    st.cb_arg = config->self_test_cb_arg;
    st.current_type = NULL;
    st.current_desc = NULL;
    st.event = &event;

#ifdef QUDO_FIPS_MODULE
    if (config->module_path != NULL && config->module_checksum_hex != NULL) {
        if (!qudo_pqc_verify_integrity(config, &st)) {
            qudo_audit_log(QUDO_SEV_FATAL, QUDO_ERR_POST_INTEGRITY_FAIL,
                           QUDO_AUDIT_COMP_INTEGRITY,
                           "Config-based integrity verification failed");
            ok = 0;
            goto done;
        }
        {
            size_t plen = strlen(config->module_path);
            size_t hlen = strlen(config->module_checksum_hex);
            if (plen < sizeof(g_stored_module_path)
                && hlen < sizeof(g_stored_module_mac)) {
                memcpy(g_stored_module_path, config->module_path, plen + 1);
                memcpy(g_stored_module_mac, config->module_checksum_hex,
                       hlen + 1);
                g_stored_used_cnf = 1;
            }
        }
        qudo_audit_log(QUDO_SEV_INFO, QUDO_ERR_NONE, QUDO_AUDIT_COMP_INTEGRITY,
                       "Config-based integrity verification passed");
        qudo_pqc_post_mark_integrity_passed();
    } else {
#ifdef QUDO_PQC_DISABLE_EMBEDDED_HMAC
        /* The host verifies integrity of the binary this library is linked
         * into; no embedded self-check runs here. */
        qudo_audit_log(QUDO_SEV_INFO, QUDO_ERR_NONE, QUDO_AUDIT_COMP_INTEGRITY,
                       "Embedded integrity disabled; host owns module integrity");
        qudo_pqc_post_mark_integrity_passed();
#else
        int embedded_ret = qudo_pqc_verify_integrity_embedded(&st);
        if (embedded_ret == 0) {
            qudo_audit_log(QUDO_SEV_FATAL, QUDO_ERR_INTEGRITY_MISMATCH,
                           QUDO_AUDIT_COMP_INTEGRITY,
                           "Embedded integrity verification failed");
            ok = 0;
            goto done;
        } else if (embedded_ret < 0) {
            qudo_audit_log(QUDO_SEV_FATAL, QUDO_ERR_INTEGRITY_NO_CONFIG,
                           QUDO_AUDIT_COMP_INTEGRITY,
                           "No integrity config or embedded HMAC available");
            ok = 0;
            goto done;
        } else {
            qudo_audit_log(QUDO_SEV_INFO, QUDO_ERR_NONE,
                           QUDO_AUDIT_COMP_INTEGRITY,
                           "Embedded integrity verification passed");
            qudo_pqc_post_mark_integrity_passed();
        }
#endif /* QUDO_PQC_DISABLE_EMBEDDED_HMAC */
    }

    qudo_audit_log(QUDO_SEV_INFO, QUDO_ERR_NONE, QUDO_AUDIT_COMP_POST,
                   "POST primitive KATs starting");
    if (!qudo_pqc_run_post_primitives(&st)) {
        qudo_audit_log(QUDO_SEV_FATAL, QUDO_ERR_POST_KAT_FAIL,
                       QUDO_AUDIT_COMP_POST, "POST primitive KATs failed");
        ok = 0;
        goto done;
    }
    qudo_audit_log(QUDO_SEV_INFO, QUDO_ERR_NONE, QUDO_AUDIT_COMP_POST,
                   "POST primitive KATs passed");

    if (qudo_fips_rand_seed_from_platform() != 0) {
        qudo_audit_log(QUDO_SEV_FATAL, QUDO_ERR_DRBG_SEED_FAIL,
                       QUDO_AUDIT_COMP_DRBG,
                       "Failed to seed DRBG from platform entropy");
        ok = 0;
        goto done;
    }

    qudo_audit_log(QUDO_SEV_INFO, QUDO_ERR_NONE, QUDO_AUDIT_COMP_POST,
                   "POST algorithm KATs starting");
    if (!qudo_pqc_run_post_algorithms(&st)) {
        qudo_audit_log(QUDO_SEV_FATAL, QUDO_ERR_POST_KAT_FAIL,
                       QUDO_AUDIT_COMP_POST, "POST algorithm KATs failed");
        ok = 0;
        goto done;
    }
    qudo_audit_log(QUDO_SEV_INFO, QUDO_ERR_NONE, QUDO_AUDIT_COMP_POST,
                   "POST algorithm KATs passed");

done:
#else
    (void)st;

    if (qudo_fips_rand_seed_from_platform() != 0) {
        qudo_audit_log(QUDO_SEV_FATAL, QUDO_ERR_DRBG_SEED_FAIL,
                       QUDO_AUDIT_COMP_DRBG,
                       "Failed to seed DRBG from platform entropy");
        ok = 0;
    }
#endif

    if (ok) {
        qudo_atomic_store(&g_module_state, QUDO_PQC_STATE_RUNNING);
        qudo_audit_log(QUDO_SEV_INFO, QUDO_ERR_NONE, QUDO_AUDIT_COMP_STATE,
                       "SELFTEST -> RUNNING");
    } else {
        qudo_atomic_store(&g_module_state, QUDO_PQC_STATE_ERROR);
        qudo_audit_log(QUDO_SEV_FATAL, QUDO_ERR_MODULE_ERROR_STATE,
                       QUDO_AUDIT_COMP_STATE, "SELFTEST -> ERROR");
    }

    return ok;
}

int qudo_pqc_init(const qudo_pqc_config_t *config)
{
    qudo_pqc_config_t default_config;
    int ok;

    if (config == NULL) {
        memset(&default_config, 0, sizeof(default_config));
        default_config.conditional_errors = 1;
        config = &default_config;
    }

    if (!qudo_once(&g_self_test_once, do_self_test_lock_init))
        return 0;
    if (g_self_test_lock == NULL)
        return 0;

    if (qudo_atomic_load(&g_module_state) == QUDO_PQC_STATE_RUNNING) {
        if (!qudo_rwlock_wrlock(g_self_test_lock))
            return 0;
        g_self_test_cb = config->self_test_cb;
        g_self_test_cb_arg = config->self_test_cb_arg;
        g_error_cb = config->error_cb;
        g_error_cb_arg = config->error_cb_arg;
        if (config->audit_cb != NULL)
            qudo_audit_set_callback(config->audit_cb, config->audit_cb_arg);
        qudo_rwlock_unlock(g_self_test_lock);
        return 1;
    }
    if (qudo_atomic_load(&g_module_state) == QUDO_PQC_STATE_ERROR)
        return 0;

    if (!qudo_rwlock_wrlock(g_self_test_lock))
        return 0;

    if (qudo_atomic_load(&g_module_state) == QUDO_PQC_STATE_RUNNING) {
        qudo_rwlock_unlock(g_self_test_lock);
        return 1;
    }
    if (qudo_atomic_load(&g_module_state) == QUDO_PQC_STATE_ERROR) {
        qudo_rwlock_unlock(g_self_test_lock);
        return 0;
    }

    g_self_test_cb = config->self_test_cb;
    g_self_test_cb_arg = config->self_test_cb_arg;
    g_error_cb = config->error_cb;
    g_error_cb_arg = config->error_cb_arg;
    qudo_audit_set_callback(config->audit_cb, config->audit_cb_arg);
    qudo_atomic_store(&g_conditional_error_check, config->conditional_errors);

    qudo_atomic_store(&g_config_set, 1);

    qudo_atomic_store(&g_module_state, QUDO_PQC_STATE_SELFTEST);
    qudo_audit_log(QUDO_SEV_INFO, QUDO_ERR_NONE, QUDO_AUDIT_COMP_STATE,
                   "INIT -> SELFTEST (POST starting)");

    ok = qudo_pqc_run_self_tests(config);

    qudo_rwlock_unlock(g_self_test_lock);
    return ok;
}

int qudo_pqc_self_test(void)
{
    qudo_st_ctx_t st;
    int state;
    int ok;

    if (!qudo_atomic_load(&g_config_set))
        return 0;

    if (g_self_test_lock == NULL)
        return 0;

    state = qudo_atomic_load(&g_module_state);
    if (state != QUDO_PQC_STATE_RUNNING)
        return (state == QUDO_PQC_STATE_ERROR) ? 0 : 1;

    if (!qudo_rwlock_wrlock(g_self_test_lock))
        return 0;

    state = qudo_atomic_load(&g_module_state);
    if (state != QUDO_PQC_STATE_RUNNING) {
        qudo_rwlock_unlock(g_self_test_lock);
        return (state == QUDO_PQC_STATE_ERROR) ? 0 : 1;
    }

    qudo_atomic_store(&g_module_state, QUDO_PQC_STATE_SELFTEST);

    {
        void *event = NULL;

        st.cb = g_self_test_cb;
        st.cb_arg = g_self_test_cb_arg;
        st.current_type = NULL;
        st.current_desc = NULL;
        st.event = &event;

#ifdef QUDO_FIPS_MODULE
        {
            int integrity_ret;
            if (g_stored_used_cnf) {
                qudo_pqc_config_t rv_cfg;
                memset(&rv_cfg, 0, sizeof(rv_cfg));
                rv_cfg.module_path = g_stored_module_path;
                rv_cfg.module_checksum_hex = g_stored_module_mac;
                integrity_ret = qudo_pqc_verify_integrity(&rv_cfg, &st);
            } else {
#ifdef QUDO_PQC_DISABLE_EMBEDDED_HMAC
                integrity_ret = 1; /* host owns integrity — treat as verified */
#else
                integrity_ret = qudo_pqc_verify_integrity_embedded(&st);
#endif
            }
            if (integrity_ret <= 0) {
                qudo_audit_log(QUDO_SEV_FATAL,
                               (integrity_ret == 0)
                                   ? QUDO_ERR_INTEGRITY_MISMATCH
                                   : QUDO_ERR_INTEGRITY_NO_CONFIG,
                               QUDO_AUDIT_COMP_INTEGRITY,
                               "On-demand integrity verification failed");
                ok = 0;
            } else {
                qudo_audit_log(QUDO_SEV_INFO, QUDO_ERR_NONE,
                               QUDO_AUDIT_COMP_INTEGRITY,
                               "On-demand integrity verification passed");
                ok = qudo_pqc_run_post(&st);
            }
        }
#else
        (void)st;
        ok = 1;
#endif
    }

    if (ok) {
        qudo_atomic_store(&g_module_state, QUDO_PQC_STATE_RUNNING);
        qudo_audit_log(QUDO_SEV_INFO, QUDO_ERR_NONE, QUDO_AUDIT_COMP_POST,
                       "On-demand self-test passed (KATs only)");
    } else {
        qudo_atomic_store(&g_module_state, QUDO_PQC_STATE_ERROR);
        qudo_audit_log(QUDO_SEV_FATAL, QUDO_ERR_POST_KAT_FAIL,
                       QUDO_AUDIT_COMP_POST, "On-demand self-test failed");
    }

    qudo_rwlock_unlock(g_self_test_lock);
    return ok;
}

void qudo_pqc_unregister_callbacks(const void *self_test_cb_arg)
{
    if (g_self_test_lock == NULL)
        return;
    if (!qudo_rwlock_wrlock(g_self_test_lock))
        return;
    if (g_self_test_cb_arg == self_test_cb_arg) {
        g_self_test_cb = NULL;
        g_self_test_cb_arg = NULL;
        g_error_cb = NULL;
        g_error_cb_arg = NULL;
        qudo_audit_set_callback(NULL, NULL);
    }
    qudo_rwlock_unlock(g_self_test_lock);
}

void qudo_pqc_fini(void)
{
    if (g_self_test_lock != NULL)
        qudo_rwlock_wrlock(g_self_test_lock);
    g_self_test_cb = NULL;
    g_self_test_cb_arg = NULL;
    g_error_cb = NULL;
    g_error_cb_arg = NULL;
    g_error_reason = NULL;
    qudo_pqc_post_reset_status();
    qudo_audit_set_callback(NULL, NULL);
    qudo_atomic_store(&g_config_set, 0);
    /* A latched ERROR is not cleared here: it persists until the module is
     * reloaded. */
    if (qudo_atomic_load(&g_module_state) != QUDO_PQC_STATE_ERROR)
        qudo_atomic_store(&g_module_state, QUDO_PQC_STATE_INIT);
    if (g_self_test_lock != NULL)
        qudo_rwlock_unlock(g_self_test_lock);

    qudo_fips_rand_cleanup();
    qudo_audit_cleanup();

    /* The self-test lock is deliberately not freed: it is a process-lifetime
     * singleton reused by a later qudo_pqc_init (see qudo_dep_cleanup). */
}

QUDO_PQC_API const char *qudo_pqc_version(void)
{
    return QUDO_PQC_VERSION_STRING;
}
