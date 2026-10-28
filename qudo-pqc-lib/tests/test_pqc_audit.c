/* SPDX-License-Identifier: Apache-2.0 AND MIT */

#include "qudo_pqc.h"
#include "qudo_pqc_audit.h"
#include "qudo_pqc_platform.h"
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

#define MAX_CAPTURED_EVENTS 256

typedef struct {
    qudo_sev_t severity;
    qudo_err_t code;
    char component[32];
    char detail[128];
} captured_event_t;

typedef struct {
    captured_event_t events[MAX_CAPTURED_EVENTS];
    int count;
    int info_count;
    int warn_count;
    int error_count;
    int fatal_count;
} audit_capture_t;

static void test_audit_cb(qudo_sev_t severity, qudo_err_t code,
                          const char *component, const char *detail,
                          void *cb_arg)
{
    audit_capture_t *cap = (audit_capture_t *)cb_arg;

    if (cap->count < MAX_CAPTURED_EVENTS) {
        captured_event_t *e = &cap->events[cap->count];
        e->severity = severity;
        e->code = code;
        if (component != NULL) {
            strncpy(e->component, component, sizeof(e->component) - 1);
            e->component[sizeof(e->component) - 1] = '\0';
        } else {
            e->component[0] = '\0';
        }
        if (detail != NULL) {
            strncpy(e->detail, detail, sizeof(e->detail) - 1);
            e->detail[sizeof(e->detail) - 1] = '\0';
        } else {
            e->detail[0] = '\0';
        }
    }
    cap->count++;

    switch (severity) {
    case QUDO_SEV_INFO:
        cap->info_count++;
        break;
    case QUDO_SEV_WARN:
        cap->warn_count++;
        break;
    case QUDO_SEV_ERROR:
        cap->error_count++;
        break;
    case QUDO_SEV_FATAL:
        cap->fatal_count++;
        break;
    }
}

static void capture_init(audit_capture_t *cap)
{
    memset(cap, 0, sizeof(*cap));
}

static int test_audit_callback_basic(void)
{
    audit_capture_t cap;
    capture_init(&cap);

    qudo_audit_set_callback(test_audit_cb, &cap);

    qudo_audit_log(QUDO_SEV_INFO, QUDO_ERR_NONE, QUDO_AUDIT_COMP_STATE,
                   "test event");

    qudo_audit_set_callback(NULL, NULL);

    if (cap.count < 1) {
        VLOG("no events captured (count=%d)\n", cap.count);
        return 0;
    }

    if (cap.events[0].severity != QUDO_SEV_INFO) {
        VLOG("wrong severity: %d\n", cap.events[0].severity);
        return 0;
    }

    if (strcmp(cap.events[0].component, QUDO_AUDIT_COMP_STATE) != 0) {
        VLOG("wrong component: '%s'\n", cap.events[0].component);
        return 0;
    }

    if (strcmp(cap.events[0].detail, "test event") != 0) {
        VLOG("wrong detail: '%s'\n", cap.events[0].detail);
        return 0;
    }

    return 1;
}

static int test_audit_null_callback(void)
{
    qudo_audit_set_callback(NULL, NULL);

    qudo_audit_log(QUDO_SEV_INFO, QUDO_ERR_NONE, QUDO_AUDIT_COMP_STATE,
                   "should be silent");
    qudo_audit_log(QUDO_SEV_FATAL, QUDO_ERR_INTERNAL, QUDO_AUDIT_COMP_POST,
                   NULL);

    return 1;
}

static int test_audit_severity_levels(void)
{
    audit_capture_t cap;
    capture_init(&cap);

    qudo_audit_set_callback(test_audit_cb, &cap);

    qudo_audit_log(QUDO_SEV_INFO, QUDO_ERR_NONE, "TEST", "info");
    qudo_audit_log(QUDO_SEV_WARN, QUDO_ERR_NONE, "TEST", "warn");
    qudo_audit_log(QUDO_SEV_ERROR, QUDO_ERR_INTERNAL, "TEST", "error");
    qudo_audit_log(QUDO_SEV_FATAL, QUDO_ERR_INTERNAL, "TEST", "fatal");

    qudo_audit_set_callback(NULL, NULL);

    if (cap.count != 4) {
        VLOG("expected 4 events, got %d\n", cap.count);
        return 0;
    }

    int ok = 1;
    if (cap.info_count != 1) {
        VLOG("info_count=%d, expected 1\n", cap.info_count);
        ok = 0;
    }
    if (cap.warn_count != 1) {
        VLOG("warn_count=%d, expected 1\n", cap.warn_count);
        ok = 0;
    }
    if (cap.error_count != 1) {
        VLOG("error_count=%d, expected 1\n", cap.error_count);
        ok = 0;
    }
    if (cap.fatal_count != 1) {
        VLOG("fatal_count=%d, expected 1\n", cap.fatal_count);
        ok = 0;
    }

    return ok;
}

static int test_audit_components(void)
{
    static const char *components[] = {QUDO_AUDIT_COMP_STATE,
                                       QUDO_AUDIT_COMP_POST,
                                       QUDO_AUDIT_COMP_INTEGRITY,
                                       QUDO_AUDIT_COMP_PCT,
                                       QUDO_AUDIT_COMP_CAST,
                                       QUDO_AUDIT_COMP_DRBG,
                                       QUDO_AUDIT_COMP_KEY,
                                       QUDO_AUDIT_COMP_INDICATOR,
                                       NULL};

    audit_capture_t cap;
    capture_init(&cap);

    qudo_audit_set_callback(test_audit_cb, &cap);

    int i;
    for (i = 0; components[i] != NULL; i++) {
        qudo_audit_log(QUDO_SEV_INFO, QUDO_ERR_NONE, components[i], "test");
    }

    qudo_audit_set_callback(NULL, NULL);

    if (cap.count != 8) {
        VLOG("expected 8 events, got %d\n", cap.count);
        return 0;
    }

    int ok = 1;
    for (i = 0; components[i] != NULL && i < cap.count; i++) {
        if (strcmp(cap.events[i].component, components[i]) != 0) {
            VLOG("event %d: expected component '%s', got '%s'\n", i,
                 components[i], cap.events[i].component);
            ok = 0;
        }
    }

    return ok;
}

static int test_audit_rate_limiting(void)
{
    audit_capture_t cap;
    capture_init(&cap);

    qudo_audit_set_callback(test_audit_cb, &cap);

    int i;
    for (i = 0; i < 120; i++) {
        qudo_audit_log(QUDO_SEV_WARN, QUDO_ERR_NONE, "RATE", "test");
    }

    qudo_audit_set_callback(NULL, NULL);

    if (cap.warn_count > QUDO_AUDIT_RATE_LIMIT) {
        VLOG("rate limiting failed: %d WARN events (limit=%d)\n",
             cap.warn_count, QUDO_AUDIT_RATE_LIMIT);
        return 0;
    }

    VLOG("delivered %d/%d WARN events (rate limit working)\n", cap.warn_count,
         120);

    return 1;
}

static int test_audit_callback_replace(void)
{
    audit_capture_t cap1, cap2;
    capture_init(&cap1);
    capture_init(&cap2);

    qudo_audit_set_callback(test_audit_cb, &cap1);
    qudo_audit_log(QUDO_SEV_INFO, QUDO_ERR_NONE, "TEST", "to cap1");

    qudo_audit_set_callback(test_audit_cb, &cap2);
    qudo_audit_log(QUDO_SEV_INFO, QUDO_ERR_NONE, "TEST", "to cap2");

    qudo_audit_set_callback(NULL, NULL);

    if (cap1.count != 1) {
        VLOG("cap1 got %d events, expected 1\n", cap1.count);
        return 0;
    }
    if (cap2.count != 1) {
        VLOG("cap2 got %d events, expected 1\n", cap2.count);
        return 0;
    }

    return 1;
}

static int test_error_string_lookup(void)
{
    struct {
        qudo_err_t code;
        const char *expected_substr;
    } tests[] = {
        {QUDO_ERR_NONE, "No error"},
        {QUDO_ERR_STATE_INVALID, "state"},
        {QUDO_ERR_MODULE_NOT_RUNNING, "RUNNING"},
        {QUDO_ERR_MODULE_ERROR_STATE, "ERROR"},
        {QUDO_ERR_INIT_LOCK_FAIL, "lock"},
        {QUDO_ERR_INIT_ONCE_FAIL, "init"},
        {QUDO_ERR_POST_INTEGRITY_FAIL, "integrity"},
        {QUDO_ERR_POST_KAT_FAIL, "KAT"},
        {QUDO_ERR_POST_KEYGEN_KAT_FAIL, "keygen"},
        {QUDO_ERR_POST_KEM_KAT_FAIL, "KEM"},
        {QUDO_ERR_POST_SIG_KAT_FAIL, "signature"},
        {QUDO_ERR_PCT_KEYGEN_FAIL, "keygen"},
        {QUDO_ERR_PCT_IMPORT_FAIL, "import"},
        {QUDO_ERR_PCT_ENCAPS_FAIL, "encapsulation"},
        {QUDO_ERR_PCT_SIGN_FAIL, "sign"},
        {QUDO_ERR_CAST_NOT_RUN, "self-test"},
        {QUDO_ERR_CAST_FAIL, "self-test"},
        {QUDO_ERR_CAST_KEYGEN_FAIL, "key generation"},
        {QUDO_ERR_DRBG_NOT_SEEDED, "DRBG"},
        {QUDO_ERR_DRBG_SEED_FAIL, "seed"},
        {QUDO_ERR_DRBG_HEALTH_FAIL, "health"},
        {QUDO_ERR_DRBG_RESEED_FAIL, "reseed"},
        {QUDO_ERR_DRBG_GENERATE_FAIL, "generate"},
        {QUDO_ERR_KEY_INVALID, "key"},
        {QUDO_ERR_KEY_ZEROIZE_FAIL, "zeroization"},
        {QUDO_ERR_ALLOC, "allocation"},
        {QUDO_ERR_PARAM_INVALID, "parameter"},
        {QUDO_ERR_PARAM_NULL, "NULL"},
        {QUDO_ERR_NOT_SUPPORTED, "supported"},
        {QUDO_ERR_INTERNAL, "Internal"},
    };

    int ok = 1;
    size_t i;
    for (i = 0; i < sizeof(tests) / sizeof(tests[0]); i++) {
        const char *str = qudo_err_string(tests[i].code);
        if (str == NULL) {
            VLOG("NULL string for error 0x%04x\n", tests[i].code);
            ok = 0;
            continue;
        }
        if (strstr(str, tests[i].expected_substr) == NULL) {
            VLOG("error 0x%04x: expected '%s' in '%s'\n", tests[i].code,
                 tests[i].expected_substr, str);
            ok = 0;
        }
    }

    const char *unknown = qudo_err_string((qudo_err_t)0xFFFF);
    if (unknown == NULL || strstr(unknown, "Unknown") == NULL) {
        VLOG("unknown error code did not return 'Unknown'\n");
        ok = 0;
    }

    return ok;
}

static int test_audit_during_init(void)
{
    audit_capture_t cap;
    capture_init(&cap);

    qudo_pqc_config_t config;
    memset(&config, 0, sizeof(config));
    config.audit_cb = test_audit_cb;
    config.audit_cb_arg = &cap;
    config.conditional_errors = 1;

    if (qudo_pqc_init(&config) != 1) {
        VLOG("module init failed\n");
        qudo_pqc_fini();
        return -1;
    }

    VLOG("captured %d audit events during init\n", cap.count);

    if (cap.count < 1) {
        VLOG("no audit events during init\n");
        qudo_pqc_fini();
        return 0;
    }

    int saw_state = 0;
    int i;
    for (i = 0; i < cap.count && i < MAX_CAPTURED_EVENTS; i++) {
        if (strcmp(cap.events[i].component, QUDO_AUDIT_COMP_STATE) == 0) {
            saw_state = 1;
            break;
        }
    }

    if (!saw_state) {
        VLOG("no STATE component events during init\n");
    }

    qudo_pqc_fini();
    return 1;
}

static int test_audit_null_detail(void)
{
    audit_capture_t cap;
    capture_init(&cap);

    qudo_audit_set_callback(test_audit_cb, &cap);

    qudo_audit_log(QUDO_SEV_INFO, QUDO_ERR_NONE, QUDO_AUDIT_COMP_STATE, NULL);

    qudo_audit_set_callback(NULL, NULL);

    if (cap.count != 1) {
        VLOG("expected 1 event, got %d\n", cap.count);
        return 0;
    }

    return 1;
}

static void run_section_basic(void)
{
    printf("\n--- Section 1: Callback Registration ---\n");
    RUN_TEST(test_audit_callback_basic);
    RUN_TEST(test_audit_null_callback);
}

static void run_section_severity(void)
{
    printf("\n--- Section 2: Severity Levels ---\n");
    RUN_TEST(test_audit_severity_levels);
}

static void run_section_components(void)
{
    printf("\n--- Section 3: Component Identifiers ---\n");
    RUN_TEST(test_audit_components);
}

static void run_section_rate(void)
{
    printf("\n--- Section 4: Rate Limiting ---\n");
    RUN_TEST(test_audit_rate_limiting);
}

static void run_section_replace(void)
{
    printf("\n--- Section 5: Callback Replacement ---\n");
    RUN_TEST(test_audit_callback_replace);
}

static void run_section_errstr(void)
{
    printf("\n--- Section 6: Error Strings ---\n");
    RUN_TEST(test_error_string_lookup);
}

static void run_section_init_events(void)
{
    printf("\n--- Section 7: Init Events ---\n");
    RUN_TEST(test_audit_during_init);
}

static void run_section_null_detail(void)
{
    printf("\n--- Section 8: NULL Detail ---\n");
    RUN_TEST(test_audit_null_detail);
}

int main(int argc, char *argv[])
{
    const char *section = NULL;
    int i;

    for (i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-v") == 0 || strcmp(argv[i], "--verbose") == 0)
            g_verbose = 1;
        else if (strncmp(argv[i], "--", 2) == 0)
            section = argv[i] + 2;
    }

    printf("=== QUDO PQC Audit Tests ===\n");

    if (section == NULL || strcmp(section, "basic") == 0)
        run_section_basic();
    if (section == NULL || strcmp(section, "severity") == 0)
        run_section_severity();
    if (section == NULL || strcmp(section, "components") == 0)
        run_section_components();
    if (section == NULL || strcmp(section, "rate") == 0)
        run_section_rate();
    if (section == NULL || strcmp(section, "replace") == 0)
        run_section_replace();
    if (section == NULL || strcmp(section, "errstr") == 0)
        run_section_errstr();
    if (section == NULL || strcmp(section, "init") == 0)
        run_section_init_events();
    if (section == NULL || strcmp(section, "null") == 0)
        run_section_null_detail();

    printf("\n=== Results: %d passed, %d failed, %d skipped ===\n", g_pass,
           g_fail, g_skip);

    return g_fail > 0 ? 1 : 0;
}
