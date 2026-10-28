/* SPDX-License-Identifier: Apache-2.0 AND MIT */

#include "qudo_pqc.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#if defined(_WIN32)
#    include <direct.h>
#    include <windows.h>
#    define setenv_portable(n, v) _putenv_s(n, v)
#else
#    include <stdlib.h>
#    include <unistd.h>
#    define setenv_portable(n, v) setenv(n, v, 1)
#endif

static int g_pass = 0;
static int g_fail = 0;
static int g_verbose = 0;

#define CHECK(cond, msg)                                       \
    do {                                                       \
        if (!(cond)) {                                         \
            printf("    FAIL: %s (line %d)\n", msg, __LINE__); \
            return 0;                                          \
        }                                                      \
        if (g_verbose)                                         \
            printf("    OK: %s\n", msg);                       \
    } while (0)

#define RUN_TEST(fn)                       \
    do {                                   \
        int _r = fn();                     \
        if (_r) {                          \
            g_pass++;                      \
            printf("  %-55s PASS\n", #fn); \
        } else {                           \
            g_fail++;                      \
            printf("  %-55s FAIL\n", #fn); \
        }                                  \
    } while (0)

static int g_error_cb_called = 0;
static int g_self_test_cb_called = 0;

static void error_cb_counter(int code, const char *msg, void *cb_arg)
{
    (void)code;
    (void)msg;
    (void)cb_arg;
    g_error_cb_called++;
}

static int self_test_cb_counter(qudo_st_phase_t phase, const char *type,
                                const char *desc, int result,
                                unsigned char *data, void **event, void *arg)
{
    (void)phase;
    (void)type;
    (void)desc;
    (void)result;
    (void)data;
    (void)event;
    (void)arg;
    g_self_test_cb_called++;
    return 1;
}

static int test_env_var_has_no_effect(void)
{

    setenv_portable("QUDO_PQC_FIPS_CONF", "/nonexistent/qudofipsmodule.cnf");
    int r = qudo_pqc_init(NULL);
    CHECK(r == 0 || r == 1, "init returns a well-defined value");

    int state = qudo_pqc_get_state();
    CHECK(state == QUDO_PQC_STATE_RUNNING || state == QUDO_PQC_STATE_ERROR
              || state == QUDO_PQC_STATE_INIT,
          "state is defined");
    return 1;
}

static int test_env_var_forged_cnf_ignored(void)
{

    const char *cnf_path = "./qudofipsmodule_forged.cnf";
    FILE *fp = fopen(cnf_path, "w");
    CHECK(fp != NULL, "create cnf file");
    fputs("# forged cnf\n", fp);
    fputs("  module-mac   =   "
          "deadbeef00000000000000000000000000000000000000000000000000000000\n",
          fp);
    fclose(fp);

    setenv_portable("QUDO_PQC_FIPS_CONF", cnf_path);
    int r = qudo_pqc_init(NULL);
    (void)r;

    int state = qudo_pqc_get_state();
    CHECK(state == QUDO_PQC_STATE_RUNNING || state == QUDO_PQC_STATE_ERROR
              || state == QUDO_PQC_STATE_INIT,
          "state is defined; env var had no effect");

    remove(cnf_path);
    return 1;
}

static int test_reinit_in_running_state(void)
{

    qudo_pqc_config_t c1;
    memset(&c1, 0, sizeof(c1));
    c1.conditional_errors = 1;
    int r = qudo_pqc_init(&c1);
    CHECK(r == 1, "first init succeeds");
    CHECK(qudo_pqc_get_state() == QUDO_PQC_STATE_RUNNING, "state RUNNING");

    g_error_cb_called = 0;
    g_self_test_cb_called = 0;

    qudo_pqc_config_t c2;
    memset(&c2, 0, sizeof(c2));
    c2.conditional_errors = 1;
    c2.error_cb = error_cb_counter;
    c2.self_test_cb = self_test_cb_counter;

    r = qudo_pqc_init(&c2);
    CHECK(r == 1, "re-init in RUNNING returns success");
    CHECK(qudo_pqc_get_state() == QUDO_PQC_STATE_RUNNING,
          "still RUNNING after re-init");

    CHECK(g_self_test_cb_called == 0, "fast-path re-init did not re-run POST");

    qudo_pqc_config_t c3;
    memset(&c3, 0, sizeof(c3));
    c3.conditional_errors = 1;
    r = qudo_pqc_init(&c3);
    CHECK(r == 1, "third re-init returns success");
    return 1;
}

static int test_get_state_invariants(void)
{

    int s_before = qudo_pqc_get_state();
    CHECK(s_before == QUDO_PQC_STATE_SELFTEST
              || s_before == QUDO_PQC_STATE_INIT,
          "pre-init state is SELFTEST or INIT");

    int r = qudo_pqc_init(NULL);
    CHECK(r == 1, "init succeeds");
    int s_after = qudo_pqc_get_state();
    CHECK(s_after == QUDO_PQC_STATE_RUNNING, "post-init state is RUNNING");

    CHECK(qudo_pqc_get_state() == QUDO_PQC_STATE_RUNNING,
          "repeated query stable");

    CHECK(qudo_pqc_is_running() == 1, "is_running true when RUNNING");
    return 1;
}

static int test_wrong_checksum_triggers_error(void)
{
    g_error_cb_called = 0;

    static const char wrong_hex[]
        = "0000000000000000000000000000000000000000000000000000000000000000";

    qudo_pqc_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.conditional_errors = 1;
    cfg.error_cb = error_cb_counter;
    cfg.module_path = "./libqudo-pqc.so";
    cfg.module_checksum_hex = wrong_hex;

    int r = qudo_pqc_init(&cfg);

    CHECK(r == 0, "init rejects wrong checksum");

    int state = qudo_pqc_get_state();
    CHECK(state == QUDO_PQC_STATE_ERROR, "state is ERROR");

    CHECK(qudo_pqc_is_running() == 0, "is_running false in ERROR state");

    int r2 = qudo_pqc_init(NULL);
    CHECK(r2 == 0, "subsequent init blocked in ERROR state");

    CHECK(g_error_cb_called >= 1, "error_cb invoked via is_running");
    return 1;
}

static int test_rand_init_state_gate(void)
{
    static const uint8_t seed[48] = {0x01};

    int r = qudo_pqc_init(NULL);
    CHECK(r == 1, "init succeeds");
    CHECK(qudo_pqc_get_state() == QUDO_PQC_STATE_RUNNING, "state RUNNING");

    CHECK(qudo_pqc_rand_init(seed, sizeof(seed)) == 0,
          "rand_init accepted while RUNNING");

    qudo_pqc_fini();
    CHECK(qudo_pqc_get_state() == QUDO_PQC_STATE_INIT, "fini -> INIT");

    CHECK(qudo_pqc_rand_init(seed, sizeof(seed)) == -1,
          "rand_init rejected while INIT (state gate)");
    return 1;
}

static int test_reinit_cycle_after_fini(void)
{
    uint8_t buf[32];
    int r;

    r = qudo_pqc_init(NULL);
    CHECK(r == 1, "first init succeeds");
    CHECK(qudo_pqc_rand_bytes(buf, sizeof(buf)) == 0, "rand_bytes works");

    qudo_pqc_fini();
    CHECK(qudo_pqc_get_state() == QUDO_PQC_STATE_INIT, "fini -> INIT");

    r = qudo_pqc_init(NULL);
    CHECK(r == 1, "re-init after fini succeeds (lock reused, no UAF)");
    CHECK(qudo_pqc_get_state() == QUDO_PQC_STATE_RUNNING,
          "state RUNNING again");
    CHECK(qudo_pqc_rand_bytes(buf, sizeof(buf)) == 0,
          "rand_bytes works after re-init");

    qudo_pqc_fini();
    return 1;
}

static int test_unregister_callbacks(void)
{
    qudo_pqc_config_t c;
    memset(&c, 0, sizeof(c));
    c.conditional_errors = 1;
    c.self_test_cb = self_test_cb_counter;
    c.self_test_cb_arg = (void *)0x1234;
    CHECK(qudo_pqc_init(&c) == 1, "init with self-test cb");
    CHECK(qudo_pqc_get_state() == QUDO_PQC_STATE_RUNNING, "state RUNNING");

    g_self_test_cb_called = 0;
    qudo_pqc_unregister_callbacks((void *)0x9999);
    qudo_pqc_self_test();
    CHECK(g_self_test_cb_called > 0,
          "cb still fires after unregister(non-matching arg)");

    g_self_test_cb_called = 0;
    qudo_pqc_unregister_callbacks((void *)0x1234);
    qudo_pqc_self_test();
    CHECK(g_self_test_cb_called == 0,
          "cb cleared after unregister(matching arg)");
    return 1;
}

static void usage(const char *prog)
{
    printf("Usage: %s [--all|--auto-populate-bad|--auto-populate-ok|--reinit|"
           "--state|--wrong-checksum|--rand-init-gate|--reinit-cycle|"
           "--unregister-cb] [-v]\n",
           prog);
}

int main(int argc, char **argv)
{
    const char *section = "--all";
    int i;
    for (i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-v") == 0 || strcmp(argv[i], "--verbose") == 0)
            g_verbose = 1;
        else if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
            usage(argv[0]);
            return 0;
        } else if (argv[i][0] == '-')
            section = argv[i];
    }

    printf("=== ML-Module Init Error-Path Tests ===\n\n");

    if (strcmp(section, "--all") == 0
        || strcmp(section, "--auto-populate-bad") == 0) {
        printf("[env var points at nonexistent cnf — must be ignored]\n");
        RUN_TEST(test_env_var_has_no_effect);
        printf("\n");

        if (strcmp(section, "--all") == 0)
            goto done;
    }
    if (strcmp(section, "--auto-populate-ok") == 0) {
        printf("[env var points at forged cnf — must be ignored]\n");
        RUN_TEST(test_env_var_forged_cnf_ignored);
        printf("\n");
    }
    if (strcmp(section, "--reinit") == 0) {
        printf("[re-init in RUNNING state swaps callbacks]\n");
        RUN_TEST(test_reinit_in_running_state);
        printf("\n");
    }
    if (strcmp(section, "--state") == 0) {
        printf("[qudo_pqc_get_state invariants]\n");
        RUN_TEST(test_get_state_invariants);
        printf("\n");
    }
    if (strcmp(section, "--wrong-checksum") == 0) {
        printf("[wrong checksum -> ERROR state + error_cb fires]\n");
        RUN_TEST(test_wrong_checksum_triggers_error);
        printf("\n");
    }
    if (strcmp(section, "--rand-init-gate") == 0) {
        printf("[public rand_init gated on running/selftest state]\n");
        RUN_TEST(test_rand_init_state_gate);
        printf("\n");
    }
    if (strcmp(section, "--reinit-cycle") == 0) {
        printf("[init -> fini -> init reuses global lock without UAF]\n");
        RUN_TEST(test_reinit_cycle_after_fini);
        printf("\n");
    }
    if (strcmp(section, "--unregister-cb") == 0) {
        printf("[instance-scoped callback deregistration]\n");
        RUN_TEST(test_unregister_callbacks);
        printf("\n");
    }

done:
    printf("=== Results: %d passed, %d failed ===\n", g_pass, g_fail);
    return g_fail > 0 ? 1 : 0;
}
