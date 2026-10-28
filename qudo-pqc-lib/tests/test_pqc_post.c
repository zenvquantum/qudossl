/* SPDX-License-Identifier: Apache-2.0 AND MIT */

#include "qudo_pqc.h"
#include "qudo_pqc_platform.h"
#include "qudo_pqc_selftest.h"
#include "test_fips_init.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

extern int qudo_pqc_run_post(qudo_st_ctx_t *st);

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

typedef struct {
    int begin_count;
    int corrupt_count;
    int end_count;
    int end_pass_count;
    int end_fail_count;
    int saw_keygen_mlkem;
    int saw_keygen_mldsa;
    int saw_keygen_slhdsa;
    int saw_kem;
    int saw_sig_mldsa;
    int saw_sig_slhdsa;
} test_cb_data_t;

static int counting_cb(qudo_st_phase_t phase, const char *type,
                       const char *desc, int result, unsigned char *data,
                       void **event, void *cb_arg)
{
    test_cb_data_t *d = (test_cb_data_t *)cb_arg;
    (void)data;
    (void)event;

    switch (phase) {
    case QUDO_ST_PHASE_BEGIN:
        d->begin_count++;
        if (strcmp(type, QUDO_ST_TYPE_KAT_ASYM_KEYGEN) == 0) {
            if (strstr(desc, "ML-KEM") != NULL)
                d->saw_keygen_mlkem = 1;
            else if (strstr(desc, "ML-DSA") != NULL)
                d->saw_keygen_mldsa = 1;
            else if (strstr(desc, "SLH-DSA") != NULL)
                d->saw_keygen_slhdsa = 1;
        } else if (strcmp(type, QUDO_ST_TYPE_KAT_KEM) == 0) {
            d->saw_kem = 1;
        } else if (strcmp(type, QUDO_ST_TYPE_KAT_SIGNATURE) == 0) {
            if (strstr(desc, "ML-DSA") != NULL)
                d->saw_sig_mldsa = 1;
            else if (strstr(desc, "SLH-DSA") != NULL)
                d->saw_sig_slhdsa = 1;
        }
        break;
    case QUDO_ST_PHASE_CORRUPT:
        d->corrupt_count++;
        break;
    case QUDO_ST_PHASE_END:
        d->end_count++;
        if (result)
            d->end_pass_count++;
        else
            d->end_fail_count++;
        break;
    }
    return 1;
}

static const char *g_corrupt_target_type = NULL;

static int corrupt_cb(qudo_st_phase_t phase, const char *type, const char *desc,
                      int result, unsigned char *data, void **event,
                      void *cb_arg)
{

    counting_cb(phase, type, desc, result, data, event, cb_arg);

    if (phase == QUDO_ST_PHASE_CORRUPT && data != NULL) {
        if (g_corrupt_target_type == NULL
            || strcmp(type, g_corrupt_target_type) == 0) {
            *data ^= 0xFF;
        }
    }
    return 1;
}

static const char *state_name(int state)
{
    switch (state) {
    case QUDO_PQC_STATE_INIT:
        return "INIT";
    case QUDO_PQC_STATE_SELFTEST:
        return "SELFTEST";
    case QUDO_PQC_STATE_RUNNING:
        return "RUNNING";
    case QUDO_PQC_STATE_ERROR:
        return "ERROR";
    default:
        return "UNKNOWN";
    }
}

static int g_real_init_done = 0;

static int do_real_fips_init(void)
{
    int ret = test_fips_init();
    if (ret)
        g_real_init_done = 1;
    return ret;
}

static int g_fips_drbg_seeded = 0;

static int ensure_fips_drbg_seeded(void)
{

    if (!g_fips_drbg_seeded) {
        if (qudo_pqc_rand_seed_from_platform() != 0)
            return 0;
        g_fips_drbg_seeded = 1;
    }
    return 1;
}

static int test_is_fips(void)
{
    int fips = qudo_pqc_is_fips();
#ifdef QUDO_FIPS_MODULE
    VLOG("Expected: is_fips = 1 (FIPS build)\n");
    VLOG("Got:      is_fips = %d\n", fips);
    if (fips != 1)
        return 0;
#else
    VLOG("Expected: is_fips = 0 (standard build)\n");
    VLOG("Got:      is_fips = %d\n", fips);
    if (fips != 0)
        return 0;
#endif
    return 1;
}

static int test_post_kats_pass(void)
{
    qudo_st_ctx_t st;
    test_cb_data_t data;
    int ok;

    if (!ensure_fips_drbg_seeded()) {
        fprintf(stderr, "    failed to seed FIPS DRBG\n");
        return 0;
    }

    memset(&data, 0, sizeof(data));
    st.cb = counting_cb;
    st.cb_arg = &data;
    st.current_type = NULL;
    st.current_desc = NULL;

    VLOG("Calling qudo_pqc_run_post() with counting callback\n");
    ok = qudo_pqc_run_post(&st);

    VLOG("Expected: run_post returns 1, events > 0, all pass\n");
    VLOG("Got:      run_post = %d, begin = %d, end = %d, fail = %d\n", ok,
         data.begin_count, data.end_count, data.end_fail_count);
    if (!ok)
        return 0;
    if (data.begin_count == 0)
        return 0;
    if (data.begin_count != data.end_count)
        return 0;
    if (data.end_fail_count != 0)
        return 0;

    return 1;
}

static int test_post_covers_all_families(void)
{
    qudo_st_ctx_t st;
    test_cb_data_t data;

    if (!ensure_fips_drbg_seeded())
        return 0;
    memset(&data, 0, sizeof(data));
    st.cb = counting_cb;
    st.cb_arg = &data;
    st.current_type = NULL;
    st.current_desc = NULL;

    VLOG("Running POST and checking all algorithm families present\n");
    if (!qudo_pqc_run_post(&st))
        return 0;

    VLOG(
        "Expected: keygen(mlkem=1 mldsa=1 slhdsa=1) kem=1 sig(mldsa=1 slhdsa=1)\n");
    VLOG(
        "Got:      keygen(mlkem=%d mldsa=%d slhdsa=%d) kem=%d sig(mldsa=%d slhdsa=%d)\n",
        data.saw_keygen_mlkem, data.saw_keygen_mldsa, data.saw_keygen_slhdsa,
        data.saw_kem, data.saw_sig_mldsa, data.saw_sig_slhdsa);

    if (!data.saw_keygen_mlkem || !data.saw_keygen_mldsa
        || !data.saw_keygen_slhdsa)
        return 0;
    if (!data.saw_kem || !data.saw_sig_mldsa || !data.saw_sig_slhdsa)
        return 0;

    return 1;
}

static int test_post_event_pairing(void)
{
    qudo_st_ctx_t st;
    test_cb_data_t data;

    if (!ensure_fips_drbg_seeded())
        return 0;
    memset(&data, 0, sizeof(data));
    st.cb = counting_cb;
    st.cb_arg = &data;
    st.current_type = NULL;
    st.current_desc = NULL;

    VLOG("Running POST and checking begin=corrupt=end pairing\n");
    if (!qudo_pqc_run_post(&st))
        return 0;

    VLOG("Expected: begin = corrupt = end, all pass\n");
    VLOG("Got:      begin=%d corrupt=%d end=%d pass=%d\n", data.begin_count,
         data.corrupt_count, data.end_count, data.end_pass_count);

    if (data.begin_count != data.corrupt_count)
        return 0;
    if (data.begin_count != data.end_count)
        return 0;
    if (data.end_pass_count != data.end_count)
        return 0;

    return 1;
}

static int test_post_null_callback(void)
{
    qudo_st_ctx_t st;

    if (!ensure_fips_drbg_seeded())
        return 0;
    VLOG("Running POST with cb=NULL\n");
    st.cb = NULL;
    st.cb_arg = NULL;
    st.current_type = NULL;
    st.current_desc = NULL;

    {
        int ret = qudo_pqc_run_post(&st);
        VLOG("Expected: returns 1 (pass without callback)\n");
        VLOG("Got:      returns %d\n", ret);
        if (!ret)
            return 0;
    }
    return 1;
}

static int test_post_negative_keygen(void)
{
    qudo_st_ctx_t st;
    test_cb_data_t data;

    if (!ensure_fips_drbg_seeded())
        return 0;
    VLOG("Corrupting %s events during POST\n", QUDO_ST_TYPE_KAT_ASYM_KEYGEN);
    memset(&data, 0, sizeof(data));
    g_corrupt_target_type = QUDO_ST_TYPE_KAT_ASYM_KEYGEN;
    st.cb = corrupt_cb;
    st.cb_arg = &data;
    st.current_type = NULL;
    st.current_desc = NULL;

    {
        int ret = qudo_pqc_run_post(&st);
        VLOG("Expected: run_post returns 0, fail_count > 0\n");
        VLOG("Got:      run_post = %d, fail_count = %d\n", ret,
             data.end_fail_count);
        g_corrupt_target_type = NULL;
        if (ret != 0)
            return 0;
        if (data.end_fail_count == 0)
            return 0;
    }
    return 1;
}

static int test_post_negative_kem(void)
{
    qudo_st_ctx_t st;
    test_cb_data_t data;

    if (!ensure_fips_drbg_seeded())
        return 0;
    VLOG("Corrupting %s events during POST\n", QUDO_ST_TYPE_KAT_KEM);
    memset(&data, 0, sizeof(data));
    g_corrupt_target_type = QUDO_ST_TYPE_KAT_KEM;
    st.cb = corrupt_cb;
    st.cb_arg = &data;
    st.current_type = NULL;
    st.current_desc = NULL;

    {
        int ret = qudo_pqc_run_post(&st);
        VLOG("Expected: run_post returns 0, fail_count > 0\n");
        VLOG("Got:      run_post = %d, fail_count = %d\n", ret,
             data.end_fail_count);
        g_corrupt_target_type = NULL;
        if (ret != 0)
            return 0;
        if (data.end_fail_count == 0)
            return 0;
    }
    return 1;
}

static int test_post_negative_signature(void)
{
    qudo_st_ctx_t st;
    test_cb_data_t data;

    if (!ensure_fips_drbg_seeded())
        return 0;
    VLOG("Corrupting %s events during POST\n", QUDO_ST_TYPE_KAT_SIGNATURE);
    memset(&data, 0, sizeof(data));
    g_corrupt_target_type = QUDO_ST_TYPE_KAT_SIGNATURE;
    st.cb = corrupt_cb;
    st.cb_arg = &data;
    st.current_type = NULL;
    st.current_desc = NULL;

    {
        int ret = qudo_pqc_run_post(&st);
        VLOG("Expected: run_post returns 0, fail_count > 0\n");
        VLOG("Got:      run_post = %d, fail_count = %d\n", ret,
             data.end_fail_count);
        g_corrupt_target_type = NULL;
        if (ret != 0)
            return 0;
    }

    if (data.end_fail_count == 0) {
        fprintf(stderr, "    no signature failures reported\n");
        g_corrupt_target_type = NULL;
        return 0;
    }

    g_corrupt_target_type = NULL;
    return 1;
}

static int test_post_minimum_events(void)
{
    qudo_st_ctx_t st;
    test_cb_data_t data;

    if (!ensure_fips_drbg_seeded())
        return 0;
    memset(&data, 0, sizeof(data));
    st.cb = counting_cb;
    st.cb_arg = &data;
    st.current_type = NULL;
    st.current_desc = NULL;

    VLOG("Running POST and counting total events\n");
    if (!qudo_pqc_run_post(&st))
        return 0;

    VLOG("Expected: begin_count >= 12\n");
    VLOG("Got:      begin_count = %d\n", data.begin_count);
    if (data.begin_count < 12)
        return 0;

    return 1;
}

static int test_full_init(void)
{
    int ret;

    VLOG("Initializing module with embedded HMAC\n");
    ret = do_real_fips_init();

    VLOG("Expected: init returns 1, state = RUNNING\n");
    VLOG("Got:      init returns %d, state = %s\n", ret,
         state_name(qudo_pqc_get_state()));
    if (!ret)
        return 0;
    if (qudo_pqc_get_state() != QUDO_PQC_STATE_RUNNING)
        return 0;
    return 1;
}

static int test_is_running_after_real_init(void)
{
    int running = qudo_pqc_is_running();
    VLOG("Expected: is_running = 1\n");
    VLOG("Got:      is_running = %d\n", running);
    if (running != 1)
        return 0;
    return 1;
}

static int test_not_self_testing_after_real_init(void)
{
    int testing = qudo_pqc_is_self_testing();
    VLOG("Expected: is_self_testing = 0\n");
    VLOG("Got:      is_self_testing = 0\n");
    if (testing != 0)
        return 0;
    return 1;
}

static int test_self_test_rerun(void)
{

    if (!g_real_init_done) {
        VLOG("Module not initialized — running real init first\n");
        if (!do_real_fips_init()) {
            VLOG("Real init failed — cannot test self_test\n");
            return -1;
        }
    }

    VLOG("Calling qudo_pqc_self_test() (on-demand re-test)\n");
    {
        int ret = qudo_pqc_self_test();
        int state = qudo_pqc_get_state();
        VLOG("Expected: returns 1, state = RUNNING\n");
        VLOG("Got:      returns %d, state = %s\n", ret, state_name(state));
        if (!ret)
            return 0;
        if (state != QUDO_PQC_STATE_RUNNING)
            return 0;
    }
    return 1;
}

static int test_set_error_state_pct_import(void)
{
    int state_before;

    if (!g_real_init_done) {
        if (!do_real_fips_init()) {
            VLOG("Real init failed — cannot test error state\n");
            return -1;
        }
    }

    state_before = qudo_pqc_get_state();
    if (state_before != QUDO_PQC_STATE_RUNNING) {
        VLOG("Module not RUNNING (state=%s) — cannot test\n",
             state_name(state_before));
        return -1;
    }

    VLOG("Calling set_error_state(PCT_IMPORT) — should be transient\n");
    qudo_pqc_set_error_state(QUDO_ST_TYPE_PCT_IMPORT);

    {
        int state_after = qudo_pqc_get_state();
        VLOG("Expected: state unchanged (RUNNING)\n");
        VLOG("Got:      state = %s\n", state_name(state_after));
        if (state_after != state_before)
            return 0;
    }
    return 1;
}

static int test_state_error_is_terminal(void)
{

    if (!g_real_init_done) {
        if (!do_real_fips_init())
            return -1;
    }

    if (qudo_pqc_get_state() != QUDO_PQC_STATE_RUNNING) {
        VLOG("Module not RUNNING — cannot test error state\n");
        return -1;
    }

    VLOG("Forcing ERROR state with set_error_state(KAT_Signature)\n");
    qudo_pqc_set_error_state(QUDO_ST_TYPE_KAT_SIGNATURE);

    int state = qudo_pqc_get_state();
    VLOG("State after forced error: %s\n", state_name(state));
    if (state != QUDO_PQC_STATE_ERROR) {
        VLOG("Expected ERROR state\n");
        return 0;
    }

    if (qudo_pqc_is_running()) {
        VLOG("is_running returned 1 in ERROR state\n");
        return 0;
    }

    int retest = qudo_pqc_self_test();
    VLOG("self_test in ERROR state returned: %d (expected 0)\n", retest);
    if (retest != 0) {
        VLOG("self_test should fail in ERROR state\n");
        return 0;
    }

    if (qudo_pqc_get_state() != QUDO_PQC_STATE_ERROR) {
        VLOG("State changed from ERROR after self_test\n");
        return 0;
    }

    qudo_pqc_fini();
    g_real_init_done = 0;

    return 1;
}

static int test_state_pct_conditional(void)
{

    if (!ensure_fips_drbg_seeded())
        return 0;
    if (!do_real_fips_init())
        return -1;

    if (qudo_pqc_get_state() != QUDO_PQC_STATE_RUNNING) {
        VLOG("Module not RUNNING after re-init\n");
        return -1;
    }

    qudo_pqc_set_error_state(QUDO_ST_TYPE_PCT_IMPORT);
    int state = qudo_pqc_get_state();
    VLOG("State after PCT_IMPORT error: %s (expected RUNNING)\n",
         state_name(state));

    if (state != QUDO_PQC_STATE_RUNNING) {
        VLOG("PCT_IMPORT should not cause ERROR state\n");
        qudo_pqc_fini();
        g_real_init_done = 0;
        return 0;
    }

    return 1;
}

static int test_state_double_init(void)
{

    if (qudo_pqc_get_state() != QUDO_PQC_STATE_RUNNING) {
        if (!ensure_fips_drbg_seeded())
            return 0;
        if (!do_real_fips_init())
            return -1;
    }

    int ret = test_fips_init();
    VLOG("Double init returned: %d (expected 1)\n", ret);

    if (ret != 1) {
        VLOG("Double init failed\n");
        return 0;
    }

    if (qudo_pqc_get_state() != QUDO_PQC_STATE_RUNNING) {
        VLOG("State not RUNNING after double init\n");
        return 0;
    }

    return 1;
}

static int test_state_fini_resets(void)
{

    if (qudo_pqc_get_state() != QUDO_PQC_STATE_RUNNING) {
        if (!ensure_fips_drbg_seeded())
            return 0;
        if (!do_real_fips_init())
            return -1;
    }

    qudo_pqc_fini();
    g_real_init_done = 0;

    if (qudo_pqc_is_running()) {
        VLOG("is_running returned 1 after fini\n");
        return 0;
    }

    if (!ensure_fips_drbg_seeded())
        return 0;
    int ret = do_real_fips_init();
    VLOG("Re-init after fini returned: %d (expected 1)\n", ret);

    if (!ret)
        return 0;
    if (qudo_pqc_get_state() != QUDO_PQC_STATE_RUNNING) {
        VLOG("State not RUNNING after re-init\n");
        return 0;
    }

    return 1;
}

static int run_section(const char *filter, const char *name)
{
    if (filter == NULL)
        return 1;
    return (strcmp(filter, name) == 0);
}

static void print_usage(const char *prog)
{
    printf("Usage: %s [SECTION]\n\n", prog);
    printf("Sections:\n");
    printf("  --init         Full FIPS init (real binary integrity + POST)\n");
    printf("  --kats         POST KAT tests (direct crypto verification)\n");
    printf("  --negative     Corruption detection tests\n");
    printf("  --selftest     On-demand self-test and error state\n");
    printf("  --statemachine Exhaustive state transition tests\n");
    printf("  (no args)      Run all sections\n");
}

int main(int argc, char *argv[])
{
    test_fips_init_set_args(&argc, argv);
    const char *section = NULL;

    if (argc >= 2) {
        if (strcmp(argv[1], "--help") == 0 || strcmp(argv[1], "-h") == 0) {
            print_usage(argv[0]);
            return 0;
        }
        section = argv[1];
    }

    printf("=== QUDO PQC POST Tests ===\n");
#ifdef QUDO_FIPS_MODULE
    printf("Build mode: FIPS\n");
#else
    printf("Build mode: Standard\n");
#endif
    printf("Sections: --init --kats --negative --selftest --statemachine\n\n");

    if (section != NULL)
        g_verbose = 1;

    if (run_section(section, "--init")) {
        printf("[Full FIPS Init]\n");
        RUN_TEST(test_is_fips);
        RUN_TEST(test_full_init);
        RUN_TEST(test_is_running_after_real_init);
        RUN_TEST(test_not_self_testing_after_real_init);
    }

    if (run_section(section, "--kats")) {
        printf("\n[POST KATs]\n");
        RUN_TEST(test_post_kats_pass);
        RUN_TEST(test_post_covers_all_families);
        RUN_TEST(test_post_event_pairing);
        RUN_TEST(test_post_null_callback);
        RUN_TEST(test_post_minimum_events);
    }

    if (run_section(section, "--negative")) {
        printf("\n[POST Negative — Corruption Detection]\n");
        RUN_TEST(test_post_negative_keygen);
        RUN_TEST(test_post_negative_kem);
        RUN_TEST(test_post_negative_signature);
    }

    if (run_section(section, "--selftest")) {
        printf("\n[On-Demand Self-Test / Error State]\n");
        RUN_TEST(test_self_test_rerun);
        RUN_TEST(test_set_error_state_pct_import);
    }

    if (run_section(section, "--statemachine")) {
        printf("\n[Exhaustive State Machine]\n");
        RUN_TEST(test_state_error_is_terminal);
        RUN_TEST(test_state_pct_conditional);
        RUN_TEST(test_state_double_init);
        RUN_TEST(test_state_fini_resets);
    }

    printf("\n=== Results: %d passed, %d failed, %d skipped ===\n", g_pass,
           g_fail, g_skip);

    return g_fail > 0 ? 1 : 0;
}
