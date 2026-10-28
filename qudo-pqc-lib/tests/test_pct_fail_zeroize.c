/* SPDX-License-Identifier: Apache-2.0 AND MIT */

#include "mldsa_wrapper.h"
#include "mlkem_wrapper.h"
#include "qudo_pqc.h"
#include "qudo_pqc_platform.h"
#include "slhdsa_wrapper.h"
#include "test_fips_init.h"
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef QUDO_FIPS_MODULE

#    if defined(_WIN32)
#        include <process.h>
#    else
#        include <sys/wait.h>
#        include <unistd.h>
#    endif

static int g_pct_corrupt_armed = 0;

static int pct_fail_cb(qudo_st_phase_t phase, const char *type,
                       const char *desc, int result, unsigned char *data,
                       void **event, void *cb_arg)
{
    (void)desc;
    (void)result;
    (void)event;
    (void)cb_arg;

    if (phase == QUDO_ST_PHASE_CORRUPT && g_pct_corrupt_armed && type != NULL
        && strcmp(type, QUDO_ST_TYPE_PCT) == 0 && data != NULL) {
        data[0] ^= 0xFFu;
    }
    return 1;
}

static int is_all_zero(const uint8_t *buf, size_t len)
{
    size_t i;
    for (i = 0; i < len; i++) {
        if (buf[i] != 0)
            return 0;
    }
    return 1;
}

static int module_init_with_cb(void)
{
    qudo_pqc_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.self_test_cb = pct_fail_cb;
    cfg.self_test_cb_arg = NULL;
    cfg.conditional_errors = 1;
    if (test_fips_fill_config(&cfg) < 0)
        return 0;
    return qudo_pqc_init(&cfg) == 1;
}

static void module_reset(void)
{
    qudo_pqc_fini();
}

static int check_mlkem(void)
{
    QUDO_KEM *kem = NULL;
    uint8_t *pk = NULL, *sk = NULL;
    size_t pk_len, sk_len;
    int ok = 0;

    if (!module_init_with_cb()) {
        fprintf(stderr, "ML-KEM: qudo_pqc_init failed\n");
        return 0;
    }

    kem = QUDO_KEM_new("ML-KEM-512");
    if (kem == NULL) {
        fprintf(stderr, "ML-KEM: QUDO_KEM_new failed\n");
        goto done;
    }
    pk_len = kem->length_public_key;
    sk_len = kem->length_secret_key;
    pk = (uint8_t *)malloc(pk_len);
    sk = (uint8_t *)malloc(sk_len);
    if (pk == NULL || sk == NULL) {
        fprintf(stderr, "ML-KEM: malloc failed\n");
        goto done;
    }

    memset(pk, 0xA5, pk_len);
    memset(sk, 0x5A, sk_len);

    g_pct_corrupt_armed = 1;
    {
        QUDO_KEM_status_t rc = QUDO_KEM_keypair(kem, pk, sk);
        g_pct_corrupt_armed = 0;
        if (rc == QUDO_KEM_SUCCESS) {
            fprintf(stderr,
                    "ML-KEM: keypair returned SUCCESS (expected fail)\n");
            goto done;
        }
    }

    if (qudo_pqc_get_state() != QUDO_PQC_STATE_ERROR) {
        fprintf(stderr, "ML-KEM: module state %d, expected ERROR\n",
                qudo_pqc_get_state());
        goto done;
    }
    if (!is_all_zero(pk, pk_len) || !is_all_zero(sk, sk_len)) {
        fprintf(stderr, "ML-KEM: caller buffers not zeroized\n");
        goto done;
    }

    if (QUDO_KEM_keypair(kem, pk, sk) == QUDO_KEM_SUCCESS) {
        fprintf(stderr, "ML-KEM: module not locked after ERROR state\n");
        goto done;
    }

    ok = 1;
done:
    if (sk != NULL) {
        qudo_cleanse(sk, sk_len);
        free(sk);
    }
    free(pk);
    QUDO_KEM_free(kem);
    module_reset();
    return ok;
}

static int check_mldsa(void)
{
    QUDO_MLDSA *sig = NULL;
    uint8_t *pk = NULL, *sk = NULL;
    size_t pk_len, sk_len;
    int ok = 0;

    if (!module_init_with_cb()) {
        fprintf(stderr, "ML-DSA: qudo_pqc_init failed\n");
        return 0;
    }

    sig = QUDO_MLDSA_new("ML-DSA-44");
    if (sig == NULL) {
        fprintf(stderr, "ML-DSA: QUDO_MLDSA_new failed\n");
        goto done;
    }
    pk_len = sig->length_public_key;
    sk_len = sig->length_secret_key;
    pk = (uint8_t *)malloc(pk_len);
    sk = (uint8_t *)malloc(sk_len);
    if (pk == NULL || sk == NULL) {
        fprintf(stderr, "ML-DSA: malloc failed\n");
        goto done;
    }
    memset(pk, 0xA5, pk_len);
    memset(sk, 0x5A, sk_len);

    g_pct_corrupt_armed = 1;
    {
        QUDO_MLDSA_status_t rc = QUDO_MLDSA_keypair(sig, pk, sk);
        g_pct_corrupt_armed = 0;
        if (rc == QUDO_MLDSA_SUCCESS) {
            fprintf(stderr,
                    "ML-DSA: keypair returned SUCCESS (expected fail)\n");
            goto done;
        }
    }

    if (qudo_pqc_get_state() != QUDO_PQC_STATE_ERROR) {
        fprintf(stderr, "ML-DSA: module state %d, expected ERROR\n",
                qudo_pqc_get_state());
        goto done;
    }
    if (!is_all_zero(pk, pk_len) || !is_all_zero(sk, sk_len)) {
        fprintf(stderr, "ML-DSA: caller buffers not zeroized\n");
        goto done;
    }
    if (QUDO_MLDSA_keypair(sig, pk, sk) == QUDO_MLDSA_SUCCESS) {
        fprintf(stderr, "ML-DSA: module not locked after ERROR state\n");
        goto done;
    }

    ok = 1;
done:
    if (sk != NULL) {
        qudo_cleanse(sk, sk_len);
        free(sk);
    }
    free(pk);
    QUDO_MLDSA_free(sig);
    module_reset();
    return ok;
}

static int check_slhdsa(void)
{
    QUDO_SLHDSA *sig = NULL;
    uint8_t *pk = NULL, *sk = NULL;
    size_t pk_len, sk_len;
    int ok = 0;

    if (!module_init_with_cb()) {
        fprintf(stderr, "SLH-DSA: qudo_pqc_init failed\n");
        return 0;
    }

    sig = QUDO_SLHDSA_new("SLH-DSA-SHA2-128f");
    if (sig == NULL) {
        fprintf(stderr, "SLH-DSA: QUDO_SLHDSA_new failed\n");
        goto done;
    }
    pk_len = sig->length_public_key;
    sk_len = sig->length_secret_key;
    pk = (uint8_t *)malloc(pk_len);
    sk = (uint8_t *)malloc(sk_len);
    if (pk == NULL || sk == NULL) {
        fprintf(stderr, "SLH-DSA: malloc failed\n");
        goto done;
    }
    memset(pk, 0xA5, pk_len);
    memset(sk, 0x5A, sk_len);

    g_pct_corrupt_armed = 1;
    {
        QUDO_SLHDSA_status_t rc = QUDO_SLHDSA_keypair(sig, pk, sk);
        g_pct_corrupt_armed = 0;
        if (rc == QUDO_SLHDSA_SUCCESS) {
            fprintf(stderr,
                    "SLH-DSA: keypair returned SUCCESS (expected fail)\n");
            goto done;
        }
    }

    if (qudo_pqc_get_state() != QUDO_PQC_STATE_ERROR) {
        fprintf(stderr, "SLH-DSA: module state %d, expected ERROR\n",
                qudo_pqc_get_state());
        goto done;
    }
    if (!is_all_zero(pk, pk_len) || !is_all_zero(sk, sk_len)) {
        fprintf(stderr, "SLH-DSA: caller buffers not zeroized\n");
        goto done;
    }
    if (QUDO_SLHDSA_keypair(sig, pk, sk) == QUDO_SLHDSA_SUCCESS) {
        fprintf(stderr, "SLH-DSA: module not locked after ERROR state\n");
        goto done;
    }

    ok = 1;
done:
    if (sk != NULL) {
        qudo_cleanse(sk, sk_len);
        free(sk);
    }
    free(pk);
    QUDO_SLHDSA_free(sig);
    module_reset();
    return ok;
}

typedef int (*check_fn)(void);

static int run_isolated(check_fn fn, const char *self, const char *algo)
{
    /* The ERROR state persists for the life of the process, so each check
     * runs in a fresh process: fork() on POSIX, re-exec on Windows. */
#    if defined(_WIN32)
    intptr_t rc;
    (void)fn;
    if (test_fips_cnf_path_ != NULL)
        rc = _spawnl(_P_WAIT, self, self, algo, "--fips-cnf",
                     test_fips_cnf_path_, (const char *)NULL);
    else
        rc = _spawnl(_P_WAIT, self, self, algo, (const char *)NULL);
    if (rc < 0)
        fprintf(stderr, "failed to spawn child '%s %s'\n", self, algo);
    return rc == 0;
#    else
    pid_t pid;
    int status = 0;
    (void)self;
    (void)algo;
    fflush(NULL);
    pid = fork();
    if (pid < 0) {
        perror("fork");
        return 0;
    }
    if (pid == 0)
        _exit(fn() ? 0 : 1);
    if (waitpid(pid, &status, 0) < 0)
        return 0;
    return (WIFEXITED(status) && WEXITSTATUS(status) == 0) ? 1 : 0;
#    endif
}

#endif

int main(int argc, char **argv)
{
    test_fips_init_set_args(&argc, argv);
#ifndef QUDO_FIPS_MODULE
    (void)argc;
    (void)argv;
    printf("=== QUDO PQC PCT Failure Zeroize ===\n");
    printf("Non-FIPS build — SKIP\n");
    return 0;
#else
    if (argc > 1) {
        if (strcmp(argv[1], "mlkem") == 0)
            return check_mlkem() ? 0 : 1;
        if (strcmp(argv[1], "mldsa") == 0)
            return check_mldsa() ? 0 : 1;
        if (strcmp(argv[1], "slhdsa") == 0)
            return check_slhdsa() ? 0 : 1;
    }

    {
        static const struct {
            const char *label;
            const char *algo;
            check_fn fn;
        } cases[] = {
            {"ML-KEM-512", "mlkem", check_mlkem},
            {"ML-DSA-44", "mldsa", check_mldsa},
            {"SLH-DSA-SHA2-128f", "slhdsa", check_slhdsa},
        };
        int pass = 0;
        int fail = 0;
        size_t i;

        printf("=== QUDO PQC PCT Failure Zeroize ===\n");
        for (i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
            int ok = run_isolated(cases[i].fn, argv[0], cases[i].algo);
            if (ok)
                pass++;
            else
                fail++;
            printf("  %-18s %s\n", cases[i].label, ok ? "PASS" : "FAIL");
        }
        printf("=== Results: %d passed, %d failed ===\n", pass, fail);
        return (fail > 0) ? 1 : 0;
    }
#endif
}
