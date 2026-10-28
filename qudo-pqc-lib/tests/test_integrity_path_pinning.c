/* SPDX-License-Identifier: Apache-2.0 AND MIT */

#include "qudo_pqc.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#if defined(_WIN32)
#    include <windows.h>
#    define setenv_portable(n, v) _putenv_s(n, v)
#else
#    include <unistd.h>
#    define setenv_portable(n, v) setenv(n, v, 1)
#endif

static int s_error_cb_count = 0;

static void count_errors(int code, const char *msg, void *arg)
{
    (void)code;
    (void)msg;
    (void)arg;
    s_error_cb_count++;
}

int main(void)
{

    const char *cnf_path = "./forged_qudofipsmodule.cnf";
    FILE *fp = fopen(cnf_path, "w");
    if (fp == NULL) {
        fprintf(stderr, "FAIL: cannot create forged cnf file\n");
        return 1;
    }
    fputs("# forged cnf\n", fp);
    fputs("module-mac = "
          "0000000000000000000000000000000000000000000000000000000000000000\n",
          fp);
    fclose(fp);

    setenv_portable("QUDO_PQC_FIPS_CONF", cnf_path);

    qudo_pqc_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.conditional_errors = 1;
    cfg.error_cb = count_errors;

    (void)cfg;
    int r = qudo_pqc_init(NULL);

    int state = qudo_pqc_get_state();

    remove(cnf_path);

    if (r != 0 && r != 1) {
        fprintf(stderr, "FAIL: qudo_pqc_init returned %d\n", r);
        return 1;
    }
    if (state != QUDO_PQC_STATE_RUNNING && state != QUDO_PQC_STATE_ERROR
        && state != QUDO_PQC_STATE_INIT) {
        fprintf(stderr, "FAIL: undefined state %d after init\n", state);
        return 1;
    }

    printf("PASS: QUDO_PQC_FIPS_CONF env var had no effect (r=%d state=%d)\n",
           r, state);
    return 0;
}
