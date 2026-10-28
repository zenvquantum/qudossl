/* SPDX-License-Identifier: Apache-2.0 AND MIT */

#ifndef TEST_FIPS_INIT_H
#define TEST_FIPS_INIT_H

#include "qudo_pqc.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static const char *test_fips_cnf_path_ = NULL;

static void test_fips_init_set_args(int *argc, char **argv)
{
    if (argc == NULL || argv == NULL)
        return;
    int i;
    for (i = 1; i + 1 < *argc; i++) {
        if (strcmp(argv[i], "--fips-cnf") == 0) {
            test_fips_cnf_path_ = argv[i + 1];

            int j;
            for (j = i; j + 2 < *argc; j++)
                argv[j] = argv[j + 2];
            *argc -= 2;
            argv[*argc] = NULL;
            return;
        }
    }
}

static int test_fips_parse_cnf(const char *path, char *module_out, size_t m_sz,
                               char *mac_out, size_t mac_sz)
{
    if (path == NULL || module_out == NULL || mac_out == NULL)
        return -1;
    FILE *fp = fopen(path, "r");
    if (fp == NULL)
        return -1;
    module_out[0] = '\0';
    mac_out[0] = '\0';
    char line[1024];
    while (fgets(line, sizeof(line), fp) != NULL) {
        const char *p = line;
        while (*p == ' ' || *p == '\t')
            p++;
        if (strncmp(p, "module-mac", 10) == 0) {
            const char *q = p + 10;
            while (*q == ' ' || *q == '\t')
                q++;
            if (*q != '=')
                continue;
            q++;
            while (*q == ' ' || *q == '\t')
                q++;
            size_t i = 0;
            while (*q != '\0' && *q != '\r' && *q != '\n' && i + 1 < mac_sz) {
                if ((*q >= '0' && *q <= '9') || (*q >= 'a' && *q <= 'f')
                    || (*q >= 'A' && *q <= 'F') || *q == ':')
                    mac_out[i++] = *q;
                q++;
            }
            mac_out[i] = '\0';
        } else if (strncmp(p, "module", 6) == 0
                   && (p[6] == ' ' || p[6] == '\t' || p[6] == '=')) {
            const char *q = p + 6;
            while (*q == ' ' || *q == '\t')
                q++;
            if (*q != '=')
                continue;
            q++;
            while (*q == ' ' || *q == '\t')
                q++;
            size_t i = 0;
            while (*q != '\0' && *q != '\r' && *q != '\n' && i + 1 < m_sz)
                module_out[i++] = *q++;

            while (i > 0
                   && (module_out[i - 1] == ' ' || module_out[i - 1] == '\t'))
                i--;
            module_out[i] = '\0';
        }
    }
    fclose(fp);
    return (module_out[0] != '\0' && mac_out[0] != '\0') ? 0 : -1;
}

static int test_fips_fill_config(qudo_pqc_config_t *cfg)
{
    static char module[1024];
    static char mac[256];
    const char *p = test_fips_cnf_path_;
    if (cfg == NULL || p == NULL)
        return 0;
    if (test_fips_parse_cnf(p, module, sizeof(module), mac, sizeof(mac)) != 0)
        return -1;
    cfg->module_path = module;
    cfg->module_checksum_hex = mac;
    return 1;
}

static inline int test_fips_init(void)
{
    const char *p = test_fips_cnf_path_;
    if (p == NULL)
        return qudo_pqc_init(NULL);

    qudo_pqc_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.conditional_errors = 1;
    if (test_fips_fill_config(&cfg) != 1)
        return 0;
    return qudo_pqc_init(&cfg);
}

#endif
