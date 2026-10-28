/* SPDX-License-Identifier: Apache-2.0 AND MIT */

#include "qudo_pqc.h"
#include "qudo_pqc_audit.h"
#include "qudo_pqc_indicator.h"
#include "qudo_pqc_platform.h"
#include <string.h>

typedef struct {
    const char *name;
    int level;
} qudo_sec_level_entry_t;

static const qudo_sec_level_entry_t g_sec_levels[] = {{"ML-KEM-512", 1},
                                                      {"ML-KEM-768", 3},
                                                      {"ML-KEM-1024", 5},

                                                      {"ML-DSA-44", 2},
                                                      {"ML-DSA-65", 3},
                                                      {"ML-DSA-87", 5},

                                                      {"SLH-DSA-SHA2-128s", 1},
                                                      {"SLH-DSA-SHA2-128f", 1},
                                                      {"SLH-DSA-SHA2-192s", 3},
                                                      {"SLH-DSA-SHA2-192f", 3},
                                                      {"SLH-DSA-SHA2-256s", 5},
                                                      {"SLH-DSA-SHA2-256f", 5},

                                                      {"SLH-DSA-SHAKE-128s", 1},
                                                      {"SLH-DSA-SHAKE-128f", 1},
                                                      {"SLH-DSA-SHAKE-192s", 3},
                                                      {"SLH-DSA-SHAKE-192f", 3},
                                                      {"SLH-DSA-SHAKE-256s", 5},
                                                      {"SLH-DSA-SHAKE-256f", 5},

                                                      {NULL, 0}};

static QUDO_ATOMIC_QUALIFIER int g_min_security_level = 1;

int qudo_pqc_get_security_level(const char *algorithm_name)
{
    size_t i;

    if (algorithm_name == NULL)
        return 0;

    for (i = 0; g_sec_levels[i].name != NULL; i++) {
        if (strcmp(algorithm_name, g_sec_levels[i].name) == 0)
            return g_sec_levels[i].level;
    }
    return 0;
}

void qudo_pqc_set_min_security_level(int level)
{
    if (level >= 1 && level <= 5)
        qudo_atomic_store(&g_min_security_level, level);
}

int qudo_pqc_get_min_security_level(void)
{
    return qudo_atomic_load(&g_min_security_level);
}

int qudo_pqc_check_security_level(const char *algorithm_name,
                                  qudo_fips_ind_t *ind)
{
    int level;
    int min_level;

    if (algorithm_name == NULL)
        return 0;

    level = qudo_pqc_get_security_level(algorithm_name);
    if (level == 0)
        return 0;

    min_level = qudo_atomic_load(&g_min_security_level);
    if (level < min_level) {
        qudo_audit_log(QUDO_SEV_WARN, QUDO_ERR_PARAM_INVALID,
                       QUDO_AUDIT_COMP_INDICATOR,
                       "Algorithm below minimum security level");
        if (ind != NULL)
            return qudo_fips_ind_set_unapproved(ind);
        return 0;
    }

    return 1;
}
