/* SPDX-License-Identifier: Apache-2.0 AND MIT */

#ifndef QUDO_PQC_INDICATOR_H
#define QUDO_PQC_INDICATOR_H

#include <stddef.h>

#ifndef QUDO_PQC_API
#    if defined(_WIN32) || defined(__CYGWIN__)
#        ifdef QUDO_PQC_BUILDING
#            define QUDO_PQC_API __declspec(dllexport)
#        else
#            define QUDO_PQC_API __declspec(dllimport)
#        endif
#    elif defined(__GNUC__) && __GNUC__ >= 4
#        define QUDO_PQC_API __attribute__((visibility("default")))
#    else
#        define QUDO_PQC_API
#    endif
#endif

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    int approved;
    int strict;
} qudo_fips_ind_t;

static inline void qudo_fips_ind_init(qudo_fips_ind_t *ind, int strict)
{
    if (ind != NULL) {
        ind->approved = 1;
        ind->strict = strict;
    }
}

static inline int qudo_fips_ind_set_unapproved(qudo_fips_ind_t *ind)
{
    if (ind == NULL)
        return 1;
    ind->approved = 0;
    return ind->strict ? 0 : 1;
}

static inline int qudo_fips_ind_is_approved(const qudo_fips_ind_t *ind)
{
    if (ind == NULL)
        return 1;
    return ind->approved;
}

QUDO_PQC_API int qudo_fips_ind_get_default_strict(void);

QUDO_PQC_API int qudo_fips_ind_check_operation(const char *algorithm_name);

#ifdef __cplusplus
}
#endif

#endif
