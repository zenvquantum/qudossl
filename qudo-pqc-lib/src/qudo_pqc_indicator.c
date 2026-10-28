/* SPDX-License-Identifier: Apache-2.0 AND MIT */

#include "qudo_pqc_indicator.h"
#include "qudo_pqc.h"

#ifdef QUDO_FIPS_MODULE
#    include "qudo_fips_rand.h"
#endif

int qudo_fips_ind_get_default_strict(void)
{
#ifdef QUDO_FIPS_MODULE
    return 1;
#else
    return 0;
#endif
}

int qudo_fips_ind_check_operation(const char *algorithm_name)
{
    if (!qudo_pqc_is_running())
        return 0;

    if (!qudo_pqc_is_fips_approved(algorithm_name))
        return 0;

#ifdef QUDO_FIPS_MODULE
    if (!qudo_fips_rand_is_ready())
        return 0;
#endif

    return 1;
}
