/* SPDX-License-Identifier: Apache-2.0 AND MIT */

#include "../include/mldsa_version.h"

QUDO_MLDSA_API int QUDO_MLDSA_api_version(void)
{
    return QUDO_MLDSA_API_VERSION;
}

QUDO_MLDSA_API int QUDO_MLDSA_version_major(void)
{
    return QUDO_MLDSA_VERSION_MAJOR_NUM;
}

QUDO_MLDSA_API int QUDO_MLDSA_version_minor(void)
{
    return QUDO_MLDSA_VERSION_MINOR_NUM;
}

QUDO_MLDSA_API int QUDO_MLDSA_version_patch(void)
{
    return QUDO_MLDSA_VERSION_PATCH_NUM;
}
