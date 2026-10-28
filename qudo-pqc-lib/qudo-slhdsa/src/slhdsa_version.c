/* SPDX-License-Identifier: Apache-2.0 AND MIT */

#include "../include/slhdsa_version.h"

QUDO_SLHDSA_API int QUDO_SLHDSA_api_version(void)
{
    return QUDO_SLHDSA_API_VERSION;
}

QUDO_SLHDSA_API int QUDO_SLHDSA_version_major(void)
{
    return QUDO_SLHDSA_VERSION_MAJOR_NUM;
}

QUDO_SLHDSA_API int QUDO_SLHDSA_version_minor(void)
{
    return QUDO_SLHDSA_VERSION_MINOR_NUM;
}

QUDO_SLHDSA_API int QUDO_SLHDSA_version_patch(void)
{
    return QUDO_SLHDSA_VERSION_PATCH_NUM;
}
