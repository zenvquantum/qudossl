/* SPDX-License-Identifier: Apache-2.0 AND MIT */

#include "../include/mlkem_version.h"

QUDO_KEM_API int QUDO_KEM_api_version(void)
{
    return QUDO_KEM_API_VERSION;
}

QUDO_KEM_API int QUDO_KEM_version_major(void)
{
    return QUDO_KEM_VERSION_MAJOR_NUM;
}

QUDO_KEM_API int QUDO_KEM_version_minor(void)
{
    return QUDO_KEM_VERSION_MINOR_NUM;
}

QUDO_KEM_API int QUDO_KEM_version_patch(void)
{
    return QUDO_KEM_VERSION_PATCH_NUM;
}
