/* SPDX-License-Identifier: Apache-2.0 AND MIT */

#ifndef MLKEM_VERSION_H
#define MLKEM_VERSION_H

#include "mlkem_types.h"

#ifdef __cplusplus
extern "C" {
#endif

#define QUDO_KEM_API_VERSION     1
#define QUDO_KEM_API_VERSION_MIN 1

#define QUDO_KEM_VERSION_MAJOR_NUM 1
#define QUDO_KEM_VERSION_MINOR_NUM 0
#define QUDO_KEM_VERSION_PATCH_NUM 0

#define QUDO_KEM_VERSION_AT_LEAST(major, minor, patch) \
    ((QUDO_KEM_VERSION_MAJOR_NUM > (major))            \
     || (QUDO_KEM_VERSION_MAJOR_NUM == (major)         \
         && QUDO_KEM_VERSION_MINOR_NUM > (minor))      \
     || (QUDO_KEM_VERSION_MAJOR_NUM == (major)         \
         && QUDO_KEM_VERSION_MINOR_NUM == (minor)      \
         && QUDO_KEM_VERSION_PATCH_NUM >= (patch)))

QUDO_KEM_API int QUDO_KEM_api_version(void);
QUDO_KEM_API int QUDO_KEM_version_major(void);
QUDO_KEM_API int QUDO_KEM_version_minor(void);
QUDO_KEM_API int QUDO_KEM_version_patch(void);

#ifdef __cplusplus
}
#endif

#endif
