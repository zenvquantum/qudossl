/* SPDX-License-Identifier: Apache-2.0 AND MIT */

#ifndef MLDSA_VERSION_H
#define MLDSA_VERSION_H

#include "mldsa_types.h"

#ifdef __cplusplus
extern "C" {
#endif

#define QUDO_MLDSA_API_VERSION     1
#define QUDO_MLDSA_API_VERSION_MIN 1

#define QUDO_MLDSA_VERSION_MAJOR_NUM 1
#define QUDO_MLDSA_VERSION_MINOR_NUM 0
#define QUDO_MLDSA_VERSION_PATCH_NUM 0

#define QUDO_MLDSA_VERSION_AT_LEAST(major, minor, patch) \
    ((QUDO_MLDSA_VERSION_MAJOR_NUM > (major))            \
     || (QUDO_MLDSA_VERSION_MAJOR_NUM == (major)         \
         && QUDO_MLDSA_VERSION_MINOR_NUM > (minor))      \
     || (QUDO_MLDSA_VERSION_MAJOR_NUM == (major)         \
         && QUDO_MLDSA_VERSION_MINOR_NUM == (minor)      \
         && QUDO_MLDSA_VERSION_PATCH_NUM >= (patch)))

QUDO_MLDSA_API int QUDO_MLDSA_api_version(void);
QUDO_MLDSA_API int QUDO_MLDSA_version_major(void);
QUDO_MLDSA_API int QUDO_MLDSA_version_minor(void);
QUDO_MLDSA_API int QUDO_MLDSA_version_patch(void);

#ifdef __cplusplus
}
#endif

#endif
