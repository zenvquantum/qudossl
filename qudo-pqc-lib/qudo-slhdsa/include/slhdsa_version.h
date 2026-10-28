/* SPDX-License-Identifier: Apache-2.0 AND MIT */

#ifndef SLHDSA_VERSION_H
#define SLHDSA_VERSION_H

#include "slhdsa_types.h"

#ifdef __cplusplus
extern "C" {
#endif

#define QUDO_SLHDSA_API_VERSION     1
#define QUDO_SLHDSA_API_VERSION_MIN 1

#define QUDO_SLHDSA_VERSION_MAJOR_NUM 1
#define QUDO_SLHDSA_VERSION_MINOR_NUM 0
#define QUDO_SLHDSA_VERSION_PATCH_NUM 0

#define QUDO_SLHDSA_VERSION_AT_LEAST(major, minor, patch) \
    ((QUDO_SLHDSA_VERSION_MAJOR_NUM > (major))            \
     || (QUDO_SLHDSA_VERSION_MAJOR_NUM == (major)         \
         && QUDO_SLHDSA_VERSION_MINOR_NUM > (minor))      \
     || (QUDO_SLHDSA_VERSION_MAJOR_NUM == (major)         \
         && QUDO_SLHDSA_VERSION_MINOR_NUM == (minor)      \
         && QUDO_SLHDSA_VERSION_PATCH_NUM >= (patch)))

QUDO_SLHDSA_API int QUDO_SLHDSA_api_version(void);
QUDO_SLHDSA_API int QUDO_SLHDSA_version_major(void);
QUDO_SLHDSA_API int QUDO_SLHDSA_version_minor(void);
QUDO_SLHDSA_API int QUDO_SLHDSA_version_patch(void);

#ifdef __cplusplus
}
#endif

#endif
