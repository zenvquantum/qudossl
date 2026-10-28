// SPDX-License-Identifier: Apache-2.0
#ifndef QUDO_CPU_FEATURES_H
#define QUDO_CPU_FEATURES_H

#include <stdint.h>

typedef enum {
    MLD_CPU_EXT_INIT = 0,
    MLD_CPU_EXT_AVX2,
    MLD_CPU_EXT_NEON,
    MLD_CPU_EXT_COUNT         /* Must be last */
} mld_cpu_ext;

void mld_cpu_init(void);

int mld_cpu_has_extension(mld_cpu_ext ext);

const char* mld_cpu_get_os(void);

const char* mld_cpu_get_arch(void);

void mld_cpu_print_info(void);

#endif /* QUDO_CPU_FEATURES_H */
