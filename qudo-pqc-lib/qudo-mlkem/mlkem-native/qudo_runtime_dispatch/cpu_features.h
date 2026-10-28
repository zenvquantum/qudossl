// SPDX-License-Identifier: Apache-2.0
#ifndef QUDO_CPU_FEATURES_H
#define QUDO_CPU_FEATURES_H

#include <stdint.h>

typedef enum {
    MLK_CPU_EXT_INIT = 0,
    MLK_CPU_EXT_AVX2,
    MLK_CPU_EXT_NEON,
    MLK_CPU_EXT_COUNT         /* Must be last */
} mlk_cpu_ext;

void mlk_cpu_init(void);

int mlk_cpu_has_extension(mlk_cpu_ext ext);

const char* mlk_cpu_get_os(void);

const char* mlk_cpu_get_arch(void);

void mlk_cpu_print_info(void);

#endif /* QUDO_CPU_FEATURES_H */
