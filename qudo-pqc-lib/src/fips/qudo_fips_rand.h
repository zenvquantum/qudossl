// SPDX-License-Identifier: Apache-2.0 AND MIT

#ifndef QUDO_FIPS_RAND_H
#define QUDO_FIPS_RAND_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

int qudo_fips_rand_init(const uint8_t *entropy, size_t entropy_len);

int qudo_fips_rand_bytes(uint8_t *out, size_t out_len);

int qudo_fips_rand_reseed(const uint8_t *entropy, size_t entropy_len);

void qudo_fips_rand_cleanup(void);

void qudo_fips_rand_dep_cleanup(void);

int qudo_fips_rand_seed_from_platform(void);

int qudo_fips_rand_is_ready(void);

#ifdef __cplusplus
}
#endif

#endif
