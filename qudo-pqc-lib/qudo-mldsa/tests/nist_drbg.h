/* SPDX-License-Identifier: Apache-2.0 AND MIT */

#ifndef NIST_DRBG_H
#define NIST_DRBG_H

#include <stdint.h>
#include <stddef.h>

void nist_drbg_init(const uint8_t *entropy_input, const uint8_t *personalization_string);

int nist_drbg_generate(uint8_t *out, size_t outlen);

#endif
