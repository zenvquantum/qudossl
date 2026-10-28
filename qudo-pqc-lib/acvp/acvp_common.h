/* SPDX-License-Identifier: Apache-2.0 AND MIT */

#ifndef ACVP_COMMON_H
#define ACVP_COMMON_H

#include <stdint.h>
#include <stddef.h>
#include <setjmp.h>

#ifdef __cplusplus
extern "C" {
#endif

int acvp_hex_decode(const char *hex, uint8_t *out, size_t out_len);

int acvp_hex_decode_alloc(const char *hex, uint8_t **out, size_t *out_len);

void acvp_hex_encode(const uint8_t *in, size_t in_len, char *out);

const char *acvp_parse_arg(const char *arg, const char *prefix);

int acvp_parse_hex_arg(const char *arg, const char *prefix,
                       uint8_t *out, size_t out_len);

int acvp_parse_hex_arg_alloc(const char *arg, const char *prefix,
                             uint8_t **out, size_t *out_len);

int acvp_parse_int_arg(const char *arg, const char *prefix, int *value);

const char *acvp_parse_str_arg(const char *arg, const char *prefix);

void acvp_print_hex(const char *name, const uint8_t *data, size_t len);

void acvp_print_bool(const char *name, int value);

void acvp_fatal(const char *fmt, ...);

extern int acvp_batch_active;
extern jmp_buf acvp_batch_jmp;

char *acvp_read_line(void);

int acvp_tokenize(char *line, char **argv, int max_tokens);

#ifdef __cplusplus
}
#endif

#endif
