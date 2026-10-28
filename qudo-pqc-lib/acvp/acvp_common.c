/* SPDX-License-Identifier: Apache-2.0 AND MIT */

#include "acvp_common.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <setjmp.h>

int acvp_batch_active = 0;
jmp_buf acvp_batch_jmp;

static unsigned char hex_char_to_nibble(char c)
{
    if (c >= '0' && c <= '9')
        return (unsigned char)(c - '0');
    if (c >= 'A' && c <= 'F')
        return (unsigned char)(10 + (c - 'A'));
    if (c >= 'a' && c <= 'f')
        return (unsigned char)(10 + (c - 'a'));
    return 0xFF;
}

int acvp_hex_decode(const char *hex, uint8_t *out, size_t out_len)
{
    size_t hex_len;
    size_t i;

    if (hex == NULL || out == NULL)
        return -1;

    hex_len = strlen(hex);
    if (hex_len != 2 * out_len)
        return -1;

    for (i = 0; i < out_len; i++) {
        unsigned char hi = hex_char_to_nibble(hex[2 * i]);
        unsigned char lo = hex_char_to_nibble(hex[2 * i + 1]);
        if (hi == 0xFF || lo == 0xFF)
            return -1;
        out[i] = (uint8_t)((hi << 4) | lo);
    }
    return 0;
}

int acvp_hex_decode_alloc(const char *hex, uint8_t **out, size_t *out_len)
{
    size_t hex_len;
    size_t byte_len;
    uint8_t *buf;

    if (hex == NULL || out == NULL || out_len == NULL)
        return -1;

    *out = NULL;
    *out_len = 0;

    hex_len = strlen(hex);
    if (hex_len % 2 != 0)
        return -1;

    byte_len = hex_len / 2;
    if (byte_len == 0) {
        *out = (uint8_t *)calloc(1, 1);
        *out_len = 0;
        return (*out != NULL) ? 0 : -1;
    }

    buf = (uint8_t *)malloc(byte_len);
    if (buf == NULL)
        return -1;

    if (acvp_hex_decode(hex, buf, byte_len) != 0) {
        free(buf);
        return -1;
    }

    *out = buf;
    *out_len = byte_len;
    return 0;
}

void acvp_hex_encode(const uint8_t *in, size_t in_len, char *out)
{
    static const char hex_chars[] = "0123456789ABCDEF";
    size_t i;

    if (in == NULL || out == NULL) {
        if (out != NULL)
            out[0] = '\0';
        return;
    }

    for (i = 0; i < in_len; i++) {
        out[2 * i]     = hex_chars[(in[i] >> 4) & 0x0F];
        out[2 * i + 1] = hex_chars[in[i] & 0x0F];
    }
    out[2 * in_len] = '\0';
}

const char *acvp_parse_arg(const char *arg, const char *prefix)
{
    size_t prefix_len;

    if (arg == NULL || prefix == NULL)
        return NULL;

    prefix_len = strlen(prefix);
    if (strncmp(arg, prefix, prefix_len) != 0)
        return NULL;
    if (arg[prefix_len] != '=')
        return NULL;

    return &arg[prefix_len + 1];
}

int acvp_parse_hex_arg(const char *arg, const char *prefix,
                       uint8_t *out, size_t out_len)
{
    const char *val = acvp_parse_arg(arg, prefix);
    if (val == NULL)
        return -1;
    if (acvp_hex_decode(val, out, out_len) != 0)
        return -2;
    return 0;
}

int acvp_parse_hex_arg_alloc(const char *arg, const char *prefix,
                             uint8_t **out, size_t *out_len)
{
    const char *val = acvp_parse_arg(arg, prefix);
    if (val == NULL)
        return -1;
    if (acvp_hex_decode_alloc(val, out, out_len) != 0)
        return -2;
    return 0;
}

int acvp_parse_int_arg(const char *arg, const char *prefix, int *value)
{
    const char *val = acvp_parse_arg(arg, prefix);
    char *end;
    long v;

    if (val == NULL)
        return -1;

    v = strtol(val, &end, 10);
    if (end == val || *end != '\0')
        return -1;

    *value = (int)v;
    return 0;
}

const char *acvp_parse_str_arg(const char *arg, const char *prefix)
{
    return acvp_parse_arg(arg, prefix);
}

void acvp_print_hex(const char *name, const uint8_t *data, size_t len)
{
    size_t i;
    printf("%s=", name);
    for (i = 0; i < len; i++)
        printf("%02X", data[i]);
    printf("\n");
}

void acvp_print_bool(const char *name, int value)
{
    printf("%s=%d\n", name, value ? 1 : 0);
}

void acvp_fatal(const char *fmt, ...)
{
    va_list args;
    va_start(args, fmt);
    fprintf(stderr, "ERROR: ");
    vfprintf(stderr, fmt, args);
    fprintf(stderr, "\n");
    va_end(args);
    if (acvp_batch_active)
        longjmp(acvp_batch_jmp, 1);
    exit(1);
}

char *acvp_read_line(void)
{
    size_t cap = 256, len = 0;
    char *buf = (char *)malloc(cap);
    int c;

    if (buf == NULL)
        return NULL;

    while ((c = getchar()) != EOF && c != '\n') {
        if (len + 1 >= cap) {
            char *nb;
            cap *= 2;
            nb = (char *)realloc(buf, cap);
            if (nb == NULL) {
                free(buf);
                return NULL;
            }
            buf = nb;
        }
        buf[len++] = (char)c;
    }

    if (c == EOF && len == 0) {
        free(buf);
        return NULL;
    }

    buf[len] = '\0';
    return buf;
}

int acvp_tokenize(char *line, char **argv, int max_tokens)
{
    int argc = 0;
    char *p = line;

    while (*p != '\0' && argc < max_tokens) {
        while (*p == ' ' || *p == '\t' || *p == '\r')
            p++;
        if (*p == '\0')
            break;
        argv[argc++] = p;
        while (*p != '\0' && *p != ' ' && *p != '\t' && *p != '\r')
            p++;
        if (*p != '\0')
            *p++ = '\0';
    }
    return argc;
}
