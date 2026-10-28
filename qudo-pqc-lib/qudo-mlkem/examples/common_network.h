/* SPDX-License-Identifier: Apache-2.0 AND MIT */
#ifndef COMMON_NETWORK_H
#define COMMON_NETWORK_H

#include <stdint.h>
#include <stddef.h>

#define SERVER_PORT 8443
#define SERVER_IP "127.0.0.1"
#define BUFFER_SIZE 8192

#define MSG_GET_PUBLIC_KEY "GET_PUBLIC_KEY"
#define MSG_ENCRYPTED_DATA "ENCRYPTED_DATA"

static void print_hex(const char* label, const uint8_t* data, size_t len) {
    size_t i;
    printf("%s: ", label);
    for (i = 0; i < (len < 32 ? len : 32); i++) {
        printf("%02x", data[i]);
    }
    if (len > 32) printf("... (%zu bytes total)", len);
    else printf(" (%zu bytes)", len);
    printf("\n");
}

static void xor_encrypt_decrypt(uint8_t* output, const uint8_t* input,
                                size_t len, const uint8_t* key, size_t key_len) {
    size_t i;
    for (i = 0; i < len; i++) {
        output[i] = input[i] ^ key[i % key_len];
    }
}

#endif
