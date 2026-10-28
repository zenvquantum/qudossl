/* SPDX-License-Identifier: Apache-2.0 AND MIT */
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include "mlkem_wrapper.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    if (size < 2)
        return 0;

    uint8_t op = data[0] % 3;
    QUDO_KEM_security_level_t levels[] = {QUDO_KEM_512, QUDO_KEM_768, QUDO_KEM_1024};
    QUDO_KEM_security_level_t level = levels[data[1] % 3];
    const uint8_t *payload = data + 2;
    size_t payload_len = size - 2;

    QUDO_KEM *kem = QUDO_KEM_new_by_level(level);
    if (!kem)
        return 0;

    uint8_t shared_secret[32];
    uint8_t ciphertext[1568];

    switch (op) {
    case 0: {
        if (payload_len >= kem->length_public_key) {
            QUDO_KEM_encaps(kem, ciphertext, shared_secret, payload);
        }
        break;
    }
    case 1: {
        if (payload_len >= kem->length_ciphertext + kem->length_secret_key) {
            QUDO_KEM_decaps(kem, shared_secret, payload,
                            payload + kem->length_ciphertext);
        }
        break;
    }
    case 2: {
        uint8_t pk[1568], sk[3168];
        if (QUDO_KEM_keypair(kem, pk, sk) == QUDO_KEM_SUCCESS) {
            if (payload_len >= kem->length_ciphertext) {
                QUDO_KEM_decaps(kem, shared_secret, payload, sk);
            }
        }
        break;
    }
    }

    QUDO_KEM_free(kem);
    return 0;
}
