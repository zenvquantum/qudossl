/* SPDX-License-Identifier: Apache-2.0 AND MIT */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "mldsa_wrapper.h"

static void print_hex(const char *label, const uint8_t *data, size_t len) {
    printf("%s: ", label);
    for (size_t i = 0; i < (len > 32 ? 32 : len); i++) {
        printf("%02x", data[i]);
    }
    if (len > 32) printf("... (%zu bytes total)", len);
    printf("\n");
}

int main(void) {
    printf("=== Concatenated Format Signing Example ===\n\n");

    const char *variant = "ML-DSA-65";
    const char *message = "This message will be concatenated with signature";
    size_t msglen = strlen(message);
    const char *context = "email-signature-v1";
    size_t ctxlen = strlen(context);

    QUDO_MLDSA *sig = QUDO_MLDSA_new(variant);
    if (!sig) {
        fprintf(stderr, "Failed to create context\n");
        return 1;
    }

    size_t sig_len = QUDO_MLDSA_get_signature_bytes(sig);

    uint8_t pk[ML_DSA_87_PUBLIC_KEY_BYTES];
    uint8_t sk[ML_DSA_87_SECRET_KEY_BYTES];

    printf("--- Keypair Generation ---\n");
    QUDO_MLDSA_status_t ret = QUDO_MLDSA_keypair(sig, pk, sk);
    if (ret != QUDO_MLDSA_SUCCESS) {
        fprintf(stderr, "Keypair generation failed\n");
        QUDO_MLDSA_free(sig);
        return 1;
    }
    printf("✓ Keypair generated\n\n");

    printf("--- Concatenated Format Signing ---\n");
    size_t sm_max_len = sig_len + msglen + 100;
    uint8_t *sm = malloc(sm_max_len);
    if (!sm) {
        fprintf(stderr, "Memory allocation failed\n");
        QUDO_MLDSA_free(sig);
        return 1;
    }
    size_t sm_len = sm_max_len;

    print_hex("Original message", (const uint8_t *)message, msglen);
    printf("Message length: %zu bytes\n", msglen);
    printf("Context: \"%s\"\n", context);
    printf("Expected concatenated length: ~%zu bytes (sig + msg)\n", sm_max_len);

    ret = QUDO_MLDSA_sign_concat(sig, sm, &sm_len,
                                (const uint8_t *)message, msglen,
                                (const uint8_t *)context, ctxlen,
                                sk);
    if (ret != QUDO_MLDSA_SUCCESS) {
        fprintf(stderr, "Concatenated signing failed: %s\n",
                QUDO_MLDSA_error_string(ret));
        QUDO_MLDSA_free(sig);
        return 1;
    }

    printf("\nConcatenated message created:\n");
    print_hex("Signed message (sig||msg)", sm, sm_len);
    printf("Signed message length: %zu bytes\n", sm_len);
    printf("✓ Concatenated format signature created\n\n");

    printf("--- Opening Concatenated Format ---\n");
    uint8_t *msg_out = malloc(msglen + 100);
    if (!msg_out) {
        fprintf(stderr, "Memory allocation failed\n");
        free(sm);
        QUDO_MLDSA_free(sig);
        return 1;
    }
    size_t msg_out_len = msglen + 100;
    memset(msg_out, 0, msglen + 100);

    ret = QUDO_MLDSA_open(sig, msg_out, &msg_out_len, sm, sm_len,
                        (const uint8_t *)context, ctxlen, pk);

    if (ret == QUDO_MLDSA_SUCCESS) {
        printf("✓ Signature VALID - Message extracted:\n");
        print_hex("Extracted message", msg_out, msg_out_len);
        printf("Extracted length: %zu bytes\n", msg_out_len);

        if (msg_out_len == msglen && memcmp(msg_out, message, msglen) == 0) {
            printf("✓ Extracted message matches original!\n");
            printf("Original:  \"%s\"\n", message);
            printf("Extracted: \"%.*s\"\n", (int)msg_out_len, msg_out);
        } else {
            printf("✗ Extracted message differs from original!\n");
        }
    } else {
        printf("✗ Signature INVALID or open failed: %s\n",
               QUDO_MLDSA_error_string(ret));
    }

    printf("\n--- Negative Test: Tampered Message ---\n");
    uint8_t *sm_tampered = malloc(sm_len);
    if (!sm_tampered) {
        fprintf(stderr, "Memory allocation failed\n");
        free(msg_out);
        free(sm);
        QUDO_MLDSA_free(sig);
        return 1;
    }
    memcpy(sm_tampered, sm, sm_len);

    if (sm_len > sig_len + 10) {
        sm_tampered[sig_len + 5] ^= 0xFF;
        printf("Tampered byte at position %zu\n", sig_len + 5);
    }

    uint8_t *msg_tampered = malloc(msglen + 100);
    if (!msg_tampered) {
        fprintf(stderr, "Memory allocation failed\n");
        free(sm_tampered);
        free(msg_out);
        free(sm);
        QUDO_MLDSA_free(sig);
        return 1;
    }
    size_t msg_tampered_len = msglen + 100;

    ret = QUDO_MLDSA_open(sig, msg_tampered, &msg_tampered_len, sm_tampered, sm_len,
                        (const uint8_t *)context, ctxlen, pk);

    if (ret != QUDO_MLDSA_SUCCESS) {
        printf("✓ Tampered message correctly rejected\n");
    } else {
        printf("✗ WARNING: Tampered message was accepted!\n");
    }

    printf("\n--- Negative Test: Wrong Context ---\n");
    const char *wrong_context = "wrong-context";

    ret = QUDO_MLDSA_open(sig, msg_out, &msg_out_len, sm, sm_len,
                        (const uint8_t *)wrong_context, strlen(wrong_context), pk);

    if (ret != QUDO_MLDSA_SUCCESS) {
        printf("✓ Wrong context correctly rejected\n");
    } else {
        printf("✗ WARNING: Wrong context was accepted!\n");
    }

    printf("\n=== Direct API (ML-DSA-65) ===\n");
    uint8_t *sm_direct = malloc(ML_DSA_65_SIGNATURE_BYTES + msglen + 100);
    if (!sm_direct) {
        fprintf(stderr, "Memory allocation failed\n");
        free(msg_tampered);
        free(sm_tampered);
        free(msg_out);
        free(sm);
        QUDO_MLDSA_free(sig);
        return 1;
    }
    size_t sm_direct_len = ML_DSA_65_SIGNATURE_BYTES + msglen + 100;

    ret = QUDO_MLDSA_ML_DSA_65_sign_concat(sm_direct, &sm_direct_len,
                                          (const uint8_t *)message, msglen,
                                          (const uint8_t *)context, ctxlen,
                                          sk);
    if (ret == QUDO_MLDSA_SUCCESS) {
        printf("Direct API signed message length: %zu bytes\n", sm_direct_len);

        uint8_t *msg_direct = malloc(msglen + 100);
        if (msg_direct) {
            size_t msg_direct_len = msglen + 100;

            ret = QUDO_MLDSA_ML_DSA_65_open(msg_direct, &msg_direct_len,
                                           sm_direct, sm_direct_len,
                                           (const uint8_t *)context, ctxlen,
                                           pk);
            printf("Direct API open: %s\n",
                   (ret == QUDO_MLDSA_SUCCESS) ? "✓ SUCCESS" : "✗ FAILED");
            free(msg_direct);
        }
    }
    free(sm_direct);
    free(msg_tampered);
    free(sm_tampered);
    free(msg_out);
    free(sm);
    QUDO_MLDSA_free(sig);

    printf("\n=== Use Cases ===\n");
    printf("Concatenated format is useful for:\n");
    printf("  - Email signatures (PGP-style)\n");
    printf("  - Single-blob signed documents\n");
    printf("  - APIs expecting combined sig+msg\n");
    printf("  - Backwards compatibility\n");
    printf("  - Simplified transmission (one buffer)\n");

    return 0;
}
