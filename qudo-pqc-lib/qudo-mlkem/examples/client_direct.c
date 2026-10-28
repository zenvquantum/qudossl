/* SPDX-License-Identifier: Apache-2.0 AND MIT */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
    #include <winsock2.h>
    #include <ws2tcpip.h>
    #include <BaseTsd.h>
    typedef SSIZE_T ssize_t;
    #pragma comment(lib, "ws2_32.lib")
    #define close closesocket
    typedef int socklen_t;
#else
    #include <unistd.h>
    #include <arpa/inet.h>
    #include <sys/socket.h>
#endif

#include "mlkem_wrapper.h"
#include "common_network.h"

int main(int argc, char *argv[]) {
#ifdef _WIN32
    WSADATA wsa_data;
    if (WSAStartup(MAKEWORD(2, 2), &wsa_data) != 0) {
        fprintf(stderr, "ERROR: WSAStartup failed\n");
        return 1;
    }
#endif

    int sock = 0;
    struct sockaddr_in serv_addr;
    QUDO_KEM_security_level_t level = QUDO_KEM_768;

    if (argc > 1) {
        if (strcmp(argv[1], "512") == 0) level = QUDO_KEM_512;
        else if (strcmp(argv[1], "768") == 0) level = QUDO_KEM_768;
        else if (strcmp(argv[1], "1024") == 0) level = QUDO_KEM_1024;
        else {
            fprintf(stderr, "Usage: %s [512|768|1024]\n", argv[0]);
            return 1;
        }
    }

    printf("==================================================\n");
    printf("ML-KEM Client - Direct API\n");
    printf("==================================================\n\n");

    printf("[INIT] Initializing QUDO KEM library...\n");
    if (QUDO_KEM_init() != QUDO_KEM_SUCCESS) {
        fprintf(stderr, "ERROR: Library initialization failed\n");
        return 1;
    }
    printf("  Library version: %s\n", QUDO_KEM_get_version());
    printf("  Platform: %s (%s)\n", QUDO_KEM_get_platform(), QUDO_KEM_get_architecture());
    printf("  Algorithm: %s\n\n", QUDO_KEM_get_algorithm_name(level));

    size_t pk_len = QUDO_KEM_get_public_key_size(level);
    size_t ct_len = QUDO_KEM_get_ciphertext_size(level);
    size_t ss_len = QUDO_KEM_get_shared_secret_size(level);

    printf("[INFO] Key sizes:\n");
    printf("  Public key:    %zu bytes\n", pk_len);
    printf("  Ciphertext:    %zu bytes\n", ct_len);
    printf("  Shared secret: %zu bytes\n\n", ss_len);
    printf("  Connecting to: %s:%d\n\n", SERVER_IP, SERVER_PORT);

    uint8_t *public_key = malloc(pk_len);
    uint8_t *ciphertext = malloc(ct_len);
    uint8_t *shared_secret = malloc(ss_len);

    if (!public_key || !ciphertext || !shared_secret) {
        fprintf(stderr, "ERROR: Memory allocation failed\n");
        return 1;
    }

    printf("[1] Creating socket...\n");
    if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        perror("  ERROR: Socket creation failed");
        goto cleanup;
    }
    printf("  [OK] Socket created\n\n");

    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(SERVER_PORT);

    if (inet_pton(AF_INET, SERVER_IP, &serv_addr.sin_addr) <= 0) {
        perror("  ERROR: Invalid address");
        goto cleanup;
    }

    printf("[2] Connecting to server...\n");
    if (connect(sock, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
        perror("  ERROR: Connection failed");
        goto cleanup;
    }
    printf("  [OK] Connected to server\n\n");

    printf("[3] Requesting public key...\n");
    const char *request = MSG_GET_PUBLIC_KEY;
    if (send(sock, request, strlen(request), 0) < 0) {
        fprintf(stderr, "  ERROR: Failed to send request\n");
        close(sock);
        goto cleanup;
    }

    ssize_t bytes_read = read(sock, public_key, pk_len);
    if (bytes_read != (ssize_t)pk_len) {
        fprintf(stderr, "  ERROR: Expected %zu bytes, got %zd\n", pk_len, bytes_read);
        close(sock);
        goto cleanup;
    }
    printf("  [OK] Public key received (%zd bytes)\n", bytes_read);
    print_hex("  Public key", public_key, pk_len);
    printf("\n");

    printf("[4] Encapsulating shared secret (Direct API)...\n");

    QUDO_KEM_status_t status = QUDO_KEM_encapsulate(level, ciphertext, shared_secret, public_key);

    if (status != QUDO_KEM_SUCCESS) {
        fprintf(stderr, "  ERROR: Encapsulation failed (status=%d)\n", status);
        close(sock);
        goto cleanup;
    }

    printf("  [OK] Encapsulation successful\n");
    print_hex("  Shared secret", shared_secret, ss_len);
    print_hex("  Ciphertext", ciphertext, ct_len);
    printf("\n");

    printf("[5] Sending ciphertext to server...\n");
    if (send(sock, ciphertext, ct_len, 0) != (ssize_t)ct_len) {
        fprintf(stderr, "  ERROR: Failed to send ciphertext\n");
        close(sock);
        goto cleanup;
    }
    printf("  [OK] Ciphertext sent (%zu bytes)\n\n", ct_len);

    printf("[6] Sending encrypted message...\n");
    const char *message = "Hello from Client (PQC secured)";
    uint8_t encrypted_msg[256];
    size_t msg_len = strlen(message);
    xor_encrypt_decrypt(encrypted_msg, (const uint8_t*)message, msg_len, shared_secret, ss_len);

    if (send(sock, encrypted_msg, msg_len, 0) < 0) {
        fprintf(stderr, "  ERROR: Failed to send encrypted message\n");
    } else {
        printf("  [OK] Encrypted message sent\n");

        uint8_t encrypted_response[256];
        bytes_read = read(sock, encrypted_response, sizeof(encrypted_response));
        if (bytes_read > 0) {
            uint8_t decrypted_response[256];
            xor_encrypt_decrypt(decrypted_response, encrypted_response, bytes_read, shared_secret, ss_len);
            decrypted_response[bytes_read] = '\0';
            printf("  [OK] Decrypted response: \"%s\"\n", decrypted_response);
        }
    }

    printf("\n==================================================\n");
    printf("[OK] Key exchange complete - secure channel established!\n");
    printf("==================================================\n");

    close(sock);

cleanup:
    free(public_key);
    free(ciphertext);
    free(shared_secret);
    QUDO_KEM_cleanup();

#ifdef _WIN32
    WSACleanup();
#endif

    return 0;
}
