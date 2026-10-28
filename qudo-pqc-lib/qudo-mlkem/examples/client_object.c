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
    const char *algorithm = QUDO_KEM_alg_mlkem_768;
    QUDO_KEM *kem = NULL;

    if (argc > 1) {
        if (strcmp(argv[1], "512") == 0) algorithm = QUDO_KEM_alg_mlkem_512;
        else if (strcmp(argv[1], "768") == 0) algorithm = QUDO_KEM_alg_mlkem_768;
        else if (strcmp(argv[1], "1024") == 0) algorithm = QUDO_KEM_alg_mlkem_1024;
        else {
            fprintf(stderr, "Usage: %s [512|768|1024]\n", argv[0]);
            return 1;
        }
    }

    printf("==================================================\n");
    printf("ML-KEM Client - Object API\n");
    printf("==================================================\n\n");

    printf("[INIT] Creating QUDO_KEM object...\n");
    kem = QUDO_KEM_new(algorithm);
    if (!kem) {
        fprintf(stderr, "ERROR: Failed to create QUDO_KEM object for %s\n", algorithm);
        return 1;
    }
    printf("  Library version: %s\n", QUDO_KEM_get_version());
    printf("  Platform: %s (%s)\n", QUDO_KEM_get_platform(), QUDO_KEM_get_architecture());

    printf("  Algorithm:     %s\n", kem->algorithm_name);
    printf("  NIST Level:    %d\n\n", kem->claimed_nist_level);

    printf("[INFO] Key sizes:\n");
    printf("  Public key:    %zu bytes\n", kem->length_public_key);
    printf("  Ciphertext:    %zu bytes\n", kem->length_ciphertext);
    printf("  Shared secret: %zu bytes\n\n", kem->length_shared_secret);
    printf("  Connecting to: %s:%d\n\n", SERVER_IP, SERVER_PORT);

    uint8_t *public_key = malloc(kem->length_public_key);
    uint8_t *ciphertext = malloc(kem->length_ciphertext);
    uint8_t *shared_secret = malloc(kem->length_shared_secret);

    if (!public_key || !ciphertext || !shared_secret) {
        fprintf(stderr, "ERROR: Memory allocation failed\n");
        QUDO_KEM_free(kem);
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

    ssize_t bytes_read = read(sock, public_key, kem->length_public_key);
    if (bytes_read != (ssize_t)kem->length_public_key) {
        fprintf(stderr, "  ERROR: Expected %zu bytes, got %zd\n", kem->length_public_key, bytes_read);
        close(sock);
        goto cleanup;
    }
    printf("  [OK] Public key received (%zd bytes)\n", bytes_read);
    print_hex("  Public key", public_key, kem->length_public_key);
    printf("\n");

    printf("[4] Encapsulating shared secret (Object API)...\n");

    QUDO_KEM_status_t status = QUDO_KEM_encaps(kem, ciphertext, shared_secret, public_key);

    if (status != QUDO_KEM_SUCCESS) {
        fprintf(stderr, "  ERROR: Encapsulation failed (status=%d)\n", status);
        close(sock);
        goto cleanup;
    }

    printf("  [OK] Encapsulation successful\n");
    print_hex("  Shared secret", shared_secret, kem->length_shared_secret);
    print_hex("  Ciphertext", ciphertext, kem->length_ciphertext);
    printf("\n");

    printf("[5] Sending ciphertext to server...\n");
    if (send(sock, ciphertext, kem->length_ciphertext, 0) != (ssize_t)kem->length_ciphertext) {
        fprintf(stderr, "  ERROR: Failed to send ciphertext\n");
        close(sock);
        goto cleanup;
    }
    printf("  [OK] Ciphertext sent (%zu bytes)\n\n", kem->length_ciphertext);

    printf("[6] Sending encrypted message...\n");
    const char *message = "Hello from Client (PQC secured - Object API)";
    uint8_t encrypted_msg[256];
    size_t msg_len = strlen(message);
    xor_encrypt_decrypt(encrypted_msg, (const uint8_t*)message, msg_len,
                       shared_secret, kem->length_shared_secret);

    if (send(sock, encrypted_msg, msg_len, 0) < 0) {
        fprintf(stderr, "  ERROR: Failed to send encrypted message\n");
    } else {
        printf("  [OK] Encrypted message sent\n");

        uint8_t encrypted_response[256];
        bytes_read = read(sock, encrypted_response, sizeof(encrypted_response));
        if (bytes_read > 0) {
            uint8_t decrypted_response[256];
            xor_encrypt_decrypt(decrypted_response, encrypted_response, bytes_read,
                              shared_secret, kem->length_shared_secret);
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
    QUDO_KEM_free(kem);

#ifdef _WIN32
    WSACleanup();
#endif

    return 0;
}
