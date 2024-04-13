/*
 * This file runs a simple implementation of the RSA encryption/decryption of a message
 * using the OpenSSL library
 *
 * Author: Felipe Marques Allevato
 * Author: Nika Ghasemi Barmi
 */

#include <stdio.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>

#define KEY_LEN 2048
#define MESSAGE_LEN KEY_LEN / 8

// Initialize OpenSSL algorithms
void initialize_openssl() {
    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();
}

// Cleanup OpenSSL variables and strings
void cleanup_openssl() {
    EVP_cleanup();
    ERR_free_strings();
}

// Create RSA key pair
RSA *create_rsa_key() {
    int ret;
    RSA *rsa = NULL;
    BIGNUM *bn = NULL;

    bn = BN_new();
    ret = BN_set_word(bn, RSA_F4); // RSA_F4 is the macro for 65537
    if (ret != 1) {
        fprintf(stderr, "BN_set_word failed\n");
        return NULL;
    }

    rsa = RSA_new();
    ret = RSA_generate_key_ex(rsa, KEY_LEN, bn, NULL);
    if (ret != 1) {
        fprintf(stderr, "RSA_generate_key_ex failed\n");
        RSA_free(rsa);
        rsa = NULL;
    }

    BN_free(bn);
    return rsa;
}

// Main function to execute experiment
int main() {
    initialize_openssl();

    RSA *rsa = create_rsa_key();
    if (rsa == NULL) {
        fprintf(stderr, "RSA key generation failed\n");
        cleanup_openssl();
        return 1;
    }

    // Message to be encrypted
    char *message = "Hello, world!";
    unsigned char encrypted[MESSAGE_LEN];
    unsigned char decrypted[MESSAGE_LEN];

    // Encrypt the message
    int encrypted_length = RSA_public_encrypt(strlen(message) + 1, (unsigned char*)message, encrypted, rsa, RSA_PKCS1_PADDING);
    if (encrypted_length == -1) {
        char err[130];
        ERR_error_string(ERR_get_error(), err);
        fprintf(stderr, "Error encrypting message: %s\n", err);
        RSA_free(rsa);
        cleanup_openssl();
        return 1;
    }

    printf("Encrypted message hex: %x\n", encrypted);
    printf("Encrypted message length = %d\n", encrypted_length);

    // Decrypt the message
    int decrypted_length = RSA_private_decrypt(encrypted_length, encrypted, decrypted, rsa, RSA_PKCS1_PADDING);
    if (decrypted_length == -1) {
        char err[130];
        ERR_error_string(ERR_get_error(), err);
        fprintf(stderr, "Error decrypting message: %s\n", err);
        RSA_free(rsa);
        cleanup_openssl();
        return 1;
    }

    printf("Decrypted message: %s\n", decrypted);

    RSA_free(rsa);
    cleanup_openssl();
    return 0;
}
