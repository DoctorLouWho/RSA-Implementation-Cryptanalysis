/*
 * This file runs a simple implementation of the RSA encryption/decryption of a message
 * using the mbedTLS library
 *
 * Author: Felipe Marques Allevato
 * Author: Nika Ghasemi Barmi
 */

#include "mbedtls/pk.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include <string.h>
#include <stdio.h>

#define KEY_LEN 2048
#define MESSAGE_LEN KEY_LEN / 8
#define EXPONENT 65537

int main(void) {
    int ret;
    mbedtls_pk_context pk;
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;

    const char *personalization = "rsa_example";

    unsigned char ciphertext[MESSAGE_LEN];
    size_t olen;

    mbedtls_pk_init(&pk);
    mbedtls_ctr_drbg_init(&ctr_drbg);
    mbedtls_entropy_init(&entropy);

    // Seed the random number generator
    ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy,
                                (const unsigned char *)personalization, strlen(personalization));
    if (ret != 0) {
        printf("Failed in mbedtls_ctr_drbg_seed: %d\n", ret);
        return -1;
    }

    // Generate an RSA key pair
    ret = mbedtls_pk_setup(&pk, mbedtls_pk_info_from_type(MBEDTLS_PK_RSA));
    if (ret != 0) {
        printf("Failed in mbedtls_pk_setup: %d\n", ret);
        return -1;
    }

    ret = mbedtls_rsa_gen_key(mbedtls_pk_rsa(pk), mbedtls_ctr_drbg_random, &ctr_drbg, KEY_LEN, EXPONENT);
    if (ret != 0) {
        printf("Failed in mbedtls_rsa_gen_key: %d\n", ret);
        return -1;  
    }

    // Message to encrypt
    const char *message = "The quick brown fox jumps over the lazy dog";

    // Encrypt the message
    ret = mbedtls_pk_encrypt(&pk, (const unsigned char *)message, strlen(message),
                             ciphertext, &olen, MESSAGE_LEN,
                             mbedtls_ctr_drbg_random, &ctr_drbg);
    if (ret != 0) {
        printf("Failed in mbedtls_pk_encrypt: %d\n", ret);
        return -1;
    }

    printf("Encrypted message hex: ");
    for(int i = 0; i < MESSAGE_LEN; i++) {
        printf("%02x", ciphertext[i]); // Print each byte as a two-digit hexadecimal number
    }
    printf("\n");

    printf("Encrypted Message len: %d\n", MESSAGE_LEN);
    unsigned char decrypted[MESSAGE_LEN]; // Ensure this buffer is large enough

    // Decrypt the message
    ret = mbedtls_pk_decrypt(&pk, ciphertext, olen, decrypted, &olen,
                             sizeof(decrypted), mbedtls_ctr_drbg_random, &ctr_drbg);
    if (ret != 0) {
        printf("Failed in mbedtls_pk_decrypt: %d\n", ret);
        return -1;
    }

    // Output the decrypted message
    printf("Decrypted message: %.*s\n", (int)olen, decrypted);
    
    return 0;
}
