/*
 * This file runs a simple implementation of the RSA encryption/decryption of a message
 * using the WolfSSL/WolfCrypt library
 *
 * Author: Felipe Marques Allevato
 * Author: Nika Ghasemi Barmi
 */

#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/rsa.h>
#include <wolfssl/wolfcrypt/random.h>
#include <stdio.h>
#include <stdlib.h>

#define RSA_KEY_SIZE 2048
#define BUFFER_SIZE RSA_KEY_SIZE / 8
#define EXPONENT 65537

int main() {
    int ret;
    RsaKey key;
    WC_RNG rng;

    byte plainText[] = "This is the message to be encrypted";
    byte cipherText[BUFFER_SIZE];
    byte decryptedText[BUFFER_SIZE];

    word32 cipherLen, plainLen;

    /* Initialize the RNG */
    ret = wc_InitRng(&rng);
    if (ret != 0) {
        printf("RNG initialization failed\n");
        return -1;
    }

    /* Initialize the RSA key */
    ret = wc_InitRsaKey(&key, NULL);
    if (ret != 0) {
        printf("RSA key initialization failed\n");
        wc_FreeRng(&rng);
        return -1;
    }

    /* Set RSA RNG */
    ret = wc_RsaSetRNG(&key, &rng);
    if (ret != 0){
    	printf("RSA RNG Setting failed\n");
    	return -1;
    }

    /* Generate a new RSA keypair */
    ret = wc_MakeRsaKey(&key, RSA_KEY_SIZE, EXPONENT, &rng);
    if (ret != 0) {
        printf("RSA key generation failed\n");
        return -1;
    }

    /* Encrypt the message */
    plainLen = sizeof(plainText) - 1; // excluding null terminator
    ret = wc_RsaPublicEncrypt(plainText, plainLen, cipherText, BUFFER_SIZE, &key, &rng);
    if (ret < 0) {
        printf("RSA encryption failed\n");
        return -1;
    }

    cipherLen = ret; // Length of the cipher text

    printf("Encryption successful!\n");
    
	/* Decrypt the message */
	ret = wc_RsaPrivateDecrypt(cipherText, cipherLen, decryptedText, BUFFER_SIZE, &key);
	if (ret < 0) {
	    printf("RSA decryption failed with error: %d\n", ret);
	    return -1;
	}

    plainLen = ret; // Length of the decrypted text

    printf("Decryption successful!\n");
    printf("Decrypted text: %s\n", decryptedText);

    /* Clean up */
    wc_FreeRsaKey(&key);
    wc_FreeRng(&rng);

    return 0;
}