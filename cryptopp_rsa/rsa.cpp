#include <cryptopp/rsa.h>
#include <cryptopp/osrng.h>
#include <cryptopp/hex.h>
#include <cryptopp/files.h>
#include <iostream>
#include <string>

using namespace CryptoPP;

#define KEY_LEN 2048
#define MESSAGE_LEN KEY_LEN / 8
#define PUBLIC_EXPONENT 65537

int main() {
    // Message to be encrypted
    std::string plain = "Hello, World!";
    std::string cipher, recovered;

    // Generate RSA keys
    AutoSeededRandomPool rng;
    RSA::PrivateKey privateKey;
    RSA::PublicKey publicKey;

    // Initialize the key generator with 2048 bits and public exponent 65537
    InvertibleRSAFunction parameters;
    parameters.GenerateRandomWithKeySize(rng, KEY_LEN);
    parameters.SetPublicExponent(Integer(PUBLIC_EXPONENT));

    privateKey.Initialize(rng, KEY_LEN);
    publicKey.AssignFrom(privateKey);

    // Encryptor and decryptor
    RSAES_OAEP_SHA_Encryptor encryptor(publicKey);
    RSAES_OAEP_SHA_Decryptor decryptor(privateKey);

    // Encrypt
    StringSource(plain, true,
        new PK_EncryptorFilter(rng, encryptor,
            new StringSink(cipher)
        ) // PK_EncryptorFilter
    ); // StringSource

    // Decrypt
    StringSource(cipher, true,
        new PK_DecryptorFilter(rng, decryptor,
            new StringSink(recovered)
        ) // PK_DecryptorFilter
    ); // StringSource

    // Output results in hexadecimal
    std::cout << "Encrypted Message Hex: ";
    StringSource(cipher, true, new HexEncoder(new FileSink(std::cout)));
    std::cout << std::endl;

    std::cout << "Ecnrypted Message Length: " << MESSAGE_LEN << std::endl;

    std::cout << "Decrypted Message: " << recovered << std::endl;
    return 0;
}
