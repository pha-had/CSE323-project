#include <stdio.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include "kdf.h"

int derive_key(const char *password, const unsigned char *salt, unsigned char *key) {
    int result = PKCS5_PBKDF2_HMAC(
        password, (int)strlen(password),
        salt, SALT_LEN,
        KDF_ITERATIONS,
        EVP_sha256(),
        KEY_LEN, key
    );
    if (result != 1) {
        fprintf(stderr, "Error: Key derivation failed.\n");
        return 0;
    }
    return 1;
}

int generate_random_bytes(unsigned char *buffer, int length) {
    if (RAND_bytes(buffer, length) != 1) {
        fprintf(stderr, "Error: Failed to generate random bytes.\n");
        return 0;
    }
    return 1;
}
