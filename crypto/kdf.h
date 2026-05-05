#ifndef FENC_KDF_H
#define FENC_KDF_H

#include <openssl/evp.h>

#define KEY_LEN        32      /* 256-bit AES key       */
#define SALT_LEN       16      /* 128-bit random salt   */
#define IV_LEN         16      /* 128-bit IV for AES-CBC */
#define KDF_ITERATIONS 200000  /* PBKDF2 iteration count */

int derive_key(const char *password, const unsigned char *salt, unsigned char *key);
int generate_random_bytes(unsigned char *buffer, int length);

#endif
