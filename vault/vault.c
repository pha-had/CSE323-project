#include <stdio.h>
#include <string.h>
#include "../crypto/kdf.h"
#include "vault.h"

int vault_write_header(FILE *f, const VaultHeader *header) {
    if (fwrite(header, sizeof(VaultHeader), 1, f) != 1) {
        fprintf(stderr, "Error: Failed to write vault header.\n");
        return 0;
    }
    return 1;
}

int vault_read_header(FILE *f, VaultHeader *header) {
    rewind(f);
    if (fread(header, sizeof(VaultHeader), 1, f) != 1) {
        fprintf(stderr, "Error: Failed to read vault header.\n");
        return 0;
    }
    return 1;
}

int vault_validate_header(const VaultHeader *header) {
    if (memcmp(header->magic, MAGIC, MAGIC_LEN) != 0) {
        fprintf(stderr, "Error: Not a valid vault file.\n");
        return 0;
    }
    if (header->version != VERSION) {
        fprintf(stderr, "Error: Unsupported vault version %d.\n", header->version);
        return 0;
    }
    if (header->duress_flag != 0 && header->duress_flag != 1) {
        fprintf(stderr, "Error: Invalid duress flag value %u in vault header.\n", (unsigned)header->duress_flag);
        return 0;
    }
    return 1;
}

int vault_write_hmac(FILE *f, const unsigned char *hmac) {
    /* Seek to end and append the 32-byte HMAC */
    if (fseek(f, 0, SEEK_END) != 0) return 0;
    if (fwrite(hmac, 1, HMAC_LEN, f) != HMAC_LEN) {
        fprintf(stderr, "Error: Failed to write HMAC.\n");
        return 0;
    }
    return 1;
}

int vault_read_hmac(FILE *f, unsigned char *hmac) {
    /* HMAC sits in the last 32 bytes of the file */
    if (fseek(f, -(long)HMAC_LEN, SEEK_END) != 0) return 0;
    if (fread(hmac, 1, HMAC_LEN, f) != HMAC_LEN) {
        fprintf(stderr, "Error: Failed to read HMAC.\n");
        return 0;
    }
    return 1;
}

/* Duress mode: write second HMAC for decoy file (between real and decoy ciphertext) */
int vault_write_decoy_hmac(FILE *f, const unsigned char *hmac) {
    if (fwrite(hmac, 1, HMAC_LEN, f) != HMAC_LEN) {
        fprintf(stderr, "Error: Failed to write decoy HMAC.\n");
        return 0;
    }
    return 1;
}

/* Duress mode: read second HMAC for decoy file */
int vault_read_decoy_hmac(FILE *f, long real_cipher_len, unsigned char *hmac) {
    /* Decoy HMAC comes right after real ciphertext + real HMAC */
    long pos = (long)sizeof(VaultHeader) + real_cipher_len + (long)HMAC_LEN;
    if (fseek(f, pos, SEEK_SET) != 0) return 0;
    if (fread(hmac, 1, HMAC_LEN, f) != HMAC_LEN) {
        fprintf(stderr, "Error: Failed to read decoy HMAC.\n");
        return 0;
    }
    return 1;
}
