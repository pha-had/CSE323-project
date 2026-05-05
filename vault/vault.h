#ifndef FENC_VAULT_H
#define FENC_VAULT_H

#include <stdio.h>
#include <stdint.h>
#include "../crypto/kdf.h"

#define MAGIC     "FENC"
#define MAGIC_LEN 4
#define HMAC_LEN  32
#define VERSION   1

/*
 * .enc file layout:
 * Standard mode: [ VaultHeader | ciphertext | HMAC (32 bytes) ]
 * Duress mode:   [ VaultHeader | real_ciphertext | real_HMAC (32) | decoy_ciphertext | decoy_HMAC (32) ]
 *
 * VaultHeader:
 *   magic[4] | version[1] | duress_flag[1] | salt[16] | iv[16] | original_size[8] |
 *   decoy_salt[16] | decoy_iv[16] | decoy_size[8]
 *
 * Note: This header is read/written as a raw C struct in vault.c.
 * On the current toolchain it is 88 bytes due to alignment padding.
 */

typedef struct {
    unsigned char  magic[MAGIC_LEN];      /*  4 bytes */
    unsigned char  version;               /*  1 byte  */
    unsigned char  duress_flag;           /*  1 byte  (0=standard, 1=duress mode) */
    unsigned char  salt[SALT_LEN];        /* 16 bytes (real file) */
    unsigned char  iv[IV_LEN];            /* 16 bytes (real file) */
    uint64_t       original_size;         /*  8 bytes (real file) */
    unsigned char  decoy_salt[SALT_LEN];  /* 16 bytes (decoy file, only if duress_flag=1) */
    unsigned char  decoy_iv[IV_LEN];      /* 16 bytes (decoy file, only if duress_flag=1) */
    uint64_t       decoy_size;            /*  8 bytes (decoy file, only if duress_flag=1) */
} VaultHeader;

int vault_write_header(FILE *f, const VaultHeader *header);
int vault_read_header (FILE *f, VaultHeader *header);
int vault_validate_header(const VaultHeader *header);

/* HMAC management */
int vault_write_hmac(FILE *f, const unsigned char *hmac);
int vault_read_hmac (FILE *f, unsigned char *hmac);

/* Duress mode: manage decoy HMAC (second HMAC in duress files) */
int vault_write_decoy_hmac(FILE *f, const unsigned char *hmac);
int vault_read_decoy_hmac (FILE *f, long real_cipher_len, unsigned char *hmac);

#endif
