#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include "../vault/vault.h"
#include "kdf.h"
#include "../utils/utils.h"
#include "../utils/audit.h"
#include "integrity.h"

#define CHUNK_SIZE 65536

static uint64_t pkcs7_cipher_len(uint64_t plain_len) {
    return ((plain_len / 16ULL) + 1ULL) * 16ULL;
}

static int read_bytes_at(FILE *f, long offset, unsigned char *buf, size_t len) {
    if (fseek(f, offset, SEEK_SET) != 0) {
        return 0;
    }
    return fread(buf, 1, len, f) == len;
}

static int compute_hmac_over_range(FILE *f, long start_offset, uint64_t data_len,
                                   const unsigned char *key, const unsigned char *iv,
                                   unsigned char *out) {
    if (fseek(f, start_offset, SEEK_SET) != 0) {
        return 0;
    }

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        return 0;
    }

    if (!EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv)) {
        EVP_CIPHER_CTX_free(ctx);
        return 0;
    }

    EVP_MAC *mac = EVP_MAC_fetch(NULL, "HMAC", NULL);
    if (!mac) {
        EVP_CIPHER_CTX_free(ctx);
        return 0;
    }

    EVP_MAC_CTX *hctx = EVP_MAC_CTX_new(mac);
    if (!hctx) {
        EVP_MAC_free(mac);
        EVP_CIPHER_CTX_free(ctx);
        return 0;
    }

    OSSL_PARAM params[] = {
        OSSL_PARAM_construct_utf8_string("digest", "SHA256", 0),
        OSSL_PARAM_construct_end()
    };

    int ok = 0;
    if (!EVP_MAC_init(hctx, key, KEY_LEN, params)) {
        goto cleanup;
    }

    unsigned char cipher_buf[CHUNK_SIZE];
    unsigned char plain_buf[CHUNK_SIZE + EVP_MAX_BLOCK_LENGTH];
    uint64_t remaining = data_len;
    int plain_len = 0;
    while (remaining > 0) {
        size_t to_read = (remaining < CHUNK_SIZE) ? (size_t)remaining : CHUNK_SIZE;
        size_t n = fread(cipher_buf, 1, to_read, f);
        if (n != to_read) {
            goto cleanup;
        }
        if (!EVP_DecryptUpdate(ctx, plain_buf, &plain_len, cipher_buf, (int)n)) {
            goto cleanup;
        }
        if (!EVP_MAC_update(hctx, plain_buf, (size_t)plain_len)) {
            goto cleanup;
        }
        remaining -= n;
    }

    if (!EVP_DecryptFinal_ex(ctx, plain_buf, &plain_len)) {
        goto cleanup;
    }
    if (plain_len > 0 && !EVP_MAC_update(hctx, plain_buf, (size_t)plain_len)) {
        goto cleanup;
    }

    size_t out_len = HMAC_LEN;
    if (!EVP_MAC_final(hctx, out, &out_len, HMAC_LEN) || out_len != HMAC_LEN) {
        goto cleanup;
    }

    ok = 1;

cleanup:
    EVP_MAC_CTX_free(hctx);
    EVP_MAC_free(mac);
    EVP_CIPHER_CTX_free(ctx);
    return ok;
}

int integrity_compute(const unsigned char *key, int key_len,
                      const unsigned char *data, size_t data_len,
                      unsigned char *out) {
    unsigned int out_len = 32;
    if (!HMAC(EVP_sha256(), key, key_len, data, data_len, out, &out_len))
        return 0;
    return 1;
}

int integrity_verify(const unsigned char *expected, const unsigned char *actual, size_t len) {
    /* Constant-time compare — never short-circuit on mismatch */
    volatile unsigned char diff = 0;
    for (size_t i = 0; i < len; i++)
        diff |= expected[i] ^ actual[i];
    return diff == 0;
}

int verify_file(const char *in_path, const char *password) {
    printf("[*] Verifying integrity: %s\n", in_path);

    FILE *f = fopen(in_path, "rb");
    if (!f) {
        printf("[!] Integrity FAILED - file may be corrupted or tampered!\n");
        audit_log(AUDIT_VERIFY, in_path, 0);
        return 0;
    }

    VaultHeader hdr;
    int ok = 0;

    if (!vault_read_header(f, &hdr) || !vault_validate_header(&hdr)) {
        goto done;
    }

    if (fseek(f, 0, SEEK_END) != 0) {
        goto done;
    }

    long file_size = ftell(f);
    if (file_size <= 0) {
        goto done;
    }

    unsigned char key[KEY_LEN];

    if (hdr.duress_flag == 0) {
        long cipher_start = (long)sizeof(VaultHeader);
        long cipher_len = file_size - cipher_start - (long)HMAC_LEN;
        if (cipher_len <= 0) {
            goto done;
        }

        unsigned char stored_hmac[HMAC_LEN];
        if (!vault_read_hmac(f, stored_hmac)) {
            goto done;
        }

        if (!derive_key(password, hdr.salt, key)) {
            goto done;
        }

        unsigned char computed_hmac[HMAC_LEN];
        if (!compute_hmac_over_range(f, cipher_start, (uint64_t)cipher_len, key, hdr.iv, computed_hmac)) {
            goto done;
        }

        ok = integrity_verify(stored_hmac, computed_hmac, HMAC_LEN);
    } else {
        uint64_t real_cipher_len = pkcs7_cipher_len(hdr.original_size);
        uint64_t decoy_cipher_len = pkcs7_cipher_len(hdr.decoy_size);
        long real_cipher_start = (long)sizeof(VaultHeader);
        long real_hmac_pos = real_cipher_start + (long)real_cipher_len;
        long decoy_cipher_start = real_hmac_pos + (long)HMAC_LEN;
        long expected_size = decoy_cipher_start + (long)decoy_cipher_len + (long)HMAC_LEN;

        if ((long)file_size != expected_size) {
            goto done;
        }

        unsigned char real_hmac[HMAC_LEN];
        if (!read_bytes_at(f, real_hmac_pos, real_hmac, HMAC_LEN)) {
            goto done;
        }

        if (derive_key(password, hdr.salt, key)) {
            unsigned char computed_hmac[HMAC_LEN];
            if (compute_hmac_over_range(f, real_cipher_start, real_cipher_len, key, hdr.iv, computed_hmac) &&
                integrity_verify(real_hmac, computed_hmac, HMAC_LEN)) {
                ok = 1;
            }
        }

        if (!ok) {
            unsigned char decoy_hmac[HMAC_LEN];
            if (!vault_read_hmac(f, decoy_hmac)) {
                goto done;
            }

            if (derive_key(password, hdr.decoy_salt, key)) {
                unsigned char computed_hmac[HMAC_LEN];
                if (compute_hmac_over_range(f, decoy_cipher_start, decoy_cipher_len, key, hdr.decoy_iv, computed_hmac) &&
                    integrity_verify(decoy_hmac, computed_hmac, HMAC_LEN)) {
                    ok = 1;
                }
            }
        }
    }

done:
    fclose(f);

    if (ok) {
        printf("[+] Integrity PASSED - file is authentic and untampered\n");
    } else {
        printf("[!] Integrity FAILED - file may be corrupted or tampered!\n");
    }

    audit_log(AUDIT_VERIFY, in_path, ok);
    secure_wipe(key, KEY_LEN);
    return ok;
}
