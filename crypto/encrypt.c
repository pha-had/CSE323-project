#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <time.h>
#ifdef _WIN32
#include <io.h>
#endif
#include <openssl/evp.h>
#include "../vault/vault.h"
#include "kdf.h"
#include "encrypt.h"
#include "../utils/utils.h"
#include "../utils/audit.h"

#define CHUNK_SIZE 65536  /* 64 KB read chunks — handles files of any size */

static void normalize_input_path(char *path) {
    if (!path) return;

    if (path[0] == '/' && path[1] != '\0' && path[2] == '/' &&
        ((path[1] >= 'a' && path[1] <= 'z') || (path[1] >= 'A' && path[1] <= 'Z'))) {
        path[0] = (char)((path[1] >= 'a' && path[1] <= 'z') ? (path[1] - 'a' + 'A') : path[1]);
        path[1] = ':';
        path[2] = '/';
    }

    char *start = path;
    while (*start && isspace((unsigned char)*start)) {
        start++;
    }

    char *end = start + strlen(start);
    while (end > start && isspace((unsigned char)*(end - 1))) {
        end--;
    }
    *end = '\0';

    if ((end - start) >= 2 && start[0] == '"' && start[(end - start) - 1] == '"') {
        start++;
        end--;
        *end = '\0';
    }

    if (start != path) {
        memmove(path, start, strlen(start) + 1);
    }

    for (int i = 0; path[i] != '\0'; i++) {
        if (path[i] == '\\') {
            path[i] = '/';
        }
    }
}

int encrypt_file(const char *in_path, const char *out_path, const char *password) {
    FILE *in  = fopen(in_path,  "rb");
    FILE *out = fopen(out_path, "wb");
    if (!in)  { fprintf(stderr, "Error: Cannot open input file: %s\n",  in_path);  audit_log(AUDIT_ENCRYPT_FAILED_OPEN_INPUT, in_path, 0); return 0; }
    if (!out) { fprintf(stderr, "Error: Cannot open output file: %s\n", out_path); fclose(in); audit_log(AUDIT_ENCRYPT_FAILED_OPEN_OUTPUT, in_path, 0); return 0; }

    /* Show password strength */
    password_entropy_score(password);

    /* --- Get file size for progress bar --- */
#ifdef _WIN32
    long long file_size = _filelengthi64(_fileno(in));
#else
    fseek(in, 0, SEEK_END);
    long long file_size = ftell(in);
    fseek(in, 0, SEEK_SET);
#endif
    if (file_size < 0) {
        fprintf(stderr, "Error: Failed to determine input file size: %s\n", in_path);
        audit_log(AUDIT_ENCRYPT_FAILED_OPEN_INPUT, in_path, 0);
        fclose(in); fclose(out);
        return 0;
    }

    /* --- Build header --- */
    VaultHeader hdr;
    memset(&hdr, 0, sizeof(hdr));
    memcpy(hdr.magic, MAGIC, MAGIC_LEN);
    hdr.version       = VERSION;
    hdr.duress_flag   = 0;
    hdr.original_size = 0;

    if (!generate_random_bytes(hdr.salt, SALT_LEN) ||
        !generate_random_bytes(hdr.iv,   IV_LEN)) {
        audit_log(AUDIT_ENCRYPT_FAILED_RANDOM, in_path, 0);
        fclose(in); fclose(out); return 0;
    }

    /* Write placeholder header — will rewrite with original_size at end */
    if (!vault_write_header(out, &hdr)) {
        audit_log(AUDIT_ENCRYPT_FAILED_HEADER, in_path, 0);
        fclose(in); fclose(out); return 0;
    }

    /* --- Derive key --- */
    unsigned char key[KEY_LEN];
    if (!derive_key(password, hdr.salt, key)) {
        audit_log(AUDIT_ENCRYPT_FAILED_KDF, in_path, 0);
        fclose(in); fclose(out); return 0;
    }

    /* --- AES-256-CBC encryption --- */
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, hdr.iv);

    /* --- HMAC-SHA256 over plaintext (OpenSSL 3.0 EVP_MAC API) --- */
    EVP_MAC       *mac      = EVP_MAC_fetch(NULL, "HMAC", NULL);
    EVP_MAC_CTX   *hctx     = EVP_MAC_CTX_new(mac);
    OSSL_PARAM     params[] = {
        OSSL_PARAM_construct_utf8_string("digest", "SHA256", 0),
        OSSL_PARAM_construct_end()
    };
    EVP_MAC_init(hctx, key, KEY_LEN, params);

    unsigned char *in_buf  = malloc(CHUNK_SIZE);
    unsigned char *out_buf = malloc(CHUNK_SIZE + EVP_MAX_BLOCK_LENGTH);
    if (!in_buf || !out_buf) {
        fprintf(stderr, "Error: Out of memory.\n");
        free(in_buf); free(out_buf);
        EVP_CIPHER_CTX_free(ctx); EVP_MAC_CTX_free(hctx); EVP_MAC_free(mac);
        audit_log(AUDIT_ENCRYPT_FAILED_MEMORY, in_path, 0);
        fclose(in); fclose(out); return 0;
    }

    size_t n;
    int out_len;
    long long bytes_done = 0;
    clock_t start   = clock();

    printf("[*] Encrypting...\n");

    while ((n = fread(in_buf, 1, CHUNK_SIZE, in)) > 0) {
        hdr.original_size += (uint64_t)n;
        EVP_MAC_update(hctx, in_buf, n);
        EVP_EncryptUpdate(ctx, out_buf, &out_len, in_buf, (int)n);
        fwrite(out_buf, 1, out_len, out);

        /* --- Progress bar --- */
        bytes_done += (long long)n;
        int percent = (file_size > 0) ? (int)((bytes_done * 100LL) / file_size) : 100;
        int filled  = percent / 10;

        double elapsed = (double)(clock() - start) / CLOCKS_PER_SEC;
        double speed   = (elapsed > 0) ? (bytes_done / (1024.0 * 1024.0)) / elapsed : 0;

        printf("\r    [");
        for (int i = 0; i < 10; i++) printf("%c", i < filled ? '#' : '-');
        printf("] %3d%% | %.1f MB / %.1f MB | %.1f MB/s",
            percent,
            (double)bytes_done / (1024.0 * 1024.0),
            (double)file_size  / (1024.0 * 1024.0),
            speed);
        fflush(stdout);
    }

    /* Print final 100% */
    double total_time = (double)(clock() - start) / CLOCKS_PER_SEC;
    double avg_speed  = (total_time > 0) ? (file_size / (1024.0 * 1024.0)) / total_time : 0;
    printf("\r    [##########] 100%% | %.1f MB / %.1f MB | %.1f MB/s\n",
        (double)file_size / (1024.0 * 1024.0),
        (double)file_size / (1024.0 * 1024.0),
        avg_speed);
    printf("[+] Done in %.2f seconds\n", total_time);

    /* Flush final AES block (padding) */
    EVP_EncryptFinal_ex(ctx, out_buf, &out_len);
    fwrite(out_buf, 1, out_len, out);

    /* Finalise HMAC and append it */
    unsigned char hmac[HMAC_LEN];
    size_t hmac_len = HMAC_LEN;
    EVP_MAC_final(hctx, hmac, &hmac_len, HMAC_LEN);
    vault_write_hmac(out, hmac);
    EVP_MAC_CTX_free(hctx);
    EVP_MAC_free(mac);

    /* Rewrite header now that we know original_size */
    rewind(out);
    vault_write_header(out, &hdr);

    /* --- Zero key from memory --- */
    secure_wipe(key, KEY_LEN);
    secure_wipe(in_buf, CHUNK_SIZE);

    free(in_buf); free(out_buf);
    EVP_CIPHER_CTX_free(ctx);
    fclose(in); fclose(out);

    printf("[+] Encrypted:  %s  ->  %s\n", in_path, out_path);
    audit_log(AUDIT_ENCRYPT, in_path, 1);
    return 1;
}

/* === DURESS MODE: Encrypt real file + decoy file with different passwords === */
int encrypt_file_with_duress(const char *real_path, const char *decoy_path,
                             const char *out_path, const char *real_password,
                             const char *decoy_password) {
    char real_clean[2048];
    char decoy_clean[2048];

    snprintf(real_clean, sizeof(real_clean), "%s", real_path);
    snprintf(decoy_clean, sizeof(decoy_clean), "%s", decoy_path);
    normalize_input_path(real_clean);
    normalize_input_path(decoy_clean);

    FILE *real_in  = fopen(real_clean,  "rb");
    FILE *decoy_in = fopen(decoy_clean, "rb");
    FILE *out      = fopen(out_path,   "wb");
    if (!real_in)  { fprintf(stderr, "Error: Cannot open real file: %s\n", real_clean);     return 0; }
    if (!decoy_in) { fprintf(stderr, "Error: Cannot open decoy file: %s\n", decoy_clean);   fclose(real_in); return 0; }
    if (!out)      { fprintf(stderr, "Error: Cannot open output file: %s\n", out_path);    fclose(real_in); fclose(decoy_in); return 0; }

    printf("[*] Setting up duress encryption (real + decoy passwords)...\n");
    password_entropy_score(real_password);

    /* --- Build header with duress flag --- */
    VaultHeader hdr;
    memcpy(hdr.magic, MAGIC, MAGIC_LEN);
    hdr.version = VERSION;
    hdr.duress_flag = 1;  /* Mark as duress mode */
    hdr.original_size = 0;
    hdr.decoy_size = 0;

    /* Generate salt and IV for real file */
    if (!generate_random_bytes(hdr.salt, SALT_LEN) ||
        !generate_random_bytes(hdr.iv, IV_LEN)) {
        fprintf(stderr, "Error: Random generation failed.\n");
        fclose(real_in); fclose(decoy_in); fclose(out);
        return 0;
    }

    /* Generate salt and IV for decoy file */
    if (!generate_random_bytes(hdr.decoy_salt, SALT_LEN) ||
        !generate_random_bytes(hdr.decoy_iv, IV_LEN)) {
        fprintf(stderr, "Error: Random generation failed.\n");
        fclose(real_in); fclose(decoy_in); fclose(out);
        return 0;
    }

    /* Write header (placeholder, will rewrite at end) */
    if (!vault_write_header(out, &hdr)) {
        fclose(real_in); fclose(decoy_in); fclose(out);
        return 0;
    }

    /* --- Encrypt REAL file with real password --- */
    unsigned char real_key[KEY_LEN];
    if (!derive_key(real_password, hdr.salt, real_key)) {
        fclose(real_in); fclose(decoy_in); fclose(out);
        return 0;
    }

    EVP_CIPHER_CTX *real_ctx = EVP_CIPHER_CTX_new();
    EVP_EncryptInit_ex(real_ctx, EVP_aes_256_cbc(), NULL, real_key, hdr.iv);

    EVP_MAC *real_mac = EVP_MAC_fetch(NULL, "HMAC", NULL);
    EVP_MAC_CTX *real_hctx = EVP_MAC_CTX_new(real_mac);
    OSSL_PARAM real_params[] = {
        OSSL_PARAM_construct_utf8_string("digest", "SHA256", 0),
        OSSL_PARAM_construct_end()
    };
    EVP_MAC_init(real_hctx, real_key, KEY_LEN, real_params);

    unsigned char *in_buf  = malloc(CHUNK_SIZE);
    unsigned char *out_buf = malloc(CHUNK_SIZE + EVP_MAX_BLOCK_LENGTH);
    if (!in_buf || !out_buf) {
        fprintf(stderr, "Error: Out of memory.\n");
        free(in_buf); free(out_buf);
        EVP_CIPHER_CTX_free(real_ctx);
        EVP_MAC_CTX_free(real_hctx); EVP_MAC_free(real_mac);
        fclose(real_in); fclose(decoy_in); fclose(out);
        return 0;
    }

    printf("[*] Encrypting real file with real password...\n");
    size_t n;
    int out_len;
    while ((n = fread(in_buf, 1, CHUNK_SIZE, real_in)) > 0) {
        hdr.original_size += (uint64_t)n;
        EVP_MAC_update(real_hctx, in_buf, n);
        EVP_EncryptUpdate(real_ctx, out_buf, &out_len, in_buf, (int)n);
        fwrite(out_buf, 1, out_len, out);
    }

    EVP_EncryptFinal_ex(real_ctx, out_buf, &out_len);
    fwrite(out_buf, 1, out_len, out);

    unsigned char real_hmac[HMAC_LEN];
    size_t hmac_len = HMAC_LEN;
    EVP_MAC_final(real_hctx, real_hmac, &hmac_len, HMAC_LEN);
    vault_write_hmac(out, real_hmac);

    EVP_MAC_CTX_free(real_hctx);
    EVP_MAC_free(real_mac);
    EVP_CIPHER_CTX_free(real_ctx);
    fclose(real_in);

    printf("[+] Real file encrypted and HMAC appended.\n");

    /* --- Encrypt DECOY file with decoy password --- */
    unsigned char decoy_key[KEY_LEN];
    if (!derive_key(decoy_password, hdr.decoy_salt, decoy_key)) {
        fclose(decoy_in); fclose(out);
        return 0;
    }

    EVP_CIPHER_CTX *decoy_ctx = EVP_CIPHER_CTX_new();
    EVP_EncryptInit_ex(decoy_ctx, EVP_aes_256_cbc(), NULL, decoy_key, hdr.decoy_iv);

    EVP_MAC *decoy_mac = EVP_MAC_fetch(NULL, "HMAC", NULL);
    EVP_MAC_CTX *decoy_hctx = EVP_MAC_CTX_new(decoy_mac);
    OSSL_PARAM decoy_params[] = {
        OSSL_PARAM_construct_utf8_string("digest", "SHA256", 0),
        OSSL_PARAM_construct_end()
    };
    EVP_MAC_init(decoy_hctx, decoy_key, KEY_LEN, decoy_params);

    printf("[*] Encrypting decoy file with decoy password...\n");
    while ((n = fread(in_buf, 1, CHUNK_SIZE, decoy_in)) > 0) {
        hdr.decoy_size += (uint64_t)n;
        EVP_MAC_update(decoy_hctx, in_buf, n);
        EVP_EncryptUpdate(decoy_ctx, out_buf, &out_len, in_buf, (int)n);
        fwrite(out_buf, 1, out_len, out);
    }

    EVP_EncryptFinal_ex(decoy_ctx, out_buf, &out_len);
    fwrite(out_buf, 1, out_len, out);

    unsigned char decoy_hmac[HMAC_LEN];
    hmac_len = HMAC_LEN;
    EVP_MAC_final(decoy_hctx, decoy_hmac, &hmac_len, HMAC_LEN);
    vault_write_decoy_hmac(out, decoy_hmac);

    EVP_MAC_CTX_free(decoy_hctx);
    EVP_MAC_free(decoy_mac);
    EVP_CIPHER_CTX_free(decoy_ctx);
    fclose(decoy_in);

    printf("[+] Decoy file encrypted and HMAC appended.\n");

    /* --- Rewrite header with final sizes --- */
    rewind(out);
    vault_write_header(out, &hdr);

    /* --- Zero keys from memory --- */
    secure_wipe(real_key, KEY_LEN);
    secure_wipe(decoy_key, KEY_LEN);
    secure_wipe(in_buf, CHUNK_SIZE);
    free(in_buf); free(out_buf);

    fclose(out);
    printf("[+] Duress encryption complete: %s\n", out_path);
    printf("[+] Real file: %s (%.1f MB)\n", real_clean, (double)hdr.original_size / (1024.0 * 1024.0));
    printf("[+] Decoy file: %s (%.1f MB)\n", decoy_clean, (double)hdr.decoy_size / (1024.0 * 1024.0));
    audit_log(AUDIT_ENCRYPT, real_path, 1);
    return 1;
}
