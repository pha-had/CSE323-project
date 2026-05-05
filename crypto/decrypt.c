#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <stdint.h>
#ifdef _WIN32
#include <io.h>
#endif
#include <openssl/evp.h>
#include "../vault/vault.h"
#include "../alerts/discord.h"
#include "kdf.h"
#include "decrypt.h"
#include "integrity.h"
#include "../utils/utils.h"
#include "../security/lockout.h"
#include "../utils/audit.h"

#define CHUNK_SIZE 65536

static uint64_t pkcs7_cipher_len(uint64_t plain_len) {
	return ((plain_len + 15ULL) / 16ULL) * 16ULL;
}

static int verify_password_for_segment(FILE *in,
									   long start_offset,
									   uint64_t cipher_len,
									   const unsigned char *salt,
									   const unsigned char *iv,
									   const unsigned char *expected_hmac,
									   const char *password) {
	unsigned char key[KEY_LEN] = {0};
	int ok = 0;

	if (!derive_key(password, salt, key)) {
		return 0;
	}

	if (fseek(in, start_offset, SEEK_SET) != 0) {
		goto done;
	}

	EVP_CIPHER_CTX *dctx = EVP_CIPHER_CTX_new();
	if (!dctx) {
		goto done;
	}
	if (!EVP_DecryptInit_ex(dctx, EVP_aes_256_cbc(), NULL, key, iv)) {
		EVP_CIPHER_CTX_free(dctx);
		goto done;
	}

	EVP_MAC *mac = EVP_MAC_fetch(NULL, "HMAC", NULL);
	if (!mac) {
		EVP_CIPHER_CTX_free(dctx);
		goto done;
	}

	EVP_MAC_CTX *hctx = EVP_MAC_CTX_new(mac);
	if (!hctx) {
		EVP_MAC_free(mac);
		EVP_CIPHER_CTX_free(dctx);
		goto done;
	}

	OSSL_PARAM params[] = {
		OSSL_PARAM_construct_utf8_string("digest", "SHA256", 0),
		OSSL_PARAM_construct_end()
	};

	if (!EVP_MAC_init(hctx, key, KEY_LEN, params)) {
		EVP_MAC_CTX_free(hctx);
		EVP_MAC_free(mac);
		EVP_CIPHER_CTX_free(dctx);
		goto done;
	}

	unsigned char in_buf[CHUNK_SIZE];
	unsigned char plain_buf[CHUNK_SIZE + EVP_MAX_BLOCK_LENGTH];
	uint64_t remaining = cipher_len;
	int plain_len = 0;

	while (remaining > 0) {
		size_t to_read = (remaining < CHUNK_SIZE) ? (size_t)remaining : CHUNK_SIZE;
		size_t n = fread(in_buf, 1, to_read, in);
		if (n != to_read) {
			EVP_MAC_CTX_free(hctx);
			EVP_MAC_free(mac);
			EVP_CIPHER_CTX_free(dctx);
			goto done;
		}

		if (!EVP_DecryptUpdate(dctx, plain_buf, &plain_len, in_buf, (int)n) ||
			!EVP_MAC_update(hctx, plain_buf, (size_t)plain_len)) {
			EVP_MAC_CTX_free(hctx);
			EVP_MAC_free(mac);
			EVP_CIPHER_CTX_free(dctx);
			goto done;
		}

		remaining -= n;
	}

	if (!EVP_DecryptFinal_ex(dctx, plain_buf, &plain_len)) {
		EVP_MAC_CTX_free(hctx);
		EVP_MAC_free(mac);
		EVP_CIPHER_CTX_free(dctx);
		goto done;
	}

	if (plain_len > 0 && !EVP_MAC_update(hctx, plain_buf, (size_t)plain_len)) {
		EVP_MAC_CTX_free(hctx);
		EVP_MAC_free(mac);
		EVP_CIPHER_CTX_free(dctx);
		goto done;
	}

	unsigned char computed_hmac[HMAC_LEN];
	size_t hmac_len = HMAC_LEN;
	if (EVP_MAC_final(hctx, computed_hmac, &hmac_len, HMAC_LEN) && hmac_len == HMAC_LEN &&
		integrity_verify(expected_hmac, computed_hmac, HMAC_LEN)) {
		ok = 1;
	}

	EVP_MAC_CTX_free(hctx);
	EVP_MAC_free(mac);
	EVP_CIPHER_CTX_free(dctx);

done:
	secure_wipe(key, KEY_LEN);
	return ok;
}

static int stream_reencrypt_segment(FILE *in,
									FILE *out,
									long start_offset,
									uint64_t cipher_len,
									const unsigned char *old_key,
									const unsigned char *old_iv,
									const unsigned char *new_key,
									const unsigned char *new_iv,
									unsigned char *out_hmac) {
	if (fseek(in, start_offset, SEEK_SET) != 0) {
		return 0;
	}

	EVP_CIPHER_CTX *dctx = EVP_CIPHER_CTX_new();
	EVP_CIPHER_CTX *ectx = EVP_CIPHER_CTX_new();
	if (!dctx || !ectx) {
		EVP_CIPHER_CTX_free(dctx);
		EVP_CIPHER_CTX_free(ectx);
		return 0;
	}

	if (!EVP_DecryptInit_ex(dctx, EVP_aes_256_cbc(), NULL, old_key, old_iv) ||
		!EVP_EncryptInit_ex(ectx, EVP_aes_256_cbc(), NULL, new_key, new_iv)) {
		EVP_CIPHER_CTX_free(dctx);
		EVP_CIPHER_CTX_free(ectx);
		return 0;
	}

	EVP_MAC *mac = EVP_MAC_fetch(NULL, "HMAC", NULL);
	if (!mac) {
		EVP_CIPHER_CTX_free(dctx);
		EVP_CIPHER_CTX_free(ectx);
		return 0;
	}

	EVP_MAC_CTX *hctx = EVP_MAC_CTX_new(mac);
	if (!hctx) {
		EVP_MAC_free(mac);
		EVP_CIPHER_CTX_free(dctx);
		EVP_CIPHER_CTX_free(ectx);
		return 0;
	}

	OSSL_PARAM params[] = {
		OSSL_PARAM_construct_utf8_string("digest", "SHA256", 0),
		OSSL_PARAM_construct_end()
	};

	if (!EVP_MAC_init(hctx, new_key, KEY_LEN, params)) {
		EVP_MAC_CTX_free(hctx);
		EVP_MAC_free(mac);
		EVP_CIPHER_CTX_free(dctx);
		EVP_CIPHER_CTX_free(ectx);
		return 0;
	}

	unsigned char in_buf[CHUNK_SIZE];
	unsigned char plain_buf[CHUNK_SIZE + EVP_MAX_BLOCK_LENGTH];
	unsigned char out_buf[CHUNK_SIZE + EVP_MAX_BLOCK_LENGTH];
	uint64_t remaining = cipher_len;
	int plain_len = 0;
	int out_len = 0;

	while (remaining > 0) {
		size_t to_read = (remaining < CHUNK_SIZE) ? (size_t)remaining : CHUNK_SIZE;
		size_t n = fread(in_buf, 1, to_read, in);
		if (n != to_read) {
			EVP_MAC_CTX_free(hctx);
			EVP_MAC_free(mac);
			EVP_CIPHER_CTX_free(dctx);
			EVP_CIPHER_CTX_free(ectx);
			return 0;
		}

		if (!EVP_DecryptUpdate(dctx, plain_buf, &plain_len, in_buf, (int)n)) {
			EVP_MAC_CTX_free(hctx);
			EVP_MAC_free(mac);
			EVP_CIPHER_CTX_free(dctx);
			EVP_CIPHER_CTX_free(ectx);
			return 0;
		}

		if (plain_len > 0) {
			if (!EVP_MAC_update(hctx, plain_buf, (size_t)plain_len) ||
				!EVP_EncryptUpdate(ectx, out_buf, &out_len, plain_buf, plain_len) ||
				fwrite(out_buf, 1, (size_t)out_len, out) != (size_t)out_len) {
				EVP_MAC_CTX_free(hctx);
				EVP_MAC_free(mac);
				EVP_CIPHER_CTX_free(dctx);
				EVP_CIPHER_CTX_free(ectx);
				return 0;
			}
		}

		remaining -= n;
	}

	if (!EVP_DecryptFinal_ex(dctx, plain_buf, &plain_len)) {
		EVP_MAC_CTX_free(hctx);
		EVP_MAC_free(mac);
		EVP_CIPHER_CTX_free(dctx);
		EVP_CIPHER_CTX_free(ectx);
		return 0;
	}

	if (plain_len > 0) {
		if (!EVP_MAC_update(hctx, plain_buf, (size_t)plain_len) ||
			!EVP_EncryptUpdate(ectx, out_buf, &out_len, plain_buf, plain_len) ||
			fwrite(out_buf, 1, (size_t)out_len, out) != (size_t)out_len) {
			EVP_MAC_CTX_free(hctx);
			EVP_MAC_free(mac);
			EVP_CIPHER_CTX_free(dctx);
			EVP_CIPHER_CTX_free(ectx);
			return 0;
		}
	}

	if (!EVP_EncryptFinal_ex(ectx, out_buf, &out_len) ||
		fwrite(out_buf, 1, (size_t)out_len, out) != (size_t)out_len) {
		EVP_MAC_CTX_free(hctx);
		EVP_MAC_free(mac);
		EVP_CIPHER_CTX_free(dctx);
		EVP_CIPHER_CTX_free(ectx);
		return 0;
	}

	size_t hmac_len = HMAC_LEN;
	int ok = EVP_MAC_final(hctx, out_hmac, &hmac_len, HMAC_LEN) && hmac_len == HMAC_LEN;

	EVP_MAC_CTX_free(hctx);
	EVP_MAC_free(mac);
	EVP_CIPHER_CTX_free(dctx);
	EVP_CIPHER_CTX_free(ectx);
	return ok;
}

int change_password_file(const char *in_path,
						const char *old_password,
						const char *new_password,
						const char *old_decoy_password,
						const char *new_decoy_password) {
	FILE *in = fopen(in_path, "rb");
	if (!in) {
		fprintf(stderr, "Error: Cannot open encrypted file: %s\n", in_path);
		audit_log(AUDIT_CHANGE_PASSWORD, in_path, 0);
		return 0;
	}

	VaultHeader old_hdr;
	if (!vault_read_header(in, &old_hdr) || !vault_validate_header(&old_hdr)) {
		fprintf(stderr, "Error: Invalid encrypted file header.\n");
		fclose(in);
		audit_log(AUDIT_CHANGE_PASSWORD, in_path, 0);
		return 0;
	}

	if (fseek(in, 0, SEEK_END) != 0) {
		fclose(in);
		audit_log(AUDIT_CHANGE_PASSWORD, in_path, 0);
		return 0;
	}
	long file_size = ftell(in);
	if (file_size <= 0) {
		fclose(in);
		audit_log(AUDIT_CHANGE_PASSWORD, in_path, 0);
		return 0;
	}

	if (old_hdr.duress_flag == 1 && (!old_decoy_password || !new_decoy_password)) {
		fprintf(stderr, "Error: Duress file detected. Provide --decoy-password and --new-decoy-password.\n");
		fclose(in);
		audit_log(AUDIT_CHANGE_PASSWORD, in_path, 0);
		return 0;
	}

	if (old_hdr.duress_flag == 0 && (old_decoy_password || new_decoy_password)) {
		fprintf(stderr, "Error: Decoy passwords were provided, but this file is not in duress mode.\n");
		fclose(in);
		audit_log(AUDIT_CHANGE_PASSWORD, in_path, 0);
		return 0;
	}

	unsigned char old_real_key[KEY_LEN] = {0};
	unsigned char new_real_key[KEY_LEN] = {0};
	unsigned char old_decoy_key[KEY_LEN] = {0};
	unsigned char new_decoy_key[KEY_LEN] = {0};

	unsigned char real_stored_hmac[HMAC_LEN];
	unsigned char decoy_stored_hmac[HMAC_LEN];
	uint64_t real_cipher_len = 0;
	uint64_t decoy_cipher_len = 0;
	long real_cipher_start = (long)sizeof(VaultHeader);
	long decoy_cipher_start = 0;

	if (old_hdr.duress_flag == 0) {
		long cipher_len = file_size - (long)sizeof(VaultHeader) - (long)HMAC_LEN;
		if (cipher_len <= 0 || !vault_read_hmac(in, real_stored_hmac)) {
			fprintf(stderr, "Error: Invalid encrypted file structure.\n");
			fclose(in);
			audit_log(AUDIT_CHANGE_PASSWORD, in_path, 0);
			return 0;
		}
		real_cipher_len = (uint64_t)cipher_len;
	} else {
		real_cipher_len = pkcs7_cipher_len(old_hdr.original_size);
		decoy_cipher_len = pkcs7_cipher_len(old_hdr.decoy_size);

		long real_hmac_pos = (long)sizeof(VaultHeader) + (long)real_cipher_len;
		decoy_cipher_start = real_hmac_pos + (long)HMAC_LEN;
		long expected_size = decoy_cipher_start + (long)decoy_cipher_len + (long)HMAC_LEN;

		if (expected_size != file_size) {
			fprintf(stderr, "Error: Encrypted file layout is invalid.\n");
			fclose(in);
			audit_log(AUDIT_CHANGE_PASSWORD, in_path, 0);
			return 0;
		}

		if (fseek(in, real_hmac_pos, SEEK_SET) != 0 || fread(real_stored_hmac, 1, HMAC_LEN, in) != HMAC_LEN) {
			fprintf(stderr, "Error: Failed to read real HMAC.\n");
			fclose(in);
			audit_log(AUDIT_CHANGE_PASSWORD, in_path, 0);
			return 0;
		}

		if (!vault_read_hmac(in, decoy_stored_hmac)) {
			fprintf(stderr, "Error: Failed to read decoy HMAC.\n");
			fclose(in);
			audit_log(AUDIT_CHANGE_PASSWORD, in_path, 0);
			return 0;
		}
	}

	printf("[*] Verifying existing password(s)...\n");
	if (!verify_password_for_segment(in, real_cipher_start, real_cipher_len,
									 old_hdr.salt, old_hdr.iv,
									 real_stored_hmac, old_password)) {
		fprintf(stderr, "Error: Real/old password is incorrect, or file was tampered.\n");
		fclose(in);
		audit_log(AUDIT_CHANGE_PASSWORD, in_path, 0);
		return 0;
	}

	if (old_hdr.duress_flag == 1) {
		if (!verify_password_for_segment(in, decoy_cipher_start, decoy_cipher_len,
										 old_hdr.decoy_salt, old_hdr.decoy_iv,
										 decoy_stored_hmac, old_decoy_password)) {
			fprintf(stderr, "Error: Decoy old password is incorrect, or decoy data was tampered.\n");
			fclose(in);
			audit_log(AUDIT_CHANGE_PASSWORD, in_path, 0);
			return 0;
		}
	}

	if (!derive_key(old_password, old_hdr.salt, old_real_key) ||
		!derive_key(new_password, old_hdr.salt, new_real_key)) {
		fprintf(stderr, "Error: Key derivation failed.\n");
		fclose(in);
		audit_log(AUDIT_CHANGE_PASSWORD, in_path, 0);
		return 0;
	}

	if (old_hdr.duress_flag == 1) {
		if (!derive_key(old_decoy_password, old_hdr.decoy_salt, old_decoy_key) ||
			!derive_key(new_decoy_password, old_hdr.decoy_salt, new_decoy_key)) {
			fprintf(stderr, "Error: Decoy key derivation failed.\n");
			fclose(in);
			secure_wipe(old_real_key, KEY_LEN);
			secure_wipe(new_real_key, KEY_LEN);
			audit_log(AUDIT_CHANGE_PASSWORD, in_path, 0);
			return 0;
		}
	}

	VaultHeader new_hdr = old_hdr;
	if (!generate_random_bytes(new_hdr.salt, SALT_LEN) || !generate_random_bytes(new_hdr.iv, IV_LEN)) {
		fprintf(stderr, "Error: Failed to generate new real salt/IV.\n");
		fclose(in);
		secure_wipe(old_real_key, KEY_LEN);
		secure_wipe(new_real_key, KEY_LEN);
		secure_wipe(old_decoy_key, KEY_LEN);
		secure_wipe(new_decoy_key, KEY_LEN);
		audit_log(AUDIT_CHANGE_PASSWORD, in_path, 0);
		return 0;
	}

	if (new_hdr.duress_flag == 1) {
		if (!generate_random_bytes(new_hdr.decoy_salt, SALT_LEN) || !generate_random_bytes(new_hdr.decoy_iv, IV_LEN)) {
			fprintf(stderr, "Error: Failed to generate new decoy salt/IV.\n");
			fclose(in);
			secure_wipe(old_real_key, KEY_LEN);
			secure_wipe(new_real_key, KEY_LEN);
			secure_wipe(old_decoy_key, KEY_LEN);
			secure_wipe(new_decoy_key, KEY_LEN);
			audit_log(AUDIT_CHANGE_PASSWORD, in_path, 0);
			return 0;
		}
	}

	if (!derive_key(new_password, new_hdr.salt, new_real_key)) {
		fprintf(stderr, "Error: Failed to derive new real key with new salt.\n");
		fclose(in);
		secure_wipe(old_real_key, KEY_LEN);
		secure_wipe(new_real_key, KEY_LEN);
		secure_wipe(old_decoy_key, KEY_LEN);
		secure_wipe(new_decoy_key, KEY_LEN);
		audit_log(AUDIT_CHANGE_PASSWORD, in_path, 0);
		return 0;
	}

	if (new_hdr.duress_flag == 1 && !derive_key(new_decoy_password, new_hdr.decoy_salt, new_decoy_key)) {
		fprintf(stderr, "Error: Failed to derive new decoy key with new salt.\n");
		fclose(in);
		secure_wipe(old_real_key, KEY_LEN);
		secure_wipe(new_real_key, KEY_LEN);
		secure_wipe(old_decoy_key, KEY_LEN);
		secure_wipe(new_decoy_key, KEY_LEN);
		audit_log(AUDIT_CHANGE_PASSWORD, in_path, 0);
		return 0;
	}

	char tmp_path[2048];
	snprintf(tmp_path, sizeof(tmp_path), "%s.rekey.tmp", in_path);

	FILE *out = fopen(tmp_path, "wb");
	if (!out) {
		fprintf(stderr, "Error: Cannot create temporary file: %s\n", tmp_path);
		fclose(in);
		secure_wipe(old_real_key, KEY_LEN);
		secure_wipe(new_real_key, KEY_LEN);
		secure_wipe(old_decoy_key, KEY_LEN);
		secure_wipe(new_decoy_key, KEY_LEN);
		audit_log(AUDIT_CHANGE_PASSWORD, in_path, 0);
		return 0;
	}

	if (!vault_write_header(out, &new_hdr)) {
		fprintf(stderr, "Error: Failed to write temporary header.\n");
		fclose(in);
		fclose(out);
		remove(tmp_path);
		secure_wipe(old_real_key, KEY_LEN);
		secure_wipe(new_real_key, KEY_LEN);
		secure_wipe(old_decoy_key, KEY_LEN);
		secure_wipe(new_decoy_key, KEY_LEN);
		audit_log(AUDIT_CHANGE_PASSWORD, in_path, 0);
		return 0;
	}

	printf("[*] Re-encrypting with new password(s)...\n");
	unsigned char new_real_hmac[HMAC_LEN];
	if (!stream_reencrypt_segment(in, out, real_cipher_start, real_cipher_len,
								  old_real_key, old_hdr.iv,
								  new_real_key, new_hdr.iv,
								  new_real_hmac)) {
		fprintf(stderr, "Error: Failed to re-encrypt real segment.\n");
		fclose(in);
		fclose(out);
		remove(tmp_path);
		secure_wipe(old_real_key, KEY_LEN);
		secure_wipe(new_real_key, KEY_LEN);
		secure_wipe(old_decoy_key, KEY_LEN);
		secure_wipe(new_decoy_key, KEY_LEN);
		audit_log(AUDIT_CHANGE_PASSWORD, in_path, 0);
		return 0;
	}

	if (!vault_write_hmac(out, new_real_hmac)) {
		fprintf(stderr, "Error: Failed to write real HMAC.\n");
		fclose(in);
		fclose(out);
		remove(tmp_path);
		secure_wipe(old_real_key, KEY_LEN);
		secure_wipe(new_real_key, KEY_LEN);
		secure_wipe(old_decoy_key, KEY_LEN);
		secure_wipe(new_decoy_key, KEY_LEN);
		audit_log(AUDIT_CHANGE_PASSWORD, in_path, 0);
		return 0;
	}

	if (new_hdr.duress_flag == 1) {
		unsigned char new_decoy_hmac[HMAC_LEN];
		if (!stream_reencrypt_segment(in, out, decoy_cipher_start, decoy_cipher_len,
									  old_decoy_key, old_hdr.decoy_iv,
									  new_decoy_key, new_hdr.decoy_iv,
									  new_decoy_hmac)) {
			fprintf(stderr, "Error: Failed to re-encrypt decoy segment.\n");
			fclose(in);
			fclose(out);
			remove(tmp_path);
			secure_wipe(old_real_key, KEY_LEN);
			secure_wipe(new_real_key, KEY_LEN);
			secure_wipe(old_decoy_key, KEY_LEN);
			secure_wipe(new_decoy_key, KEY_LEN);
			audit_log(AUDIT_CHANGE_PASSWORD, in_path, 0);
			return 0;
		}

		if (!vault_write_decoy_hmac(out, new_decoy_hmac)) {
			fprintf(stderr, "Error: Failed to write decoy HMAC.\n");
			fclose(in);
			fclose(out);
			remove(tmp_path);
			secure_wipe(old_real_key, KEY_LEN);
			secure_wipe(new_real_key, KEY_LEN);
			secure_wipe(old_decoy_key, KEY_LEN);
			secure_wipe(new_decoy_key, KEY_LEN);
			audit_log(AUDIT_CHANGE_PASSWORD, in_path, 0);
			return 0;
		}
	}

	fclose(in);
	fclose(out);

	char backup_path[2048];
	snprintf(backup_path, sizeof(backup_path), "%s.rekey.bak", in_path);

	remove(backup_path);
	if (rename(in_path, backup_path) != 0) {
		fprintf(stderr, "Error: Failed to stage original file for replacement.\n");
		remove(tmp_path);
		secure_wipe(old_real_key, KEY_LEN);
		secure_wipe(new_real_key, KEY_LEN);
		secure_wipe(old_decoy_key, KEY_LEN);
		secure_wipe(new_decoy_key, KEY_LEN);
		audit_log(AUDIT_CHANGE_PASSWORD, in_path, 0);
		return 0;
	}

	if (rename(tmp_path, in_path) != 0) {
		fprintf(stderr, "Error: Failed to install updated encrypted file.\n");
		rename(backup_path, in_path);
		remove(tmp_path);
		secure_wipe(old_real_key, KEY_LEN);
		secure_wipe(new_real_key, KEY_LEN);
		secure_wipe(old_decoy_key, KEY_LEN);
		secure_wipe(new_decoy_key, KEY_LEN);
		audit_log(AUDIT_CHANGE_PASSWORD, in_path, 0);
		return 0;
	}

	remove(backup_path);

	secure_wipe(old_real_key, KEY_LEN);
	secure_wipe(new_real_key, KEY_LEN);
	secure_wipe(old_decoy_key, KEY_LEN);
	secure_wipe(new_decoy_key, KEY_LEN);

	printf("[+] Password change successful: %s\n", in_path);
	if (new_hdr.duress_flag == 1) {
		printf("[+] Updated both real and decoy passwords.\n");
	}
	audit_log(AUDIT_CHANGE_PASSWORD, in_path, 1);
	return 1;
}

static int try_decrypt_with_password(FILE *in, FILE *out,
									  const VaultHeader *hdr,
									  const unsigned char *salt,
									  const unsigned char *iv,
									  long start_offset,
									  uint64_t cipher_len,
									  const char *password,
									  const unsigned char *expected_hmac,
									  int show_progress) {
	unsigned char key[KEY_LEN];
	if (!derive_key(password, (unsigned char *)salt, key)) return 0;

	if (fseek(in, start_offset, SEEK_SET) != 0) {
		secure_wipe(key, KEY_LEN);
		return 0;
	}

	EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
	EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv);

	EVP_MAC     *mac    = EVP_MAC_fetch(NULL, "HMAC", NULL);
	EVP_MAC_CTX *hctx   = EVP_MAC_CTX_new(mac);
	OSSL_PARAM   params[] = {
		OSSL_PARAM_construct_utf8_string("digest", "SHA256", 0),
		OSSL_PARAM_construct_end()
	};
	EVP_MAC_init(hctx, key, KEY_LEN, params);

	unsigned char *in_buf  = malloc(CHUNK_SIZE);
	unsigned char *out_buf = malloc(CHUNK_SIZE + EVP_MAX_BLOCK_LENGTH);
	if (!in_buf || !out_buf) {
		free(in_buf); free(out_buf);
		EVP_CIPHER_CTX_free(ctx);
		EVP_MAC_CTX_free(hctx); EVP_MAC_free(mac);
		secure_wipe(key, KEY_LEN);
		return 0;
	}

	long long bytes_done = 0;
	size_t  n;
	int     out_len;
	clock_t start = clock();

	if (show_progress) printf("[*] Decrypting...\n");

	while (bytes_done < (long long)cipher_len) {
		long long remaining = (long long)cipher_len - bytes_done;
		long long to_read   = remaining < CHUNK_SIZE ? remaining : CHUNK_SIZE;

		n = fread(in_buf, 1, (size_t)to_read, in);
		if (n == 0) break;

		EVP_DecryptUpdate(ctx, out_buf, &out_len, in_buf, (int)n);
		EVP_MAC_update(hctx, out_buf, (size_t)out_len);
		fwrite(out_buf, 1, (size_t)out_len, out);
		bytes_done += (long long)n;

		if (show_progress) {
			int    percent = (int)((bytes_done * 100LL) / cipher_len);
			int    filled  = percent / 10;
			double elapsed = (double)(clock() - start) / CLOCKS_PER_SEC;
			double speed   = (elapsed > 0) ? (bytes_done / (1024.0 * 1024.0)) / elapsed : 0;

			printf("\r    [");
			for (int i = 0; i < 10; i++) printf("%c", i < filled ? '#' : '-');
			printf("] %3d%% | %.1f MB / %.1f MB | %.1f MB/s",
				percent,
				(double)bytes_done / (1024.0 * 1024.0),
				(double)cipher_len / (1024.0 * 1024.0),
				speed);
			fflush(stdout);
		}
	}

	int final_ret = EVP_DecryptFinal_ex(ctx, out_buf, &out_len);
	if (out_len > 0) {
		EVP_MAC_update(hctx, out_buf, (size_t)out_len);
		fwrite(out_buf, 1, (size_t)out_len, out);
	}

	if (show_progress) {
		double total_time = (double)(clock() - start) / CLOCKS_PER_SEC;
		double avg_speed  = (total_time > 0) ? ((double)cipher_len / (1024.0 * 1024.0)) / total_time : 0;
		printf("\r    [##########] 100%% | %.1f MB / %.1f MB | %.1f MB/s\n",
			(double)cipher_len / (1024.0 * 1024.0),
			(double)cipher_len / (1024.0 * 1024.0),
			avg_speed);
		printf("[+] Done in %.2f seconds\n", total_time);
	}

	if (final_ret <= 0) {
		secure_wipe(key, KEY_LEN);
		free(in_buf); free(out_buf);
		EVP_CIPHER_CTX_free(ctx);
		EVP_MAC_CTX_free(hctx); EVP_MAC_free(mac);
		return 0;
	}

	unsigned char computed_hmac[HMAC_LEN];
	size_t hmac_len = HMAC_LEN;
	EVP_MAC_final(hctx, computed_hmac, &hmac_len, HMAC_LEN);

	int hmac_match = (memcmp(computed_hmac, expected_hmac, HMAC_LEN) == 0);
	if (!hmac_match) {
		printf("[DEBUG] computed_hmac: ");
		for(int i=0; i<32; i++) printf("%02x", computed_hmac[i]);
		printf("\n");
		printf("[DEBUG] stored_hmac: ");
		for(int i=0; i<32; i++) printf("%02x", expected_hmac[i]);
		printf("\n");
	}

	secure_wipe(key, KEY_LEN);
	secure_wipe(in_buf, CHUNK_SIZE);
	free(in_buf); free(out_buf);
	EVP_CIPHER_CTX_free(ctx);
	EVP_MAC_CTX_free(hctx); EVP_MAC_free(mac);

	return hmac_match;
}

int decrypt_file(const char *in_path, const char *out_path, const char *password) {

	if (lockout_is_locked(in_path)) {
		fprintf(stderr, "[!] Vault is LOCKED after %d failed attempts.\n", MAX_ATTEMPTS);
		fprintf(stderr, "[!] Delete %s.lock to reset.\n", in_path);
		discord_vault_locked_alert(in_path);
		audit_log(AUDIT_LOCKED, in_path, 0);
		return DECRYPT_FAILED;
	}

	FILE *in  = fopen(in_path, "rb");
	FILE *out = fopen(out_path, "wb");
	if (!in)  { fprintf(stderr, "Error: Cannot open input file: %s\n",  in_path);  audit_log(AUDIT_DECRYPT_FAILED, in_path, 0); return DECRYPT_FAILED; }
	if (!out) { fprintf(stderr, "Error: Cannot open output file: %s\n", out_path); fclose(in); audit_log(AUDIT_DECRYPT_FAILED, in_path, 0); return DECRYPT_FAILED; }

	VaultHeader hdr;
	if (!vault_read_header(in, &hdr) || !vault_validate_header(&hdr)) {
		audit_log(AUDIT_DECRYPT_FAILED, in_path, 0);
		fclose(in); fclose(out); return DECRYPT_FAILED;
	}
	printf("[DEBUG] hdr.duress_flag=%u\n", (unsigned)hdr.duress_flag);
	printf("[DEBUG] sizeof(VaultHeader)=%zu\n", sizeof(VaultHeader));

	#ifdef _WIN32
	long long file_size = _filelengthi64(_fileno(in));
	#else
	fseek(in, 0, SEEK_END);
	long long file_size = ftell(in);
	#endif
	long long total_cipher_len = file_size - (long long)sizeof(VaultHeader) - (long long)HMAC_LEN;
	if (total_cipher_len <= 0) {
		fprintf(stderr, "Error: File too small to contain ciphertext.\n");
		audit_log(AUDIT_DECRYPT_FAILED, in_path, 0);
		fclose(in); fclose(out); return DECRYPT_FAILED;
	}

	/* --- Non-duress mode --- */
	if (hdr.duress_flag == 0) {
		unsigned char stored_hmac[HMAC_LEN];
		if (!vault_read_hmac(in, stored_hmac)) {
			audit_log(AUDIT_DECRYPT_FAILED, in_path, 0);
			fclose(in); fclose(out); return DECRYPT_FAILED;
		}

		long long cipher_start = (long long)sizeof(VaultHeader);

		if (try_decrypt_with_password(in, out, &hdr, hdr.salt, hdr.iv,
									   cipher_start, (uint64_t)total_cipher_len,
									   password, stored_hmac, 1)) {
			lockout_reset(in_path);
			printf("[+] Decrypted:  %s  ->  %s\n", in_path, out_path);
			audit_log(AUDIT_DECRYPT, in_path, 1);
			fclose(in); fclose(out);
			return DECRYPT_REAL;
		} else {
			int attempts = lockout_record_failure(in_path);
			if (attempts < MAX_ATTEMPTS) {
				fprintf(stderr, "Error: Wrong password or corrupted file.\n");
				discord_alert("FAILED DECRYPTION ATTEMPT!", in_path, attempts);
			} else {
				discord_vault_locked_alert(in_path);
			}
			audit_log(AUDIT_DECRYPT_FAILED, in_path, 0);
			fclose(in); fclose(out); return DECRYPT_FAILED;
		}
	}

	/* --- Duress mode --- */
	uint64_t real_cipher_len  = ((hdr.original_size + 15) / 16) * 16;
	uint64_t decoy_cipher_len = ((hdr.decoy_size   + 15) / 16) * 16;

	unsigned char real_hmac[HMAC_LEN];
	long long real_hmac_pos = (long long)sizeof(VaultHeader) + (long long)real_cipher_len;
	if (fseek(in, real_hmac_pos, SEEK_SET) != 0 ||
		fread(real_hmac, 1, HMAC_LEN, in) != HMAC_LEN) {
		fprintf(stderr, "Error: Failed to read real HMAC.\n");
		audit_log(AUDIT_DECRYPT_FAILED, in_path, 0);
		fclose(in); fclose(out); return DECRYPT_FAILED;
	}

	long long real_cipher_start = (long long)sizeof(VaultHeader);

	if (try_decrypt_with_password(in, out, &hdr, hdr.salt, hdr.iv,
								   real_cipher_start, real_cipher_len,
								   password, real_hmac, 1)) {
		lockout_reset(in_path);
		printf("[+] Decrypted:  %s  ->  %s\n", in_path, out_path);
		audit_log(AUDIT_DECRYPT, in_path, 1);
		fclose(in); fclose(out);
		return DECRYPT_REAL;
	}

	/* --- Try decoy password --- */

	fclose(out);
	out = fopen(out_path, "wb");
	if (!out) {
		fprintf(stderr, "Error: Cannot reopen output file: %s\n", out_path);
		fclose(in); return DECRYPT_FAILED;
	}

	long long decoy_cipher_start = (long long)sizeof(VaultHeader) + (long long)real_cipher_len + (long long)HMAC_LEN;

	unsigned char decoy_hmac[HMAC_LEN];
	if (!vault_read_hmac(in, decoy_hmac)) {
		fprintf(stderr, "Error: Failed to read decoy HMAC.\n");
		audit_log(AUDIT_DECRYPT_FAILED, in_path, 0);
		fclose(in); fclose(out); return DECRYPT_FAILED;
	}

	if (try_decrypt_with_password(in, out, &hdr, hdr.decoy_salt, hdr.decoy_iv,
								   decoy_cipher_start, decoy_cipher_len,
								   password, decoy_hmac, 1)) {
		discord_duress_password_alert(in_path);
		lockout_reset(in_path);
		printf("[+] Decrypted:  %s  ->  %s\n", in_path, out_path);
		audit_log(AUDIT_DECRYPT, in_path, 1);
		fclose(in); fclose(out);
		return DECRYPT_DECOY;
	}

	/* --- Both passwords failed --- */
	printf("[!] Decryption failed.\n");
	int attempts = lockout_record_failure(in_path);
	if (attempts < MAX_ATTEMPTS) {
		fprintf(stderr, "Error: Wrong password. If you are sure the password is correct, the file may be corrupted or tampered.\n");
		discord_alert("FAILED DECRYPTION ATTEMPT!", in_path, attempts);
	} else {
		discord_vault_locked_alert(in_path);
	}
	audit_log(AUDIT_DECRYPT_FAILED, in_path, 0);
	fclose(in); fclose(out);
	return DECRYPT_FAILED;
}