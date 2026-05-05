#ifndef FENC_DECRYPT_H
#define FENC_DECRYPT_H

/* Decrypt status codes */
#define DECRYPT_FAILED 0  /* Decryption failed */
#define DECRYPT_REAL   1  /* Successfully decrypted with real password (or standard file) */
#define DECRYPT_DECOY  2  /* Successfully decrypted with decoy password (duress mode) */

/* Decrypts in_path -> out_path using password.
 * Returns: DECRYPT_FAILED (0) on failure,
 *          DECRYPT_REAL (1) if real password used or standard file,
 *          DECRYPT_DECOY (2) if decoy password used in duress mode. */
int decrypt_file(const char *in_path, const char *out_path, const char *password);

/* Changes password(s) of an existing encrypted file without creating plaintext files.
 * Standard mode requires old_password + new_password.
 * Duress mode requires both real and decoy old/new passwords.
 * Returns 1 on success, 0 on failure. */
int change_password_file(const char *in_path,
                        const char *old_password,
                        const char *new_password,
                        const char *old_decoy_password,
                        const char *new_decoy_password);

#endif
