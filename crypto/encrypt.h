#ifndef FENC_ENCRYPT_H
#define FENC_ENCRYPT_H

/* Encrypts in_path -> out_path using password.
 * Returns 1 on success, 0 on failure. */
int encrypt_file(const char *in_path, const char *out_path, const char *password);

/* Duress encryption: encrypts real file with real password and decoy file with decoy password.
 * Both stored in single .enc file. Sets duress_flag=1 in header.
 * Returns 1 on success, 0 on failure. */
int encrypt_file_with_duress(const char *real_path, const char *decoy_path,
                             const char *out_path, const char *real_password,
                             const char *decoy_password);

#endif
