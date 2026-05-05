#ifndef FENC_INTEGRITY_H
#define FENC_INTEGRITY_H

int integrity_compute(const unsigned char *key, int key_len,
                      const unsigned char *data, size_t data_len,
                      unsigned char *out);

int integrity_verify(const unsigned char *expected, const unsigned char *actual, size_t len);

int verify_file(const char *in_path, const char *password);

#endif
