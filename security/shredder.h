#ifndef SHREDDER_H
#define SHREDDER_H

/* 3-pass DoD wipe: overwrite with 0x00, 0xFF, then random bytes, then delete.
 * Returns 1 on success, 0 on failure. */
int shred_file(const char *path);

#endif
