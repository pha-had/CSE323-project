#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "lockout.h"

static void lock_path(const char *vault_path, char *out, size_t out_size) {
    snprintf(out, out_size, "%s.lock", vault_path);
}

int lockout_is_locked(const char *vault_path) {
    char lpath[1024];
    lock_path(vault_path, lpath, sizeof(lpath));

    FILE *f = fopen(lpath, "r");
    if (!f) return 0;

    int attempts = 0;
    fscanf(f, "%d", &attempts);
    fclose(f);

    return attempts > MAX_ATTEMPTS;
}

int lockout_record_failure(const char *vault_path) {
    char lpath[1024];
    lock_path(vault_path, lpath, sizeof(lpath));

    int attempts = 0;

    FILE *f = fopen(lpath, "r");
    if (f) { fscanf(f, "%d", &attempts); fclose(f); }

    attempts++;

    f = fopen(lpath, "w");
    if (f) { fprintf(f, "%d\n", attempts); fclose(f); }

    if (attempts > MAX_ATTEMPTS) {
        fprintf(stderr, "[!] Too many failed attempts - vault is now LOCKED.\n");
        fprintf(stderr, "[!] Delete %s to reset.\n", lpath);
    } else {
        fprintf(stderr, "[!] Failed attempt %d / %d\n", attempts, MAX_ATTEMPTS);
    }

    return attempts;
}

void lockout_reset(const char *vault_path) {
    char lpath[1024];
    lock_path(vault_path, lpath, sizeof(lpath));
    remove(lpath);
}
