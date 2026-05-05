#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <openssl/rand.h>
#include "shredder.h"

#define CHUNK_SIZE 65536

static int overwrite_pass(FILE *f, long file_size, unsigned char fill) {
    unsigned char *buf = malloc(CHUNK_SIZE);
    long remaining = file_size;

    if (!buf) return 0;
    memset(buf, fill, CHUNK_SIZE);
    rewind(f);

    while (remaining > 0) {
        size_t to_write = (remaining > CHUNK_SIZE) ? CHUNK_SIZE : (size_t)remaining;
        if (fwrite(buf, 1, to_write, f) != to_write) {
            free(buf);
            return 0;
        }
        remaining -= (long)to_write;
    }

    fflush(f);
    free(buf);
    return 1;
}

static int overwrite_random(FILE *f, long file_size) {
    unsigned char *buf = malloc(CHUNK_SIZE);
    long remaining = file_size;

    if (!buf) return 0;
    rewind(f);

    while (remaining > 0) {
        size_t to_write = (remaining > CHUNK_SIZE) ? CHUNK_SIZE : (size_t)remaining;
        if (RAND_bytes(buf, (int)to_write) != 1) {
            free(buf);
            return 0;
        }
        if (fwrite(buf, 1, to_write, f) != to_write) {
            free(buf);
            return 0;
        }
        remaining -= (long)to_write;
    }

    fflush(f);
    free(buf);
    return 1;
}

int shred_file(const char *path) {
    char clean_path[2048];
    size_t path_len = strlen(path);
    if (path_len >= sizeof(clean_path)) {
        fprintf(stderr, "Error: Path too long for shredding.\n");
        return 0;
    }

    memcpy(clean_path, path, path_len + 1);

    /* Trim leading/trailing whitespace and one pair of surrounding quotes. */
    char *start = clean_path;
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

    if (start != clean_path) {
        memmove(clean_path, start, strlen(start) + 1);
    }

    FILE *f = fopen(clean_path, "r+b");
    if (!f) {
        fprintf(stderr, "Error: Cannot open file for shredding: %s\n", clean_path);
        return 0;
    }

    if (fseek(f, 0, SEEK_END) != 0) {
        fclose(f);
        return 0;
    }

    long file_size = ftell(f);
    if (file_size < 0) {
        fclose(f);
        return 0;
    }

    if (file_size == 0) {
        fclose(f);
        if (remove(clean_path) != 0) return 0;
        printf("[+] Shredded (empty file): %s\n", clean_path);
        return 1;
    }

    printf("[*] Shredding %s (%ld bytes) ...\n", clean_path, file_size);
    printf("[*] Pass 1/3: zeros\n");
    if (!overwrite_pass(f, file_size, 0x00)) {
        fprintf(stderr, "Error: Pass 1 failed.\n");
        fclose(f);
        return 0;
    }

    printf("[*] Pass 2/3: ones\n");
    if (!overwrite_pass(f, file_size, 0xFF)) {
        fprintf(stderr, "Error: Pass 2 failed.\n");
        fclose(f);
        return 0;
    }

    printf("[*] Pass 3/3: random\n");
    if (!overwrite_random(f, file_size)) {
        fprintf(stderr, "Error: Pass 3 failed.\n");
        fclose(f);
        return 0;
    }

    fclose(f);
    if (remove(clean_path) != 0) {
        fprintf(stderr, "Error: Failed to delete file after shredding.\n");
        return 0;
    }

    printf("[+] Shredded and deleted: %s\n", clean_path);
    return 1;
}
