#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <dirent.h>
#include <errno.h>
#include <openssl/evp.h>
#ifdef _WIN32
#include <conio.h>
#else
#include <termios.h>
#include <unistd.h>
#endif
#include "encrypt.h"
#include "decrypt.h"
#include "integrity.h"
#include "shredder.h"
#include "audit.h"

#define MAX_PATH_LEN 1024

static void print_usage(const char *prog) {
    printf("\n=== File Encryption System ===\n\n");
    printf("Usage:\n");
    printf("  Encrypt file:  %s --encrypt <file> --password <pass>\n", prog);
    printf("  Encrypt folder: %s --encrypt <folder> --password <pass>\n", prog);
    printf("  Encrypt w/ decoy: %s --encrypt <file> --password <pass> --decoy <decoy_file> --decoy-password <decoy_pass>\n", prog);
    printf("  Decrypt:       %s --decrypt <file> --password <pass>\n", prog);
    printf("  Verify:        %s --verify <file> --password <pass>\n", prog);
    printf("  Change password: %s --change-password <file> --password <old_pass> --new-password <new_pass>\n", prog);
    printf("  Change password (duress): %s --change-password <file> --password <old_real> --new-password <new_real> --decoy-password <old_decoy> --new-decoy-password <new_decoy>\n", prog);
    printf("  Shred:         %s --shred <file>\n", prog);
    printf("  Audit log:     %s --log\n", prog);
    printf("\nExamples:\n");
    printf("  %s --encrypt secret.txt --password mypass123\n", prog);
    printf("  %s --encrypt my_folder --password mypass123\n", prog);
    printf("  %s --encrypt secret.txt --password realpass --decoy innocent.txt --decoy-password decoypass\n", prog);
    printf("  %s --decrypt secret.txt.enc --password mypass123\n", prog);
    printf("  %s --verify secret.txt.enc --password mypass123\n", prog);
    printf("  %s --change-password secret.txt.enc --password oldpass --new-password newpass\n", prog);
    printf("\n");
}

static int is_directory(const char *path) {
    struct stat st;
    if (stat(path, &st) != 0) return 0;
    return S_ISDIR(st.st_mode);
}

static void list_dir_recursive(const char *path, const char *prefix) {
    DIR *d = opendir(path);
    if (!d) { fprintf(stderr, "Error opening directory %s: %s\n", path, strerror(errno)); return; }
    struct dirent *ent;
    while ((ent = readdir(d)) != NULL) {
        if (strcmp(ent->d_name, ".") == 0 || strcmp(ent->d_name, "..") == 0) continue;
        char child[MAX_PATH_LEN];
        snprintf(child, sizeof(child), "%s/%s", path, ent->d_name);
        printf("%s%s\n", prefix, ent->d_name);
        if (is_directory(child)) {
            char newpref[MAX_PATH_LEN];
            snprintf(newpref, sizeof(newpref), "%s%s/", prefix, ent->d_name);
            list_dir_recursive(child, newpref);
        }
    }
    closedir(d);
}

static int prompt_yes_no(const char *msg) {
    char ans[8];
    printf("%s [y/N]: ", msg);
    fflush(stdout);
    if (!fgets(ans, sizeof(ans), stdin)) return 0;
    return (ans[0] == 'y' || ans[0] == 'Y');
}

static int check_file_integrity(const char *filepath) {
    FILE *f = fopen(filepath, "rb");
    if (!f) {
        fprintf(stderr, "[!] Integrity check FAILED: cannot open file %s\n", filepath);
        return 0;
    }

    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    if (!mdctx) {
        fprintf(stderr, "[!] Integrity check FAILED: memory allocation failed\n");
        fclose(f);
        return 0;
    }
    
    if (!EVP_DigestInit_ex(mdctx, EVP_sha256(), NULL)) {
        fprintf(stderr, "[!] Integrity check FAILED: digest init failed\n");
        EVP_MD_CTX_free(mdctx);
        fclose(f);
        return 0;
    }
    
    unsigned char buf[65536];
    size_t n;
    while ((n = fread(buf, 1, sizeof(buf), f)) > 0) {
        EVP_DigestUpdate(mdctx, buf, n);
    }
    fclose(f);

    unsigned char hash[EVP_MAX_MD_SIZE];
    unsigned int hash_len;
    if (!EVP_DigestFinal_ex(mdctx, hash, &hash_len)) {
        fprintf(stderr, "[!] Integrity check FAILED: digest finalize failed\n");
        EVP_MD_CTX_free(mdctx);
        return 0;
    }
    EVP_MD_CTX_free(mdctx);
    
    printf("[+] Integrity check SUCCEEDED\n");
    printf("    SHA-256: ");
    for (unsigned int i = 0; i < hash_len; i++)
        printf("%02x", hash[i]);
    printf("\n");
    return 1;
}

static const char *path_basename(const char *path) {
    const char *slash = strrchr(path, '/');
    const char *bslash = strrchr(path, '\\');
    const char *base = path;

    if (slash && bslash)
        base = (slash > bslash) ? slash + 1 : bslash + 1;
    else if (slash)
        base = slash + 1;
    else if (bslash)
        base = bslash + 1;

    return (*base) ? base : path;
}

static void path_dirname(const char *path, char *out, size_t out_size) {
    const char *slash = strrchr(path, '/');
    const char *bslash = strrchr(path, '\\');
    const char *sep = NULL;

    if (slash && bslash)
        sep = (slash > bslash) ? slash : bslash;
    else if (slash)
        sep = slash;
    else
        sep = bslash;

    if (!sep) {
        snprintf(out, out_size, ".");
        return;
    }

    if (sep == path) {
        snprintf(out, out_size, "/");
        return;
    }

    size_t len = (size_t)(sep - path);
    if (len >= out_size)
        len = out_size - 1;

    memcpy(out, path, len);
    out[len] = '\0';
}

static int shred_directory_recursive(const char *dir_path) {
    DIR *d = opendir(dir_path);
    if (!d) {
        fprintf(stderr, "[!] Failed to open directory for shredding: %s (%s)\n", dir_path, strerror(errno));
        return 0;
    }

    int ok = 1;
    struct dirent *ent;
    while ((ent = readdir(d)) != NULL) {
        if (strcmp(ent->d_name, ".") == 0 || strcmp(ent->d_name, "..") == 0) continue;

        char child[MAX_PATH_LEN];
        snprintf(child, sizeof(child), "%s/%s", dir_path, ent->d_name);

        if (is_directory(child)) {
            if (!shred_directory_recursive(child)) ok = 0;
        } else {
            if (!shred_file(child)) {
                fprintf(stderr, "[!] Failed to shred file: %s\n", child);
                ok = 0;
            } else {
                audit_log(AUDIT_SHRED, child, 1);
            }
        }
    }

    closedir(d);

    if (rmdir(dir_path) != 0) {
        fprintf(stderr, "[!] Failed to remove directory: %s (%s)\n", dir_path, strerror(errno));
        ok = 0;
    }

    return ok;
}

static void normalize_path(char *path) {
    if (!path) return;
    /* Convert MSYS-style /x/... paths to X:/... first. */
    if (path[0] == '/' && path[1] != '\0' && path[2] == '/' &&
        ((path[1] >= 'a' && path[1] <= 'z') || (path[1] >= 'A' && path[1] <= 'Z'))) {
        path[0] = (char)((path[1] >= 'a' && path[1] <= 'z') ? (path[1] - 'a' + 'A') : path[1]);
        path[1] = ':';
        path[2] = '/';
    }

    /* Convert backslashes to forward slashes (if they survived shell parsing). */
    for (int i = 0; path[i] != '\0'; i++) {
        if (path[i] == '\\') {
            path[i] = '/';
        }
    }
}

static int validate_path(const char *path) {
    if (!path || path[0] == '\0') {
        fprintf(stderr, "[!] Error: Empty path provided\n");
        return 0;
    }
    /* Check for obviously malformed paths (no path separators or only drive letter) */
    if (strchr(path, '/') == NULL && strchr(path, '\\') == NULL) {
        /* Might be just a filename in current directory, that's ok */
    }
    return 1;
}

int main(int argc, char *argv[]) {
    if (argc < 2) { print_usage(argv[0]); return 1; }

    char *mode           = NULL;
    char *filepath       = NULL;
    char *password       = NULL;
    char *new_password   = NULL;
    char *decoy_file     = NULL;
    char *decoy_password = NULL;
    char *new_decoy_password = NULL;

    for (int i = 1; i < argc; i++) {
        if      (strcmp(argv[i], "--encrypt")        == 0 && i+1 < argc) { mode = "encrypt"; filepath = argv[++i]; }
        else if (strcmp(argv[i], "--decrypt")        == 0 && i+1 < argc) { mode = "decrypt"; filepath = argv[++i]; }
        else if (strcmp(argv[i], "--verify")         == 0 && i+1 < argc) { mode = "verify";  filepath = argv[++i]; }
        else if (strcmp(argv[i], "--change-password") == 0 && i+1 < argc) { mode = "change-password"; filepath = argv[++i]; }
        else if (strcmp(argv[i], "--shred")          == 0 && i+1 < argc) { mode = "shred";   filepath = argv[++i]; }
        else if (strcmp(argv[i], "--log")            == 0)                { mode = "log"; }
        else if (strcmp(argv[i], "--password")       == 0 && i+1 < argc) { password = argv[++i]; }
        else if (strcmp(argv[i], "--new-password")   == 0 && i+1 < argc) { new_password = argv[++i]; }
        else if (strcmp(argv[i], "--decoy")          == 0 && i+1 < argc) { decoy_file = argv[++i]; }
        else if (strcmp(argv[i], "--decoy-password") == 0 && i+1 < argc) { decoy_password = argv[++i]; }
        else if (strcmp(argv[i], "--new-decoy-password") == 0 && i+1 < argc) { new_decoy_password = argv[++i]; }
        else { printf("Unknown argument: %s\n", argv[i]); print_usage(argv[0]); return 1; }
    }

    if (!mode) { printf("Error: No mode specified.\n"); print_usage(argv[0]); return 1; }

    if (filepath) {
        if (!validate_path(filepath)) {
            return 1;
        }
        normalize_path(filepath);
    }

    if (decoy_file) {
        if (!validate_path(decoy_file)) {
            return 1;
        }
        normalize_path(decoy_file);
    }

    if ((strcmp(mode, "encrypt") == 0 || strcmp(mode, "decrypt") == 0 || strcmp(mode, "verify") == 0 || strcmp(mode, "change-password") == 0) && !password) {
        printf("Error: --password is required for encrypt/decrypt/verify/change-password.\n"); return 1;
    }

    if (strcmp(mode, "change-password") == 0 && !new_password) {
        printf("Error: --new-password is required for --change-password.\n");
        return 1;
    }

    /* Validate encrypt-mode duress flags */
    if (strcmp(mode, "encrypt") == 0) {
        if ((decoy_file != NULL && decoy_password == NULL) || (decoy_file == NULL && decoy_password != NULL)) {
            printf("Error: --decoy and --decoy-password must both be specified together.\n"); return 1;
        }
    } else if (decoy_file != NULL) {
        printf("Error: --decoy flag only works with --encrypt mode.\n");
        return 1;
    }

    if (decoy_password && strcmp(mode, "encrypt") != 0 && strcmp(mode, "change-password") != 0) {
        printf("Error: --decoy-password only works with --encrypt or --change-password mode.\n");
        return 1;
    }

    if (new_decoy_password && strcmp(mode, "change-password") != 0) {
        printf("Error: --new-decoy-password only works with --change-password mode.\n");
        return 1;
    }

    if (strcmp(mode, "encrypt") == 0) {
        if (is_directory(filepath)) {
            /* Folder detected: list contents, confirm, archive, encrypt */
            printf("\n[*] Folder detected: %s\n", filepath);
            printf("[*] Contents:\n");
            list_dir_recursive(filepath, "  ");
            printf("\n");
            
            if (!prompt_yes_no("Archive and encrypt this folder?")) {
                printf("Aborted.\n");
                return 1;
            }

            /* Create archive alongside source folder: <parent>/<foldername>.tar.gz */
            char archive_name[MAX_PATH_LEN];
            const char *folder_name = path_basename(filepath);
            char parent_dir[MAX_PATH_LEN];
            path_dirname(filepath, parent_dir, sizeof(parent_dir));
            snprintf(archive_name, sizeof(archive_name), "%s/%s.tar.gz", parent_dir, folder_name);
            char cmd[MAX_PATH_LEN * 2];
            snprintf(cmd, sizeof(cmd), "tar --force-local -czf \"%s\" -C \"%s\" \"%s\"", archive_name, parent_dir, folder_name);
            
            printf("[*] Creating archive: %s\n", archive_name);
            int rc = system(cmd);
            if (rc != 0) {
                fprintf(stderr, "Error: Archive creation failed (tar returned %d)\n", rc);
                return 1;
            }
            
            /* Check integrity of archive before encryption */
            printf("\n[*] Checking archive integrity...\n");
            if (!check_file_integrity(archive_name)) {
                return 1;
            }
            
            /* Now encrypt the archive */
            char out_path[MAX_PATH_LEN];
            snprintf(out_path, sizeof(out_path), "%s.enc", archive_name);
            printf("\n[*] Encrypting archive...\n");
            int ok;
            if (decoy_file && decoy_password) {
                printf("[*] Duress mode: using real and decoy passwords.\n");
                ok = encrypt_file_with_duress(archive_name, decoy_file, out_path, password, decoy_password);
            } else {
                ok = encrypt_file(archive_name, out_path, password);
            }
            int overall_ok = ok;
            if (ok) {
                printf("[+] Encrypted to: %s\n", out_path);
                /* Shred original archive */
                printf("[*] Shredding original archive...\n");
                if (shred_file(archive_name)) {
                    printf("[+] Original archive securely shredded\n");
                    audit_log(AUDIT_SHRED, archive_name, 1);
                } else {
                    fprintf(stderr, "[!] Failed to shred archive, please delete manually: %s\n", archive_name);
                    overall_ok = 0;
                }

                /* Shred original source folder recursively */
                printf("[*] Shredding original folder recursively...\n");
                if (shred_directory_recursive(filepath)) {
                    printf("[+] Original folder securely shredded: %s\n", filepath);
                    audit_log(AUDIT_SHRED, filepath, 1);
                } else {
                    fprintf(stderr, "[!] Failed to fully shred original folder: %s\n", filepath);
                    overall_ok = 0;
                }

                printf("[+] Encrypted file location: %s\n", out_path);
            }
            return overall_ok ? 0 : 1;
        } else {
            /* Regular file: check integrity, encrypt, shred */
            printf("[*] Checking file integrity...\n");
            if (!check_file_integrity(filepath)) {
                return 1;
            }
            
            char out_path[MAX_PATH_LEN];
            snprintf(out_path, sizeof(out_path), "%s.enc", filepath);
            printf("\n[*] Encrypting file...\n");
            int ok;
            if (decoy_file && decoy_password) {
                printf("[*] Duress mode: using real and decoy passwords.\n");
                ok = encrypt_file_with_duress(filepath, decoy_file, out_path, password, decoy_password);
            } else {
                ok = encrypt_file(filepath, out_path, password);
            }
            int overall_ok = ok;
            if (ok) {
                printf("[+] Encrypted to: %s\n", out_path);
                /* Shred original file */
                printf("[*] Shredding original file...\n");
                if (shred_file(filepath)) {
                    printf("[+] Original file securely shredded\n");
                    audit_log(AUDIT_SHRED, filepath, 1);
                } else {
                    fprintf(stderr, "[!] Failed to shred file, please delete manually: %s\n", filepath);
                    overall_ok = 0;
                }
            }
            return overall_ok ? 0 : 1;
        }

    } else if (strcmp(mode, "decrypt") == 0) {
        /* Output filename: strip .enc if present, else append .dec */
        char out_path[MAX_PATH_LEN];
        strncpy(out_path, filepath, sizeof(out_path) - 5);
        out_path[sizeof(out_path) - 5] = '\0';
        size_t len = strlen(out_path);
        if (len > 4 && strcmp(out_path + len - 4, ".enc") == 0)
            out_path[len - 4] = '\0';
        else
            strncat(out_path, ".dec", 5);
        
        int decrypt_status = decrypt_file(filepath, out_path, password);
        if (decrypt_status == DECRYPT_FAILED) return 1;
        
        /* Determine .enc cleanup behavior based on duress status */
        int should_shred_enc = 1;  /* Default: shred .enc after decrypt */
        if (decrypt_status == DECRYPT_DECOY) {
            /* Decoy password used: keep .enc automatically */
            should_shred_enc = 0;
        } else if (decrypt_status == DECRYPT_REAL) {
            /* Real password used: ask user */
            should_shred_enc = prompt_yes_no("[?] Shred encrypted file?");
        }

        /* If output is a tar.gz, automatically extract it */
        len = strlen(out_path);
        if (len > 7 && strcmp(out_path + len - 7, ".tar.gz") == 0) {
            printf("[*] Archive detected. Extracting...\n");
            char extract_dir[MAX_PATH_LEN];
            path_dirname(out_path, extract_dir, sizeof(extract_dir));
            char cmd[MAX_PATH_LEN * 2];
            snprintf(cmd, sizeof(cmd), "tar --force-local -C \"%s\" -xzf \"%s\"", extract_dir, out_path);
            int rc = system(cmd);
            if (rc == 0) {
                printf("[+] Folder extracted successfully.\n");
                printf("[*] Removing temporary archive...\n");
                if (shred_file(out_path)) {
                    printf("[+] Temporary archive securely deleted: %s\n", out_path);
                    audit_log(AUDIT_SHRED, out_path, 1);
                } else {
                    fprintf(stderr, "[!] Failed to remove temporary archive: %s\n", out_path);
                }

                /* Handle encrypted archive based on duress status */
                if (should_shred_enc) {
                    printf("[*] Removing encrypted archive...\n");
                    if (shred_file(filepath)) {
                        printf("[+] Encrypted archive securely deleted: %s\n", filepath);
                        audit_log(AUDIT_SHRED, filepath, 1);
                    } else {
                        fprintf(stderr, "[!] Failed to remove encrypted archive: %s\n", filepath);
                    }
                }
            } else {
                fprintf(stderr, "[!] Extraction failed (tar returned %d), but archive is available at %s\n", rc, out_path);
                return 1;
            }
        } else {
            /* Handle regular file based on duress status */
            if (should_shred_enc) {
                printf("[*] Removing encrypted file...\n");
                if (shred_file(filepath)) {
                    printf("[+] Encrypted file securely deleted: %s\n", filepath);
                    audit_log(AUDIT_SHRED, filepath, 1);
                } else {
                    fprintf(stderr, "[!] Failed to remove encrypted file: %s\n", filepath);
                    return 1;
                }
            }
        }
        return 0;

    } else if (strcmp(mode, "verify") == 0) {
        int ok = verify_file(filepath, password);
        return ok ? 0 : 1;

    } else if (strcmp(mode, "change-password") == 0) {
        int ok = change_password_file(filepath, password, new_password, decoy_password, new_decoy_password);
        return ok ? 0 : 1;

    } else if (strcmp(mode, "shred") == 0) {
        int ok = shred_file(filepath);
        audit_log(AUDIT_SHRED, filepath, ok);
        return ok ? 0 : 1;

    } else if (strcmp(mode, "log") == 0) {
        audit_print();
    }

    return 0;
}