# Technical Report: File Encryption System

## 1. Executive Summary

The File Encryption System is a C-based command-line application that encrypts files and folders using AES-256-CBC, derives keys from passwords with PBKDF2-SHA256, authenticates plaintext with HMAC-SHA256, and securely shreds source data after successful processing. It supports standard single-password encryption, duress/decoy mode with two independently protected payloads, integrity verification, password changes, account lockout, audit logging, and Discord-based alerting for failed access attempts.

The system is built for scenarios where users need local file confidentiality, tamper detection, and coercion resistance. The design emphasizes streaming processing so large files are handled in 65 KB chunks without loading the full file into memory.

## 2. System Architecture

The project is organized as a layered pipeline:

- `main.c` performs CLI parsing, path normalization, workflow orchestration, and user interaction.
- `crypto/` provides encryption, decryption, key derivation, and HMAC verification.
- `vault/` defines the on-disk `.enc` file format and header/HMAC I/O.
- `security/` provides lockout enforcement and secure file shredding.
- `utils/` provides secure memory wiping, password-strength scoring, and audit logging.
- `alerts/` sends real-time Discord webhook notifications for suspicious events.

### Text-Based Module Dependency Diagram

```text
main.c
├─ crypto/encrypt.c
│  ├─ crypto/kdf.c
│  ├─ vault/vault.c
│  └─ utils/{utils.c,audit.c}
├─ crypto/decrypt.c
│  ├─ crypto/kdf.c
│  ├─ crypto/integrity.c
│  ├─ vault/vault.c
│  ├─ security/lockout.c
│  ├─ security/shredder.c
│  ├─ alerts/discord.c
│  └─ utils/{utils.c,audit.c}
├─ crypto/integrity.c
│  ├─ crypto/kdf.c
│  ├─ vault/vault.c
│  └─ utils/audit.c
├─ vault/vault.c
│  └─ crypto/kdf.h
├─ security/lockout.c
├─ security/shredder.c
├─ utils/{utils.c,audit.c}
└─ alerts/discord.c
   └─ security/lockout.h
```

The control flow is intentionally centralized in `main.c`, while the cryptographic and file-format logic is separated into reusable modules. This makes the system easier to audit and reduces coupling between UI logic and cryptographic operations.

## 3. Module-by-Module Technical Breakdown

### `main.c`

**Purpose**

`main.c` is the CLI front end and workflow controller. It parses command-line arguments, validates flags, normalizes paths, detects folders, builds archive paths, and dispatches to encryption, decryption, verification, password change, shredding, or log display functions.

**Key Functions**

- `main()` routes each mode (`--encrypt`, `--decrypt`, `--verify`, `--change-password`, `--shred`, `--log`).
- `normalize_path()` converts MSYS-style `/g/...` paths and backslashes into a format that `fopen()` can consume.
- `is_directory()` detects folder inputs.
- `list_dir_recursive()` prints folder contents before encryption.
- `check_file_integrity()` computes SHA-256 over the source file before encryption.
- `path_basename()` and `path_dirname()` split archive paths.
- `shred_directory_recursive()` recursively shreds folder contents.

**Notable Implementation Details**

- The code supports both files and folders. Folders are archived into `.tar.gz` before encryption.
- `main.c` enforces argument combinations for duress mode so `--decoy` and `--decoy-password` must be provided together.
- Decryption uses the return code from `decrypt_file()` to decide whether to delete the encrypted file. `DECRYPT_DECOY` suppresses automatic shredding so the decoy path can preserve the encrypted container if needed.
- File paths are normalized before use, which is important for MSYS2/UCRT64 paths and quoted shell input.

**Important Function Snippet**

```c
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
```

### `crypto/encrypt.c`

**Purpose**

`encrypt.c` implements standard file encryption and duress-mode encryption. It handles streaming AES-256-CBC encryption, HMAC generation over plaintext, and header/HMAC writing to the vault format.

**Key Functions**

- `encrypt_file()` encrypts a single file with one password.
- `encrypt_file_with_duress()` encrypts a real file and a decoy file into one `.enc` container.
- `normalize_input_path()` cleans up incoming file paths before `fopen()`.

**Notable Implementation Details**

- The encryption path is streaming-based and uses `CHUNK_SIZE = 65536`.
- File size is read with `_filelengthi64()` on Windows and `ftell()` elsewhere for progress reporting.
- `VaultHeader hdr` is zero-initialized with `memset()` before fields are populated, which avoids uninitialized padding and stale duress flags.
- The code computes HMAC over plaintext using `EVP_MAC` with SHA-256.
- Duress mode stores two independent salts, IVs, keys, ciphertexts, and HMACs in one file.

**Important Function Snippet**

```c
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
```

### `crypto/decrypt.c`

**Purpose**

`decrypt.c` performs decryption, HMAC verification, duress detection, password change re-encryption, and lockout integration. It is the most complex runtime module because it supports both standard and dual-password file layouts.

**Key Functions**

- `decrypt_file()` is the main entry point.
- `try_decrypt_with_password()` streams one segment through AES-256-CBC, recomputes HMAC, and checks the supplied password.
- `change_password_file()` re-encrypts existing ciphertext with new salts, IVs, and passwords without writing plaintext to disk.
- `stream_reencrypt_segment()` supports rekeying in place for standard and duress layouts.
- `verify_password_for_segment()` verifies candidate passwords in rekeying logic.

**Notable Implementation Details**

- `decrypt_file()` first checks `lockout_is_locked()` before opening the file.
- In standard mode, it decrypts one payload and verifies one HMAC.
- In duress mode, it tries the real password first, then the decoy password, using the return codes `DECRYPT_REAL`, `DECRYPT_DECOY`, and `DECRYPT_FAILED`.
- Progress reporting uses `long long` math to avoid overflow on large files.
- The code emits debug output for `hdr.duress_flag` and `sizeof(VaultHeader)` and prints computed/stored HMAC values on mismatch.

**Important Function Snippet**

```c
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
...

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
```

### `crypto/kdf.c`

**Purpose**

`kdf.c` derives encryption keys from passwords using PBKDF2-HMAC-SHA256 and generates secure random bytes for salts and IVs.

**Key Functions**

- `derive_key()` derives a 32-byte AES key from a password and salt.
- `generate_random_bytes()` wraps `RAND_bytes()` and returns success/failure.

**Notable Implementation Details**

- `PKCS5_PBKDF2_HMAC()` is used with `KDF_ITERATIONS` defined in `kdf.h`.
- The derived key length is `KEY_LEN`, and salts are `SALT_LEN` bytes.
- This module contains the only password-to-key derivation path, so it is central to both standard and duress modes.

**Important Function Snippet**

```c
int derive_key(const char *password, const unsigned char *salt, unsigned char *key) {
    int result = PKCS5_PBKDF2_HMAC(
        password, (int)strlen(password),
        salt, SALT_LEN,
        KDF_ITERATIONS,
        EVP_sha256(),
        KEY_LEN, key
    );
    if (result != 1) {
        fprintf(stderr, "Error: Key derivation failed.\n");
        return 0;
    }
    return 1;
}
```

### `crypto/integrity.c`

**Purpose**

`integrity.c` computes and verifies HMAC-SHA256 tags and provides file integrity verification.

**Key Functions**

- `integrity_compute()` computes an HMAC over a buffer.
- `integrity_verify()` performs constant-time comparison.
- `verify_file()` verifies a full `.enc` file using the vault header and stored HMAC(s).

**Notable Implementation Details**

- `integrity_verify()` avoids short-circuiting and compares all bytes to reduce timing leakage.
- `verify_file()` handles both standard and duress mode structures.
- In duress mode, it tries the real segment first and falls back to the decoy segment.

**Important Function Snippet**

```c
int integrity_verify(const unsigned char *expected, const unsigned char *actual, size_t len) {
    /* Constant-time compare — never short-circuit on mismatch */
    volatile unsigned char diff = 0;
    for (size_t i = 0; i < len; i++)
        diff |= expected[i] ^ actual[i];
    return diff == 0;
}
```

### `vault/vault.c`

**Purpose**

`vault.c` is responsible for raw file-format I/O. It writes and reads the vault header and HMACs and validates the file signature and version.

**Key Functions**

- `vault_write_header()` writes the raw `VaultHeader` struct.
- `vault_read_header()` rewinds and reads the header.
- `vault_validate_header()` checks magic, version, and duress flag.
- `vault_write_hmac()` appends the HMAC to the end of a standard file.
- `vault_read_hmac()` reads the trailing HMAC.
- `vault_write_decoy_hmac()` writes the second HMAC in duress mode.
- `vault_read_decoy_hmac()` reads the decoy HMAC at a computed offset.

**Notable Implementation Details**

- The header is written as a raw C struct, so alignment/padding is part of the on-disk format on the current toolchain.
- The code validates that `duress_flag` is either `0` or `1`.
- Standard files store one HMAC at the end of the file.
- Duress files store two encrypted segments and two HMACs.

**Important Function Snippet**

```c
int vault_validate_header(const VaultHeader *header) {
    if (memcmp(header->magic, MAGIC, MAGIC_LEN) != 0) {
        fprintf(stderr, "Error: Not a valid vault file.\n");
        return 0;
    }
    if (header->version != VERSION) {
        fprintf(stderr, "Error: Unsupported vault version %d.\n", header->version);
        return 0;
    }
    if (header->duress_flag != 0 && header->duress_flag != 1) {
        fprintf(stderr, "Error: Invalid duress flag value %u in vault header.\n", (unsigned)header->duress_flag);
        return 0;
    }
    return 1;
}
```

### `security/lockout.c`

**Purpose**

`lockout.c` tracks failed decryption attempts per vault and writes `.lock` files to enforce brute-force protection.

**Key Functions**

- `lockout_is_locked()` checks whether the vault should be blocked.
- `lockout_record_failure()` increments the attempt counter and prints status.
- `lockout_reset()` deletes the `.lock` file on success.

**Notable Implementation Details**

- The lock file uses the same vault path with `.lock` appended.
- Attempts are read from the existing file before incrementing, so state persists across runs.
- The lockout threshold is controlled by `MAX_ATTEMPTS`.

**Important Function Snippet**

```c
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
```

### `security/shredder.c`

**Purpose**

`shredder.c` securely overwrites files before deletion.

**Key Functions**

- `shred_file()` normalizes the path, opens the file, overwrites it in three passes, and removes it.
- `overwrite_pass()` writes zeros or 0xFF over the file.
- `overwrite_random()` writes cryptographically random bytes.

**Notable Implementation Details**

- It trims leading/trailing whitespace and removes a single pair of surrounding quotes.
- It uses direct `fopen()` and `remove()` rather than shell commands.
- The three-pass sequence is 0x00 → 0xFF → random.

**Important Function Snippet**

```c
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
```

### `utils/audit.c`

**Purpose**

`audit.c` records security-relevant events to `audit.log` and prints the log on demand.

**Key Functions**

- `audit_log()` appends a timestamped line to `audit.log`.
- `audit_print()` prints the log to stdout.
- `event_name()` maps enum values to human-readable event strings.

**Notable Implementation Details**

- Every major action can write a success/failure entry.
- The log format is fixed-width and includes timestamp, event, filename, and status.

**Important Function Snippet**

```c
void audit_log(AuditEvent event, const char *filename, int success) {
    FILE *f = fopen(LOG_FILE, "a");
    if (!f) return;

    time_t now = time(NULL);
    struct tm *t = localtime(&now);
    char timestamp[32];
    strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", t);

    fprintf(f, "[%s] %-24.24s %-40.40s %s\n",
            timestamp,
            event_name(event),
            filename ? filename : "-",
            success ? "SUCCESS" : "FAILURE");

    fclose(f);
}
```

### `alerts/discord.c`

**Purpose**

`discord.c` sends Discord webhook notifications for suspicious events such as failed decrypt attempts, vault lockout, and duress password usage.

**Key Functions**

- `discord_alert()` sends a failed-attempt alert.
- `discord_duress_password_alert()` signals that a duress password was used.
- `discord_vault_locked_alert()` announces a locked vault.
- `discord_send_content()` builds the JSON payload and invokes `curl`.
- `get_webhook_url()` returns `DISCORD_WEBHOOK_URL` if set, otherwise the compiled fallback webhook URL.

**Notable Implementation Details**

- The code writes a JSON payload to `C:\msys64\tmp\discord_alert.json`.
- It writes a curl config file to `C:\msys64\tmp\discord_alert.curl`.
- It runs `curl.exe` from `C:\msys64\usr\bin\curl.exe` and posts the JSON to the webhook.
- The alert content includes file path, timestamp, attempt count, and machine name.
- The environment variable `DISCORD_WEBHOOK_URL` overrides the compiled webhook string.

**Important Function Snippet**

```c
static int discord_send_content(const char *content) {
    FILE *json = fopen(ALERT_JSON_PATH, "w");
    if (!json) {
        return 0;
    }

    fprintf(json, "{\"content\": \"%s\"}", content);
    fclose(json);

    FILE *curl_config = fopen(ALERT_CURL_CONFIG_PATH, "w");
    if (!curl_config) {
        return 0;
    }

    fprintf(curl_config, "silent\n");
    fprintf(curl_config, "header = \"Content-Type: application/json\"\n");
    fprintf(curl_config, "data-binary = \"@C:/msys64/tmp/discord_alert.json\"\n");
    fprintf(curl_config, "url = \"%s\"\n", get_webhook_url());
    fclose(curl_config);
```

## 4. Encryption Pipeline (End-to-End Flow)

The standard encryption path begins in `main()` when the user runs `./encrypt --encrypt file.txt --password pass`.

1. `main()` parses arguments and normalizes paths.
2. `check_file_integrity()` computes SHA-256 over the source file.
3. `encrypt_file()` opens the input and output files.
4. `password_entropy_score()` evaluates password strength for feedback.
5. `derive_key()` generates a 256-bit AES key from the password and salt.
6. `vault_write_header()` writes a placeholder `VaultHeader`.
7. `EVP_EncryptInit_ex()` configures AES-256-CBC.
8. `EVP_MAC_init()` configures HMAC-SHA256 over plaintext.
9. The file is read in 65 KB chunks, encrypted, and fed into the HMAC context.
10. The final AES block is flushed with `EVP_EncryptFinal_ex()`.
11. `EVP_MAC_final()` produces the plaintext HMAC.
12. `vault_write_hmac()` appends the HMAC.
13. The header is rewritten with the final size fields.
14. `shred_file()` deletes the original plaintext.

In folder mode, `main()` archives the folder to `.tar.gz` first, encrypts the archive, then shreds both the archive and the original folder tree.

## 5. Decryption Pipeline (End-to-End Flow)

The decryption path begins in `main()` when the user runs `./encrypt --decrypt file.enc --password pass`.

1. `main()` derives the output filename from the `.enc` path.
2. `decrypt_file()` checks whether the vault is already locked via `lockout_is_locked()`.
3. `vault_read_header()` reads the header from disk.
4. `vault_validate_header()` checks the signature, version, and duress flag.
5. `decrypt_file()` computes file sizes and segment offsets.
6. For standard files, it reads the stored HMAC and calls `try_decrypt_with_password()` once.
7. For duress files, it first tries the real password, then reopens the output and tries the decoy password.
8. `try_decrypt_with_password()` derives a key, decrypts the segment, recomputes HMAC over plaintext, and compares it to the stored HMAC.
9. On success, `decrypt_file()` returns `DECRYPT_REAL` or `DECRYPT_DECOY`.
10. On failure, `lockout_record_failure()` increments the `.lock` file and may trigger `discord_alert()` or `discord_vault_locked_alert()`.
11. `main()` optionally shreds the encrypted file depending on the return code and user prompt.
12. If the output is `.tar.gz`, `main()` extracts the archive and then shreds the temporary archive.

## 6. Vault File Format

The vault format is defined in `vault/vault.h` and implemented in `vault/vault.c`.

### `VaultHeader`

The raw header contains:

- `magic[4]` = `FENC`
- `version` = `1`
- `duress_flag` = `0` or `1`
- `salt[16]` and `iv[16]` for the real payload
- `original_size` for the real plaintext size
- `decoy_salt[16]` and `decoy_iv[16]` for the decoy payload
- `decoy_size` for the decoy plaintext size

The current toolchain writes the raw struct directly, and the in-memory/on-disk size is 88 bytes due to alignment.

### Standard Mode Layout

```text
[VaultHeader | ciphertext | HMAC]
```

Where:
- `VaultHeader` identifies the file and stores the real salt/IV and plaintext size.
- `ciphertext` is the AES-256-CBC output.
- `HMAC` is the 32-byte SHA-256 HMAC over the plaintext.

### Duress Mode Layout

```text
[VaultHeader | real_ciphertext | real_HMAC | decoy_ciphertext | decoy_HMAC]
```

Where:
- The real segment uses `salt` and `iv`.
- The decoy segment uses `decoy_salt` and `decoy_iv`.
- Both segments are independently encrypted and independently authenticated.

`vault_read_hmac()` reads the trailing HMAC in standard files, while `vault_read_decoy_hmac()` can read the decoy HMAC at a computed offset in duress files.

## 7. Duress / Decoy Password System

Duress mode is a coercion-resistance feature that stores two separately protected payloads in one `.enc` file.

### Technical Behavior

- The real file is encrypted with the real password, real salt, real IV, and real AES key.
- The decoy file is encrypted with the decoy password, decoy salt, decoy IV, and decoy AES key.
- Both payloads are stored sequentially in one vault file.
- Each payload has its own HMAC for authentication.

### Decryption Decision Order

`decrypt_file()` attempts the real password first:

1. Read `real_hmac`.
2. Call `try_decrypt_with_password()` with `hdr.salt`, `hdr.iv`, and the real ciphertext length.
3. If that fails, reopen the output and try the decoy path.
4. If the decoy path succeeds, return `DECRYPT_DECOY`.
5. If both fail, return `DECRYPT_FAILED` and increment lockout state.

### Return Codes

- `DECRYPT_REAL (1)` means the real password succeeded or a standard file decrypted.
- `DECRYPT_DECOY (2)` means the decoy password succeeded.
- `DECRYPT_FAILED (0)` means no valid password or the file is corrupted/tampered.

### Threat Model

Protects against:
- Coerced disclosure where the attacker can only observe the decryption output.
- Casual password guessing.
- Tampering with the encrypted container.

Does not protect against:
- An attacker who independently knows the decoy content.
- Forensics that recover both plaintext sources.
- Someone watching the screen during decryption.
- Passwords extracted from memory.

## 8. Discord Webhook Alert System

The alerting system is implemented in `alerts/discord.c`.

### Trigger Conditions

- A failed decryption attempt before lockout triggers `discord_alert()`.
- A vault reaching the lockout threshold triggers `discord_vault_locked_alert()`.
- A successful duress-password decrypt triggers `discord_duress_password_alert()`.

### Alert Content

The alert includes:
- File path
- Timestamp
- Attempt count
- Machine name

### Technical Flow

1. The code formats a JSON payload string.
2. It writes that payload to `C:\msys64\tmp\discord_alert.json`.
3. It writes a curl config file to `C:\msys64\tmp\discord_alert.curl`.
4. The config file references the JSON file and the webhook URL.
5. `curl.exe` posts the payload to Discord.
6. `DISCORD_WEBHOOK_URL` overrides the compiled fallback URL if set.

### Sample Alert Payload

```json
{
  "content": "\ud83d\udea8 FAILED DECRYPTION ATTEMPT!\n\ud83d\udcc1 File: G:/file encryption test/movies/file.enc\n\u23f0 Time: 2026-05-05 12:34:56\n\u274c Attempts: 2/5\n\ud83d\udcbb Machine: Fahad-PC\n\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500"
}
```

### Operational Value

This provides near-real-time visibility into unauthorized password attempts and lockout events without requiring the user to actively monitor the terminal.

## 9. Security Analysis

### Strengths

- **AES-256-CBC** provides strong confidentiality when used with unique keys and IVs.
- **HMAC-SHA256** detects tampering and wrong-password attempts.
- **PBKDF2-SHA256** with `KDF_ITERATIONS` increases the cost of offline password guessing.
- **Constant-time comparison** in `integrity_verify()` reduces timing leakage.
- **Lockout protection** slows repeated online password attempts.
- **3-pass shredding** reduces plaintext recovery risk after deletion.
- **Streaming I/O** prevents memory exhaustion on large files.

### Limitations

- Passwords still exist in memory during processing.
- Metadata such as filenames and folder structure can remain visible in some workflows.
- CBC mode does not provide built-in AEAD semantics; the design compensates with a separate HMAC.
- PBKDF2 is serviceable but weaker than modern memory-hard alternatives.
- Discord webhook URLs are sensitive configuration and should be protected.

## 10. Challenges Faced — STAR Format

### Challenge 1: Duress Mode Without Revealing Which Password Is Real

**Situation:** The project needed to support a coercion-resistant mode while keeping the real and decoy files indistinguishable from the outside.

**Task:** Implement two-password encryption and decryption without leaking which payload was authentic.

**Action:** I separated the real and decoy payloads, gave each its own salt, IV, key, ciphertext, and HMAC, and made `decrypt_file()` try the real payload first before falling back to the decoy payload.

**Result:** The system can now decrypt either the real or decoy content from one `.enc` file while returning `DECRYPT_REAL` or `DECRYPT_DECOY` to preserve caller behavior.

### Challenge 2: Cross-Platform Path Handling in MSYS2/UCRT64

**Situation:** Paths arriving from MSYS2 shells could be formatted as `/g/...` or contain backslashes and quotes, which caused file-open failures.

**Task:** Make the CLI and shredding code accept Windows-style and MSYS-style paths reliably.

**Action:** I added path normalization in `main.c`, plus local normalization inside `crypto/encrypt.c` for duress input paths and cleanup logic in `security/shredder.c`.

**Result:** The program now accepts the shell formats used in practice and can open, encrypt, decrypt, and shred files that live on Windows-mounted drives.

### Challenge 3: Discord Alerts on Windows

**Situation:** Alerts had to be posted from Windows systems where `curl`, temp files, and quoting rules differ from Unix environments.

**Task:** Build a webhook notification path that could run reliably on Windows.

**Action:** I implemented `alerts/discord.c` to write a JSON payload to `C:\msys64\tmp`, generate a curl config file, and call `curl.exe` using the configured webhook URL.

**Result:** The project can send Discord notifications for failed decrypt attempts, lockout events, and duress-password usage.

### Challenge 4: Avoiding Timing Attacks in HMAC Comparison

**Situation:** A naive byte-by-byte comparison can leak partial-match information through timing.

**Task:** Compare HMAC values without short-circuiting on the first mismatch.

**Action:** I implemented `integrity_verify()` with a full-length XOR accumulation loop using a `volatile` accumulator.

**Result:** HMAC comparisons are now constant-time at the algorithmic level, reducing timing leakage during verification.

### Challenge 5: Streaming Large Files Safely

**Situation:** The system needed to encrypt and decrypt multi-hundred-megabyte files without loading them into memory.

**Task:** Process large files efficiently and report progress without integer overflow.

**Action:** I used 65 KB chunked reads/writes, added `long long` progress counters, and used `_filelengthi64()` on Windows to obtain accurate file sizes.

**Result:** The system can process large files with stable memory usage and accurate progress reporting.

## 11. Testing & Verification

### Unit Tests

- `crypto/kdf.c`: Verify key length, salt handling, and failure behavior on invalid input.
- `crypto/integrity.c`: Test `integrity_verify()` with matching and mismatching HMACs.
- `vault/vault.c`: Test header write/read round-trips and invalid header rejection.
- `security/lockout.c`: Test failure counting, lockout threshold, and reset behavior.
- `security/shredder.c`: Test path cleanup and deletion on small test files.
- `utils/audit.c`: Verify that audit lines are written with the expected format.
- `alerts/discord.c`: Test payload generation and environment-variable override.

### Integration Tests

- Full encrypt → verify → decrypt round-trip on a small file.
- Duress encrypt/decrypt round-trip with both real and decoy passwords.
- Folder encryption/decryption with archive creation and extraction.
- Intentional failed decrypt attempts to verify `.lock` file behavior and Discord alerts.
- Password-change flow for both standard and duress-mode files.

### Manual Verification Steps

```bash
./encrypt --encrypt test.txt --password StrongPass123!
./encrypt --verify test.txt.enc --password StrongPass123!
./encrypt --decrypt test.txt.enc --password StrongPass123!
```

For Discord alert testing, intentionally fail decrypt attempts until the lockout threshold is reached and confirm the webhook receives the alert.

## 12. Known Limitations & Future Improvements

- Upgrade from AES-256-CBC plus HMAC to **AES-256-GCM** for built-in authenticated encryption.
- Replace PBKDF2 with **Argon2id** for stronger password hashing resistance.
- Add a **GUI or TUI** to simplify duress and archive workflows.
- Consider stronger memory hygiene, such as page locking or password lifetime minimization, to reduce swap exposure.
- Replace raw struct serialization with explicit packed serialization to avoid ABI/padding dependence.
- Add automated tests for webhook and lockout behavior.

## 13. Conclusion

The File Encryption System is a modular C application that combines encryption, authentication, secure deletion, lockout enforcement, audit logging, and Discord alerting into a single workflow. It works well for local file protection, large-file streaming, and coercion-resistant duress mode. Its security posture is solid for an application of this class, especially because it separates responsibilities across focused modules and verifies plaintext with HMAC while keeping large-file processing streaming-based. The main areas for future improvement are modernizing the password derivation and authenticated-encryption design, tightening memory handling, and replacing raw struct serialization with a more explicit file format.
