# File Encryption System

A secure file encryption tool written in C that provides AES-256 encryption with HMAC integrity verification, password-based key derivation, and secure file shredding.

## Features

- **AES-256 Encryption** — Military-grade symmetric encryption
- **HMAC-SHA256 Integrity** — Verify file hasn't been tampered with
- **Password-Based Key Derivation** — Secure key generation from passwords
- **Secure Shredding** — Permanently delete files with overwriting
- **Live Progress Bars** — Show percent, speed, and bytes completed during encrypt/decrypt operations
- **Audit Logging** — Track all encryption/decryption/shredding operations
- **Integrity Verification** — Verify encrypted files without decrypting them
- **Account Lockout Protection** — Prevent brute-force password attacks
- **Duress/Decoy Passwords** — Hidden file mode for coercion resistance (dual-password system)
- **Discord Webhook Alerts** — Send a webhook notification after failed decrypt attempts

## Build Instructions

### Prerequisites
- GCC compiler
- OpenSSL development libraries (`libssl-dev` / `openssl-devel`)

### Compile

Using Make:
```bash
make
```

This builds the real executable at `bin/encrypt` and also leaves a top-level launcher at `./encrypt` for convenience.

Or directly with GCC:
```bash
gcc main.c crypto/encrypt.c crypto/decrypt.c crypto/integrity.c crypto/kdf.c vault/vault.c security/lockout.c security/shredder.c utils/audit.c utils/utils.c alerts/discord.c -o encrypt -lssl -lcrypto -lm -I. -I./crypto -I./vault -I./security -I./alerts -I./utils
```

### Clean
```bash
make clean
```

## Commands

### Encrypt a File
```bash
./encrypt --encrypt <file> --password <password>
```
Encrypts a single file to `.enc` format. Process:
1. Checks file integrity (SHA-256)
2. Displays password strength with entropy score and visual bar
3. Encrypts using AES-256 with live progress bar (%, speed, bytes done)
4. Securely shreds original file

**Example:**
```bash
./encrypt --encrypt secret.txt --password mypass123
```
Output: `secret.txt.enc` (original securely deleted)

**Windows users:** You can paste paths directly from File Manager, but **quote them if using backslashes**:
```bash
# Option 1: Quote the path (with backslashes)
./encrypt --encrypt "F:\Documents\secret.txt" --password mypass123

# Option 2: Use forward slashes (no quotes needed)
./encrypt --encrypt F:/Documents/secret.txt --password mypass123

# Option 3: Drag and drop from File Manager (auto-handles formatting)
# Type: ./encrypt --encrypt [SPACE]
# Then drag file into terminal
```

**Why quotes are needed:** In bash/MSYS2, backslashes are escape characters. Without quotes, `\` is interpreted by the shell before reaching the program.

### Encrypt a Folder
```bash
./encrypt --encrypt <folder> --password <password>
```
Automatically archives and encrypts a folder. Process:
1. Displays all folder contents for confirmation
2. Creates `.tar.gz` archive
3. Checks archive integrity (SHA-256)
4. Encrypts archive using AES-256
5. Securely shreds the temporary archive
6. Securely shreds the original source folder and all its contents

**Example:**
```bash
./encrypt --encrypt my_media --password mypass123
```
Output: `my_media.tar.gz.enc` (original folder completely removed)

**Windows users:** Quote the path if using backslashes:
```bash
./encrypt --encrypt "F:\recording\my_media" --password mypass123

# Or use forward slashes:
./encrypt --encrypt F:/recording/my_media --password mypass123

# Or drag-and-drop from File Manager (easiest)
```

### Decrypt a File or Archive
```bash
./encrypt --decrypt <file> --password <password>
```
Decrypts an encrypted file. Output filename automatically determined:
- If input ends with `.enc`, removes the extension
- Otherwise, appends `.dec`
- **After a successful decrypt, the encrypted `.enc` input is securely deleted**
- **If output is a `.tar.gz` archive, it is automatically extracted and then cleaned up**

If decryption fails, the program can increment the lockout counter and send a Discord webhook alert for monitoring repeated wrong-password attempts.

**Discord alert configuration:**
- Set `DISCORD_WEBHOOK_URL` to override the built-in webhook URL
- If `DISCORD_WEBHOOK_URL` is not set, the compiled fallback URL is used
- Alert payloads are written to `C:\msys64\tmp\discord_alert.json` before curl sends them

### Verify an Encrypted File
```bash
./encrypt --verify <file> --password <password>
```
Checks the vault header and HMAC to confirm the `.enc` file has not been tampered with.

**Example:**
```bash
./encrypt --verify secret.txt.enc --password MyS3cur3P@ss!
```
Output on success:
```bash
[*] Verifying integrity: secret.txt.enc
[+] Integrity PASSED - file is authentic and untampered
```

### Change Password on Encrypted File
```bash
./encrypt --change-password <file> --password <old_password> --new-password <new_password>
```
Changes the password of an encrypted file without creating plaintext output files.

**Example:**
```bash
./encrypt --change-password secret.txt.enc --password oldpass --new-password newpass
```

For duress-mode files (real + decoy), provide both old/new decoy passwords too:
```bash
./encrypt --change-password secret.txt.enc --password old_real --new-password new_real --decoy-password old_decoy --new-decoy-password new_decoy
```

**Examples:**
```bash
# Decrypt a single file
./encrypt --decrypt document.pdf.enc --password mypass123
# Output: document.pdf

# Decrypt a folder (auto-extracts and cleans up)
./encrypt --decrypt my_photos.tar.gz.enc --password mypass123
# Output: my_photos folder restored to original location
# (temporary archives and the encrypted .enc file are automatically deleted)
```

### Encrypt with Duress Password (Coercion Resistance)
```bash
./encrypt --encrypt <file> --password <real_password> --decoy <decoy_file> --decoy-password <decoy_password>
```

**What is Duress Password Mode?**

Duress mode is a coercion-resistant encryption system designed for situations where an attacker may forcibly demand you decrypt a file. The system encrypts TWO files into a single `.enc` file with TWO different passwords:

1. **Real password** → Decrypts to the actual sensitive file you want to protect
2. **Decoy password** → Decrypts to an innocuous "harmless" file that appears legitimate

If coerced to decrypt, you can provide the **decoy password** and the system will reveal only the harmless file, protecting your real data. The attacker has no way to prove which file is "real" — both are equally valid and complete.

**How It Works Internally:**
- Both files are encrypted separately with their own AES-256 keys, IVs, and salts
- Both encrypted blobs are stored in the same `.enc` file
- The system tries the real password first during decryption
- If the real password fails HMAC verification, it tries the decoy password
- Only ONE password will successfully verify — the user controls which one is revealed

**When to Use:**
- ✓ Working with sensitive data in countries with surveillance or legal coercion
- ✓ Protecting against forced disclosure (border searches, "national security" demands)
- ✓ Creating plausible deniability for encrypted files
- ✓ Journalistic or activist work in repressive regions
- ✗ NOT suitable for casual backup encryption (use regular encryption instead)
- ✗ NOT for cases where the attacker physically examines the decrypted file (content is examined anyway)

**Examples:**

Create duress-protected file:
```bash
# Create a harmless decoy file first
echo "Recipes and restaurant reviews" > recipes.txt

# Encrypt real file with decoy protection
./encrypt --encrypt confidential.pdf --password MyRealPass123 --decoy recipes.txt --decoy-password MyDecoyPass123
# Output: confidential.pdf.enc (contains both encrypted files)
```

Decrypt with real password (normal situation):
```bash
./encrypt --decrypt confidential.pdf.enc --password MyRealPass123
# System displays: "Decrypted: confidential.pdf.enc -> confidential.pdf"
# Output: confidential.pdf (your actual file)
# Prompt: "Shred encrypted file? [y/N]:"
```

Decrypt with decoy password (under coercion):
```bash
./encrypt --decrypt confidential.pdf.enc --password MyDecoyPass123
# System displays: "Decrypted: confidential.pdf.enc -> confidential.pdf"
# Output: confidential.pdf (shows the harmless recipes.txt content instead)
# The .enc file is automatically kept (no deletion prompt)
```

**Alerting behavior:**
- Wrong-password decrypt attempts can trigger a Discord webhook notification before the lockout limit is reached
- The alert includes the file path, timestamp, attempt count, and machine name
- Once the vault is locked, no further alerts are sent until the lock is cleared

**Critical Notes:**
1. **Both passwords are equally secure** — The system cannot prove which is "real"
2. **Decoy file must be plausible** — Use a file that looks like something you'd normally have encrypted (documents, archives, etc.)
3. **Create good decoy content** — Empty files or obviously fake content is suspicious
4. **Practice decryption** — Test both passwords beforehand so you don't accidentally reveal which is which
5. **Entropy matters** — Both passwords should have good entropy (entropy score shown during encryption)
6. **Keep both passwords secure** — Losing either password means one of the files becomes inaccessible
7. **Plausibility theory** — This protects against coercion only if the decoy file is believable as your "actual" data

**Threat Model for Duress:**

This feature protects against:
- ✓ Coerced decryption where attacker cannot independently verify which file is real
- ✓ Border/customs searches demanding encrypted file access
- ✓ Malicious "national security" letter demanding decryption
- ✓ Social engineering or threats demanding you reveal secrets

This feature does NOT protect against:
- ✗ Attacker that physically seizes both the encrypted file AND your decoy file source (they can compare content)
- ✗ Attacker that monitors your computer during decryption (they see which file is produced)
- ✗ Sophisticated forensics that can determine file metadata or creation patterns
- ✗ Attacker with knowledge of your decoy file's content (they can verify if decoy was actually decrypted)
- ✗ Situations where decoy content itself is incriminating or implausible

**Real-World Scenario:**

Alice has confidential documents but lives in a country with strict surveillance. She:
1. Creates a harmless PDF: "Budget_2024.pdf" (actual household budget)
2. Encrypts real file: `./encrypt --encrypt classified.pdf --password RealAlice2024 --decoy Budget_2024.pdf --decoy-password DecoyAlice2024`
3. Result: Only `classified.pdf.enc` exists (1.2 MB)

Later, customs officers demand: "Decrypt that file or we arrest you."

Alice complies by providing the decoy password:
```bash
./encrypt --decrypt classified.pdf.enc --password DecoyAlice2024
# Output: Budget_2024.pdf (household budget: groceries, utilities, rent, etc.)
```

Officers examine the budget PDF. It's mundane and legitimate. They have no technical way to prove another file exists. Alice's classified documents remain protected.

### Securely Shred a File
```bash
./encrypt --shred <file>
```
Permanently deletes a file by overwriting it multiple times with random data before deletion.

**Example:**
```bash
./encrypt --shred sensitive.txt
```

### View Audit Log
```bash
./encrypt --log
```
Displays security audit trail of all encryption, decryption, and shredding operations with timestamps.

## Usage Examples

### Encrypt and Decrypt a Single File
```bash
# Encrypt
./encrypt --encrypt document.pdf --password StrongPass123!

# Decrypt
./encrypt --decrypt document.pdf.enc --password StrongPass123!
```

### Encrypt and Decrypt a Folder
```bash
# Encrypt folder (auto-archives and shreds original)
./encrypt --encrypt my_photos --password StrongPass123!
# System will:
# - List all contents in my_photos
# - Ask for confirmation
# - Create my_photos.tar.gz and encrypt it to my_photos.tar.gz.enc
# - Securely delete the temporary archive
# - Securely delete the original my_photos folder
# Result: Only my_photos.tar.gz.enc exists

# Decrypt folder (auto-extracts and cleans up)
./encrypt --decrypt my_photos.tar.gz.enc --password StrongPass123!
# System will:
# - Decrypt to my_photos.tar.gz
# - Automatically extract the archive to original location
# - Securely delete the temporary archive
# - Securely delete the .enc file
# Result: Only my_photos folder with restored contents exists
```

## How It Works

**Encrypt workflow:**
1. ✓ **Integrity Check** — SHA-256 hash computed and verified
2. ✓ **Password Strength** — Entropy calculated using log2(charset) * length; color-coded (Very Weak/Weak/Fair/Strong/Very Strong)
3. ✓ **Encryption** — AES-256-CBC applied with HMAC-SHA256 authentication; live progress bar shows %, speed, bytes done
4. ✓ **Shredding** — Original file/folder securely deleted (multi-pass overwrite)

**Decrypt workflow:**
1. ✓ **Verification** — HMAC checked; file integrity confirmed
2. ✓ **Decryption** — AES-256-CBC decrypted to plaintext
3. ✓ **Auto-Extract** — If `.tar.gz`, automatically extracts to restore original folder structure
4. ✓ **Cleanup** — The encrypted `.enc` file is securely deleted after success; for folders, the temporary archive is also deleted

## File Structure

```
main.c               — Command-line interface and argument parsing
crypto/encrypt.c/h   — AES-256 encryption routines
crypto/decrypt.c/h   — AES-256 decryption routines
crypto/kdf.c/h       — Key derivation from passwords (PBKDF2)
crypto/integrity.c/h — HMAC-SHA256 integrity verification
security/shredder.c/h — Secure file deletion (multi-pass overwriting)
security/lockout.c/h — Account lockout protection
vault/vault.c/h      — Vault management for encrypted storage
utils/audit.c/h      — Operation logging and audit trail
utils/utils.c/h      — Utility functions (logging, encoding)
alerts/discord.c/h   — Discord webhook alerts
Makefile             — Build automation
```

## Technical Details

### Encrypted File Header Structure
Every encrypted file contains:
```
[Magic (4 bytes: "FENC")] [Version (1 byte)] [Duress Flag (1 byte)] [Salt (16 bytes)] [IV (16 bytes)] [Original Size (8 bytes)] [Decoy Salt (16 bytes)] [Decoy IV (16 bytes)] [Decoy Size (8 bytes)] [Real HMAC (32 bytes)] [Real Ciphertext] [Decoy HMAC (32 bytes)] [Decoy Ciphertext]
```

**Standard encryption (Duress Flag = 0):**
```
[Magic] [Version] [Duress=0] [Salt] [IV] [Size] [zeros...] [zeros...] [zeros...] [HMAC] [Ciphertext]
```

**Duress encryption (Duress Flag = 1):**
```
[Magic] [Version] [Duress=1] [Salt] [IV] [Real_Size] [Decoy_Salt] [Decoy_IV] [Decoy_Size] [Real_HMAC] [Real_Ciphertext] [Decoy_HMAC] [Decoy_Ciphertext]
```

- **Magic**: File signature for format validation
- **Version**: Format versioning for future compatibility
- **Duress Flag**: 0 = standard encryption, 1 = duress mode with two passwords
- **Salt / Decoy Salt**: Random per-file/per-password for PBKDF2 key derivation
- **IV / Decoy IV**: Initialization vector for each AES-CBC mode
- **Original Size / Decoy Size**: Plaintext sizes for exact decryption
- **Real HMAC / Decoy HMAC**: Authentication tags (one for each password)

### Encryption Algorithm Details
- **Cipher**: AES-256 in CBC mode
- **Key Derivation**: PBKDF2-SHA256 with 10,000 iterations
- **Authentication**: HMAC-SHA256 over plaintext
- **Key Size**: 256 bits (32 bytes)
- **IV Size**: 128 bits (16 bytes)
- **Salt Size**: 128 bits (16 bytes)

### File Shredding Process
- **Multi-pass Overwriting**: 3-pass algorithm
  1. **Pass 1**: Overwrite with zeros (0x00)
  2. **Pass 2**: Overwrite with ones (0xFF)
  3. **Pass 3**: Overwrite with cryptographically-random bytes
- **Folder Shredding**: Recursively shreds all files, then removes empty directory structure
- **Irreversibility**: After shredding, data recovery is extremely difficult without specialized hardware

## Security & Design

### Threat Model
This system protects against:
- **Passive Attacks**: Confidentiality via AES-256 encryption
- **Tampering**: Integrity verification via HMAC-SHA256
- **Brute-Force Attacks**: Account lockout after 5 failed attempts
- **Data Recovery**: Secure shredding prevents recovery of deleted files
- **Coerced Decryption** (duress mode): Plausible deniability via dual-password system

This system does NOT protect against:
- **Active Key Compromise**: If attacker has encryption key, system is compromised
- **Memory Attacks**: Passwords exist in memory during operation
- **Metadata**: Filenames and timestamps are preserved in archives
- **Denial of Service**: No protection against intentional file corruption
- **Duress Limitations**: Decoy file can be verified by attacker if they have source; physical observation during decryption reveals which file is real

### Account Lockout Mechanism
- Tracks failed password attempts per file in `.lock` file
- Allows 5 failed attempts; the file locks on the 6th failed attempt
- Prevents brute-force password guessing
- Lockout resets after successful decryption

### Why These Algorithms?
- **AES-256**: NIST-approved, military-grade, hardware-accelerated on modern CPUs
- **CBC Mode**: Deterministic, widely audited, suitable for file encryption
- **HMAC-SHA256**: Provides authentication without adding encryption layers
- **PBKDF2**: Industry standard for password-based key derivation, tunable iteration count

## System Information

### Supported Platforms
- **Linux**: Full support with GCC and OpenSSL
- **Windows**: Full support via MSYS2/UCRT64 with automatic path conversion
- **macOS**: Expected to work with Homebrew OpenSSL (untested)

**Windows Path Note:** 
- Paths with backslashes must be **quoted**: `"F:\folder\file"`
- Or use forward slashes: `F:/folder/file` (no quotes needed)
- Or use drag-and-drop from File Manager (easiest method)

This is a bash requirement, not a program limitation. In bash/MSYS2, backslash is an escape character and affects argument parsing.

### Requirements
- **GCC**: 7.0 or newer
- **OpenSSL**: 3.0+ (3.1+ recommended)
- **tar**: GNU tar for folder archiving (pre-installed on most systems)
- **C Math Library**: `-lm` flag during compilation (for password entropy calculation)
- **RAM**: Minimum 512 MB; large file encryption uses streaming (65 KB chunks)

### File Size Limits
- **Single File**: Up to 2 TB (64-bit file size tracking)
- **Encrypted File**: Same as plaintext + ~150 bytes header
- **Archive**: Limited by available disk space (tar format limit is 8 EB)
- **Folder Nesting**: No practical limit (recursively handled)

### Performance Expectations
- **Small Files (<1 MB)**: <100 ms
- **Medium Files (100-500 MB)**: 1-5 seconds
- **Large Files (>1 GB)**: ~100-200 MB/s (varies by CPU, storage speed)
- **Shredding**: Same as encryption speed for file overwriting

### Temporary Files
During operations, these temporary files may exist briefly:
- **Folder Encryption**: `.tar.gz` archive (same size as source folder, deleted after encryption)
- **Folder Decryption**: Temp `.tar.gz` from decryption (deleted after extraction)
- **Lock Files**: `.lock` file tracks failed attempts (cleaned on success)

## Operational Guide

### Troubleshooting

**"Permission denied" error**
- Ensure you have write access to the directory containing the file
- On Windows, check that the folder isn't read-only
- Try running terminal as Administrator

**"HMAC verification failed" error**
- File is corrupted or tampered with
- Encrypted file may have been partially downloaded or corrupted in transit
- Cannot recover original data

**"Account locked" error**
- Too many failed password attempts (5 failed tries)
- Wait 15 minutes before attempting again
- Check that you're using the correct password
- Delete `.lock` file to reset (loses attempt history)

**"Cannot create archive" error (on Windows)**
- tar command not found: Install GNU tar via MSYS2 or WSL
- Path contains unsupported characters: Use only ASCII in folder names
- Insufficient disk space: Free up space equal to source folder size

**Encryption interrupted (power failure, crash)**
- Source file/folder may still exist (not yet shredded)
- Encrypted file may be incomplete and unreadable
- Safely delete the incomplete `.enc` file
- Retry encryption

### Password Recommendations
- **Minimum**: 12 characters for acceptable security
- **Recommended**: 16+ characters with mixed case, numbers, symbols
- **Entropy Target**: 80+ bits ("Very Strong" rating)
- **Examples**:
  - ✓ `MyS3cur3P@ssw0rd!` (Very Strong ~120 bits)
  - ✓ `BlueMoon42#Winter$` (Strong ~110 bits)
  - ✗ `password123` (Weak ~36 bits)
  - ✗ `12345678` (Very Weak ~26 bits)

**Entropy Scoring:**
- Calculated as: `log2(charset_size) × password_length` bits
- Charset size increases with character types: lowercase (26), uppercase (26), digits (10), symbols (32)
- Color-coded feedback: Red (Very Weak), Yellow (Weak), Green (Fair/Strong/Very Strong)
- Warnings shown for: too short, missing uppercase, missing digits, missing symbols, common weak passwords

### Best Practices
1. **Test Recovery**: Always test decryption on a backup before deleting originals
2. **Store Passwords Safely**: Use password manager (KeePass, 1Password, Bitwarden)
3. **Verify Integrity**: Check audit log for successful operations
4. **Monitor Audit Log**: Regularly review `audit.log` for suspicious activity
5. **Keep Backups**: Maintain encrypted backups of critical files
6. **Update OpenSSL**: Keep OpenSSL updated for security patches

## Developer Documentation

### Module Overview

**main.c** — Entry point and CLI orchestration
- Argument parsing and command routing
- Folder detection and listing (`is_directory()`, `list_dir_recursive()`)
- Workflow orchestration (encryption → archive → shred → decrypt → extract)
- User interaction (confirmation prompts)
- Path handling (Windows drive letter conversion)

**crypto/encrypt.c/h** — AES-256 encryption
- Streaming encryption for large files (65 KB chunks)
- HMAC computation during encryption
- Key and IV generation
- Encrypted header creation
- **Key Functions**:
  - `encrypt_file(plaintext_path, password, encrypted_path)` — Standard single-password encryption
  - `encrypt_file_with_duress(real_path, decoy_path, out_path, real_password, decoy_password)` — Dual-password duress mode encryption
  - Both files are encrypted separately with independent salts, IVs, and keys
  - Both ciphertexts stored in single .enc file with separate HMACs for verification

**crypto/decrypt.c/h** — AES-256 decryption
- Encrypted header validation
- Streaming decryption matching chunk size
- HMAC verification pre-decryption
- Auto-extraction for `.tar.gz` files
- **Duress Password Detection**: 
  - Returns status code indicating which password was used
  - `DECRYPT_REAL (1)` — File decrypted with real password or standard encryption
  - `DECRYPT_DECOY (2)` — File decrypted with decoy password (duress mode)
  - `DECRYPT_FAILED (0)` — Decryption failed (wrong password or corrupted file)
- **Key Functions**:
  - `decrypt_file(encrypted_path, password, plaintext_path)` — Main entry point; returns status code
  - `try_decrypt_with_password()` — Helper function for attempting decryption with specific password/salt/IV combo

**kdf.c/h** — Key derivation
- PBKDF2-SHA256 implementation
- Salt generation and storage
- **Key Functions**:
  - `derive_key_from_password()` — Derives 256-bit key from password and salt

**integrity.c/h** — Authentication
- HMAC-SHA256 computation and verification
- Constant-time comparison (timing-attack resistant)
- **Key Functions**:
  - `integrity_verify()` — Verifies HMAC tag
  - `compute_hmac()` — Computes authentication tag

**shredder.c/h** — Secure deletion
- 3-pass file overwriting
- Folder recursion and cleanup
- **Key Functions**:
  - `shred_file()` — Overwrites and deletes single file
  - `shred_directory_recursive()` — Recursively shreds folder

**audit.c/h** — Operation logging
- Timestamp recording
- Event logging (ENCRYPT, DECRYPT, SHRED)
- Success/failure tracking
- **Key Functions**:
  - `audit_log()` — Records operation to audit.log

**security/lockout.c/h** — Brute-force protection
- Attempt tracking per file
- Lockout enforcement
- Automatic reset on success
- **Key Functions**:
  - `lockout_is_locked()` — Determines if file is locked
  - `lockout_record_failure()` — Reads the current count, increments it, and writes the new value
  - `lockout_reset()` — Resets on success

**vault/vault.c/h** — Header management
- Encrypted file header structure
- Magic number validation
- Version checking
- Duress mode support with dual-HMAC storage
- **Key Functions**:
  - `vault_write_header()` — Creates encrypted header (handles duress flag)
  - `vault_read_header()` — Parses header (detects duress flag)
  - `vault_write_hmac()` — Writes first HMAC (for real password)
  - `vault_read_hmac()` — Reads first HMAC at end of file (standard mode) or after real ciphertext (duress mode)
  - `vault_write_decoy_hmac()` — Writes second HMAC (for decoy password, duress mode only)
  - `vault_read_decoy_hmac()` — Reads second HMAC at calculated position after real ciphertext + real HMAC (duress mode only)

**utils/utils.c/h** — Utility functions
- Secure memory handling
- Path manipulation
- Encoding/decoding
- Random number generation

### Adding New Features

**To add a new encryption cipher:**
1. Implement encrypt/decrypt functions in a new `cipher_*.c` file
2. Add version byte to vault header
3. Update `encrypt.c` and `decrypt.c` to branch on version
4. Document in README

**To add progress reporting:**
1. Add callback function to `encrypt_stream_data()` and `decrypt_stream_data()`
2. Report `(bytes_processed / total_bytes) * 100` percentage
3. Call callback after each chunk

**To add encryption modes:**
1. Create `cipher_*.c` with CTR, GCM, or XTS mode implementation
2. Store mode identifier in vault header
3. Update decryption to detect and use correct mode

### Code Style
- **Indentation**: 4 spaces (no tabs)
- **Naming**: `snake_case` for functions, `UPPERCASE` for constants
- **Error Handling**: All system calls checked; errors logged
- **Memory**: Manual allocation/deallocation with explicit cleanup
- **Comments**: Function-level documentation, complex logic explained

## Error Handling

The program provides clear error messages for:
- Missing required arguments
- Invalid file paths
- Password verification failures
- Corruption or tampering detected
- Account lockout due to failed attempts

## Support & Reporting Issues

### Reporting Bugs
If you encounter issues:
1. Check troubleshooting guide above
2. Review audit.log for operation details
3. Verify password and file integrity
4. Test on a different system if possible
5. Include error message and command used

### Known Limitations
- OpenSSL 3.0+ deprecation warnings (functional but non-critical)
- No GUI interface (CLI only)
- No network/cloud integration
- Folder paths with special characters may require quoting

## License

This project is provided as-is for educational and secure file handling purposes.
