#ifndef AUDIT_H
#define AUDIT_H

typedef enum {
    AUDIT_ENCRYPT,
    AUDIT_ENCRYPT_FAILED_OPEN_INPUT,
    AUDIT_ENCRYPT_FAILED_OPEN_OUTPUT,
    AUDIT_ENCRYPT_FAILED_RANDOM,
    AUDIT_ENCRYPT_FAILED_HEADER,
    AUDIT_ENCRYPT_FAILED_KDF,
    AUDIT_ENCRYPT_FAILED_MEMORY,
    AUDIT_DECRYPT,
    AUDIT_SHRED,
    AUDIT_DECRYPT_FAILED,
    AUDIT_LOCKED,
    AUDIT_VERIFY,
    AUDIT_CHANGE_PASSWORD
} AuditEvent;

/* Appends one line to audit.log in the current directory.
 * Format: [YYYY-MM-DD HH:MM:SS] EVENT filename SUCCESS/FAILURE */
void audit_log(AuditEvent event, const char *filename, int success);

/* Prints the entire audit log to stdout. */
void audit_print(void);

#endif
