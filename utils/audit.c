#include <stdio.h>
#include <time.h>
#include "audit.h"

#define LOG_FILE "audit.log"

static const char *event_name(AuditEvent event) {
    switch (event) {
        case AUDIT_ENCRYPT: return "ENCRYPT";
        case AUDIT_ENCRYPT_FAILED_OPEN_INPUT: return "ENCRYPT_FAIL_OPEN_INPUT";
        case AUDIT_ENCRYPT_FAILED_OPEN_OUTPUT: return "ENCRYPT_FAIL_OPEN_OUTPUT";
        case AUDIT_ENCRYPT_FAILED_RANDOM: return "ENCRYPT_FAIL_RANDOM";
        case AUDIT_ENCRYPT_FAILED_HEADER: return "ENCRYPT_FAIL_HEADER";
        case AUDIT_ENCRYPT_FAILED_KDF: return "ENCRYPT_FAIL_KDF";
        case AUDIT_ENCRYPT_FAILED_MEMORY: return "ENCRYPT_FAIL_MEMORY";
        case AUDIT_DECRYPT: return "DECRYPT";
        case AUDIT_SHRED: return "SHRED";
        case AUDIT_DECRYPT_FAILED: return "DECRYPT_FAILED";
        case AUDIT_LOCKED: return "LOCKED";
        case AUDIT_VERIFY: return "VERIFY";
        case AUDIT_CHANGE_PASSWORD: return "CHANGE_PASSWORD";
        default: return "UNKNOWN";
    }
}

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

void audit_print(void) {
    FILE *f = fopen(LOG_FILE, "r");
    char line[256];

    if (!f) {
        printf("[*] No audit log found.\n");
        return;
    }

    printf("\n=== Audit Log ===\n");
    while (fgets(line, sizeof(line), f)) {
        char timestamp[20];
        char event[64];
        char filename[128];
        char status[16];

        if (sscanf(line, "[%19[^]]] %63s %127s %15s", timestamp, event, filename, status) == 4) {
            printf("[%s] %-24.24s %-40.40s %s\n", timestamp, event, filename, status);
        } else {
            printf("%s", line);
        }
    }
    printf("=================\n\n");

    fclose(f);
}
