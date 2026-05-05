#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <math.h>
#include "utils.h"

void secure_wipe(void *ptr, size_t len) {
    volatile unsigned char *p = (volatile unsigned char *)ptr;
    while (len--) *p++ = 0;
}

// ANSI color codes
#define COLOR_RED     "\x1b[31m"
#define COLOR_YELLOW  "\x1b[33m"
#define COLOR_GREEN   "\x1b[32m"
#define COLOR_CYAN    "\x1b[36m"
#define COLOR_BOLD    "\x1b[1m"
#define COLOR_RESET   "\x1b[0m"

int password_entropy_score(const char *password) {
    if (!password) return 0;

    int len = (int)strlen(password);
    int has_lower = 0, has_upper = 0;
    int has_digit = 0, has_symbol = 0;

    for (int i = 0; i < len; i++) {
        if (islower((unsigned char)password[i]))       has_lower = 1;
        else if (isupper((unsigned char)password[i]))  has_upper = 1;
        else if (isdigit((unsigned char)password[i]))  has_digit = 1;
        else                                           has_symbol = 1;
    }

    // Calculate charset size
    int charset = 0;
    if (has_lower)  charset += 26;
    if (has_upper)  charset += 26;
    if (has_digit)  charset += 10;
    if (has_symbol) charset += 32;

    // Calculate entropy: bits = length * log2(charset)
    double entropy = (charset > 0) ? len * log2((double)charset) : 0;

    // Score 0-4 based on entropy bits
    int score = 0;
    if (entropy >= 28) score = 1;  // Weak
    if (entropy >= 36) score = 2;  // Fair
    if (entropy >= 60) score = 3;  // Strong
    if (entropy >= 80) score = 4;  // Very Strong

    // Labels and colors
    const char *labels[] = {
        "Very Weak", "Weak", "Fair", "Strong", "Very Strong"
    };
    const char *colors[] = {
        COLOR_RED, COLOR_RED, COLOR_YELLOW, COLOR_GREEN, COLOR_GREEN
    };

    // Build visual bar (10 blocks)
    int filled = (score * 10) / 4;
    char bar[32] = {0};
    for (int i = 0; i < 10; i++) {
       strcat(bar, i < filled ? "#" : "-");
    }

    // Print strength display
    printf("\n");
    printf(COLOR_BOLD "[*] Password Strength\n" COLOR_RESET);
    printf("    Strength : %s%s%s\n", colors[score], labels[score], COLOR_RESET);
    printf("    Entropy  : %s%.1f bits%s\n", colors[score], entropy, COLOR_RESET);
    printf("    Progress : %s[%s]%s\n", colors[score], bar, COLOR_RESET);

    // Warnings
    int warned = 0;
    if (len < 8) {
        printf(COLOR_RED "    ! Too short (minimum 8 characters)\n" COLOR_RESET);
        warned = 1;
    }
    if (!has_upper) {
        printf(COLOR_YELLOW "    ! Add uppercase letters for better strength\n" COLOR_RESET);
        warned = 1;
    }
    if (!has_digit) {
        printf(COLOR_YELLOW "    ! Add numbers for better strength\n" COLOR_RESET);
        warned = 1;
    }
    if (!has_symbol) {
        printf(COLOR_YELLOW "    ! Add symbols (!@#$) for better strength\n" COLOR_RESET);
        warned = 1;
    }

    // Common weak password check
    const char *weak_passwords[] = {
        "password", "123456", "qwerty", "abc123",
        "letmein", "admin", "welcome", "monkey", NULL
    };
    for (int i = 0; weak_passwords[i] != NULL; i++) {
        if (strcmp(password, weak_passwords[i]) == 0) {
            printf(COLOR_RED "    ! This is a commonly used password!\n" COLOR_RESET);
            warned = 1;
            break;
        }
    }

    if (!warned) {
        printf(COLOR_GREEN "    [OK] Good password!\n" COLOR_RESET);
    }
    printf("\n");

    return score;
}
