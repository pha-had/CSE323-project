#ifndef DISCORD_H
#define DISCORD_H

// Sends a Discord notification via webhook
// Returns 1 on success, 0 on failure
int discord_alert(const char *title, const char *filepath, int attempts);

// Sends a Discord notification when the vault becomes locked
// Returns 1 on success, 0 on failure
int discord_vault_locked_alert(const char *filepath);

// Sends a Discord notification when a duress password decrypts the file
// Returns 1 on success, 0 on failure
int discord_duress_password_alert(const char *filepath);

#endif
