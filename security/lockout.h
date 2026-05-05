#ifndef LOCKOUT_H
#define LOCKOUT_H

#define MAX_ATTEMPTS 5

/* Returns 1 if the vault is currently locked, 0 if not.
 * Lock file is stored as <vault_path>.lock */
int lockout_is_locked(const char *vault_path);

/* Records a failed attempt. Locks vault after MAX_ATTEMPTS.
 * Returns the number of attempts so far. */
int lockout_record_failure(const char *vault_path);

/* Clears the lock file on successful decrypt */
void lockout_reset(const char *vault_path);

#endif
