#ifndef UTILS_H
#define UTILS_H

#include <stddef.h>
#include <math.h>

/* Overwrites memory before freeing to prevent key/password lingering in RAM */
void secure_wipe(void *ptr, size_t len);

/* Returns a score 0-4 and prints strength label, entropy bits, visual bar
 * 0 = Very Weak, 1 = Weak, 2 = Fair, 3 = Strong, 4 = Very Strong */
int password_entropy_score(const char *password);

#endif
