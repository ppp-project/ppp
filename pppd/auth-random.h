/* SPDX-License-Identifier: BSD-3-Clause */
/* Randomness for authentication challenges. */
#ifndef PPP_AUTH_RANDOM_H
#define PPP_AUTH_RANDOM_H

#include <stdbool.h>

extern bool allow_insecure_random;

/* Return 1 only when all bytes have been filled; on failure return 0. */
int auth_random_bytes(unsigned char *buf, int len);

#endif /* PPP_AUTH_RANDOM_H */
