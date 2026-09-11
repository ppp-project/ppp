/*
 * Randomness for authentication challenges.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>
#ifdef HAVE_SYS_RANDOM_H
#include <sys/random.h>
#endif
#if defined(__linux__) && defined(HAVE_SYS_SYSCALL_H)
#include <sys/syscall.h>
#endif

#include "pppd-private.h"
#include "auth-random.h"
#include "magic.h"

/* Use OS interfaces with explicit error returns. arc4random_buf() has no
 * recoverable error result or nonblocking flag, so it cannot implement our
 * policy of failing authentication when randomness is unavailable.
 */
/* Linux kernels can provide getrandom even when libc has no wrapper. */
#if defined(__linux__) && defined(SYS_getrandom)
#ifndef GRND_NONBLOCK
#define GRND_NONBLOCK 0x0001
#endif
#define auth_getrandom(buf, len) syscall(SYS_getrandom, buf, len, GRND_NONBLOCK)
#endif
#if defined(HAVE_GETRANDOM) && defined(HAVE_SYS_RANDOM_H) && defined(GRND_NONBLOCK)
#undef auth_getrandom
#define auth_getrandom(buf, len) getrandom(buf, len, GRND_NONBLOCK)
#endif

#ifndef O_CLOEXEC
#define O_CLOEXEC 0
#endif

bool allow_insecure_random = false;

/* No weak fallback here: errno describes why the OS source failed. */
static int
secure_random_bytes(unsigned char *buf, int len)
{
    int fd, saved_errno;
    ssize_t n;

#ifdef auth_getrandom
    while (len > 0) {
        /* Small requests also accommodate platforms with per-call limits. */
        errno = 0;
        n = auth_getrandom(buf, len > 256 ? 256 : len);
        if (n > 0) {
            buf += n;
            len -= n;
            continue;
        }
        if (errno == EINTR)
            continue;
        if (errno == ENOSYS)
            break;
        if (n == 0 && errno == 0)
            errno = EIO;
        /* In particular, do not bypass RNG initialization after EAGAIN. */
        return 0;
    }
    if (len == 0)
        return 1;
#endif

    /* Portable fallback. Older Linux kernels do not report RNG readiness
     * through this device; its early-boot limitation is documented in pppd.8.
     */
    do {
        fd = open("/dev/urandom", O_RDONLY | O_NONBLOCK | O_CLOEXEC);
    } while (fd < 0 && errno == EINTR);
    if (fd < 0)
        return 0;

    while (len > 0) {
        n = read(fd, buf, len > 256 ? 256 : len);
        if (n > 0) {
            buf += n;
            len -= n;
        } else if (n < 0 && errno == EINTR) {
            continue;
        } else {
            saved_errno = n == 0 ? EIO : errno;
            close(fd);
            errno = saved_errno;
            return 0;
        }
    }
    close(fd);
    return 1;
}

int
auth_random_bytes(unsigned char *buf, int len)
{
    int saved_errno;

    if (len < 0 || (buf == NULL && len != 0)) {
        errno = EINVAL;
        return 0;
    }
    if (len == 0 || secure_random_bytes(buf, len))
        return 1;

    saved_errno = errno;
    if (allow_insecure_random) {
        warn("Secure authentication randomness unavailable (%s); using insecure PRNG",
             strerror(saved_errno));
        /* Replace the entire buffer, including any partial OS result. */
        random_bytes(buf, len);
        return 1;
    }

    memset(buf, 0, len);
    error("Cannot obtain secure authentication randomness: %s",
          strerror(saved_errno));
    errno = saved_errno;
    return 0;
}
