/* SPDX-License-Identifier: BSD-3-Clause */
/* Exercise the real random-source selection code with scripted OS results. */
#include "config.h"
#ifdef TEST_NO_RANDOM_H
#undef HAVE_SYS_RANDOM_H
#endif
#undef NDEBUG
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#ifdef HAVE_SYS_RANDOM_H
#include <sys/random.h>
#endif
#ifdef HAVE_SYS_SYSCALL_H
#include <sys/syscall.h>
#endif
#include "pppd-private.h"
#undef HAVE_CONFIG_H

struct result { int count; int err; };
static struct result get_results[8], read_results[8];
static int get_count, read_count, opens, closes, weak_calls, warnings, errors;
static int syscall_count;
static int open_errno, open_eintr;

static ssize_t
next_result(struct result *results, int *index, void *buf, size_t len,
            unsigned char value)
{
    struct result r;
    assert(*index < 8);
    r = results[(*index)++];
    errno = r.err;
    if (r.count > 0) {
        assert((size_t)r.count <= len);
        memset(buf, value, r.count);
    }
    return r.count;
}

static ssize_t
test_getrandom(void *buf, size_t len, unsigned int flags)
{
#ifdef GRND_NONBLOCK
    assert(flags == GRND_NONBLOCK);
#elif defined(__linux__)
    assert(flags == 0x0001); /* Linux syscall ABI without the libc header. */
#else
    assert(0); /* This platform will exercise the device fallback instead. */
#endif
    return next_result(get_results, &get_count, buf, len, 0xa5);
}

static long
test_syscall(long number, void *buf, size_t len, unsigned int flags)
{
#ifdef SYS_getrandom
    assert(number == SYS_getrandom);
#else
    assert(0);
#endif
    ++syscall_count;
    return test_getrandom(buf, len, flags);
}

static int
test_open(const char *path, int flags)
{
    int expected_flags = O_RDONLY | O_NONBLOCK;

    assert(strcmp(path, "/dev/urandom") == 0);
#ifdef O_CLOEXEC
    expected_flags |= O_CLOEXEC;
#endif
    assert(flags == expected_flags);
    ++opens;
    if (open_eintr) {
        open_eintr = 0;
        errno = EINTR;
        return -1;
    }
    errno = open_errno;
    return open_errno ? -1 : 42;
}

static ssize_t
test_read(int fd, void *buf, size_t len)
{
    assert(fd == 42);
    return next_result(read_results, &read_count, buf, len, 0xb6);
}

static int
test_close(int fd)
{
    assert(fd == 42);
    ++closes;
    errno = EBADF; /* Cleanup must preserve the original read error. */
    return 0;
}

void warn(const char *fmt, ...) { ++warnings; }
void error(const char *fmt, ...) { ++errors; }
void random_bytes(unsigned char *buf, int len)
{
    ++weak_calls;
    memset(buf, 0x5a, len);
}

#ifdef TEST_NO_GETRANDOM
#undef HAVE_GETRANDOM
#undef HAVE_SYS_RANDOM_H
#undef HAVE_SYS_SYSCALL_H
#undef SYS_getrandom
#elif defined(TEST_RAW_GETRANDOM)
#undef HAVE_GETRANDOM
#endif

#define getrandom test_getrandom
#define syscall test_syscall
#define open test_open
#define read test_read
#define close test_close
#include "auth-random.c"
#undef getrandom
#undef syscall
#undef open
#undef read
#undef close

static void
reset(void)
{
    memset(get_results, 0, sizeof(get_results));
    memset(read_results, 0, sizeof(read_results));
    get_count = read_count = opens = closes = weak_calls = warnings = errors = 0;
    syscall_count = 0;
    open_errno = open_eintr = 0;
    allow_insecure_random = 0;
}

static void
expect_bytes(unsigned char *buf, int len, unsigned char value)
{
    int i;
    for (i = 0; i < len; ++i)
        assert(buf[i] == value);
}

static void
use_device(void)
{
    reset();
    get_results[0] = (struct result){ -1, ENOSYS };
}

int
main(void)
{
    unsigned char buf[300];

    reset();
    assert(auth_random_bytes(NULL, 0));
    assert(!auth_random_bytes(NULL, 1) && errno == EINVAL);
    assert(!auth_random_bytes(buf, -1) && errno == EINVAL);
    assert(get_count == 0 && opens == 0 && weak_calls == 0);

#ifdef auth_getrandom
    reset();
    get_results[0] = (struct result){ -1, EINTR };
    get_results[1] = (struct result){ 3, 0 };
    get_results[2] = (struct result){ 256, 0 };
    get_results[3] = (struct result){ 41, 0 };
    assert(auth_random_bytes(buf, sizeof(buf)));
    expect_bytes(buf, sizeof(buf), 0xa5);
    assert(get_count == 4 && opens == 0 && weak_calls == 0);
#if defined(TEST_NO_RANDOM_H) && defined(__linux__) && defined(SYS_getrandom)
    /* A libc symbol without its declaring header must not select the wrapper. */
    assert(syscall_count == get_count);
#endif

    /* Keep the prefix from getrandom and fill only the remainder via the device. */
    reset();
    memset(buf, 0xcc, sizeof(buf));
    get_results[0] = (struct result){ 3, 0 };
    get_results[1] = (struct result){ -1, ENOSYS };
    read_results[0] = (struct result){ 256, 0 };
    read_results[1] = (struct result){ 41, 0 };
    assert(auth_random_bytes(buf, sizeof(buf)));
    expect_bytes(buf, 3, 0xa5);
    expect_bytes(buf + 3, sizeof(buf) - 3, 0xb6);
    assert(get_count == 2 && read_count == 2 && opens == 1 && closes == 1);
    assert(weak_calls == 0 && warnings == 0 && errors == 0);

    /* Even after partial success, EAGAIN must never reach /dev/urandom. */
    reset();
    get_results[0] = (struct result){ 3, 0 };
    get_results[1] = (struct result){ -1, EAGAIN };
    memset(buf, 0xcc, sizeof(buf));
    assert(!auth_random_bytes(buf, sizeof(buf)) && errno == EAGAIN);
    expect_bytes(buf, sizeof(buf), 0);
    assert(opens == 0 && weak_calls == 0 && errors == 1);

    /* Permission errors are not evidence that the API is absent. */
    reset();
    get_results[0] = (struct result){ -1, EPERM };
    assert(!auth_random_bytes(buf, sizeof(buf)) && errno == EPERM);
    assert(opens == 0 && weak_calls == 0);

    reset();
    assert(!auth_random_bytes(buf, sizeof(buf)) && errno == EIO);
    assert(get_count == 1 && opens == 0);

    /* Solaris also documents zero with errno set on failure. */
    reset();
    get_results[0] = (struct result){ 0, EAGAIN };
    assert(!auth_random_bytes(buf, sizeof(buf)) && errno == EAGAIN);
    assert(get_count == 1 && opens == 0);

    reset();
    allow_insecure_random = 1;
    get_results[0] = (struct result){ 3, 0 };
    get_results[1] = (struct result){ -1, EAGAIN };
    assert(auth_random_bytes(buf, sizeof(buf)));
    expect_bytes(buf, sizeof(buf), 0x5a);
    assert(opens == 0 && weak_calls == 1 && warnings == 1);

    /* Enabling the exception must not force use of the weak generator. */
    reset();
    allow_insecure_random = 1;
    get_results[0] = (struct result){ 16, 0 };
    assert(auth_random_bytes(buf, 16));
    assert(weak_calls == 0 && warnings == 0);
#endif

    use_device();
    open_eintr = 1;
    read_results[0] = (struct result){ -1, EINTR };
    read_results[1] = (struct result){ 3, 0 };
    read_results[2] = (struct result){ 256, 0 };
    read_results[3] = (struct result){ 41, 0 };
    assert(auth_random_bytes(buf, sizeof(buf)));
    expect_bytes(buf, sizeof(buf), 0xb6);
    assert(opens == 2 && closes == 1 && read_count == 4 && weak_calls == 0);

    use_device();
    open_errno = ENOENT;
    assert(!auth_random_bytes(buf, sizeof(buf)) && errno == ENOENT);
    assert(closes == 0 && read_count == 0 && weak_calls == 0);

    use_device();
    open_errno = EACCES;
    assert(!auth_random_bytes(buf, sizeof(buf)) && errno == EACCES);
    assert(closes == 0 && weak_calls == 0);

    use_device();
    read_results[0] = (struct result){ 3, 0 };
    read_results[1] = (struct result){ -1, EAGAIN };
    assert(!auth_random_bytes(buf, sizeof(buf)) && errno == EAGAIN);
    expect_bytes(buf, sizeof(buf), 0);
    assert(closes == 1 && weak_calls == 0);

    use_device();
    read_results[0] = (struct result){ 3, 0 };
    /* A zero-byte read must terminate, not spin or accept partial data. */
    assert(!auth_random_bytes(buf, sizeof(buf)) && errno == EIO);
    expect_bytes(buf, sizeof(buf), 0);
    assert(closes == 1 && read_count == 2);

    use_device();
    open_errno = ENOENT;
    allow_insecure_random = 1;
    assert(auth_random_bytes(buf, sizeof(buf)));
    expect_bytes(buf, sizeof(buf), 0x5a);
    assert(weak_calls == 1 && warnings == 1 && errors == 0);

    use_device();
    allow_insecure_random = 1;
    read_results[0] = (struct result){ 16, 0 };
    assert(auth_random_bytes(buf, 16));
    assert(weak_calls == 0 && warnings == 0);

    puts("Authentication random-source tests passed");
    return 0;
}
