/* SPDX-License-Identifier: BSD-3-Clause */
/* Link the daemon with its entry point renamed; exercise its real options. */
#include "config.h"
#include "pppd-private.h"
#include "auth-random.h"
#undef NDEBUG
#include <assert.h>
#include <string.h>

#undef main
int main(void)
{
    char name[] = "allow-insecure-random";
    char *args[] = { name };
    struct wordlist word = { NULL, name };

    progname = "utest_auth_options";
    assert(!allow_insecure_random);

    /* Peer-specific options from an untrusted secrets entry cannot opt out. */
    assert(!options_from_list(&word, 0));
    assert(!allow_insecure_random);

    privileged = 0;
    assert(!parse_args(1, args));
    assert(!allow_insecure_random);

    privileged = 1;
    assert(parse_args(1, args));
    assert(allow_insecure_random);

    /* Privilege must still be checked after an earlier privileged setting. */
    privileged = 0;
    assert(!parse_args(1, args));
    assert(allow_insecure_random);

    puts("Authentication random option privilege tests passed");
    return 0;
}
