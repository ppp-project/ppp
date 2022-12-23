/*
 * multilink.h - Defines for multilink support in pppd.
 *
 * Copyright (c) 1984-2000 Carnegie Mellon University. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * 3. The name "Carnegie Mellon University" must not be used to
 *    endorse or promote products derived from this software without
 *    prior written permission. For permission or any legal
 *    details, please contact
 *      Office of Technology Transfer
 *      Carnegie Mellon University
 *      5000 Forbes Avenue
 *      Pittsburgh, PA  15213-3890
 *      (412) 268-4387, fax: (412) 268-7395
 *      tech-transfer@andrew.cmu.edu
 *
 * 4. Redistributions of any form whatsoever must retain the following
 *    acknowledgment:
 *    "This product includes software developed by Computing Services
 *     at Carnegie Mellon University (http://www.cmu.edu/computing/)."
 *
 * CARNEGIE MELLON UNIVERSITY DISCLAIMS ALL WARRANTIES WITH REGARD TO
 * THIS SOFTWARE, INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
 * AND FITNESS, IN NO EVENT SHALL CARNEGIE MELLON UNIVERSITY BE LIABLE
 * FOR ANY SPECIAL, INDIRECT OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN
 * AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING
 * OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#ifndef PPP_MULTILINK_H
#define PPP_MULTILINK_H

#include "pppdconf.h"

/*
 * values for epdisc.class
 */
#define EPD_NULL        0	/* null discriminator, no data */
#define EPD_LOCAL       1
#define EPD_IP          2
#define EPD_MAC         3
#define EPD_MAGIC       4
#define EPD_PHONENUM    5

struct epdisc;

#ifdef PPP_WITH_MULTILINK

/*
 * Check multilink-related options
 */
void mp_check_options(void);

/*
 * Join our link to an appropriate bundle
 */
int mp_join_bundle(void);

/*
 * Disconnected our link from the bundle
 */
void mp_exit_bundle(void);

/*
 * Multipoint bundle terminated
 */
void mp_bundle_terminated(void);

/*
 * Acting as a multilink master
 */
bool mp_master();

/*
 * Was multilink negotiated
 */
bool mp_on();

/*
 * Convert an endpoint discriminator to a string
 */
char *epdisc_to_str(struct epdisc *);

/*
 * Convert a string to an endpoint discriminator
 */
int str_to_epdisc(struct epdisc *, char *);

/*
 * Hook for plugin to hear when an interface joins a multilink bundle
 */
typedef void (multilink_join_hook_fn)(void);
extern multilink_join_hook_fn *multilink_join_hook;

#endif // PPP_WITH_MULTILINK
#endif // PPP_MULTILINK_H
