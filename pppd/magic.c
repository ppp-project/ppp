/*
 * magic.c - PPP Magic Number routines.
 *
 * Copyright (c) 1989 Carnegie Mellon University.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms are permitted
 * provided that the above copyright notice and this paragraph are
 * duplicated in all such forms and that any documentation,
 * advertising materials, and other materials related to such
 * distribution and use acknowledge that the software was developed
 * by Carnegie Mellon University.  The name of the
 * University may not be used to endorse or promote products derived
 * from this software without specific prior written permission.
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND WITHOUT ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, WITHOUT LIMITATION, THE IMPLIED
 * WARRANTIES OF MERCHANTIBILITY AND FITNESS FOR A PARTICULAR PURPOSE.
 */

#ifndef lint
static char rcsid[] = "$Id: magic.c,v 1.3 1994/09/21 06:47:37 paulus Exp $";
#endif

#include <stdio.h>
#include <sys/types.h>
#include <sys/time.h>

#include "pppd.h"
#include "magic.h"

static u_int32_t next;		/* Next value to return */

extern u_int32_t gethostid __P((void));
extern long random __P((void));
extern void srandom __P((int));


/*
 * magic_init - Initialize the magic number generator.
 *
 * Computes first magic number and seed for random number generator.
 * Attempts to compute a random number seed which will not repeat.
 * The current method uses the current hostid and current time.
 */
void magic_init()
{
    struct timeval tv;

    next = gethostid();
    if (gettimeofday(&tv, NULL)) {
	perror("gettimeofday");
	exit(1);
    }
    next ^= (u_int32_t) tv.tv_sec ^ (u_int32_t) tv.tv_usec;

    srandom((int) next);
}


/*
 * magic - Returns the next magic number.
 */
u_int32_t magic()
{
    u_int32_t m;

    m = next;
    next = (u_int32_t) random();
    return (m);
}
