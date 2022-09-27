/*
 * options.h - Options for pppd
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

#ifndef PPP_OPTIONS_H
#define PPP_OPTIONS_H

enum opt_type {
	o_special_noarg = 0,
	o_special = 1,
	o_bool,
	o_int,
	o_uint32,
	o_string,
	o_wild
};

struct option {
	char	*name;		/* name of the option */
	enum opt_type type;
	void	*addr;
	char	*description;
	unsigned int flags;
	void	*addr2;
	int	upper_limit;
	int	lower_limit;
	const char *source;
	short int priority;
	short int winner;
};

typedef struct option option_t;

/* Values for flags */
#define OPT_VALUE	0xff	/* mask for presupplied value */
#define OPT_HEX		0x100	/* int option is in hex */
#define OPT_NOARG	0x200	/* option doesn't take argument */
#define OPT_OR		0x400	/* for u32, OR in argument to value */
#define OPT_INC		0x400	/* for o_int, increment value */
#define OPT_A2OR	0x800	/* for o_bool, OR arg to *(u_char *)addr2 */
#define OPT_PRIV	0x1000	/* privileged option */
#define OPT_STATIC	0x2000	/* string option goes into static array */
#define OPT_NOINCR	0x2000	/* for o_int, value mustn't be increased */
#define OPT_LLIMIT	0x4000	/* check value against lower limit */
#define OPT_ULIMIT	0x8000	/* check value against upper limit */
#define OPT_LIMITS	(OPT_LLIMIT|OPT_ULIMIT)
#define OPT_ZEROOK	0x10000	/* 0 value is OK even if not within limits */
#define OPT_HIDE	0x10000	/* for o_string, print value as ?????? */
#define OPT_A2LIST	0x20000 /* for o_special, keep list of values */
#define OPT_A2CLRB	0x20000 /* o_bool, clr val bits in *(u_char *)addr2 */
#define OPT_ZEROINF	0x40000	/* with OPT_NOINCR, 0 == infinity */
#define OPT_PRIO	0x80000	/* process option priorities for this option */
#define OPT_PRIOSUB	0x100000 /* subsidiary member of priority group */
#define OPT_ALIAS	0x200000 /* option is alias for previous option */
#define OPT_A2COPY	0x400000 /* addr2 -> second location to rcv value */
#define OPT_ENABLE	0x800000 /* use *addr2 as enable for option */
#define OPT_A2CLR	0x1000000 /* clear *(bool *)addr2 */
#define OPT_PRIVFIX	0x2000000 /* user can't override if set by root */
#define OPT_INITONLY	0x4000000 /* option can only be set in init phase */
#define OPT_DEVEQUIV	0x8000000 /* equiv to device name */
#define OPT_DEVNAM	(OPT_INITONLY | OPT_DEVEQUIV)
#define OPT_A2PRINTER	0x10000000 /* *addr2 printer_func to print option */
#define OPT_A2STRVAL	0x20000000 /* *addr2 points to current string value */
#define OPT_NOPRINT	0x40000000 /* don't print this option at all */

#define OPT_VAL(x)	((x) & OPT_VALUE)

/* Values for priority */
#define OPRIO_DEFAULT   0	/* a default value */
#define OPRIO_CFGFILE   1	/* value from a configuration file */
#define OPRIO_CMDLINE   2	/* value from the command line */
#define OPRIO_SECFILE   3	/* value from options in a secrets file */
#define OPRIO_ROOT      100	/* added to priority if OPT_PRIVFIX && root */

extern char *current_option;    /* the name of the option being parsed */
extern int  privileged_option;  /* set iff the current option came from root */
extern char *option_source;     /* string saying where the option came from */
extern int  option_priority;    /* priority of current options */

/* Add additional supported options by e.g. plug-in */
void add_options(struct option *);

/* Parse options from an options file */
int options_from_file(char *filename, int must_exist, int check_prot,
		       int privileged);
				
/* Print an error message about an option */
void option_error(char *fmt, ...);
				
/* Simplified number_option for decimal ints */
int int_option(char *, int *);

#endif
