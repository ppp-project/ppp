/*
 * $Id: strerror.c,v 1.2 2002/02/27 15:51:20 dfs Exp $
 *
 * Copyright (C) 1996 Lars Fenneberg and Christian Graefe
 *
 * This file is provided under the terms and conditions of the GNU general
 * public license, version 2 or any later version, incorporated herein by
 * reference.
 *
 */

#include "config.h"
#include "includes.h"

/*
 * if we're missing strerror, these are mostly not defined either
 */
extern int sys_nerr;
extern char *sys_errlist[];

/*
 * Function: strerror
 *
 * Purpose:  implements strerror for systems which lack it. if these
 *			 systems even lack sys_errlist, you loose...
 *
 */


char *strerror(int err)
{
	static char buf[32];

	if (err >= 0 && err < sys_nerr)
		return sys_errlist[err];
	else {
		sprintf(buf, "unknown error: %d", errno);
		return buf;
	}
}
