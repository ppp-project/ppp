/*
 * $Id: log.c,v 1.2 2002/02/27 15:51:20 dfs Exp $
 *
 * Copyright (C) 1995,1996,1997 Lars Fenneberg
 *
 * See the file COPYRIGHT for the respective terms and conditions.
 * If the file is missing contact me at lf@elemental.net
 * and I'll send you a copy.
 *
 */

#include <config.h>
#include <includes.h>
#include <radiusclient.h>

/*
 * Function: rc_openlog
 *
 * Purpose: open log
 *
 * Arguments: identification string
 *
 * Returns: nothing
 *
 */

void rc_openlog(char *ident)
{
	openlog(ident, LOG_PID, RC_LOG_FACILITY);
}

/*
 * Function: rc_log
 *
 * Purpose: log information
 *
 * Arguments: priority (just like syslog), rest like printf
 *
 * Returns: nothing
 *
 */

void rc_log(int prio, const char *format, ...)
{
	char buff[1024];
	va_list ap;

	va_start(ap,format);
    vsnprintf(buff, sizeof(buff), format, ap);
    va_end(ap);

	syslog(prio, "%s", buff);
}
