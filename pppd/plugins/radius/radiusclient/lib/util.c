/*
 * $Id: util.c,v 1.2 2002/02/27 15:51:20 dfs Exp $
 *
 * Copyright (C) 1995,1996,1997 Lars Fenneberg
 *
 * Copyright 1992 Livingston Enterprises, Inc.
 *
 * Copyright 1992,1993, 1994,1995 The Regents of the University of Michigan
 * and Merit Network, Inc. All Rights Reserved
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
 * Function: rc_str2tm
 *
 * Purpose: Turns printable string into correct tm struct entries.
 *
 */

static const char * months[] =
		{
			"Jan", "Feb", "Mar", "Apr", "May", "Jun",
			"Jul", "Aug", "Sep", "Oct", "Nov", "Dec"
		};

void rc_str2tm (char *valstr, struct tm *tm)
{
	int             i;

	/* Get the month */
	for (i = 0; i < 12; i++)
	{
		if (strncmp (months[i], valstr, 3) == 0)
		{
			tm->tm_mon = i;
			i = 13;
		}
	}

	/* Get the Day */
	tm->tm_mday = atoi (&valstr[4]);

	/* Now the year */
	tm->tm_year = atoi (&valstr[7]) - 1900;
}

/*
 * Function: rc_getifname
 *
 * Purpose: get the network interface name associated with this tty
 *
 */

char *rc_getifname(char *tty)
{
#if defined(BSD4_4) || defined(linux)
	static char	name[512];
	int		fd;

	if ((fd = open(tty, O_RDWR|O_NDELAY)) < 0) {
		rc_log(LOG_ERR, "rc_getifname: can't open %s: %s", tty, strerror(errno));
		return NULL;
	}
#endif

#ifdef BSD4_4
	strcpy(name,ttyname(fd));
	if (strlen(name) < 1) {
		rc_log(LOG_ERR, "rc_getifname: can't get attached interface of %s: %s", tty, strerror(errno));
		close(fd);
		return NULL;
	}
#elif linux
	if (ioctl(fd, SIOCGIFNAME, name) < 0) {
		rc_log(LOG_ERR, "rc_getifname: can't ioctl %s: %s", tty, strerror(errno));
		close(fd);
		return NULL;
	}
#else
	return NULL;
#endif

#if defined(BSD4_4) || defined(linux)
	close(fd);
	return name;
#endif
}

/*
 * Function: rc_getstr
 *
 * Purpose: Reads in a string from the user (with or witout echo)
 *
 */

char *rc_getstr (char *prompt, int do_echo)
{
	int             in, out;
	char           *p;
	sigset_t        newset;
	sigset_t        oldset;
	struct termios  term_old, term_new;
	static char     buf[GETSTR_LENGTH];
	int		is_term, flags, old_flags;
	char		c;
	int		flushed = 0;

	in = fileno(stdin);
	out = fileno(stdout);

	(void) sigemptyset (&newset);
	(void) sigaddset (&newset, SIGINT);
	(void) sigaddset (&newset, SIGTSTP);
	(void) sigaddset (&newset, SIGQUIT);

	(void) sigprocmask (SIG_BLOCK, &newset, &oldset);

	if ((is_term = isatty(in)))
	{

		(void) tcgetattr (in, &term_old);
		term_new = term_old;
		if (do_echo)
			term_new.c_lflag |= ECHO;
		else
			term_new.c_lflag &= ~ECHO;

		if (tcsetattr (in, TCSAFLUSH, &term_new) == 0)
			flushed = 1;

	}
	else
	{
		is_term = 0;
		if ((flags = fcntl(in, F_GETFL, 0)) >= 0) {
			old_flags = flags;
			flags |= O_NONBLOCK;

			fcntl(in, F_SETFL, flags);

			while (read(in, &c, 1) > 0)
				/* nothing */;

			fcntl(in, F_SETFL, old_flags);

			flushed = 1;
		}
	}

	write(out, prompt, strlen(prompt));

	/* well, this looks ugly, but it handles the following end of line
	   markers: \r \r\0 \r\n \n \n\r, at least at a second pass */

	p = buf;
	for (;;)
	{
		if (read(in, &c, 1) <= 0)
			return NULL;

		if (!flushed && ((c == '\0') || (c == '\r') || (c == '\n'))) {
			flushed = 1;
			continue;
		}

		if ((c == '\r') || (c == '\n'))
			break;

		flushed = 1;

		if (p < buf + GETSTR_LENGTH)
		{
			if (do_echo && !is_term)
				write(out, &c, 1);
			*p++ = c;
		}
	}

	*p = '\0';

	if (!do_echo || !is_term) write(out, "\r\n", 2);

	if (is_term)
		tcsetattr (in, TCSAFLUSH, &term_old);
	else {
		if ((flags = fcntl(in, F_GETFL, 0)) >= 0) {
			old_flags = flags;
			flags |= O_NONBLOCK;

			fcntl(in, F_SETFL, flags);

			while (read(in, &c, 1) > 0)
				/* nothing */;

			fcntl(in, F_SETFL, old_flags);
		}
	}

	(void) sigprocmask (SIG_SETMASK, &oldset, NULL);

	return (buf);
}

void rc_mdelay(int msecs)
{
	struct timeval tv;

	tv.tv_sec = (int) msecs / 1000;
	tv.tv_usec = (msecs % 1000) * 1000;

	select(0,(fd_set *)NULL,(fd_set *)NULL,(fd_set *)NULL, &tv);
}

/*
 * Function: rc_mksid
 *
 * Purpose: generate a quite unique string
 *
 * Remarks: not that unique at all...
 *
 */

char *
rc_mksid (void)
{
  static char buf[14];
  sprintf (buf, "%08lX%04X", (unsigned long int) time (NULL), (unsigned int) getpid ());
  return buf;
}
