/*
 * $Id: messages.h,v 1.2 2002/02/27 15:51:19 dfs Exp $
 *
 * Copyright (C) 1995,1996 Lars Fenneberg
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

/*
 * Only messages that the user gets under normal use are in here.
 * Error messages and such are still in the source code.
 */

#ifndef MESSAGES_H
#define MESSAGES_H

/* radlogin.c */

#define SC_LOGIN	 "login: "
#define SC_PASSWORD	 "Password: "

#define SC_TIMEOUT	 "\r\nlogin timed out after %d seconds. Bye.\r\n"
#define SC_EXCEEDED	 "Maximum login tries exceeded. Go away!\r\n"

#define SC_RADIUS_OK	 "RADIUS: Authentication OK\r\n"
#define SC_RADIUS_FAILED "RADIUS: Authentication failure\r\n"

#define SC_LOCAL_OK	 "local: Authentication OK\r\n"
#define SC_LOCAL_FAILED	 "local: Authentication failure\r\n"
#define SC_NOLOGIN	 "\r\nSystem closed for maintenance. Try again later...\r\n"

#define SC_SERVER_REPLY	 "RADIUS: %s"

#define SC_DEFAULT_ISSUE "(\\I)\r\n\r\n\\S \\R (\\N) (port \\L)\r\n\r\n"

/* radacct.c */

#define SC_ACCT_OK	 "RADIUS accounting OK\r\n"
#define SC_ACCT_FAILED	 "RADIUS accounting failed (RC=%i)\r\n"

/* radstatus.c */

#define SC_STATUS_FAILED	"RADIUS: Status failure\r\n"

#endif /* MESSAGES_H */
