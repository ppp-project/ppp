/*
 * $Id: radexample.c,v 1.2 2002/04/02 14:09:35 dfs Exp $
 *
 * Copyright (C) 1995,1996,1997 Lars Fenneberg
 *
 * See the file COPYRIGHT for the respective terms and conditions.
 * If the file is missing contact me at lf@elemental.net
 * and I'll send you a copy.
 *
 */


static char	rcsid[] =
		"$Id: radexample.c,v 1.2 2002/04/02 14:09:35 dfs Exp $";

#include	<config.h>
#include	<includes.h>
#include	<radiusclient.h>
#include	<pathnames.h>

static char *pname = NULL;

int
main (int argc, char **argv)
{
	int             result;
	char		username[128];
	char            passwd[AUTH_PASS_LEN + 1];
	VALUE_PAIR	*send, *received;
	UINT4		service;
	char		msg[4096], username_realm[256];
	char		*default_realm = rc_conf_str("default_realm");
	char name[2048];
	char value[2048]; /* more than enough */
	char *cfile;

	pname = (pname = strrchr(argv[0],'/'))?pname+1:argv[0];

	rc_openlog(pname);


	if (argc >= 2) {
	    cfile = argv[1];
	} else {
	    cfile = RC_CONFIG_FILE;
	}
	if (rc_read_config(cfile) != 0)
		return(ERROR_RC);

	if (rc_read_dictionary(rc_conf_str("dictionary")) != 0)
		return(ERROR_RC);

	strncpy(username, rc_getstr ("login: ",1), sizeof(username));
	strncpy (passwd, rc_getstr("Password: ",0), sizeof (passwd));

	send = NULL;

	/*
	 * Fill in User-Name
	 */

	strncpy(username_realm, username, sizeof(username_realm));

	/* Append default realm */
	if ((strchr(username_realm, '@') == NULL) && default_realm &&
	    (*default_realm != '\0'))
	{
		strncat(username_realm, "@", sizeof(username_realm));
		strncat(username_realm, default_realm, sizeof(username_realm));
	}

	if (rc_avpair_add(&send, PW_USER_NAME, username_realm, 0, VENDOR_NONE) == NULL)
		return(ERROR_RC);

	/*
	 * Fill in User-Password
	 */

	if (rc_avpair_add(&send, PW_USER_PASSWORD, passwd, 0, VENDOR_NONE) == NULL)
		return (ERROR_RC);

	/*
	 * Fill in Service-Type
	 */

	service = PW_AUTHENTICATE_ONLY;
	if (rc_avpair_add(&send, PW_SERVICE_TYPE, &service, 0, VENDOR_NONE) == NULL)
		return (ERROR_RC);

	result = rc_auth(0, send, &received, msg, NULL);

	if (result == OK_RC)
	{
		fprintf(stderr, "\"%s\" RADIUS Authentication OK\n", username);
	}
	else
	{
		fprintf(stderr, "\"%s\" RADIUS Authentication failure (RC=%i)\n", username, result);
	}

	/* Print returned attributes */
	for( ; received ; received = received->next) {
	    if (rc_avpair_tostr(received, name, sizeof(name), value,
				sizeof(value)) < 0) {
		continue;
	    }
	    printf("Attr '%s' ==> Val '%s'\n",
		   name, value);
	}

	return result;
}
