/*
 * $Id: radstatus.c,v 1.1 2002/01/22 16:03:05 dfs Exp $
 *
 * Copyright (C) 1995,1996 Lars Fenneberg
 *
 * See the file COPYRIGHT for the respective terms and conditions. 
 * If the file is missing contact me at lf@elemental.net 
 * and I'll send you a copy.
 *
 */

static char	rcsid[] =
		"$Id: radstatus.c,v 1.1 2002/01/22 16:03:05 dfs Exp $";

#include <config.h>
#include <includes.h>
#include <radiusclient.h>
#include <pathnames.h>
#include <messages.h>

static char *pname;

void usage(void)
{
	fprintf(stderr,"Usage: %s [-Vh] [-f <config_file>] [server[:port]]...\n\n", pname);
	fprintf(stderr,"  -V            output version information\n");
	fprintf(stderr,"  -h            output this text\n");
	fprintf(stderr,"  -f		filename of alternate config file\n");
	exit(ERROR_RC);
}

void version(void)
{
	fprintf(stderr,"%s: %s\n", pname ,rcsid);
	exit(ERROR_RC);
}

int main (int argc, char **argv)
{
	int	result = ERROR_RC;
   	int	c,i;
	char	*p, msg[4096];
	SERVER	*srv;
	char	*path_radiusclient_conf = RC_CONFIG_FILE;
	
	extern int optind;

	pname = (pname = strrchr(argv[0],'/'))?pname+1:argv[0];

	rc_openlog(pname);

	while ((c = getopt(argc,argv,"hVf:")) > 0)
	{
		switch(c) {
			case 'f':
				path_radiusclient_conf = optarg;
				break;
			case 'V':
				version();
				break;
			case 'h':
				usage();
				break;
			default:
				exit(ERROR_RC);
				break;
		}
	}

	argc -= optind;
	argv += optind;

	if (rc_read_config(path_radiusclient_conf) != 0)
		exit(ERROR_RC);
	
	if (rc_read_dictionary(rc_conf_str("dictionary")) != 0)
		exit (ERROR_RC);

	if (argc > 0) {
		for (i = 0; i < argc; i++) {
			if ((p = strchr(argv[i], ':')) == NULL) {
				result = rc_check(argv[i],rc_getport(AUTH), msg);
			} else if (!strcmp(p+1, "auth")) {
				*p = '\0';
				result = rc_check(argv[i],rc_getport(AUTH), msg);
			} else if (!strcmp(p+1, "acct")) {
				*p = '\0';
				result = rc_check(argv[i],rc_getport(ACCT), msg);
			} else {
				*p = '\0';
				result = rc_check(argv[i], atoi(p+1), msg);
			}
			if (result == OK_RC)
				fputs(msg, stdout);
			else
				printf(SC_STATUS_FAILED);
		}
	} else {
		srv = rc_conf_srv("authserver");
		for(i=0; i<srv->max ; i++)
		{
			result = rc_check(srv->name[i], srv->port[i], msg);
			fputs(msg, stdout);
		}
		
		srv = rc_conf_srv("acctserver");
		for(i=0; i<srv->max ; i++)
		{
			result = rc_check(srv->name[i], srv->port[i], msg);
			fputs(msg, stdout);
		}
	}
	return 0;
}
