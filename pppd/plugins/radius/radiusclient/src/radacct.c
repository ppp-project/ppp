/*
 * $Id: radacct.c,v 1.1 2002/01/22 16:03:04 dfs Exp $
 *
 * Copyright (C) 1995,1996 Lars Fenneberg
 *
 * See the file COPYRIGHT for the respective terms and conditions. 
 * If the file is missing contact me at lf@elemental.net 
 * and I'll send you a copy.
 *
 */

static char	rcsid[] =
		"$Id: radacct.c,v 1.1 2002/01/22 16:03:04 dfs Exp $";

#include <config.h>
#include <includes.h>
#include <radiusclient.h>
#include <messages.h>
#include <pathnames.h>

static char *pname;

void usage(void)
{
	fprintf(stderr,"Usage: %s [-Vh] [-f <config_file>] [-i <client_port>]\n\n", pname);
	fprintf(stderr,"  -V            output version information\n");
	fprintf(stderr,"  -h            output this text\n");
	fprintf(stderr,"  -f		filename of alternate config file\n");
	fprintf(stderr,"  -i            ttyname to send to the server\n");
	exit(ERROR_RC);
}

void version(void)
{
	fprintf(stderr,"%s: %s\n", pname ,rcsid);
	exit(ERROR_RC);
}

int
main (int argc, char **argv)
{
	int			result = ERROR_RC;
	VALUE_PAIR	*send = NULL;
   	UINT4		client_port;
   	int			c;
	VALUE_PAIR	*vp;
	DICT_VALUE  *dval;
	char *username, *service, *fproto, *type;
	char *path_radiusclient_conf = RC_CONFIG_FILE;
	char *ttyn = NULL;

	extern char *optarg;

	pname = (pname = strrchr(argv[0],'/'))?pname+1:argv[0];

	rc_openlog(pname);

	while ((c = getopt(argc,argv,"f:i:hV")) > 0)
	{
		switch(c)
		{
			case 'f':
				path_radiusclient_conf = optarg;
				break;
			case 'i':
				ttyn = optarg;
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

	if (rc_read_config(path_radiusclient_conf) != 0)
		exit(ERROR_RC);
	
	if (rc_read_dictionary(rc_conf_str("dictionary")) != 0)
		exit (ERROR_RC);

	if (rc_read_mapfile(rc_conf_str("mapfile")) != 0)
		exit (ERROR_RC);

	if (ttyn != NULL)
	{
		client_port = rc_map2id(ttyn);
	}
	else
	{	
		/* we take stdout here, because stdin is usually connected
	 	 *  to our input file
	 	 */
	 	if ((ttyn = ttyname(1)) != NULL)
	 	{
			client_port = rc_map2id(ttyn);
		}
		else
		{
			client_port = 0;
		}
	}

	if ((send = rc_avpair_readin(stdin))) {

		username = service = type = "(unknown)";
		fproto = NULL;
	
		if ((vp = rc_avpair_get(send, PW_ACCT_STATUS_TYPE)) != NULL)
				if ((dval = rc_dict_getval(vp->lvalue, vp->name)) != NULL) {
					type = dval->name;
				}

		if ((vp = rc_avpair_get(send, PW_USER_NAME)) != NULL)
				username = vp->strvalue;

		if ((vp = rc_avpair_get(send, PW_SERVICE_TYPE)) != NULL)
				if ((dval = rc_dict_getval(vp->lvalue, vp->name)) != NULL) {
					service = dval->name;
				}

		if (vp && (vp->lvalue == PW_FRAMED) &&
			((vp = rc_avpair_get(send, PW_FRAMED_PROTOCOL)) != NULL))
				if ((dval = rc_dict_getval(vp->lvalue, vp->name)) != NULL) {
					fproto = dval->name;
				}

		result = rc_acct(client_port, send);
		if (result == OK_RC)
		{
			fprintf(stderr, SC_ACCT_OK);
			rc_log(LOG_NOTICE, "accounting OK, type %s, username %s, service %s%s%s",
				   type, username, service,(fproto)?"/":"", (fproto)?fproto:"");
		}
		else
		{
			fprintf(stderr, SC_ACCT_FAILED, result);
			rc_log(LOG_NOTICE, "accounting FAILED, type %s, username %s, service %s%s%s",
				   type, username, service,(fproto)?"/":"", (fproto)?fproto:"");
		}
		rc_avpair_free(send);
	}

	exit (result);
}
