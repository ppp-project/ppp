/*
 * $Id: radlogin.c,v 1.1 2002/01/22 16:03:04 dfs Exp $
 *
 * Copyright (C) 1995,1996 Lars Fenneberg
 *
 * See the file COPYRIGHT for the respective terms and conditions. 
 * If the file is missing contact me at lf@elemental.net 
 * and I'll send you a copy.
 *
 */

static char	rcsid[] =
		"$Id: radlogin.c,v 1.1 2002/01/22 16:03:04 dfs Exp $";

#include	<config.h>
#include	<includes.h>
#include	<radiusclient.h>
#include	<messages.h>
#include	<pathnames.h>
#include	<radlogin.h>

ENV *env = NULL;
static char *pname = NULL;

static RETSIGTYPE
alarm_handler(int sn)
{
	fprintf(stderr, SC_TIMEOUT, rc_conf_int("login_timeout"));
	sleep(1);
	exit(ERROR_RC);	
}

static int
login_allowed(char *tty)
{
	FILE *fp;
	char fname[PATH_MAX];
	int c;

	strcpy(fname, rc_conf_str("nologin"));
	if (access(fname, F_OK) < 0) {
		if (tty) {
			sprintf(fname, "%s.%s", rc_conf_str("nologin"), tty);
			if (access(fname, F_OK) < 0)
				return 1;
		} else {
			return 1;
		}
	}

	if ((fp = fopen(fname, "r")) != NULL)
	{
		while ((c = fgetc(fp)) != EOF)
		{
			if (c == '\n')
				fputc('\r', stdout);
			fputc(c, stdout);
		}
		fflush(stdout);
		fclose(fp);
	} else {
		printf(SC_NOLOGIN);
	}
	return (0);		
}

static char *
subst_placeholders(char *str, char *tty)
{
	char *p,*q;
	static char buf[4096];
#if defined(HAVE_UNAME)
	struct utsname uts;
#endif
#if !defined(HAVE_STRUCT_UTSNAME_DOMAINNAME) && defined(HAVE_GETDOMAINNAME)
	char domainname[256];
#endif

#if defined(HAVE_UNAME)	
	uname(&uts);
#endif
	
	p = str;
	q = buf;	

	while (*p != '\0') {
		switch (*p) {
			case '\\':
				if (*(p+1) == '\0')
					break;
				p++;
				switch (*p) {
					case 'I':
						strcpy(q, rcsid);
						q += strlen(rcsid);
						break;
					case 'L':
					case 'P':
						strcpy(q, tty);
						q += strlen(tty);
						break;
#if defined(HAVE_UNAME)
					case 'S':
						strcpy(q, uts.sysname);
						q += strlen(uts.sysname);
						break;
					case 'N':
						strcpy(q, uts.nodename);
						q += strlen(uts.nodename);
						break;
					case 'R':
						strcpy(q, uts.release);
						q += strlen(uts.release);
						break;
					case 'V':
						strcpy(q, uts.version);
						q += strlen(uts.version);
						break;
					case 'M':
						strcpy(q, uts.machine);
						q += strlen(uts.machine);
						break;
#endif
					case 'D':
#if defined(HAVE_STRUCT_UTSNAME_DOMAINNAME)
						strcpy(q, uts.domainname);
						q += strlen(uts.domainname);
#elif defined(HAVE_GETDOMAINNAME)
						getdomainname(domainname, sizeof(domainname));
						strcpy(q, domainname);
						q += strlen(domainname);
#endif
						break;
					case '\\':
						*q = '\\';
						q++;
						break;
				}
				break;
#if defined(HAVE_UNAME)
			case '@':
				strcpy(q, uts.nodename);
				q += strlen(uts.nodename);
				break;
#endif
			case '\n':
				strcpy(q,"\r\n");
				q += 2;
				break;
			default:
				*q = *p;
				q++;
				break;
		}

		p++;
	}
	*q = '\0';

	return buf;
}

static void
usage(void)
{
	fprintf(stderr,"Usage: %s [-Vhnd] [-f <config_file>] [-i <client_port>] [-m <login_tries>]\n\n", pname);
	fprintf(stderr,"  -V		output version information\n");
	fprintf(stderr,"  -h		output this text\n");     
	fprintf(stderr,"  -n		don't display issue file\n");
	fprintf(stderr,"  -f		filename of alternate config file\n");
	fprintf(stderr,"  -i		ttyname to send to the server\n");
	fprintf(stderr,"  -m		maximum login tries (overrides value in config file)\n");
        exit(ERROR_RC);
}

static void
version(void)
{
	fprintf(stderr,"%s: %s\n", pname ,rcsid);
	exit(ERROR_RC);
}

int
main (int argc, char **argv)
{
	char		username[128];
	char		passwd[AUTH_PASS_LEN + 1];
	int 		tries, remaining, c;
	UINT4		client_port;
	void 		(*login_func)(char *);	
	FILE		*fp;
	char 		buf[4096];
	char		tty[1024], *p;
	int		noissue = 0;
	int		maxtries = 0;
	char		*ttyn  = NULL;
	char            *path_radiusclient_conf = RC_CONFIG_FILE;

        extern char *optarg;
        extern int optind;

	pname = (pname = strrchr(argv[0],'/'))?pname+1:argv[0];
	
	rc_openlog(pname);

	while ((c = getopt(argc,argv,"f:m:i:nhV")) > 0)
	{
		switch(c) {
			case 'f':
				path_radiusclient_conf = optarg;
				break;
			case 'i':
				ttyn = optarg;
				break;
			case 'n':
				noissue = 1;
				break;
			case 'm':
				maxtries = atoi(optarg);
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
		
		if ((p = strrchr(ttyn, '/')) == NULL)
			strncpy(tty, ttyn, sizeof(tty));
		else
			strncpy(tty, p+1, sizeof(tty));
	}
	else
	{
		ttyn = ttyname(0);
		if (ttyn)
		{
			if ((p = strrchr(ttyn, '/')) == NULL)
				strncpy(tty, ttyn, sizeof(tty));
			else
				strncpy(tty, p+1, sizeof(tty));

			client_port = rc_map2id(ttyn);
		}
		else 
		{
			*tty = '\0';
			client_port = 0;
		}
	}

#ifdef SETVBUF_REVERSED
	setvbuf(stdout, _IONBF, NULL, 0);
#else
	setvbuf(stdout, NULL, _IONBF, 0);
#endif

	if ((argc - optind) == 1)
	{
		strncpy(username,argv[optind], sizeof(username));
	}
	else
	{
		*username = '\0';
		
		if (!noissue) {
			if (rc_conf_str("issue") && ((fp = fopen(rc_conf_str("issue"), "r")) != NULL))
			{
				while (fgets(buf, sizeof(buf), fp) != NULL)
					fputs(subst_placeholders(buf, tty), stdout);

				fflush(stdout);
				fclose(fp);
			} else {
				fputs(subst_placeholders(SC_DEFAULT_ISSUE, tty), stdout);
				fflush(stdout);
			}
		}
	}

	if ((env = rc_new_env(ENV_SIZE)) == NULL)
	{
		rc_log(LOG_CRIT, "rc_new_env: FATAL: out of memory");
		abort();
	}
	
#ifdef SECURITY_DISABLED
	if (rc_import_env(env,environ) < 0)
	{
		rc_log(LOG_CRIT, "rc_import_env: FATAL: not enough space for environment (increase ENV_SIZE)");
		abort();
	}
#else
	rc_add_env(env, "IFS", " ");
	rc_add_env(env, "PATH", RC_SECURE_PATH);
#endif

	signal(SIGALRM, alarm_handler);

	remaining = rc_conf_int("login_timeout");
	
	if (!maxtries)
		maxtries = rc_conf_int("login_tries");
		
	tries = 1;
	while (tries <= maxtries)
	{
	 alarm(remaining);

	 while (!*username) {
	 	p = rc_getstr (SC_LOGIN, 1);
	 	if (p)
	 		strncpy(username, p, sizeof(username));
	 	else
	 		exit (ERROR_RC);
	 }
	 p = rc_getstr(SC_PASSWORD,0);
	 if (p) 
	 	strncpy (passwd, p, sizeof (passwd));		
	 else 
		exit (ERROR_RC);

	 remaining = alarm(0);
	 
	 login_func = NULL;

 	 if (rc_conf_int("auth_order") & AUTH_LOCAL_FST)
 	 {
 	 	login_func = auth_local(username, passwd);
 	 		
 	 	if (!login_func)
 	 		if (rc_conf_int("auth_order") & AUTH_RADIUS_SND)
 	 			login_func = auth_radius(client_port, username, passwd);
 	 }
 	 else
 	 {
		login_func = auth_radius(client_port, username, passwd);
 	 	if (!login_func)
 	 		if (rc_conf_int("auth_order") & AUTH_LOCAL_SND)
 	 			login_func = auth_local(username, passwd);
 	 }

	 memset(passwd, '\0', sizeof(passwd));

	 if (login_func != NULL)
	 	if (login_allowed(tty)) {
	 		(*login_func)(username);
		} else {
			sleep(1);
			exit (ERROR_RC);
		}

	 *username = '\0';
	 
	 if ((++tries) <= maxtries) {
		alarm(remaining);
	 	sleep(tries * 2);
	 	remaining = alarm(0);
	 }

	}

	fprintf(stderr, SC_EXCEEDED);
	sleep(1);
	
	exit (ERROR_RC);
}
