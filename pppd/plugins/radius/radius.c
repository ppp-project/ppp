/***********************************************************************
*
* radius.c
*
* RADIUS plugin for pppd.  Performs PAP and CHAP authentication using
* RADIUS.
*
* Copyright (C) 2002 Roaring Penguin Software Inc.
*
* Based on a patch for ipppd, which is:
*    Copyright (C) 1996, Matjaz Godec <gody@elgo.si>
*    Copyright (C) 1996, Lars Fenneberg <in5y050@public.uni-hamburg.de>
*    Copyright (C) 1997, Miguel A.L. Paraz <map@iphil.net>
*
* Uses radiusclient library, which is:
*    Copyright (C) 1995,1996,1997,1998 Lars Fenneberg <lf@elemental.net>
*    Copyright (C) 2002 Roaring Penguin Software Inc.
*
* This plugin may be distributed according to the terms of the GNU
* General Public License, version 2 or (at your option) any later version.
*
***********************************************************************/
static char const RCSID[] =
"$Id: radius.c,v 1.4 2002/03/01 15:16:51 dfs Exp $";

#include "pppd.h"
#include "chap.h"
#include "radiusclient.h"
#include "fsm.h"
#include "ipcp.h"
#include <syslog.h>
#include <sys/types.h>
#include <sys/time.h>

#define BUF_LEN 1024

static char *config_file = NULL;

static option_t Options[] = {
    { "radius-config-file", o_string, &config_file },
    { NULL }
};

static int radius_secret_check(void);
static int radius_pap_auth(char *user,
			   char *passwd,
			   char **msgp,
			   struct wordlist **paddrs,
			   struct wordlist **popts);
static int radius_chap_auth(char *user,
			    u_char *remmd,
			    int remmd_len,
			    chap_state *cstate);

static void radius_ip_up(void *opaque, int arg);
static void radius_ip_down(void *opaque, int arg);
static void make_username_realm(char *user);
static int radius_setparams(VALUE_PAIR *vp, char *msg);
static void radius_choose_ip(u_int32_t *addrp);
static int radius_init(char *msg);
static int get_client_port(char *ifname);
static int radius_allowed_address(u_int32_t addr);

#ifndef MAXSESSIONID
#define MAXSESSIONID 32
#endif

struct radius_state {
    int accounting_started;
    int initialized;
    int client_port;
    int choose_ip;
    int any_ip_addr_ok;
    int done_chap_once;
    u_int32_t ip_addr;
    char user[MAXNAMELEN];
    char config_file[MAXPATHLEN];
    char session_id[MAXSESSIONID + 1];
    time_t start_time;
    SERVER *authserver;		/* Authentication server to use */
    SERVER *acctserver;		/* Accounting server to use */
};

void (*radius_attributes_hook)(VALUE_PAIR *) = NULL;

/* The pre_auth_hook MAY set authserver and acctserver if it wants.
   In that case, they override the values in the radiusclient.conf file */
void (*radius_pre_auth_hook)(char const *user,
			     SERVER **authserver,
			     SERVER **acctserver) = NULL;

static struct radius_state rstate;

char pppd_version[] = VERSION;

/**********************************************************************
* %FUNCTION: plugin_init
* %ARGUMENTS:
*  None
* %RETURNS:
*  Nothing
* %DESCRIPTION:
*  Initializes RADIUS plugin.
***********************************************************************/
void
plugin_init(void)
{
    pap_check_hook = radius_secret_check;
    pap_auth_hook = radius_pap_auth;

    chap_check_hook = radius_secret_check;
    chap_auth_hook = radius_chap_auth;

    ip_choose_hook = radius_choose_ip;
    allowed_address_hook = radius_allowed_address;

    add_notifier(&ip_up_notifier, radius_ip_up, NULL);
    add_notifier(&ip_down_notifier, radius_ip_down, NULL);

    memset(&rstate, 0, sizeof(rstate));

    strlcpy(rstate.config_file, "/etc/radiusclient/radiusclient.conf",
	    sizeof(rstate.config_file));

    add_options(Options);

    info("RADIUS plugin initialized.");
}

/**********************************************************************
* %FUNCTION: radius_secret_check
* %ARGUMENTS:
*  None
* %RETURNS:
*  1 -- we are ALWAYS willing to supply a secret. :-)
* %DESCRIPTION:
* Tells pppd that we will try to authenticate the peer, and not to
* worry about looking in /etc/ppp/*-secrets
***********************************************************************/
static int
radius_secret_check(void)
{
    return 1;
}

/**********************************************************************
* %FUNCTION: radius_choose_ip
* %ARGUMENTS:
*  addrp -- where to store the IP address
* %RETURNS:
*  Nothing
* %DESCRIPTION:
*  If RADIUS server has specified an IP address, it is stored in *addrp.
***********************************************************************/
static void
radius_choose_ip(u_int32_t *addrp)
{
    if (rstate.choose_ip) {
	*addrp = rstate.ip_addr;
    }
}

/**********************************************************************
* %FUNCTION: radius_pap_auth
* %ARGUMENTS:
*  user -- user-name of peer
*  passwd -- password supplied by peer
*  msgp -- Message which will be sent in PAP response
*  paddrs -- set to a list of possible peer IP addresses
*  popts -- set to a list of additional pppd options
* %RETURNS:
*  1 if we can authenticate, -1 if we cannot.
* %DESCRIPTION:
* Performs PAP authentication using RADIUS
***********************************************************************/
static int
radius_pap_auth(char *user,
		char *passwd,
		char **msgp,
		struct wordlist **paddrs,
		struct wordlist **popts)
{
    VALUE_PAIR *send, *received;
    UINT4 av_type;
    int result;
    static char radius_msg[BUF_LEN];

    radius_msg[0] = 0;
    *msgp = radius_msg;

    if (radius_init(radius_msg) < 0) {
	return 0;
    }

    /* Put user with potentially realm added in rstate.user */
    make_username_realm(user);

    if (radius_pre_auth_hook) {
	radius_pre_auth_hook(rstate.user,
			     &rstate.authserver,
			     &rstate.acctserver);
    }

    send = NULL;
    received = NULL;

    /* Hack... the "port" is the ppp interface number.  Should really be
       the tty */
    rstate.client_port = get_client_port(ifname);

    av_type = PW_FRAMED;
    rc_avpair_add(&send, PW_SERVICE_TYPE, &av_type, 0, VENDOR_NONE);

    av_type = PW_PPP;
    rc_avpair_add(&send, PW_FRAMED_PROTOCOL, &av_type, 0, VENDOR_NONE);

    rc_avpair_add(&send, PW_USER_NAME, rstate.user , 0, VENDOR_NONE);
    rc_avpair_add(&send, PW_USER_PASSWORD, passwd, 0, VENDOR_NONE);
    if (*remote_number) {
	rc_avpair_add(&send, PW_CALLING_STATION_ID, remote_number, 0,
		       VENDOR_NONE);
    }

    if (rstate.authserver) {
	result = rc_auth_using_server(rstate.authserver,
				      rstate.client_port, send,
				      &received, radius_msg);
    } else {
	result = rc_auth(rstate.client_port, send, &received, radius_msg);
    }

    if (result == OK_RC) {
	if (radius_setparams(received, radius_msg) < 0) {
	    result = ERROR_RC;
	}
    }

    /* free value pairs */
    rc_avpair_free(received);
    rc_avpair_free(send);

    return (result == OK_RC) ? 1 : 0;
}

/**********************************************************************
* %FUNCTION: radius_chap_auth
* %ARGUMENTS:
*  user -- user-name of peer
*  remmd -- hash received from peer
*  remmd_len -- length of remmd
*  cstate -- pppd's chap_state structure
* %RETURNS:
*  CHAP_SUCCESS if we can authenticate, CHAP_FAILURE if we cannot.
* %DESCRIPTION:
* Performs CHAP authentication using RADIUS
***********************************************************************/
static int
radius_chap_auth(char *user,
		 u_char *remmd,
		 int remmd_len,
		 chap_state *cstate)
{
    VALUE_PAIR *send, *received;
    UINT4 av_type;
    static char radius_msg[BUF_LEN];
    int result;
    u_char cpassword[MD5_SIGNATURE_SIZE+1];
    radius_msg[0] = 0;

    if (radius_init(radius_msg) < 0) {
	error("%s", radius_msg);
	return CHAP_FAILURE;
    }

    /* we handle md5 digest at the moment */
    if (cstate->chal_type != CHAP_DIGEST_MD5) {
	error("RADIUS: Challenge type not MD5");
	return CHAP_FAILURE;
    }

    /* Put user with potentially realm added in rstate.user */
    if (!rstate.done_chap_once) {
	make_username_realm(user);
	rstate.client_port = get_client_port (ifname);
	if (radius_pre_auth_hook) {
	    radius_pre_auth_hook(rstate.user,
				 &rstate.authserver,
				 &rstate.acctserver);
	}
    }

    send = received = NULL;

    av_type = PW_FRAMED;
    rc_avpair_add (&send, PW_SERVICE_TYPE, &av_type, 0, VENDOR_NONE);

    av_type = PW_PPP;
    rc_avpair_add (&send, PW_FRAMED_PROTOCOL, &av_type, 0, VENDOR_NONE);

    rc_avpair_add (&send, PW_USER_NAME, rstate.user , 0, VENDOR_NONE);

    /*
     * add the CHAP-Password and CHAP-Challenge fields
     */

    cpassword[0] = cstate->chal_id;

    memcpy(&cpassword[1], remmd, MD5_SIGNATURE_SIZE);

    rc_avpair_add(&send, PW_CHAP_PASSWORD, cpassword, MD5_SIGNATURE_SIZE + 1, VENDOR_NONE);

    rc_avpair_add(&send, PW_CHAP_CHALLENGE, cstate->challenge, cstate->chal_len, VENDOR_NONE);

    /*
     * make authentication with RADIUS server
     */

    if (rstate.authserver) {
	result = rc_auth_using_server(rstate.authserver,
				      rstate.client_port, send,
				      &received, radius_msg);
    } else {
	result = rc_auth(rstate.client_port, send, &received, radius_msg);
    }

    if (result == OK_RC) {
	if (!rstate.done_chap_once) {
	    if (radius_setparams(received, radius_msg) < 0) {
		error("%s", radius_msg);
		result = ERROR_RC;
	    } else {
		rstate.done_chap_once = 1;
	    }
	}
    }

    rc_avpair_free(received);
    rc_avpair_free (send);
    return (result == OK_RC) ? CHAP_SUCCESS : CHAP_FAILURE;
}

/**********************************************************************
* %FUNCTION: make_username_realm
* %ARGUMENTS:
*  user -- the user given to pppd
* %RETURNS:
*  Nothing
* %DESCRIPTION:
*  Copies user into rstate.user.  If it lacks a realm (no "@domain" part),
* then the default realm from the radiusclient config file is added.
***********************************************************************/
static void
make_username_realm(char *user)
{
    char *default_realm;

    if ( user != NULL ) {
	strlcpy(rstate.user, user, sizeof(rstate.user));
    }  else {
	rstate.user[0] = 0;
    }

    default_realm = rc_conf_str("default_realm");

    if (!strchr(rstate.user, '@') &&
	default_realm &&
	(*default_realm != '\0')) {
	strlcat(rstate.user, "@", sizeof(rstate.user));
	strlcat(rstate.user, default_realm, sizeof(rstate.user));
    }
}

/**********************************************************************
* %FUNCTION: radius_setparams
* %ARGUMENTS:
*  vp -- received value-pairs
*  msg -- buffer in which to place error message.  Holds up to BUF_LEN chars
* %RETURNS:
*  >= 0 on success; -1 on failure
* %DESCRIPTION:
*  Parses attributes sent by RADIUS server and sets them in pppd.  Currently,
*  used only to set IP address.
***********************************************************************/
static int
radius_setparams(VALUE_PAIR *vp, char *msg)
{
    u_int32_t remote;

    /* Send RADIUS attributes to anyone else who might be interested */
    if (radius_attributes_hook) {
	(*radius_attributes_hook)(vp);
    }

    /*
     * service type (if not framed then quit),
     * new IP address (RADIUS can define static IP for some users),
     */

    while (vp) {
	if (vp->vendorcode == VENDOR_NONE) {
	    switch (vp->attribute) {
	    case PW_SERVICE_TYPE:
		/* check for service type       */
		/* if not FRAMED then exit      */
		if (vp->lvalue != PW_FRAMED) {
		    slprintf(msg, BUF_LEN, "RADIUS: wrong service type %ld for %s",
			     vp->lvalue, rstate.user);
		    return -1;
		}
		break;
	    case PW_FRAMED_PROTOCOL:
		/* check for framed protocol type       */
		/* if not PPP then also exit            */
		if (vp->lvalue != PW_PPP) {
		    slprintf(msg, BUF_LEN, "RADIUS: wrong framed protocol %ld for %s",
			     vp->lvalue, rstate.user);
		    return -1;
		}
		break;

	    case PW_FRAMED_IP_ADDRESS:
		/* seting up remote IP addresses */
		remote = vp->lvalue;
		if (remote == 0xffffffff) {
		    /* 0xffffffff means user should be allowed to select one */
		    rstate.any_ip_addr_ok = 1;
		} else if (remote != 0xfffffffe) {
		    /* 0xfffffffe means NAS should select an ip address */
		    remote = htonl(vp->lvalue);
		    if (bad_ip_adrs (remote)) {
			slprintf(msg, BUF_LEN, "RADIUS: bad remote IP address %I for %s",
				 remote, rstate.user);
			return -1;
		    }
		    rstate.choose_ip = 1;
		    rstate.ip_addr = remote;
		}
	    break;
	    }
	}
	vp = vp->next;
    }
    return 0;
}

/**********************************************************************
* %FUNCTION: radius_acct_start
* %ARGUMENTS:
*  None
* %RETURNS:
*  Nothing
* %DESCRIPTION:
*  Sends a "start" accounting message to the RADIUS server.
***********************************************************************/
static void
radius_acct_start(void)
{
    UINT4 av_type;
    int result;
    VALUE_PAIR *send = NULL;
    ipcp_options *ho = &ipcp_hisoptions[0];
    u_int32_t hisaddr;

    if (!rstate.initialized) {
	return;
    }

    rstate.start_time = time(NULL);

    strncpy(rstate.session_id, rc_mksid(), sizeof(rstate.session_id));

    rc_avpair_add(&send, PW_ACCT_SESSION_ID,
		   rstate.session_id, 0, VENDOR_NONE);
    rc_avpair_add(&send, PW_USER_NAME,
		   rstate.user, 0, VENDOR_NONE);

    av_type = PW_STATUS_START;
    rc_avpair_add(&send, PW_ACCT_STATUS_TYPE, &av_type, 0, VENDOR_NONE);

    av_type = PW_FRAMED;
    rc_avpair_add(&send, PW_SERVICE_TYPE, &av_type, 0, VENDOR_NONE);

    av_type = PW_PPP;
    rc_avpair_add(&send, PW_FRAMED_PROTOCOL, &av_type, 0, VENDOR_NONE);

    if (*remote_number) {
	rc_avpair_add(&send, PW_CALLING_STATION_ID,
		       remote_number, 0, VENDOR_NONE);
    }

    av_type = PW_RADIUS;
    rc_avpair_add(&send, PW_ACCT_AUTHENTIC, &av_type, 0, VENDOR_NONE);


    av_type = PW_ASYNC;
    rc_avpair_add(&send, PW_NAS_PORT_TYPE, &av_type, 0, VENDOR_NONE);

    hisaddr = ho->hisaddr;
    av_type = htonl(hisaddr);
    rc_avpair_add(&send, PW_FRAMED_IP_ADDRESS , &av_type , 0, VENDOR_NONE);

    if (rstate.acctserver) {
	result = rc_acct_using_server(rstate.acctserver,
				      rstate.client_port, send);
    } else {
	result = rc_acct(rstate.client_port, send);
    }

    rc_avpair_free(send);

    if (result != OK_RC) {
	/* RADIUS server could be down so make this a warning */
	syslog(LOG_WARNING,
		"Accounting START failed for %s", rstate.user);
    } else {
	rstate.accounting_started = 1;
    }
}

/**********************************************************************
* %FUNCTION: radius_acct_stop
* %ARGUMENTS:
*  None
* %RETURNS:
*  Nothing
* %DESCRIPTION:
*  Sends a "stop" accounting message to the RADIUS server.
***********************************************************************/
static void
radius_acct_stop(void)
{
    UINT4 av_type;
    VALUE_PAIR *send = NULL;
    ipcp_options *ho = &ipcp_hisoptions[0];
    u_int32_t hisaddr;
    int result;

    if (!rstate.initialized) {
	return;
    }

    if (!rstate.accounting_started) {
	return;
    }

    rstate.accounting_started = 0;
    rc_avpair_add(&send, PW_ACCT_SESSION_ID, rstate.session_id,
		   0, VENDOR_NONE);

    rc_avpair_add(&send, PW_USER_NAME, rstate.user, 0, VENDOR_NONE);

    av_type = PW_STATUS_STOP;
    rc_avpair_add(&send, PW_ACCT_STATUS_TYPE, &av_type, 0, VENDOR_NONE);

    av_type = PW_FRAMED;
    rc_avpair_add(&send, PW_SERVICE_TYPE, &av_type, 0, VENDOR_NONE);

    av_type = PW_PPP;
    rc_avpair_add(&send, PW_FRAMED_PROTOCOL, &av_type, 0, VENDOR_NONE);

    av_type = PW_RADIUS;
    rc_avpair_add(&send, PW_ACCT_AUTHENTIC, &av_type, 0, VENDOR_NONE);


    if (link_stats_valid) {
	av_type = link_connect_time;
	rc_avpair_add(&send, PW_ACCT_SESSION_TIME, &av_type, 0, VENDOR_NONE);

	av_type = link_stats.bytes_out;
	rc_avpair_add(&send, PW_ACCT_OUTPUT_OCTETS, &av_type, 0, VENDOR_NONE);

	av_type = link_stats.bytes_in;
	rc_avpair_add(&send, PW_ACCT_INPUT_OCTETS, &av_type, 0, VENDOR_NONE);

	av_type = link_stats.pkts_out;
	rc_avpair_add(&send, PW_ACCT_OUTPUT_PACKETS, &av_type, 0, VENDOR_NONE);

	av_type = link_stats.pkts_in;
	rc_avpair_add(&send, PW_ACCT_INPUT_PACKETS, &av_type, 0, VENDOR_NONE);
    }

    if (*remote_number) {
	rc_avpair_add(&send, PW_CALLING_STATION_ID,
		       remote_number, 0, VENDOR_NONE);
    }

    av_type = PW_ASYNC;
    rc_avpair_add(&send, PW_NAS_PORT_TYPE, &av_type, 0, VENDOR_NONE);

    hisaddr = ho->hisaddr;
    av_type = htonl(hisaddr);
    rc_avpair_add(&send, PW_FRAMED_IP_ADDRESS , &av_type , 0, VENDOR_NONE);

    if (rstate.acctserver) {
	result = rc_acct_using_server(rstate.acctserver,
				      rstate.client_port, send);
    } else {
	result = rc_acct(rstate.client_port, send);
    }

    if (result != OK_RC) {
	/* RADIUS server could be down so make this a warning */
	syslog(LOG_WARNING,
		"Accounting STOP failed for %s", rstate.user);
    }
    rc_avpair_free(send);
}

/**********************************************************************
* %FUNCTION: radius_ip_up
* %ARGUMENTS:
*  opaque -- ignored
*  arg -- ignored
* %RETURNS:
*  Nothing
* %DESCRIPTION:
*  Called when IPCP is up.  We'll do a start-accounting record.
***********************************************************************/
static void
radius_ip_up(void *opaque, int arg)
{
    radius_acct_start();
}

/**********************************************************************
* %FUNCTION: radius_ip_down
* %ARGUMENTS:
*  opaque -- ignored
*  arg -- ignored
* %RETURNS:
*  Nothing
* %DESCRIPTION:
*  Called when IPCP is down.  We'll do a stop-accounting record.
***********************************************************************/
static void
radius_ip_down(void *opaque, int arg)
{
    radius_acct_stop();
}

/**********************************************************************
* %FUNCTION: radius_init
* %ARGUMENTS:
*  msg -- buffer of size BUF_LEN for error message
* %RETURNS:
*  negative on failure; non-negative on success
* %DESCRIPTION:
*  Initializes radiusclient library
***********************************************************************/
static int
radius_init(char *msg)
{
    if (rstate.initialized) {
	return 0;
    }

    if (config_file && *config_file) {
	strlcpy(rstate.config_file, config_file, MAXPATHLEN-1);
    }

    rstate.initialized = 1;

    if (rc_read_config(rstate.config_file) != 0) {
	slprintf(msg, BUF_LEN, "RADIUS: Can't read config file %s",
		 rstate.config_file);
	return -1;
    }

    if (rc_read_dictionary(rc_conf_str("dictionary")) != 0) {
	slprintf(msg, BUF_LEN, "RADIUS: Can't read dictionary file %s",
		 rc_conf_str("dictionary"));
	return -1;
    }

    if (rc_read_mapfile(rc_conf_str("mapfile")) != 0)	{
	slprintf(msg, BUF_LEN, "RADIUS: Can't read map file %s",
		 rc_conf_str("mapfile"));
	return -1;
    }
    return 0;
}

/**********************************************************************
* %FUNCTION: get_client_port
* %ARGUMENTS:
*  ifname -- PPP interface name (e.g. "ppp7")
* %RETURNS:
*  The NAS port number (e.g. 7)
* %DESCRIPTION:
*  Extracts the port number from the interface name
***********************************************************************/
static int
get_client_port(char *ifname)
{
    int port;
    if (sscanf(ifname, "ppp%d", &port) == 1) {
	return port;
    }
    return rc_map2id(ifname);
}

/**********************************************************************
* %FUNCTION: radius_allowed_address
* %ARGUMENTS:
*  addr -- IP address
* %RETURNS:
*  1 if we're allowed to use that IP address; 0 if not; -1 if we do
*  not know.
***********************************************************************/
static int
radius_allowed_address(u_int32_t addr)
{
    ipcp_options *wo = &ipcp_wantoptions[0];

    if (!rstate.choose_ip) {
	/* If RADIUS server said any address is OK, then fine... */
	if (rstate.any_ip_addr_ok) {
	    return 1;
	}

	/* Sigh... if an address was supplied for remote host in pppd
	   options, it has to match that.  */
	if (wo->hisaddr != 0 && wo->hisaddr == addr) {
	    return 1;
	}

	return 0;
    }
    if (addr == rstate.ip_addr) return 1;
    return 0;
}

/* Useful for other plugins */
char *radius_logged_in_user(void)
{
    return rstate.user;
}
