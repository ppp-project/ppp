/*
 * chap_ms.c - Challenge Handshake Authentication Protocol.
 *
 * Copyright (c) 1993 The Australian National University.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms are permitted
 * provided that the above copyright notice and this paragraph are
 * duplicated in all such forms and that any documentation,
 * advertising materials, and other materials related to such
 * distribution and use acknowledge that the software was developed
 * by the Australian National University.  The name of the University
 * may not be used to endorse or promote products derived from this
 * software without specific prior written permission.
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND WITHOUT ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, WITHOUT LIMITATION, THE IMPLIED
 * WARRANTIES OF MERCHANTIBILITY AND FITNESS FOR A PARTICULAR PURPOSE.
 *
 * Copyright (c) 1991 Gregory M. Christy.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms are permitted
 * provided that the above copyright notice and this paragraph are
 * duplicated in all such forms and that any documentation,
 * advertising materials, and other materials related to such
 * distribution and use acknowledge that the software was developed
 * by Gregory M. Christy.  The name of the author may not be used to
 * endorse or promote products derived from this software without
 * specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND WITHOUT ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, WITHOUT LIMITATION, THE IMPLIED
 * WARRANTIES OF MERCHANTIBILITY AND FITNESS FOR A PARTICULAR PURPOSE.
 */

#define RCSID	"$Id: chap.c,v 1.33 2002/09/01 12:00:15 dfs Exp $"

/*
 * TODO:
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/time.h>

#include "pppd.h"
#include "chap.h"
#include "md5.h"
#ifdef CHAPMS
#include "chap_ms.h"
#endif

/* Hook for a plugin to say if we can possibly authenticate a peer using CHAP */
int (*chap_check_hook) __P((void)) = NULL;

/* Hook for a plugin to get the CHAP password for authenticating us */
int (*chap_passwd_hook) __P((char *user, char *passwd)) = NULL;

/* Hook for a plugin to validate CHAP challenge */
int (*chap_auth_hook) __P((char *user,
			   u_char *remmd,
			   int remmd_len,
			   chap_state *cstate)) = NULL;

static const char rcsid[] = RCSID;

#ifdef CHAPMS
/* For MPPE debug */
/* Use "[]|}{?/><,`!2&&(" (sans quotes) for RFC 3079 MS-CHAPv2 test value */
static char *mschap_challenge = NULL;
/* Use "!@\#$%^&*()_+:3|~" (sans quotes, backslash is to escape #) for ... */
static char *mschap2_peer_challenge = NULL;
#endif

/*
 * Command-line options.
 */
static option_t chap_option_list[] = {
    { "chap-restart", o_int, &chap[0].timeouttime,
      "Set timeout for CHAP", OPT_PRIO },
    { "chap-max-challenge", o_int, &chap[0].max_transmits,
      "Set max #xmits for challenge", OPT_PRIO },
    { "chap-interval", o_int, &chap[0].chal_interval,
      "Set interval for rechallenge", OPT_PRIO },
#ifdef MSLANMAN
    { "ms-lanman", o_bool, &ms_lanman,
      "Use LanMan passwd when using MS-CHAP", 1 },
#endif
#ifdef DEBUGMPPEKEY
    { "mschap-challenge", o_string, &mschap_challenge,
      "specify CHAP challenge" },
    { "mschap2-peer-challenge", o_string, &mschap2_peer_challenge,
      "specify CHAP peer challenge" },
#endif
    { NULL }
};

/*
 * Protocol entry points.
 */
static void ChapInit __P((int));
static void ChapLowerUp __P((int));
static void ChapLowerDown __P((int));
static void ChapInput __P((int, u_char *, int));
static void ChapProtocolReject __P((int));
static int  ChapPrintPkt __P((u_char *, int,
			      void (*) __P((void *, char *, ...)), void *));

struct protent chap_protent = {
    PPP_CHAP,
    ChapInit,
    ChapInput,
    ChapProtocolReject,
    ChapLowerUp,
    ChapLowerDown,
    NULL,
    NULL,
    ChapPrintPkt,
    NULL,
    1,
    "CHAP",
    NULL,
    chap_option_list,
    NULL,
    NULL,
    NULL
};

chap_state chap[NUM_PPP];		/* CHAP state; one for each unit */

static void ChapChallengeTimeout __P((void *));
static void ChapResponseTimeout __P((void *));
static void ChapReceiveChallenge __P((chap_state *, u_char *, int, int));
static void ChapRechallenge __P((void *));
static void ChapReceiveResponse __P((chap_state *, u_char *, int, int));
static void ChapReceiveSuccess __P((chap_state *, u_char *, int, int));
static void ChapReceiveFailure __P((chap_state *, u_char *, int, int));
static void ChapSendStatus __P((chap_state *, int));
static void ChapSendChallenge __P((chap_state *));
static void ChapSendResponse __P((chap_state *));
static void ChapGenChallenge __P((chap_state *));

extern double drand48 __P((void));
extern void srand48 __P((long));

/*
 * ChapInit - Initialize a CHAP unit.
 */
static void
ChapInit(unit)
    int unit;
{
    chap_state *cstate = &chap[unit];

    BZERO(cstate, sizeof(*cstate));
    cstate->unit = unit;
    cstate->clientstate = CHAPCS_INITIAL;
    cstate->serverstate = CHAPSS_INITIAL;
    cstate->timeouttime = CHAP_DEFTIMEOUT;
    cstate->max_transmits = CHAP_DEFTRANSMITS;
    /* random number generator is initialized in magic_init */
}


/*
 * ChapAuthWithPeer - Authenticate us with our peer (start client).
 *
 */
void
ChapAuthWithPeer(unit, our_name, digest)
    int unit;
    char *our_name;
    int digest;
{
    chap_state *cstate = &chap[unit];

    cstate->resp_name = our_name;
    cstate->resp_type = digest;

    if (cstate->clientstate == CHAPCS_INITIAL ||
	cstate->clientstate == CHAPCS_PENDING) {
	/* lower layer isn't up - wait until later */
	cstate->clientstate = CHAPCS_PENDING;
	return;
    }

    /*
     * We get here as a result of LCP coming up.
     * So even if CHAP was open before, we will
     * have to re-authenticate ourselves.
     */
    cstate->clientstate = CHAPCS_LISTEN;
}


/*
 * ChapAuthPeer - Authenticate our peer (start server).
 */
void
ChapAuthPeer(unit, our_name, digest)
    int unit;
    char *our_name;
    int digest;
{
    chap_state *cstate = &chap[unit];

    cstate->chal_name = our_name;
    cstate->chal_type = digest;

    if (cstate->serverstate == CHAPSS_INITIAL ||
	cstate->serverstate == CHAPSS_PENDING) {
	/* lower layer isn't up - wait until later */
	cstate->serverstate = CHAPSS_PENDING;
	return;
    }

    ChapGenChallenge(cstate);
    ChapSendChallenge(cstate);		/* crank it up dude! */
    cstate->serverstate = CHAPSS_INITIAL_CHAL;
}


/*
 * ChapChallengeTimeout - Timeout expired on sending challenge.
 */
static void
ChapChallengeTimeout(arg)
    void *arg;
{
    chap_state *cstate = (chap_state *) arg;

    /* if we aren't sending challenges, don't worry.  then again we */
    /* probably shouldn't be here either */
    if (cstate->serverstate != CHAPSS_INITIAL_CHAL &&
	cstate->serverstate != CHAPSS_RECHALLENGE)
	return;

    if (cstate->chal_transmits >= cstate->max_transmits) {
	/* give up on peer */
	error("Peer failed to respond to CHAP challenge");
	cstate->serverstate = CHAPSS_BADAUTH;
	auth_peer_fail(cstate->unit, PPP_CHAP);
	return;
    }

    ChapSendChallenge(cstate);		/* Re-send challenge */
}


/*
 * ChapResponseTimeout - Timeout expired on sending response.
 */
static void
ChapResponseTimeout(arg)
    void *arg;
{
    chap_state *cstate = (chap_state *) arg;

    /* if we aren't sending a response, don't worry. */
    if (cstate->clientstate != CHAPCS_RESPONSE)
	return;

    ChapSendResponse(cstate);		/* re-send response */
}


/*
 * ChapRechallenge - Time to challenge the peer again.
 */
static void
ChapRechallenge(arg)
    void *arg;
{
    chap_state *cstate = (chap_state *) arg;

    /* if we aren't sending a response, don't worry. */
    if (cstate->serverstate != CHAPSS_OPEN)
	return;

    ChapGenChallenge(cstate);
    ChapSendChallenge(cstate);
    cstate->serverstate = CHAPSS_RECHALLENGE;
}


/*
 * ChapLowerUp - The lower layer is up.
 *
 * Start up if we have pending requests.
 */
static void
ChapLowerUp(unit)
    int unit;
{
    chap_state *cstate = &chap[unit];

    if (cstate->clientstate == CHAPCS_INITIAL)
	cstate->clientstate = CHAPCS_CLOSED;
    else if (cstate->clientstate == CHAPCS_PENDING)
	cstate->clientstate = CHAPCS_LISTEN;

    if (cstate->serverstate == CHAPSS_INITIAL)
	cstate->serverstate = CHAPSS_CLOSED;
    else if (cstate->serverstate == CHAPSS_PENDING) {
	ChapGenChallenge(cstate);
	ChapSendChallenge(cstate);
	cstate->serverstate = CHAPSS_INITIAL_CHAL;
    }
}


/*
 * ChapLowerDown - The lower layer is down.
 *
 * Cancel all timeouts.
 */
static void
ChapLowerDown(unit)
    int unit;
{
    chap_state *cstate = &chap[unit];

    /* Timeout(s) pending?  Cancel if so. */
    if (cstate->serverstate == CHAPSS_INITIAL_CHAL ||
	cstate->serverstate == CHAPSS_RECHALLENGE)
	UNTIMEOUT(ChapChallengeTimeout, cstate);
    else if (cstate->serverstate == CHAPSS_OPEN
	     && cstate->chal_interval != 0)
	UNTIMEOUT(ChapRechallenge, cstate);
    if (cstate->clientstate == CHAPCS_RESPONSE)
	UNTIMEOUT(ChapResponseTimeout, cstate);

    cstate->clientstate = CHAPCS_INITIAL;
    cstate->serverstate = CHAPSS_INITIAL;
}


/*
 * ChapProtocolReject - Peer doesn't grok CHAP.
 */
static void
ChapProtocolReject(unit)
    int unit;
{
    chap_state *cstate = &chap[unit];

    if (cstate->serverstate != CHAPSS_INITIAL &&
	cstate->serverstate != CHAPSS_CLOSED)
	auth_peer_fail(unit, PPP_CHAP);
    if (cstate->clientstate != CHAPCS_INITIAL &&
	cstate->clientstate != CHAPCS_CLOSED)
	auth_withpeer_fail(unit, PPP_CHAP);
    ChapLowerDown(unit);		/* shutdown chap */
}


/*
 * ChapInput - Input CHAP packet.
 */
static void
ChapInput(unit, inpacket, packet_len)
    int unit;
    u_char *inpacket;
    int packet_len;
{
    chap_state *cstate = &chap[unit];
    u_char *inp;
    u_char code, id;
    int len;

    /*
     * Parse header (code, id and length).
     * If packet too short, drop it.
     */
    inp = inpacket;
    if (packet_len < CHAP_HEADERLEN) {
	CHAPDEBUG(("ChapInput: rcvd short header."));
	return;
    }
    GETCHAR(code, inp);
    GETCHAR(id, inp);
    GETSHORT(len, inp);
    if (len < CHAP_HEADERLEN) {
	CHAPDEBUG(("ChapInput: rcvd illegal length."));
	return;
    }
    if (len > packet_len) {
	CHAPDEBUG(("ChapInput: rcvd short packet."));
	return;
    }
    len -= CHAP_HEADERLEN;

    /*
     * Action depends on code (as in fact it usually does :-).
     */
    switch (code) {
    case CHAP_CHALLENGE:
	ChapReceiveChallenge(cstate, inp, id, len);
	break;

    case CHAP_RESPONSE:
	ChapReceiveResponse(cstate, inp, id, len);
	break;

    case CHAP_FAILURE:
	ChapReceiveFailure(cstate, inp, id, len);
	break;

    case CHAP_SUCCESS:
	ChapReceiveSuccess(cstate, inp, id, len);
	break;

    default:				/* Need code reject? */
	warn("Unknown CHAP code (%d) received.", code);
	break;
    }
}


/*
 * ChapReceiveChallenge - Receive Challenge and send Response.
 */
static void
ChapReceiveChallenge(cstate, inp, id, len)
    chap_state *cstate;
    u_char *inp;
    int id;
    int len;
{
    int rchallenge_len;
    u_char *rchallenge;
    int secret_len;
    char secret[MAXSECRETLEN];
    char rhostname[256];
    MD5_CTX mdContext;
    u_char hash[MD5_SIGNATURE_SIZE];

    if (cstate->clientstate == CHAPCS_CLOSED ||
	cstate->clientstate == CHAPCS_PENDING) {
	CHAPDEBUG(("ChapReceiveChallenge: in state %d", cstate->clientstate));
	return;
    }

    if (len < 2) {
	CHAPDEBUG(("ChapReceiveChallenge: rcvd short packet."));
	return;
    }

    GETCHAR(rchallenge_len, inp);
    len -= sizeof (u_char) + rchallenge_len;	/* now name field length */
    if (len < 0) {
	CHAPDEBUG(("ChapReceiveChallenge: rcvd short packet."));
	return;
    }
    rchallenge = inp;
    INCPTR(rchallenge_len, inp);

    if (len >= sizeof(rhostname))
	len = sizeof(rhostname) - 1;
    BCOPY(inp, rhostname, len);
    rhostname[len] = '\000';

    /* Microsoft doesn't send their name back in the PPP packet */
    if (explicit_remote || (remote_name[0] != 0 && rhostname[0] == 0)) {
	strlcpy(rhostname, remote_name, sizeof(rhostname));
	CHAPDEBUG(("ChapReceiveChallenge: using '%q' as remote name",
		   rhostname));
    }

    /* get secret for authenticating ourselves with the specified host */
    if (!get_secret(cstate->unit, cstate->resp_name, rhostname,
		    secret, &secret_len, 0)) {
	secret_len = 0;		/* assume null secret if can't find one */
	warn("No CHAP secret found for authenticating us to %q", rhostname);
    }

    /* cancel response send timeout if necessary */
    if (cstate->clientstate == CHAPCS_RESPONSE)
	UNTIMEOUT(ChapResponseTimeout, cstate);

    cstate->resp_id = id;
    cstate->resp_transmits = 0;

    /*  generate MD based on negotiated type */
    switch (cstate->resp_type) {

    case CHAP_DIGEST_MD5:
	MD5Init(&mdContext);
	MD5Update(&mdContext, &cstate->resp_id, 1);
	MD5Update(&mdContext, secret, secret_len);
	MD5Update(&mdContext, rchallenge, rchallenge_len);
	MD5Final(hash, &mdContext);
	BCOPY(hash, cstate->response, MD5_SIGNATURE_SIZE);
	cstate->resp_length = MD5_SIGNATURE_SIZE;
	break;

#ifdef CHAPMS
    case CHAP_MICROSOFT:
	ChapMS(cstate, rchallenge, secret, secret_len,
	       (MS_ChapResponse *) cstate->response);
	break;

    case CHAP_MICROSOFT_V2:
	ChapMS2(cstate, rchallenge,
		mschap2_peer_challenge? mschap2_peer_challenge: NULL,
		cstate->resp_name, secret, secret_len,
		(MS_Chap2Response *) cstate->response, cstate->earesponse,
		 MS_CHAP2_AUTHENTICATEE);
	break;
#endif /* CHAPMS */

    default:
	CHAPDEBUG(("unknown digest type %d", cstate->resp_type));
	return;
    }

    BZERO(secret, sizeof(secret));
    ChapSendResponse(cstate);
}


/*
 * ChapReceiveResponse - Receive and process response.
 */
static void
ChapReceiveResponse(cstate, inp, id, len)
    chap_state *cstate;
    u_char *inp;
    int id;
    int len;
{
    u_char *remmd, remmd_len;
    int secret_len, old_state;
    int code;
    char rhostname[256];
    MD5_CTX mdContext;
    char secret[MAXSECRETLEN];
    u_char hash[MD5_SIGNATURE_SIZE];

    if (cstate->serverstate == CHAPSS_CLOSED ||
	cstate->serverstate == CHAPSS_PENDING) {
	CHAPDEBUG(("ChapReceiveResponse: in state %d", cstate->serverstate));
	return;
    }

    if (id != cstate->chal_id)
	return;			/* doesn't match ID of last challenge */

    /*
     * If we have received a duplicate or bogus Response,
     * we have to send the same answer (Success/Failure)
     * as we did for the first Response we saw.
     */
    if (cstate->serverstate == CHAPSS_OPEN) {
	ChapSendStatus(cstate, CHAP_SUCCESS);
	return;
    }
    if (cstate->serverstate == CHAPSS_BADAUTH) {
	ChapSendStatus(cstate, CHAP_FAILURE);
	return;
    }

    if (len < 2) {
	CHAPDEBUG(("ChapReceiveResponse: rcvd short packet."));
	return;
    }
    GETCHAR(remmd_len, inp);		/* get length of MD */
    remmd = inp;			/* get pointer to MD */
    INCPTR(remmd_len, inp);

    len -= sizeof (u_char) + remmd_len;
    if (len < 0) {
	CHAPDEBUG(("ChapReceiveResponse: rcvd short packet."));
	return;
    }

    UNTIMEOUT(ChapChallengeTimeout, cstate);

    if (len >= sizeof(rhostname))
	len = sizeof(rhostname) - 1;
    BCOPY(inp, rhostname, len);
    rhostname[len] = '\000';

#ifdef CHAPMS
    /* copy the flags into cstate for use elsewhere */
    if (cstate->chal_type == CHAP_MICROSOFT_V2)
	cstate->resp_flags = ((MS_Chap2Response *) remmd)->Flags[0];
#endif /* CHAPMS */
    /*
     * Get secret for authenticating them with us,
     * do the hash ourselves, and compare the result.
     */
    code = CHAP_FAILURE;

    /* If a plugin will verify the response, let the plugin do it. */
    if (chap_auth_hook) {
	code = (*chap_auth_hook) ( (explicit_remote ? remote_name : rhostname),
				   remmd, (int) remmd_len,
				   cstate );
    } else {
	if (!get_secret(cstate->unit, (explicit_remote? remote_name: rhostname),
			cstate->chal_name, secret, &secret_len, 1)) {
	    warn("No CHAP secret found for authenticating %q", rhostname);
	} else {

	    /*  generate MD based on negotiated type */
	    switch (cstate->chal_type) {

	    case CHAP_DIGEST_MD5:
		if (remmd_len != MD5_SIGNATURE_SIZE)
		    break;			/* not even the right length */
		MD5Init(&mdContext);
		MD5Update(&mdContext, &cstate->chal_id, 1);
		MD5Update(&mdContext, secret, secret_len);
		MD5Update(&mdContext, cstate->challenge, cstate->chal_len);
		MD5Final(hash, &mdContext);

		/* compare MDs and send the appropriate status */
		if (memcmp(hash, remmd, MD5_SIGNATURE_SIZE) == 0)
		    code = CHAP_SUCCESS;	/* they are the same! */
		break;

#ifdef CHAPMS
	    case CHAP_MICROSOFT:
	    {
		int response_offset, response_size;
		MS_ChapResponse *rmd = (MS_ChapResponse *) remmd;
		MS_ChapResponse md;

		if (remmd_len != MS_CHAP_RESPONSE_LEN)
		    break;			/* not even the right length */

		/* Determine which part of response to verify against */
		if (rmd->UseNT[0]) {
		    response_offset = offsetof(MS_ChapResponse, NTResp);
		    response_size = sizeof(rmd->NTResp);
		} else {
#ifdef MSLANMAN
		    response_offset = offsetof(MS_ChapResponse, LANManResp);
		    response_size = sizeof(rmd->LANManResp);
#else
		    /* Should really propagate this into the error packet. */
		    notice("Peer request for LANMAN auth not supported");
		    break;
#endif /* MSLANMAN */
		}

		/* Generate the expected response. */
		ChapMS(cstate, cstate->challenge, secret, secret_len, &md);

		/* compare MDs and send the appropriate status */
		if (memcmp((u_char *) &md + response_offset,
			   (u_char *) remmd + response_offset,
			   response_size) == 0)
		    code = CHAP_SUCCESS;	/* they are the same! */
		break;
	    }

	    case CHAP_MICROSOFT_V2:
	    {
		MS_Chap2Response *rmd = (MS_Chap2Response *) remmd;
		MS_Chap2Response md;

		if (remmd_len != MS_CHAP2_RESPONSE_LEN)
		    break;			/* not even the right length */

		/* Generate the expected response and our mutual auth. */
		ChapMS2(cstate, cstate->challenge, rmd->PeerChallenge,
			(explicit_remote? remote_name: rhostname),
			secret, secret_len, &md,
			cstate->saresponse, MS_CHAP2_AUTHENTICATOR);

		/* compare MDs and send the appropriate status */
		if (memcmp(md.NTResp, rmd->NTResp, sizeof(md.NTResp)) == 0)
		    code = CHAP_SUCCESS;	/* yay! */
		break;
	    }
#endif /* CHAPMS */

	    default:
		CHAPDEBUG(("unknown digest type %d", cstate->chal_type));
	    }
	}

	BZERO(secret, sizeof(secret));
    }
    ChapSendStatus(cstate, code);

    if (code == CHAP_SUCCESS) {
	old_state = cstate->serverstate;
	cstate->serverstate = CHAPSS_OPEN;
	if (old_state == CHAPSS_INITIAL_CHAL) {
	    auth_peer_success(cstate->unit, PPP_CHAP, cstate->chal_type,
			      rhostname, len);
	}
	if (cstate->chal_interval != 0)
	    TIMEOUT(ChapRechallenge, cstate, cstate->chal_interval);
	notice("CHAP peer authentication succeeded for %q", rhostname);

    } else {
	error("CHAP peer authentication failed for remote host %q", rhostname);
	cstate->serverstate = CHAPSS_BADAUTH;
	auth_peer_fail(cstate->unit, PPP_CHAP);
    }
}

/*
 * ChapReceiveSuccess - Receive Success
 */
static void
ChapReceiveSuccess(cstate, inp, id, len)
    chap_state *cstate;
    u_char *inp;
    u_char id;
    int len;
{

    if (cstate->clientstate == CHAPCS_OPEN)
	/* presumably an answer to a duplicate response */
	return;

    if (cstate->clientstate != CHAPCS_RESPONSE) {
	/* don't know what this is */
	CHAPDEBUG(("ChapReceiveSuccess: in state %d\n", cstate->clientstate));
	return;
    }

    UNTIMEOUT(ChapResponseTimeout, cstate);

#ifdef CHAPMS
    /*
     * For MS-CHAPv2, we must verify that the peer knows our secret.
     */
    if (cstate->resp_type == CHAP_MICROSOFT_V2) {
	if ((len >= MS_AUTH_RESPONSE_LENGTH + 2) && !strncmp(inp, "S=", 2)) {
	    inp += 2; len -= 2;
	    if (!memcmp(inp, cstate->earesponse, MS_AUTH_RESPONSE_LENGTH)) {
		/* Authenticator Response matches. */
		inp += MS_AUTH_RESPONSE_LENGTH; /* Eat it */
		len -= MS_AUTH_RESPONSE_LENGTH;
		if ((len >= 3) && !strncmp(inp, " M=", 3)) {
		    inp += 3; len -= 3; /* Eat the delimiter */
		} else if (len) {
		    /* Packet has extra text which does not begin " M=" */
		    error("MS-CHAPv2 Success packet is badly formed.");
		    auth_withpeer_fail(cstate->unit, PPP_CHAP);
		}
	    } else {
		/* Authenticator Response did not match expected. */
		error("MS-CHAPv2 mutual authentication failed.");
		auth_withpeer_fail(cstate->unit, PPP_CHAP);
	    }
	} else {
	    /* Packet does not start with "S=" */
	    error("MS-CHAPv2 Success packet is badly formed.");
	    auth_withpeer_fail(cstate->unit, PPP_CHAP);
	}
    }
#endif

    /*
     * Print message.
     */
    if (len > 0)
	PRINTMSG(inp, len);

    cstate->clientstate = CHAPCS_OPEN;

    auth_withpeer_success(cstate->unit, PPP_CHAP, cstate->resp_type);
}


/*
 * ChapReceiveFailure - Receive failure.
 */
static void
ChapReceiveFailure(cstate, inp, id, len)
    chap_state *cstate;
    u_char *inp;
    u_char id;
    int len;
{
    u_char *msg;
    u_char *p = inp;

    if (cstate->clientstate != CHAPCS_RESPONSE) {
	/* don't know what this is */
	CHAPDEBUG(("ChapReceiveFailure: in state %d\n", cstate->clientstate));
	return;
    }

#ifdef CHAPMS
    /* We want a null-terminated string for strxxx(). */
    msg = malloc(len + 1);
    if (!msg) {
	p = NULL;
	notice("Out of memory in ChapReceiveFailure");
	goto print_msg;
    }
    BCOPY(inp, msg, len);
    p = msg + len; *p = '\0'; p = msg;
#endif

    UNTIMEOUT(ChapResponseTimeout, cstate);

#ifdef CHAPMS
    if ((cstate->resp_type == CHAP_MICROSOFT_V2) ||
	(cstate->resp_type == CHAP_MICROSOFT)) {
	int error;

	/*
	 * Deal with MS-CHAP formatted failure messages; just print the
	 * M=<message> part (if any).  For MS-CHAP we're not really supposed
	 * to use M=<message>, but it shouldn't hurt.  See ChapSendStatus().
	 */
	if (!strncmp(p, "E=", 2))
	    error = (int) strtol(p, NULL, 10); /* Remember the error code. */
	else
	    goto print_msg; /* Message is badly formatted. */

	if (len && ((p = strstr(p, " M=")) != NULL)) {
	    /* M=<message> field found. */
	    p += 3;
	} else {
	    /* No M=<message>; use the error code. */
	    switch(error) {
	    case MS_CHAP_ERROR_RESTRICTED_LOGON_HOURS:
		p = "E=646 Restricted logon hours";
		break;

	    case MS_CHAP_ERROR_ACCT_DISABLED:
		p = "E=647 Account disabled";
		break;

	    case MS_CHAP_ERROR_PASSWD_EXPIRED:
		p = "E=648 Password expired";
		break;

	    case MS_CHAP_ERROR_NO_DIALIN_PERMISSION:
		p = "E=649 No dialin permission";
		break;

	    case MS_CHAP_ERROR_AUTHENTICATION_FAILURE:
		p = "E=691 Authentication failure";
		break;

	    case MS_CHAP_ERROR_CHANGING_PASSWORD:
		/* Should never see this, we don't support Change Password. */
		p = "E=709 Error changing password";
		break;

	    default:
		free(msg);
		p = msg = malloc(len + 33);
		if (!msg) {
		    novm("ChapReceiveFailure");
		    goto print_msg;
		}
		slprintf(p, len + 33, "Unknown authentication failure: %.*s",
			 len, inp);
		break;
	    }
	}
	len = strlen(p);
    }
#endif

    /*
     * Print message.
     */
print_msg:
    if (len > 0 && p != NULL)
	PRINTMSG(p, len);

    error("CHAP authentication failed");
    auth_withpeer_fail(cstate->unit, PPP_CHAP);
#ifdef CHAPMS
    if (msg) free(msg);
#endif
}


/*
 * ChapSendChallenge - Send an Authenticate challenge.
 */
static void
ChapSendChallenge(cstate)
    chap_state *cstate;
{
    u_char *outp;
    int chal_len, name_len;
    int outlen;

    chal_len = cstate->chal_len;
    name_len = strlen(cstate->chal_name);
    outlen = CHAP_HEADERLEN + sizeof (u_char) + chal_len + name_len;
    outp = outpacket_buf;

    MAKEHEADER(outp, PPP_CHAP);		/* paste in a CHAP header */

    PUTCHAR(CHAP_CHALLENGE, outp);
    PUTCHAR(cstate->chal_id, outp);
    PUTSHORT(outlen, outp);

    PUTCHAR(chal_len, outp);		/* put length of challenge */
    BCOPY(cstate->challenge, outp, chal_len);
    INCPTR(chal_len, outp);

    BCOPY(cstate->chal_name, outp, name_len);	/* append hostname */

    output(cstate->unit, outpacket_buf, outlen + PPP_HDRLEN);

    TIMEOUT(ChapChallengeTimeout, cstate, cstate->timeouttime);
    ++cstate->chal_transmits;
}


/*
 * ChapSendStatus - Send a status response (ack or nak).
 * See RFC 2433 and RFC 2759 for MS-CHAP and MS-CHAPv2 message formats.
 */
static void
ChapSendStatus(cstate, code)
    chap_state *cstate;
    int code;
{
    u_char *outp;
    int i, outlen, msglen;
    char msg[256];
    char *p, *q;

    p = msg;
    q = p + sizeof(msg); /* points 1 byte past msg */

    if (code == CHAP_SUCCESS) {
#ifdef CHAPMS
	if (cstate->chal_type == CHAP_MICROSOFT_V2) {
	    /*
	     * Per RFC 2759, success message must be formatted as
	     *     "S=<auth_string> M=<message>"
	     * where
	     *     <auth_string> is the Authenticator Response (mutual auth)
	     *     <message> is a text message
	     *
	     * However, some versions of Windows (win98 tested) do not know
	     * about the M=<message> part (required per RFC 2759) and flag
	     * it as an error (reported incorrectly as an encryption error
	     * to the user).  Since the RFC requires it, and it can be
	     * useful information, we supply it if the peer is a conforming
	     * system.  Luckily (?), win98 sets the Flags field to 0x04
	     * (contrary to RFC requirements) so we can use that to
	     * distinguish between conforming and non-conforming systems.
	     *
	     * Special thanks to Alex Swiridov <say@real.kharkov.ua> for
	     * help debugging this.
	     */
	    slprintf(p, q - p, "S=");
	    p += 2;
	    slprintf(p, q - p, "%s", cstate->saresponse);
	    p += strlen(cstate->saresponse);
	    if (cstate->resp_flags != 0)
		goto msgdone;
	    slprintf(p, q - p, " M=");
	    p += 3;
	}
#endif /* CHAPMS */

	slprintf(p, q - p, "Welcome to %s.", hostname);
    } else {
#ifdef CHAPMS
	if ((cstate->chal_type == CHAP_MICROSOFT_V2) ||
	    (cstate->chal_type == CHAP_MICROSOFT)) {
	    /*
	     * Failure message must be formatted as
	     *     "E=e R=r C=c V=v M=m"
	     * where
	     *     e = error code (we use 691, ERROR_AUTHENTICATION_FAILURE)
	     *     r = retry (we use 1, ok to retry)
	     *     c = challenge to use for next response, we reuse previous
	     *     v = Change Password version supported, we use 0
	     *     m = text message
	     *
	     * The M=m part is only for MS-CHAPv2, but MS-CHAP should ignore
	     * any extra text according to RFC 2433.  So we'll go the easy
	     * (read: lazy) route and include it always.  Neither win2k nor
	     * win98 (others untested) display the message to the user anyway.
	     * They also both ignore the E=e code.
	     *
	     * Note that it's safe to reuse the same challenge as we don't
	     * actually accept another response based on the error message
	     * (and no clients try to resend a response anyway).
	     *
	     * Basically, this whole bit is useless code, even the small
	     * implementation here is only because of overspecification.
	     */
	    slprintf(p, q - p, "E=691 R=1 C=");
	    p += 12;
	    for (i = 0; i < cstate->chal_len; i++)
		sprintf(p + i * 2, "%02X", cstate->challenge[i]);
	    p += cstate->chal_len * 2;
	    slprintf(p, q - p, " V=0 M=");
	    p += 7;
	}
#endif /* CHAPMS */

	slprintf(p, q - p, "I don't like you.  Go 'way.");
    }
msgdone:
    msglen = strlen(msg);

    outlen = CHAP_HEADERLEN + msglen;
    outp = outpacket_buf;

    MAKEHEADER(outp, PPP_CHAP);	/* paste in a header */

    PUTCHAR(code, outp);
    PUTCHAR(cstate->chal_id, outp);
    PUTSHORT(outlen, outp);
    BCOPY(msg, outp, msglen);
    output(cstate->unit, outpacket_buf, outlen + PPP_HDRLEN);
}

/*
 * ChapGenChallenge is used to generate a pseudo-random challenge string of
 * a pseudo-random length between min_len and max_len.  The challenge
 * string and its length are stored in *cstate, and various other fields of
 * *cstate are initialized.
 */

static void
ChapGenChallenge(cstate)
    chap_state *cstate;
{
    int chal_len = 0; /* Avoid compiler warning */
    u_char *ptr = cstate->challenge;
    int i;

    switch (cstate->chal_type) {
    case CHAP_DIGEST_MD5:
	/*
	 * pick a random challenge length between MIN_CHALLENGE_LENGTH and
	 * MAX_CHALLENGE_LENGTH
	 */
	chal_len = (unsigned) ((drand48() *
				(MAX_CHALLENGE_LENGTH - MIN_CHALLENGE_LENGTH)) +
				MIN_CHALLENGE_LENGTH);
	break;

#ifdef CHAPMS
    case CHAP_MICROSOFT:
	/* MS-CHAP is fixed to an 8 octet challenge. */
	chal_len = 8;
	break;

    case CHAP_MICROSOFT_V2:
	/* MS-CHAPv2 is fixed to a 16 octet challenge. */
	chal_len = 16;
	break;
#endif
    default:
	fatal("ChapGenChallenge: Unsupported challenge type %d",
	      (int) cstate->chal_type);
	break;
    }

    cstate->chal_len = chal_len;
    cstate->chal_id = ++cstate->id;
    cstate->chal_transmits = 0;

#ifdef CHAPMS
    if (mschap_challenge)
	for (i = 0; i < chal_len; i++)
	    *ptr++ = mschap_challenge[i];
    else
#endif
	/* generate a random string */
	for (i = 0; i < chal_len; i++)
	    *ptr++ = (char) (drand48() * 0xff);
}

/*
 * ChapSendResponse - send a response packet with values as specified
 * in *cstate.
 */
/* ARGSUSED */
static void
ChapSendResponse(cstate)
    chap_state *cstate;
{
    u_char *outp;
    int outlen, md_len, name_len;

    md_len = cstate->resp_length;
    name_len = strlen(cstate->resp_name);
    outlen = CHAP_HEADERLEN + sizeof (u_char) + md_len + name_len;
    outp = outpacket_buf;

    MAKEHEADER(outp, PPP_CHAP);

    PUTCHAR(CHAP_RESPONSE, outp);	/* we are a response */
    PUTCHAR(cstate->resp_id, outp);	/* copy id from challenge packet */
    PUTSHORT(outlen, outp);		/* packet length */

    PUTCHAR(md_len, outp);		/* length of MD */
    BCOPY(cstate->response, outp, md_len);	/* copy MD to buffer */
    INCPTR(md_len, outp);

    BCOPY(cstate->resp_name, outp, name_len); /* append our name */

    /* send the packet */
    output(cstate->unit, outpacket_buf, outlen + PPP_HDRLEN);

    cstate->clientstate = CHAPCS_RESPONSE;
    TIMEOUT(ChapResponseTimeout, cstate, cstate->timeouttime);
    ++cstate->resp_transmits;
}

/*
 * ChapPrintPkt - print the contents of a CHAP packet.
 */
static char *ChapCodenames[] = {
    "Challenge", "Response", "Success", "Failure"
};

static int
ChapPrintPkt(p, plen, printer, arg)
    u_char *p;
    int plen;
    void (*printer) __P((void *, char *, ...));
    void *arg;
{
    int code, id, len;
    int clen, nlen;
    u_char x;

    if (plen < CHAP_HEADERLEN)
	return 0;
    GETCHAR(code, p);
    GETCHAR(id, p);
    GETSHORT(len, p);
    if (len < CHAP_HEADERLEN || len > plen)
	return 0;

    if (code >= 1 && code <= sizeof(ChapCodenames) / sizeof(char *))
	printer(arg, " %s", ChapCodenames[code-1]);
    else
	printer(arg, " code=0x%x", code);
    printer(arg, " id=0x%x", id);
    len -= CHAP_HEADERLEN;
    switch (code) {
    case CHAP_CHALLENGE:
    case CHAP_RESPONSE:
	if (len < 1)
	    break;
	clen = p[0];
	if (len < clen + 1)
	    break;
	++p;
	nlen = len - clen - 1;
	printer(arg, " <");
	for (; clen > 0; --clen) {
	    GETCHAR(x, p);
	    printer(arg, "%.2x", x);
	}
	printer(arg, ">, name = ");
	print_string((char *)p, nlen, printer, arg);
	break;
    case CHAP_FAILURE:
    case CHAP_SUCCESS:
	printer(arg, " ");
	print_string((char *)p, len, printer, arg);
	break;
    default:
	for (clen = len; clen > 0; --clen) {
	    GETCHAR(x, p);
	    printer(arg, " %.2x", x);
	}
    }

    return len + CHAP_HEADERLEN;
}
