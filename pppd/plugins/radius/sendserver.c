/*
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

#include <includes.h>
#include <signal.h>

#include "radiusclient.h"
#include "pathnames.h"
#include "pppd/crypto.h"

static void rc_random_vector (unsigned char *);
static int rc_check_reply (AUTH_HDR *, int, int, char *, unsigned char *, unsigned char);

/*
 * Calculate length occupied by an AVP in the send buffer
 */
static int rc_pack_length(VALUE_PAIR *vp)
{
    int total_length = 1;	/* attribute */
    int length;

    if (vp->vendorcode != VENDOR_NONE)
	total_length += 6;	/* length, vendor code, attribute */

    if (vp->vendorcode == VENDOR_NONE && vp->attribute == PW_USER_PASSWORD) {
	length = (vp->lvalue + (AUTH_VECTOR_LEN-1)) & ~(AUTH_VECTOR_LEN-1);
	total_length += length + 1;
    } else {
	switch (vp->type) {
	case PW_TYPE_STRING:
	    total_length += vp->lvalue + 1;
	    break;
	case PW_TYPE_INTEGER:
	case PW_TYPE_IPADDR:
	    total_length += sizeof(UINT4) + 1;
	    break;
	default:
	    fatal("rc_pack_length: Unable to calculate pack length for unknown attribute type %d", vp->type);
	}
    }

    return total_length;
}

/*
 * Function: rc_pack_list
 *
 * Purpose: Packs an attribute value pair list into a buffer.
 *
 * Returns: Number of octets packed.
 *
 */

static int rc_pack_list (VALUE_PAIR *vp, char *secret, AUTH_HDR *auth, int datalen)
{
    int             length, i, pc, secretlen, padded_length;
    int             vplen;
    UINT4           lvalue;
    unsigned char   md5buf[MD5_DIGEST_LENGTH];
    unsigned char   *buf, *vector, *lenptr;
    PPP_MD_CTX	    *md5ctx;
    unsigned	    md5len;

    buf = auth->data;

    while (vp != (VALUE_PAIR *) NULL)
	{
	    vplen = rc_pack_length(vp);
	    if ((int)(buf - auth->data) + vplen > datalen) {
		error("radius: send data would overflow buffer (%d > %d)",
		      (int)(buf - auth->data) + vplen, datalen);
		break;
	    }

	    if (vp->vendorcode != VENDOR_NONE) {
		*buf++ = PW_VENDOR_SPECIFIC;

		/* Place-holder for where to put length */
		lenptr = buf++;

		/* Insert vendor code */
		*buf++ = 0;
		*buf++ = (((unsigned int) vp->vendorcode) >> 16) & 255;
		*buf++ = (((unsigned int) vp->vendorcode) >> 8) & 255;
		*buf++ = ((unsigned int) vp->vendorcode) & 255;

		/* Insert vendor-type */
		*buf++ = vp->attribute;

		/* Insert value */
		switch(vp->type) {
		case PW_TYPE_STRING:
		    length = vp->lvalue;
		    *lenptr = length + 8;
		    *buf++ = length+2;
		    memcpy(buf, vp->strvalue, (size_t) length);
		    buf += length;
		    break;
		case PW_TYPE_INTEGER:
		case PW_TYPE_IPADDR:
		    length = sizeof(UINT4);
		    *lenptr = length + 8;
		    *buf++ = length+2;
		    lvalue = htonl(vp->lvalue);
		    memcpy(buf, (char *) &lvalue, sizeof(UINT4));
		    buf += length;
		    break;
		default:
		    break;
		}
	    } else {
		*buf++ = vp->attribute;
		switch (vp->attribute) {
		case PW_USER_PASSWORD:
		    length = vp->lvalue;

		    /* Encrypt the password */

		    /* Calculate the padded length */
		    padded_length = (length+(AUTH_VECTOR_LEN-1)) & ~(AUTH_VECTOR_LEN-1);
		    *buf++ = padded_length + 2;

		    secretlen = strlen (secret);
		    vector = auth->vector;
		    md5ctx = PPP_MD_CTX_new();
		    md5len = sizeof(md5buf);
		    if (!md5ctx)
			novm("radius: error allocating MD5 data structures for encrypting the password.");

		    for(i = 0; i < padded_length; i += AUTH_VECTOR_LEN) {
			/* Calculate the MD5 digest*/
			if (!PPP_DigestInit(md5ctx, PPP_md5()) ||
				!PPP_DigestUpdate(md5ctx, secret, secretlen) ||
				!PPP_DigestUpdate(md5ctx, vector, md5len) ||
				!PPP_DigestFinal(md5ctx, md5buf, &md5len) ||
				md5len != sizeof(md5buf))
			{
			    PPP_MD_CTX_free(md5ctx);
			    fatal("radius: Error calculating password mixing material");
			}

			/* Use the target output as the vector for the next round. */
			vector = buf;

			/* Xor the password into the MD5 digest */
			for (pc = i; pc < (i + AUTH_VECTOR_LEN); pc++) {
			    *buf++ = md5buf[pc & (AUTH_VECTOR_LEN-1)] ^ (pc < length ? vp->strvalue[pc] : 0);
			}
		    }
		    PPP_MD_CTX_free(md5ctx);

		    break;
		default:
		    switch (vp->type) {
		    case PW_TYPE_STRING:
			length = vp->lvalue;
			*buf++ = length + 2;
			memcpy (buf, vp->strvalue, (size_t) length);
			buf += length;
			break;

		    case PW_TYPE_INTEGER:
		    case PW_TYPE_IPADDR:
			*buf++ = sizeof (UINT4) + 2;
			lvalue = htonl (vp->lvalue);
			memcpy (buf, (char *) &lvalue, sizeof (UINT4));
			buf += sizeof (UINT4);
			break;

		    default:
			break;
		    }
		    break;
		}
	    }

	    vp = vp->next;
	}

    /* Should never happen unless rc_pack_length is buggy */
    if ((int)(buf - auth->data) > datalen)
	fatal("radius: BUG! send data buffer overflowed!");

    return buf - auth->data;
}

/*
 * Function: rc_send_server
 *
 * Purpose: send a request to a RADIUS server and wait for the reply
 *
 */

int rc_send_server (SEND_DATA *data, char *msg, size_t msgspace, REQUEST_INFO *info)
{
	int             sockfd;
	struct sockaddr salocal;
	struct sockaddr saremote;
	struct sockaddr_in *sin;
	struct timeval  authtime;
	fd_set          readfds;
	AUTH_HDR       *auth, *recv_auth;
	UINT4           auth_ipaddr;
	char           *server_name;	/* Name of server to query */
	socklen_t       salen;
	int             result;
	int             total_length;
	socklen_t       length;
	int             retry_max;
	int		secretlen;
	char            secret[MAX_SECRET_LENGTH + 1];
	unsigned char   vector[AUTH_VECTOR_LEN];
	char            recv_buffer[BUFFER_LEN];
	char            send_buffer[BUFFER_LEN];
	int		retries;
	VALUE_PAIR	*vp;
	PPP_MD_CTX      *md5ctx;
	unsigned	md5len;

	server_name = data->server;
	if (server_name == (char *) NULL || server_name[0] == '\0')
		return (ERROR_RC);

	if ((vp = rc_avpair_get(data->send_pairs, PW_SERVICE_TYPE)) && \
	    (vp->lvalue == PW_ADMINISTRATIVE))
	{
		strcpy(secret, MGMT_POLL_SECRET);
		if ((auth_ipaddr = rc_get_ipaddr(server_name)) == 0)
			return (ERROR_RC);
	}
	else
	{
		if (rc_find_server (server_name, &auth_ipaddr, secret) != 0)
		{
			memset (secret, '\0', sizeof (secret));
			return (ERROR_RC);
		}
	}

	sockfd = socket (AF_INET, SOCK_DGRAM, 0);
	if (sockfd < 0)
	{
		memset (secret, '\0', sizeof (secret));
		error("rc_send_server: socket: %s", strerror(errno));
		return (ERROR_RC);
	}

	length = sizeof (salocal);
	sin = (struct sockaddr_in *) & salocal;
	memset ((char *) sin, '\0', (size_t) length);
	sin->sin_family = AF_INET;
	sin->sin_addr.s_addr = htonl(rc_own_bind_ipaddress());
	sin->sin_port = htons ((unsigned short) 0);
	if (bind (sockfd, (struct sockaddr *) sin, length) < 0 ||
		   getsockname (sockfd, (struct sockaddr *) sin, &length) < 0)
	{
		close (sockfd);
		memset (secret, '\0', sizeof (secret));
		error("rc_send_server: bind: %s: %m", server_name);
		return (ERROR_RC);
	}

	retry_max = data->retries;	/* Max. numbers to try for reply */
	retries = 0;			/* Init retry cnt for blocking call */

	/* Build a request */
	auth = (AUTH_HDR *) send_buffer;
	auth->code = data->code;
	auth->id = data->seq_nbr;

	if (data->code == PW_ACCOUNTING_REQUEST)
	{
		secretlen = strlen (secret);
		total_length = rc_pack_list(data->send_pairs, secret, auth,
					    BUFFER_LEN - AUTH_HDR_LEN - secretlen) + AUTH_HDR_LEN;

		auth->length = htons ((unsigned short) total_length);

		memset((char *) auth->vector, 0, AUTH_VECTOR_LEN);
		md5ctx = PPP_MD_CTX_new();
		md5len = sizeof(vector);
		if (!md5ctx ||
			!PPP_DigestInit(md5ctx, PPP_md5()) ||
			!PPP_DigestUpdate(md5ctx, (unsigned char*)auth, total_length) ||
			!PPP_DigestUpdate(md5ctx, secret, secretlen) ||
			!PPP_DigestFinal(md5ctx, vector, &md5len) ||
			md5len != sizeof(vector))
		{
		    error("rc_send_server: Error calculating accounting message digest.");
		    if (md5ctx)
			PPP_MD_CTX_free(md5ctx);
		    return (ERROR_RC);
		}
		PPP_MD_CTX_free(md5ctx);

		memcpy ((char *) auth->vector, (char *) vector, AUTH_VECTOR_LEN);
	}
	else
	{
		rc_random_vector (vector);
		memcpy (auth->vector, vector, AUTH_VECTOR_LEN);

		total_length = rc_pack_list(data->send_pairs, secret, auth,
					    BUFFER_LEN - AUTH_HDR_LEN) + AUTH_HDR_LEN;

		auth->length = htons ((unsigned short) total_length);
	}

	sin = (struct sockaddr_in *) & saremote;
	memset ((char *) sin, '\0', sizeof (saremote));
	sin->sin_family = AF_INET;
	sin->sin_addr.s_addr = htonl (auth_ipaddr);
	sin->sin_port = htons ((unsigned short) data->svc_port);

	for (;;)
	{
		sendto (sockfd, (char *) auth, (unsigned int) total_length, (int) 0,
			(struct sockaddr *) sin, sizeof (struct sockaddr_in));

		authtime.tv_usec = 0L;
		authtime.tv_sec = (long) data->timeout;
		FD_ZERO (&readfds);
		FD_SET (sockfd, &readfds);
		if (select (sockfd + 1, &readfds, NULL, NULL, &authtime) < 0)
		{
			if (errno == EINTR && !ppp_signaled(SIGTERM))
				continue;
			error("rc_send_server: select: %m");
			memset (secret, '\0', sizeof (secret));
			close (sockfd);
			return (ERROR_RC);
		}
		if (FD_ISSET (sockfd, &readfds))
			break;

		/*
		 * Timed out waiting for response.  Retry "retry_max" times
		 * before giving up.  If retry_max = 0, don't retry at all.
		 */
		if (++retries >= retry_max)
		{
			error("rc_send_server: no reply from RADIUS server %s:%u",
			      rc_ip_hostname (auth_ipaddr), data->svc_port);
			close (sockfd);
			memset (secret, '\0', sizeof (secret));
			return (TIMEOUT_RC);
		}
	}
	salen = sizeof (saremote);
	length = recvfrom (sockfd, (char *) recv_buffer,
			   (int) sizeof (recv_buffer),
			   (int) 0, &saremote, &salen);

	if (length <= 0)
	{
		error("rc_send_server: recvfrom: %s:%d: %m", server_name,\
		      data->svc_port);
		close (sockfd);
		memset (secret, '\0', sizeof (secret));
		return (ERROR_RC);
	}

	recv_auth = (AUTH_HDR *)recv_buffer;

	result = rc_check_reply (recv_auth, length, BUFFER_LEN, secret, vector, data->seq_nbr);

	close (sockfd);
	if (info)
	{
		memcpy(info->secret, secret, sizeof(info->secret));
		memcpy(info->request_vector, vector,
		       sizeof(info->request_vector));
	}
	memset (secret, '\0', sizeof (secret));

	if (result != OK_RC) return (result);

	data->receive_pairs = rc_avpair_gen(recv_auth);

	*msg = '\0';
	vp = data->receive_pairs;
	while (vp)
	{
		if ((vp = rc_avpair_get(vp, PW_REPLY_MESSAGE)))
		{
			strlcat(msg, (char*) vp->strvalue, msgspace);
			strlcat(msg, "\n", msgspace);
			vp = vp->next;
		}
	}

	if ((recv_auth->code == PW_ACCESS_ACCEPT) ||
		(recv_auth->code == PW_PASSWORD_ACK) ||
		(recv_auth->code == PW_ACCOUNTING_RESPONSE))
	{
		result = OK_RC;
	}
	else
	{
		result = BADRESP_RC;
	}

	return (result);
}

/*
 * Function: rc_check_reply
 *
 * Purpose: verify items in returned packet.
 *
 * Returns:	OK_RC       -- upon success,
 *		BADRESP_RC  -- if anything looks funny.
 *
 */

static int rc_check_reply (AUTH_HDR *auth, int datalen, int bufferlen, char *secret,
			   unsigned char *vector, unsigned char seq_nbr)
{
	int             secretlen;
	int             totallen;
	unsigned char   calc_digest[AUTH_VECTOR_LEN];
	unsigned char   reply_digest[AUTH_VECTOR_LEN];
	PPP_MD_CTX	*md5ctx;
	unsigned	md5len;

	if (datalen < sizeof(AUTH_HDR)) {
		error("rc_check_reply: received short RADIUS server response");
		return BADRESP_RC;
	}

	totallen = ntohs (auth->length);

	secretlen = strlen (secret);

	/* Do sanity checks on packet length */
	if ((totallen < 20) || totallen > bufferlen || totallen > datalen)
	{
		error("rc_check_reply: received RADIUS server response with invalid length");
		return (BADRESP_RC);
	}

	/* Verify buffer space, should never trigger with current buffer size and check above */
	if ((totallen + secretlen) > bufferlen)
	{
		error("rc_check_reply: not enough buffer space to verify RADIUS server response");
		return (BADRESP_RC);
	}
	/* Verify that id (seq. number) matches what we sent */
	if (auth->id != seq_nbr)
	{
		error("rc_check_reply: received non-matching id in RADIUS server response");
		return (BADRESP_RC);
	}

	/* Verify the reply digest */
	memcpy ((char *) reply_digest, (char *) auth->vector, AUTH_VECTOR_LEN);
	memcpy ((char *) auth->vector, (char *) vector, AUTH_VECTOR_LEN);
	md5ctx = PPP_MD_CTX_new();
	md5len = sizeof(calc_digest);
	if (!md5ctx ||
		!PPP_DigestInit(md5ctx, PPP_md5()) ||
		!PPP_DigestUpdate(md5ctx, (unsigned char*)auth, totallen) ||
		!PPP_DigestUpdate(md5ctx, secret, secretlen) ||
		!PPP_DigestFinal(md5ctx, calc_digest, &md5len) ||
		md5len != sizeof(calc_digest))
	{
	    error("rc_check_reply: Error calculating response MD5 digest");
	    if (md5ctx)
		PPP_MD_CTX_free(md5ctx);
	    return (ERROR_RC);
	}
	PPP_MD_CTX_free(md5ctx);

#ifdef DIGEST_DEBUG
	{
		int i;

		fputs("reply_digest: ", stderr);
		for (i = 0; i < AUTH_VECTOR_LEN; i++)
		{
			fprintf(stderr,"%.2x ", (int) reply_digest[i]);
		}
		fputs("\ncalc_digest:  ", stderr);
		for (i = 0; i < AUTH_VECTOR_LEN; i++)
		{
			fprintf(stderr,"%.2x ", (int) calc_digest[i]);
		}
		fputs("\n", stderr);
	}
#endif

	if (memcmp ((char *) reply_digest, (char *) calc_digest,
		    AUTH_VECTOR_LEN) != 0)
	{
		error("rc_check_reply: received invalid reply digest from RADIUS server");
		return (BADRESP_RC);
	}

	return (OK_RC);

}

/*
 * Function: rc_random_vector
 *
 * Purpose: generates a random vector of AUTH_VECTOR_LEN octets.
 *
 * Returns: the vector (call by reference)
 *
 */

static void rc_random_vector (unsigned char *vector)
{
	int             randno;
	int             i;
	int		fd;

/* well, I added this to increase the security for user passwords.
   we use /dev/urandom here, as /dev/random might block and we don't
   need that much randomness. BTW, great idea, Ted!     -lf, 03/18/95	*/

	if ((fd = open(PPP_PATH_DEV_URANDOM, O_RDONLY)) >= 0)
	{
		unsigned char *pos;
		int readcount;

		i = AUTH_VECTOR_LEN;
		pos = vector;
		while (i > 0)
		{
			readcount = read(fd, (char *)pos, i);
			pos += readcount;
			i -= readcount;
		}

		close(fd);
		return;
	} /* else fall through */

	for (i = 0; i < AUTH_VECTOR_LEN;)
	{
		randno = magic();
		memcpy ((char *) vector, (char *) &randno, sizeof (int));
		vector += sizeof (int);
		i += sizeof (int);
	}

	return;
}
