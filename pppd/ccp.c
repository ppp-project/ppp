/*
 * ccp.c - PPP Compression Control Protocol.
 */

#ifndef lint
static char rcsid[] = "$Id: ccp.c,v 1.2 1994/08/22 00:38:36 paulus Exp $";
#endif

#include <syslog.h>
#include <sys/ioctl.h>

#include "pppd.h"
#include "ppp.h"
#include "fsm.h"
#include "ccp.h"

fsm ccp_fsm[NPPP];
ccp_options ccp_wantoptions[NPPP];	/* what to request the peer to use */
ccp_options ccp_gotoptions[NPPP];	/* what the peer agreed to do */
ccp_options ccp_allowoptions[NPPP];	/* what we'll agree to do */
ccp_options ccp_hisoptions[NPPP];	/* what we agreed to do */

/*
 * Callbacks for fsm code.
 */
static void ccp_resetci __ARGS((fsm *));
static int  ccp_cilen __ARGS((fsm *));
static void ccp_addci __ARGS((fsm *, u_char *, int *));
static int  ccp_ackci __ARGS((fsm *, u_char *, int));
static int  ccp_nakci __ARGS((fsm *, u_char *, int));
static int  ccp_rejci __ARGS((fsm *, u_char *, int));
static int  ccp_reqci __ARGS((fsm *, u_char *, int *, int));
static void ccp_up __ARGS((fsm *));
static void ccp_down __ARGS((fsm *));
static int  ccp_extcode __ARGS((fsm *, int, int, u_char *, int));
static void ccp_rack_timeout __ARGS(());

static fsm_callbacks ccp_callbacks = {
    ccp_resetci,
    ccp_cilen,
    ccp_addci,
    ccp_ackci,
    ccp_nakci,
    ccp_rejci,
    ccp_reqci,
    ccp_up,
    ccp_down,
    NULL,
    NULL,
    NULL,
    NULL,
    ccp_extcode,
    "CCP"
};

/*
 * Length of configuration options, which describe possible
 * compression methods.
 */
#define CILEN_BSD	3

/*
 * Configuration option values for compression methods.
 */
#define CI_BSD_COMPRESS	0x21

/*
 * Local state (mainly for handling reset-reqs and reset-acks
 */
static int ccp_localstate[NPPP];
#define RACK_PENDING	1	/* waiting for reset-ack */
#define RREQ_REPEAT	2	/* send another reset-req if no reset-ack */

#define RACKTIMEOUT	1	/* second */

/*
 * ccp_init - initialize CCP.
 */
void
ccp_init(unit)
    int unit;
{
    fsm *f = &ccp_fsm[unit];

    f->unit = unit;
    f->protocol = CCP;
    f->callbacks = &ccp_callbacks;
    fsm_init(f);

    memset(&ccp_wantoptions[unit],  0, sizeof(ccp_options));
    memset(&ccp_gotoptions[unit],   0, sizeof(ccp_options));
    memset(&ccp_allowoptions[unit], 0, sizeof(ccp_options));
    memset(&ccp_hisoptions[unit],   0, sizeof(ccp_options));

    ccp_wantoptions[0].bsd_bits = 12;	/* default value */

    ccp_allowoptions[0].bsd_compress = 1;
    ccp_allowoptions[0].bsd_bits = MAX_BSD_BITS;
}

/*
 * ccp_open - CCP is allowed to come up.
 */
void
ccp_open(unit)
    int unit;
{
    fsm *f = &ccp_fsm[unit];

    if (f->state != OPENED)
	ccp_flags_set(unit, 1, 0);
    if (!ccp_wantoptions[unit].bsd_compress)
	f->flags |= OPT_SILENT;
    fsm_open(f);
}

/*
 * ccp_close - Terminate CCP.
 */
void
ccp_close(unit)
    int unit;
{
    ccp_flags_set(unit, 0, 0);
    fsm_close(&ccp_fsm[unit]);
}

/*
 * ccp_lowerup - we may now transmit CCP packets.
 */
void
ccp_lowerup(unit)
    int unit;
{
    fsm_lowerup(&ccp_fsm[unit]);
}

/*
 * ccp_lowerdown - we may not transmit CCP packets.
 */
void
ccp_lowerdown(unit)
    int unit;
{
    fsm_lowerdown(&ccp_fsm[unit]);
}

/*
 * ccp_input - process a received CCP packet.
 */
void
ccp_input(unit, p, len)
    int unit;
    u_char *p;
    int len;
{
    fsm_input(&ccp_fsm[unit], p, len);
}

/*
 * Handle a CCP-specific code.
 */
static int
ccp_extcode(f, code, id, p, len)
    fsm *f;
    int code, id;
    u_char *p;
    int len;
{
    switch (code) {
    case RESETREQ:
	if (f->state != OPENED)
	    break;
	/* send a reset-ack, which the transmitter will see and
	   reset its compression state. */
	fsm_sdata(f, RESETACK, id, NULL, 0);
	break;

    case RESETACK:
	if (ccp_localstate[f->unit] & RACK_PENDING && id == f->reqid) {
	    ccp_localstate[f->unit] &= ~(RACK_PENDING | RREQ_REPEAT);
	    UNTIMEOUT(ccp_rack_timeout, (caddr_t) f);
	}
	break;

    default:
	return 0;
    }

    return 1;
}

/*
 * ccp_protrej - peer doesn't talk CCP.
 */
void
ccp_protrej(unit)
    int unit;
{
    ccp_flags_set(unit, 0, 0);
    fsm_lowerdown(&ccp_fsm[unit]);
}

/*
 * ccp_resetci - initialize at start of negotiation.
 */
static void
ccp_resetci(f)
    fsm *f;
{
    ccp_options *go = &ccp_gotoptions[f->unit];
    u_char opt_buf[16];

    *go = ccp_wantoptions[f->unit];
    if (go->bsd_compress) {
	opt_buf[0] = CI_BSD_COMPRESS;
	opt_buf[1] = CILEN_BSD;
	opt_buf[2] = go->bsd_bits;
	if (!ccp_test(f->unit, opt_buf, 3, 0))
	    go->bsd_compress = 0;
    }
}

/*
 * ccp_cilen - Return total length of our configuration info.
 */
static int
ccp_cilen(f)
    fsm *f;
{
    ccp_options *go = &ccp_gotoptions[f->unit];

    return (go->bsd_compress? CILEN_BSD: 0);
}

/*
 * ccp_addci - put our requests in a packet.
 */
static void
ccp_addci(f, p, lenp)
    fsm *f;
    u_char *p;
    int *lenp;
{
    ccp_options *go = &ccp_gotoptions[f->unit];
    u_char *p0 = p;

    if (go->bsd_compress) {
	p[0] = CI_BSD_COMPRESS;
	p[1] = CILEN_BSD;
	p[2] = go->bsd_bits;
	p += 3;
    }
    *lenp = p - p0;
}

/*
 * ccp_ackci - process a received configure-ack, and return
 * 1 iff the packet was OK.
 */
static int
ccp_ackci(f, p, len)
    fsm *f;
    u_char *p;
    int len;
{
    ccp_options *go = &ccp_gotoptions[f->unit];

    if (go->bsd_compress) {
	if (len != 3 || p[0] != CI_BSD_COMPRESS
	    || p[1] != CILEN_BSD || p[2] != go->bsd_bits)
	    return 0;
	p += 3;
	len -= 3;
    }
    if (len != 0)
	return 0;
    return 1;
}

/*
 * ccp_nakci - process received configure-nak.
 * Returns 1 iff the nak was OK.
 */
static int
ccp_nakci(f, p, len)
    fsm *f;
    u_char *p;
    int len;
{
    ccp_options *go = &ccp_gotoptions[f->unit];
    ccp_options no;		/* options we've seen already */
    ccp_options try;		/* options to ask for next time */

    memset(&no, 0, sizeof(no));
    try = *go;

    if (go->bsd_compress && len >= CILEN_BSD && p[0] == CI_BSD_COMPRESS
	&& p[1] == CILEN_BSD) {
	no.bsd_compress = 1;
	/*
	 * Peer wants us to use a different number of bits.
	 */
	if (p[2] < go->bsd_bits)
	    try.bsd_bits = p[2];
	p += CILEN_BSD;
	len -= CILEN_BSD;
    }

    /*
     * Have a look at any remaining options...???
     */

    if (len != 0)
	return 0;

    if (f->state != OPENED)
	*go = try;
    return 1;
}

/*
 * ccp_rejci - reject some of our suggested compression methods.
 */
static int
ccp_rejci(f, p, len)
    fsm *f;
    u_char *p;
    int len;
{
    ccp_options *go = &ccp_gotoptions[f->unit];
    ccp_options try;		/* options to request next time */

    try = *go;

    if (go->bsd_compress && len >= CILEN_BSD && p[0] == CI_BSD_COMPRESS
	&& p[1] == CILEN_BSD) {
	if (p[2] != go->bsd_bits)
	    return 0;
	try.bsd_compress = 0;
	p += CILEN_BSD;
	len -= CILEN_BSD;
    }

    if (len != 0)
	return 0;

    if (f->state != OPENED)
	*go = try;

    return 1;
}

/*
 * ccp_reqci - processed a received configure-request.
 * Returns CONFACK, CONFNAK or CONFREJ and the packet modified
 * appropriately.
 */
static int
ccp_reqci(f, p, lenp, dont_nak)
    fsm *f;
    u_char *p;
    int *lenp;
    int dont_nak;
{
    int ret, newret;
    u_char *p0, *retp;
    int len, clen, type;
    ccp_options *ho = &ccp_hisoptions[f->unit];
    ccp_options *ao = &ccp_allowoptions[f->unit];

    ret = CONFACK;
    retp = p0 = p;
    len = *lenp;

    memset(ho, 0, sizeof(ccp_options));

    while (len > 0) {
	newret = CONFACK;
	if (len < 2 || p[1] < 2 || p[1] > len) {
	    /* length is bad */
	    clen = len;
	    newret = CONFREJ;

	} else {
	    type = p[0];
	    clen = p[1];

	    switch (type) {
	    case CI_BSD_COMPRESS:
		if (!ao->bsd_compress || clen != CILEN_BSD) {
		    newret = CONFREJ;
		    break;
		}

		ho->bsd_compress = 1;
		ho->bsd_bits = p[2];
		if (ho->bsd_bits < MIN_BSD_BITS
		    || ho->bsd_bits > ao->bsd_bits) {
		    newret = CONFNAK;
		} else if (!ccp_test(f->unit, p, CILEN_BSD, 1)) {
		    if (ho->bsd_bits > MIN_BSD_BITS)
			newret = CONFNAK;
		    else
			newret = CONFREJ;
		}
		if (newret == CONFNAK && !dont_nak) {
		    p[2] = (ho->bsd_bits < ao->bsd_bits? MIN_BSD_BITS:
			    ao->bsd_bits);
		}

		break;

	    default:
		newret = CONFREJ;
	    }
	}

	if (!(newret == CONFACK || newret == CONFNAK && ret == CONFREJ)) {
	    /* we're returning this option */
	    ret = newret;
	    if (p != retp)
		BCOPY(p, retp, clen);
	    retp += clen;
	}

	p += clen;
	len -= clen;
    }

    if (ret != CONFACK)
	*lenp = retp - p0;
    return ret;
}

/*
 * CCP has come up - inform the kernel driver.
 */
static void
ccp_up(f)
    fsm *f;
{
    ccp_flags_set(f->unit, 1, 1);
}

/*
 * CCP has gone down - inform the kernel driver.
 */
static void
ccp_down(f)
    fsm *f;
{
    if (ccp_localstate[f->unit] & RACK_PENDING)
	UNTIMEOUT(ccp_rack_timeout, (caddr_t) f);
    ccp_localstate[f->unit] = 0;
    ccp_flags_set(f->unit, 1, 0);
}

/*
 * Print the contents of a CCP packet.
 */
char *ccp_codenames[] = {
    "ConfReq", "ConfAck", "ConfNak", "ConfRej",
    "TermReq", "TermAck", "CodeRej",
    NULL, NULL, NULL, NULL, NULL, NULL,
    "ResetReq", "ResetAck",
};

int
ccp_printpkt(p, plen, printer, arg)
    u_char *p;
    int plen;
    void (*printer) __ARGS((void *, char *, ...));
    void *arg;
{
    u_char *p0, *optend;
    int code, id, len;
    int optlen;

    p0 = p;
    if (plen < HEADERLEN)
	return 0;
    code = p[0];
    id = p[1];
    len = (p[2] << 8) + p[3];
    if (len < HEADERLEN || len > plen)
	return 0;

    if (code >= 1 && code <= sizeof(ccp_codenames) / sizeof(char *)
	&& ccp_codenames[code-1] != NULL)
	printer(arg, " %s", ccp_codenames[code-1]);
    else
	printer(arg, " code=0x%x", code);
    printer(arg, " id=0x%x", id);
    len -= HEADERLEN;
    p += HEADERLEN;

    switch (code) {
    case CONFREQ:
    case CONFACK:
    case CONFNAK:
    case CONFREJ:
	/* print list of possible compression methods */
	while (len >= 2) {
	    code = p[0];
	    optlen = p[1];
	    if (optlen < 2 || optlen > len)
		break;
	    printer(arg, " <");
	    len -= optlen;
	    optend = p + optlen;
	    switch (code) {
	    case CI_BSD_COMPRESS:
		if (optlen >= CILEN_BSD) {
		    printer(arg, "bsd %d", p[2]);
		    p += CILEN_BSD;
		}
		break;
	    }
	    while (p < optend)
		printer(arg, " %.2x", *p++);
	    printer(arg, ">");
	}
	break;
    }

    /* dump out the rest of the packet in hex */
    while (--len >= 0)
	printer(arg, " %.2x", *p++);

    return p - p0;
}

/*
 * We have received a packet that the decompressor failed to decompress.
 * Issue a reset-req (if we haven't issued one recently).
 */
void
ccp_datainput(unit, pkt, len)
    int unit;
    u_char *pkt;
    int len;
{
    fsm *f;

    f = &ccp_fsm[unit];
    if (f->state == OPENED) {
	if (!(ccp_localstate[unit] & RACK_PENDING)) {
	    fsm_sdata(f, RESETREQ, f->reqid = ++f->id, NULL, 0);
	    TIMEOUT(ccp_rack_timeout, (caddr_t) f, RACKTIMEOUT);
	    ccp_localstate[unit] |= RACK_PENDING;
	} else
	    ccp_localstate[unit] |= RREQ_REPEAT;
    }
}

/*
 * Timeout waiting for reset-ack.
 */
static void
ccp_rack_timeout(arg)
    caddr_t arg;
{
    fsm *f = (fsm *) arg;

    if (f->state == OPENED && ccp_localstate[f->unit] & RREQ_REPEAT) {
	fsm_sdata(f, RESETREQ, f->reqid, NULL, 0);
	TIMEOUT(ccp_rack_timeout, (caddr_t) f, RACKTIMEOUT);
	ccp_localstate[f->unit] &= ~RREQ_REPEAT;
    } else
	ccp_localstate[f->unit] &= ~RACK_PENDING;
}

