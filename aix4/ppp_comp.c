/*
 * ppp_comp.c - STREAMS module for kernel-level CCP support.
 *
 * Copyright (c) 1994 The Australian National University.
 * All rights reserved.
 *
 * Permission to use, copy, modify, and distribute this software and its
 * documentation is hereby granted, provided that the above copyright
 * notice appears in all copies.  This software is provided without any
 * warranty, express or implied. The Australian National University
 * makes no representations about the suitability of this software for
 * any purpose.
 *
 * IN NO EVENT SHALL THE AUSTRALIAN NATIONAL UNIVERSITY BE LIABLE TO ANY
 * PARTY FOR DIRECT, INDIRECT, SPECIAL, INCIDENTAL, OR CONSEQUENTIAL DAMAGES
 * ARISING OUT OF THE USE OF THIS SOFTWARE AND ITS DOCUMENTATION, EVEN IF
 * THE AUSTRALIAN NATIONAL UNIVERSITY HAVE BEEN ADVISED OF THE POSSIBILITY
 * OF SUCH DAMAGE.
 *
 * THE AUSTRALIAN NATIONAL UNIVERSITY SPECIFICALLY DISCLAIMS ANY WARRANTIES,
 * INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY
 * AND FITNESS FOR A PARTICULAR PURPOSE.  THE SOFTWARE PROVIDED HEREUNDER IS
 * ON AN "AS IS" BASIS, AND THE AUSTRALIAN NATIONAL UNIVERSITY HAS NO
 * OBLIGATION TO PROVIDE MAINTENANCE, SUPPORT, UPDATES, ENHANCEMENTS,
 * OR MODIFICATIONS.
 *
 * $Id: ppp_comp.c,v 1.3 1995/04/26 04:15:48 paulus Exp $
 */

#include <net/net_globals.h>
#include <sys/types.h>
#include <sys/param.h>
#include <sys/errno.h>
#include <sys/user.h>
#include <sys/stream.h>
#include <sys/stropts.h>
#include <sys/strconf.h>
#include <sys/device.h>
#include <sys/syslog.h>
#include <sys/socket.h>
#include <net/if.h>
#include <net/ppp_defs.h>
#include <net/ppp_str.h>

#define PACKETPTR	mblk_t *
#include <net/ppp-comp.h>

static int ppp_comp_open(), ppp_comp_close();
static int ppp_comp_rput(), ppp_comp_wput();
static void ppp_comp_ccp();

static struct module_info minfo = {
    0xbadf, "ppp_compress", 0, INFPSZ, 16384, 4096,
};

static struct qinit r_init = {
    ppp_comp_rput, NULL, ppp_comp_open, ppp_comp_close,
    NULL, &minfo, NULL
};

static struct qinit w_init = {
    ppp_comp_wput, NULL, NULL, NULL, NULL, &minfo, NULL
};

struct streamtab ppp_compinfo = {
    &r_init, &w_init, NULL, NULL
};

struct ppp_comp_state {
    int 	ccp_state;
    int		debug;
    int		mru;
    struct compressor *xcomp;
    void	*xstate;
    struct compressor *rcomp;
    void	*rstate;
};

/* Bits in ccp_state are as defined in ppp_str.h. */
#define CCP_ERR		(CCP_ERROR | CCP_FATALERROR)

/*
 * List of compressors we know about.
 */

extern struct compressor ppp_bsd_compress;

struct compressor *ppp_compressors[] = {
    &ppp_bsd_compress,
    NULL
};

strconf_t pppcompconf = {
    "pppcomp", &ppp_compinfo, STR_NEW_OPEN, 0, SQLVL_DEFAULT, (void *) 0
};

int pppcomp_load(int cmd, struct uio *uiop)
{
    int rc = 0;

    switch (cmd) {
        case CFG_INIT:
            rc = str_install(STR_LOAD_MOD, &pppcompconf);
            break;
        case CFG_TERM:
            rc = str_install(STR_UNLOAD_MOD, &pppcompconf);
            break;
        default:
            rc = EINVAL;
            break;
    }
    return(rc);
}

static int
ppp_comp_open(q, dev, flag, sflag)
    queue_t *q;
    dev_t dev;
    int flag;
    int sflag;
{
    struct ppp_comp_state *cp;

    if (q->q_ptr == NULL) {
	cp = (struct ppp_comp_state *)
	    xmalloc(sizeof(struct ppp_comp_state), 0, pinned_heap);
	if (cp == NULL) {
	    return(ENOSR);
	}
	bzero(cp, sizeof(struct ppp_comp_state));
	OTHERQ(q)->q_ptr = q->q_ptr = (caddr_t) cp;
	cp->ccp_state = 0;
	cp->debug = 0;
	cp->mru = PPP_MRU;
	cp->xstate = NULL;
	cp->rstate = NULL;
    }
    return 0;
}

static int
ppp_comp_close(q)
    queue_t *q;
{
    struct ppp_comp_state *cp;

    cp = (struct ppp_comp_state *) q->q_ptr;
    if (cp != NULL) {
	if (cp->xstate != NULL)
	    (*cp->xcomp->comp_free)(cp->xstate);
	if (cp->rstate != NULL)
	    (*cp->rcomp->decomp_free)(cp->rstate);
	xmfree(cp, pinned_heap);
	q->q_ptr = NULL;
	OTHERQ(q)->q_ptr = NULL;
    }
    return 0;
}

static int
ppp_comp_wput(q, mp)
    queue_t *q;
    mblk_t *mp;
{
    struct iocblk *iop;
    struct ppp_comp_state *cp;
    mblk_t *cmp;
    int error, len, proto, state;
    struct ppp_option_data *odp;
    struct compressor **comp;
    struct ppp_comp_stats *pcp;

    cp = (struct ppp_comp_state *) q->q_ptr;
    switch (mp->b_datap->db_type) {

    case M_CTL:
        switch (*(u_char *) mp->b_rptr) {
        case IF_GET_CSTATS:
            freemsg(mp);
            mp = allocb(sizeof(struct ppp_comp_stats) + sizeof(u_long),
                        BPRI_HI);
            if (mp != NULL) {
                *(u_char *) mp->b_wptr = IF_CSTATS;
                mp->b_wptr += sizeof(u_long); /* should be enough alignment */
                pcp = (struct ppp_comp_stats *) mp->b_wptr;
                mp->b_wptr += sizeof(struct ppp_comp_stats);
                bzero(pcp, sizeof(struct ppp_comp_stats));
                if (cp->xstate != NULL)
                    (*cp->xcomp->comp_stat)(cp->xstate, &pcp->c);
                if (cp->rstate != NULL)
                    (*cp->rcomp->decomp_stat)(cp->rstate, &pcp->d);
                qreply(q, mp);
            }
            break;
        default:
            putnext(q, mp);
        }
        break;

    case M_DATA:
	/* first find out what the protocol is */
	if (mp->b_wptr - mp->b_rptr >= PPP_HDRLEN
	    || pullupmsg(mp, PPP_HDRLEN)) {
	    proto = PPP_PROTOCOL(mp->b_rptr);
	    if (proto == PPP_CCP)
		ppp_comp_ccp(q, mp, 0);
	    else if (proto != PPP_LCP && (cp->ccp_state & CCP_COMP_RUN)
		     && cp->xstate != NULL) {
		len = msgdsize(mp);
		(*cp->xcomp->compress)(cp->xstate, &cmp, mp, len,
				       (cp->ccp_state & CCP_ISUP? len: 0));
		/* XXX we really want the MTU here, not len */
		if (cmp != NULL) {
		    freemsg(mp);
		    mp = cmp;
		}
	    }
	}
	putnext(q, mp);
	break;

    case M_IOCTL:
	iop = (struct iocblk *) mp->b_rptr;
	error = -1;
	switch ((unsigned int)iop->ioc_cmd) {

	case SIOCSIFCOMP:
	    /* set CCP state */
	    if ((iop->ioc_count != sizeof(int)) &&
		(iop->ioc_count != TRANSPARENT)) {
		error = EINVAL;
		break;
	    }
	    state = (*(int *) mp->b_cont->b_rptr) & (CCP_ISUP | CCP_ISOPEN);
	    if ((state & CCP_ISOPEN) == 0) {
		if (cp->xstate != NULL) {
		    (*cp->xcomp->comp_free)(cp->xstate);
		    cp->xstate = NULL;
		}
		if (cp->rstate != NULL) {
		    (*cp->rcomp->decomp_free)(cp->rstate);
		    cp->rstate = NULL;
		}
		cp->ccp_state = 0;
	    } else {
		cp->ccp_state = (cp->ccp_state & ~CCP_ISUP) | state;
	    }
	    if (cp->debug)
		bsdlog(LOG_INFO, "SIOCSIFCOMP %x, state = %x\n",
		    *(int *) mp->b_cont->b_rptr, cp->ccp_state);
	    error = 0;
	    iop->ioc_count = 0;
	    break;

	case SIOCGIFCOMP:
	    if ((mp->b_cont = allocb(sizeof(int), BPRI_MED)) == NULL) {
		error = ENOSR;
		break;
	    }
	    *(int *)mp->b_cont->b_wptr = cp->ccp_state;
	    mp->b_cont->b_wptr += iop->ioc_count = sizeof(int);
	    break;

	case SIOCSCOMPRESS:
	    error = EINVAL;
	    if (iop->ioc_count != TRANSPARENT)
		break;
	    odp = *((struct ppp_option_data **) mp->b_cont->b_rptr);
	    len = sizeof(odp->opt_data);
	    if (len > odp->length)
		len = odp->length;
	    if (odp->opt_data[1] < 2 || odp->opt_data[1] > len)
		break;
	    for (comp = ppp_compressors; *comp != NULL; ++comp)
		if ((*comp)->compress_proto == odp->opt_data[0]) {
		    /* here's the handler! */
		    error = 0;
		    if (odp->transmit) {
			if (cp->xstate != NULL)
			    (*cp->xcomp->comp_free)(cp->xstate);
			cp->xcomp = *comp;
			cp->xstate = (*comp)->comp_alloc(odp->opt_data, len);
			if (cp->xstate == NULL)
			    error = ENOSR;
		    } else {
			if (cp->rstate != NULL)
			    (*cp->rcomp->decomp_free)(cp->rstate);
			cp->rcomp = *comp;
			cp->rstate = (*comp)->decomp_alloc(odp->opt_data, len);
			if (cp->rstate == NULL)
			    error = ENOSR;
		    }
		    if (cp->debug)
			bsdlog(LOG_INFO, "SIOCSCOMPRESS %s len=%d\n",
			    odp->transmit? "xmit": "recv", len);
		    break;
		}
	    iop->ioc_count = 0;
	    break;

	case SIOCSIFDEBUG:
	    /* set our debug flag from this */
	    if ((iop->ioc_count == TRANSPARENT) ||
		(iop->ioc_count == sizeof(int))) {
		cp->debug = *(int *) mp->b_cont->b_rptr & 1;
	    }
	    break;

	case SIOCSIFMRU:
	    /* remember this value */
	    if ((iop->ioc_count == TRANSPARENT) ||
		(iop->ioc_count == sizeof(int))) {
		cp->mru = *(int *) mp->b_cont->b_rptr;
	    }
	    break;

	}

	if (error < 0)
	    putnext(q, mp);
	else if (error == 0) {
	    mp->b_datap->db_type = M_IOCACK;
	    qreply(q, mp);
	} else {
	    mp->b_datap->db_type = M_IOCNAK;
	    iop->ioc_count = 0;
	    qreply(q, mp);
	}
	break;

    default:
	putnext(q, mp);
    }
}

static int
ppp_comp_rput(q, mp)
    queue_t *q;
    mblk_t *mp;
{
    int proto, rv;
    mblk_t *dmp;
    struct ppp_comp_state *cp;

    cp = (struct ppp_comp_state *) q->q_ptr;
    switch (mp->b_datap->db_type) {

    case M_DATA:
	/* possibly a compressed packet to decompress,
	   or a CCP packet to take notice of. */
	if (mp->b_wptr - mp->b_rptr >= PPP_HDRLEN
	    || pullupmsg(mp, PPP_HDRLEN)) {
	    proto = PPP_PROTOCOL(mp->b_rptr);
	    if (proto == PPP_CCP)
		ppp_comp_ccp(q, mp, 1);
	    else if (proto == PPP_COMP) {
		if ((cp->ccp_state & CCP_ISUP)
		    && (cp->ccp_state & CCP_DECOMP_RUN) && cp->rstate
		    && (cp->ccp_state & CCP_ERR) == 0) {
		    rv = (*cp->rcomp->decompress)(cp->rstate, mp, &dmp);
		    if (dmp != NULL) {
			freemsg(mp);
			mp = dmp;
		    } else {
			switch (rv) {
			case DECOMP_OK:
			    /* no error, but no packet returned */
			    freemsg(mp);
			    mp = NULL;
			    break;
			case DECOMP_ERROR:
			    cp->ccp_state |= CCP_ERROR;
			    break;
			case DECOMP_FATALERROR:
			    cp->ccp_state |= CCP_FATALERROR;
			    break;
			}
		    }
		}
	    } else if (cp->rstate && (cp->ccp_state & CCP_DECOMP_RUN)) {
		(*cp->rcomp->incomp)(cp->rstate, mp);
	    }
	}
	if (mp != NULL)
	    putnext(q, mp);
	break;

    default:
	putnext(q, mp);
    }
}

static void
ppp_comp_ccp(q, mp, rcvd)
    queue_t *q;
    mblk_t *mp;
    int rcvd;
{
    int len, clen;
    struct ppp_comp_state *cp;
    unsigned char *dp;

    len = msgdsize(mp);
    if (len < PPP_HDRLEN + CCP_HDRLEN || !pullupmsg(mp, len))
	return;
    cp = (struct ppp_comp_state *) q->q_ptr;
    dp = mp->b_rptr + PPP_HDRLEN;
    len -= PPP_HDRLEN;
    clen = CCP_LENGTH(dp);
    if (clen > len)
	return;
    if (cp->debug)
	bsdlog(LOG_INFO, "CCP %s: code=%x len=%d\n", rcvd? "rcvd": "sent",
	    CCP_CODE(dp), clen);

    switch (CCP_CODE(dp)) {
    case CCP_CONFREQ:
    case CCP_TERMREQ:
    case CCP_TERMACK:
	cp->ccp_state &= ~CCP_ISUP;
	break;

    case CCP_CONFACK:
	if ((cp->ccp_state & (CCP_ISOPEN | CCP_ISUP)) == CCP_ISOPEN
	    && clen >= CCP_HDRLEN + CCP_OPT_MINLEN
	    && clen >= CCP_HDRLEN + CCP_OPT_LENGTH(dp + CCP_HDRLEN)) {
	    if (!rcvd) {
		if (cp->xstate != NULL
		    && (*cp->xcomp->comp_init)
		        (cp->xstate, dp + CCP_HDRLEN, clen - CCP_HDRLEN,
			 0, /* XXX: should be unit */
			 cp->debug))
		    cp->ccp_state |= CCP_COMP_RUN;
	    } else {
		if (cp->rstate != NULL
		    && (*cp->rcomp->decomp_init)
		        (cp->rstate, dp + CCP_HDRLEN, clen - CCP_HDRLEN,
			 0/* unit */, 0, cp->mru, cp->debug))
		    cp->ccp_state = (cp->ccp_state & ~CCP_ERR)
			| CCP_DECOMP_RUN;
	    }
	}
	break;

    case CCP_RESETACK:
	if (cp->ccp_state & CCP_ISUP) {
	    if (!rcvd) {
		if (cp->xstate && (cp->ccp_state & CCP_COMP_RUN))
		    (*cp->xcomp->comp_reset)(cp->xstate);
	    } else {
		if (cp->rstate && (cp->ccp_state & CCP_DECOMP_RUN)) {
		    (*cp->rcomp->decomp_reset)(cp->rstate);
		    cp->ccp_state &= ~CCP_ERROR;
		}
	    }
	}
	break;
    }

    if (cp->debug)
	bsdlog(LOG_INFO, "ccp_state = %x\n", cp->ccp_state);
}
