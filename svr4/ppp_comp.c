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
 * $Id: ppp_comp.c,v 1.1 1995/05/10 01:38:47 paulus Exp $
 */

/*
 * This file is used under SunOS 4.x, and OSF/1 on DEC Alpha.
 *
 * Beware that under OSF/1, the ioctl constants (SIOC*) end up
 * as 64-bit (long) values, so an ioctl constant should be cast to
 * int (32 bits) before being compared with the ioc_cmd field of
 * an iocblk structure.
 */

#include <sys/types.h>
#include <sys/param.h>
#include <sys/errno.h>
#include <sys/stream.h>
#include <sys/modctl.h>
#include <sys/conf.h>
#include <sys/kmem.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <net/ppp_defs.h>
#include <net/ppp_str.h>

#define ALLOCATE(n)	kmem_zalloc((n), KM_NOSLEEP)
#define FREE(p, n)	kmem_free((p), (n))

#define PACKETPTR	mblk_t *
#include <net/ppp-comp.h>

static int ppp_comp_open __P((queue_t *, dev_t *, int, int, cred_t *));
static int ppp_comp_close __P((queue_t *, int, cred_t *));
static int ppp_comp_rput __P((queue_t *, mblk_t *));
static int ppp_comp_wput __P((queue_t *, mblk_t *));
static void ppp_comp_ccp __P((queue_t *, mblk_t *, int));

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

static struct streamtab ppp_compinfo = {
    &r_init, &w_init, NULL, NULL
};

static struct fmodsw fsw = {
    "ppp_comp",
    &ppp_compinfo,
    D_NEW | D_MP | D_MTQPAIR
};

extern struct mod_ops mod_strmodops;

static struct modlstrmod modlstrmod = {
    &mod_strmodops,
    "PPP compression module",
    &fsw
};

static struct modlinkage modlinkage = {
    MODREV_1,
    (void *) &modlstrmod,
    NULL
};

struct ppp_comp_state {
    int		flags;
    int		mru;
    int		mtu;
    struct compressor *xcomp;
    void	*xstate;
    struct compressor *rcomp;
    void	*rstate;
    struct vjcompress vj_comp;
};

/* Bits in flags are as defined in pppio.h. */
#define CCP_ERR		(CCP_ERROR | CCP_FATALERROR)

#define MAX_IPHDR	128	/* max TCP/IP header size */
#define MAX_VJHDR	20	/* max VJ compressed header size (?) */

/*
 * List of compressors we know about.
 */

extern struct compressor ppp_bsd_compress;

struct compressor *ppp_compressors[] = {
#if DO_BSD_COMPRESS
    &ppp_bsd_compress,
#endif
    NULL
};

/*
 * Entry points for modloading.
 */
int
_init(void)
{
    return mod_install(&modlinkage);
}

int
_fini(void)
{
    return mod_remove(&modlinkage);
}

int
_info(mip)
    struct modinfo *mip;
{
    return mod_info(&modlinkage, mip);
}

/*
 * STREAMS module entry points.
 */
static int
ppp_comp_open(q, dev, flag, sflag, credp)
    queue_t *q;
    dev_t dev;
    int flag, sflag;
    cred_t *credp;
{
    struct ppp_comp_state *cp;

    if (q->q_ptr == NULL) {
	cp = (struct ppp_comp_state *) ALLOCATE(sizeof(struct ppp_comp_state));
	if (cp == NULL)
	    return ENOSR;
	OTHERQ(q)->q_ptr = q->q_ptr = cp;
	cp->flags = 0;
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
	FREE(cp, sizeof(struct ppp_comp_state));
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

    case M_DATA:
	/* first find out what the protocol is */
	if (mp->b_wptr - mp->b_rptr < PPP_HDRLEN
	    && !pullupmsg(mp, PPP_HDRLEN)) {
	    freemsg(mp);	/* give up on it */
	    break;
	}
	proto = PPP_PROTOCOL(mp->b_rptr);

	/*
	 * Do VJ compression if requested.
	 */
	if (proto == PPP_IP && (cp->flags & COMP_VJC)) {
	    len = msgdsize(mp);
	    if (len > MAX_IPHDR + PPP_HDRLEN)
		len = MAX_IPHDR + PPP_HDRLEN;
	    if (mp->b_wptr - mp->b_rptr >= len || pullupmsg(mp, len)) {
		ip = (struct ip *) (mp->b_rptr + PPP_HDRLEN);
		if (ip->ip_p == IPPROTO_TCP) {
		    type = vj_compress_tcp(ip, len - PPP_HDRLEN,
				cp->vj_comp, (cp->flags & COMP_VJCCID),
				&vjhdr);
		    switch (type) {
		    case TYPE_UNCOMPRESSED_TCP:
			mp->b_rptr[3] = proto = PPP_VJC_UNCOMP;
			break;
		    case TYPE_COMPRESSED_TCP:
			dp = vjhdr - PPP_HDRLEN;
			dp[1] = mp->b_rptr[1]; /* copy control field */
			dp[0] = mp->b_rptr[0]; /* copy address field */
			dp[2] = 0;		   /* set protocol field */
			dp[3] = proto = PPP_VJC_COMP;
			mp->b_rptr = dp;
			break;
		    }
		}
	    }
	}

	/*
	 * Do packet compression if enabled.
	 */
	if (proto == PPP_CCP)
	    ppp_comp_ccp(q, mp, 0);
	else if (proto != PPP_LCP && (cp->flags & CCP_COMP_RUN)
		 && cp->xstate != NULL) {
	    len = msgdsize(mp);
	    (*cp->xcomp->compress)(cp->xstate, &cmp, mp, len,
				   (cp->flags & CCP_ISUP? cp->mtu: 0));
	    if (cmp != NULL) {
		freemsg(mp);
		mp = cmp;
	    }
	}

	/*
	 * Do address/control and protocol compression if enabled.
	 */
	if (proto != PPP_LCP && (cp->flags & COMP_AC)) {
	    mp->b_rptr += 2;	/* drop the address & ctrl fields */
	    if (proto < 0x100 && (cp->flags & COMP_PROT))
		++mp->b_rptr;	/* drop the high protocol byte */
	} else if (proto < 0x100 && (cp->flags & COMP_PROT)) {
	    /* shuffle up the address & ctrl fields */
	    mp->b_rptr[2] = mp->b_rptr[1];
	    mp->b_rptr[1] = mp->b_rptr[0];
	    ++mp->b_rptr;
	}

	putnext(q, mp);
	break;

    case M_IOCTL:
	iop = (struct iocblk *) mp->b_rptr;
	error = -1;
	switch (iop->ioc_cmd) {

	case PPPIO_CFLAGS:
	    /* set CCP state */
	    if (iop->ioc_count != sizeof(int)) {
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
		cp->flags = 0;
	    } else {
		cp->flags = (cp->flags & ~CCP_ISUP) | state;
	    }
	    error = 0;
	    iop->ioc_count = 0;
	    break;

	case SIOCGIFCOMP:
	    if ((mp->b_cont = allocb(sizeof(int), BPRI_MED)) == NULL) {
		error = ENOSR;
		break;
	    }
	    *(int *)mp->b_cont->b_wptr = cp->flags;
	    mp->b_cont->b_wptr += iop->ioc_count = sizeof(int);
	    break;

	case PPPIO_COMPRESS:
	    error = EINVAL;
	    if (iop->ioc_count != sizeof(struct ppp_option_data))
		break;
	    odp = (struct ppp_option_data *) mp->b_cont->b_rptr;
	    len = mp->b_cont->b_wptr - (unsigned char *) odp->opt_data;
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
		    break;
		}
	    iop->ioc_count = 0;
	    break;

	case PPPIO_MRU:
	    /* remember this value */
	    if (iop->ioc_count == sizeof(int)) {
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
	/*
	 * First do address/control and protocol "decompression".
	 */
	len = msgdsize(mp);
	if (len > PPP_HDRLEN)
	    len = PPP_HDRLEN;
	if (mp->b_wptr - mp->b_rptr < len && !pullupmsg(mp, len)) {
	    /* XXX reset VJ */
	    freemsg(mp);
	    break;
	}
	dp = mp->b_rptr;
	if (PPP_ADDRESS(dp) == PPP_ALLSTATIONS && PPP_CONTROL(dp) == PPP_UI)
	    dp += 2;			/* skip address/control */
	proto = 0;
	if ((dp[0] & 1) == 0)
	    proto = *dp++ << 8;		/* grab high byte of protocol */
	proto += *dp++;			/* grab low byte of protocol */
	if (dp > mp->b_wptr) {
	    freemsg(mp);	/* short/bogus packet */
	    break;
	}
	if ((dp -= PPP_HDRLEN) < mp->b_datap->db_base) {
	    /* yucko, need a new message block */
	    mp->b_rptr = dp;
	    np = allocb(PPP_HDRLEN, BPRI_MED);
	    if (np == 0) {
		freemsg(mp);
		break;
	    }
	    linkb(np, mp);
	    mp = np;
	    dp = mp->b_rptr;
	    mp->b_wptr = dp + PPP_HDRLEN;
	} else
	    mp->b_rptr = dp;
	dp[0] = PPP_ALLSTATIONS;
	dp[1] = PPP_UI;
	dp[2] = proto >> 8;
	dp[3] = proto;

	/*
	 * Now see if we have a compressed packet to decompress,
	 * or a CCP packet to take notice of.
	 */
	proto = PPP_PROTOCOL(mp->b_rptr);
	if (proto == PPP_CCP)
	    ppp_comp_ccp(q, mp, 1);
	else if (proto == PPP_COMP) {
	    if ((cp->flags & CCP_ISUP)
		&& (cp->flags & CCP_DECOMP_RUN) && cp->rstate
		&& (cp->flags & CCP_ERR) == 0) {
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
			cp->flags |= CCP_ERROR;
			break;
		    case DECOMP_FATALERROR:
			cp->flags |= CCP_FATALERROR;
			break;
		    }
		}
	    }
	} else if (cp->rstate && (cp->flags & CCP_DECOMP_RUN)) {
	    (*cp->rcomp->incomp)(cp->rstate, mp);
	}

	/*
	 * Now do VJ decompression.
	 */

	if (mp != NULL)
	    putnext(q, mp);
	break;

    default:
	putnext(q, mp);
    }
}

/*
 * Handle a CCP packet being sent or received.
 */
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

    switch (CCP_CODE(dp)) {
    case CCP_CONFREQ:
    case CCP_TERMREQ:
    case CCP_TERMACK:
	cp->flags &= ~CCP_ISUP;
	break;

    case CCP_CONFACK:
	if ((cp->flags & (CCP_ISOPEN | CCP_ISUP)) == CCP_ISOPEN
	    && clen >= CCP_HDRLEN + CCP_OPT_MINLEN
	    && clen >= CCP_HDRLEN + CCP_OPT_LENGTH(dp + CCP_HDRLEN)) {
	    if (!rcvd) {
		if (cp->xstate != NULL
		    && (*cp->xcomp->comp_init)
		        (cp->xstate, dp + CCP_HDRLEN, clen - CCP_HDRLEN,
			 0, /* XXX: should be unit */ 0, 0))
		    cp->flags |= CCP_COMP_RUN;
	    } else {
		if (cp->rstate != NULL
		    && (*cp->rcomp->decomp_init)
		        (cp->rstate, dp + CCP_HDRLEN, clen - CCP_HDRLEN,
			 0/* unit */, 0, cp->mru, 0))
		    cp->flags = (cp->flags & ~CCP_ERR)
			| CCP_DECOMP_RUN;
	    }
	}
	break;

    case CCP_RESETACK:
	if (cp->flags & CCP_ISUP) {
	    if (!rcvd) {
		if (cp->xstate && (cp->flags & CCP_COMP_RUN))
		    (*cp->xcomp->comp_reset)(cp->xstate);
	    } else {
		if (cp->rstate && (cp->flags & CCP_DECOMP_RUN)) {
		    (*cp->rcomp->decomp_reset)(cp->rstate);
		    cp->flags &= ~CCP_ERROR;
		}
	    }
	}
	break;
    }

}
