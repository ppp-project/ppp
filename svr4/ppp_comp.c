/*
 * ppp_comp.c - STREAMS module for kernel-level compression and CCP support.
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
 * $Id: ppp_comp.c,v 1.2 1995/05/19 02:18:11 paulus Exp $
 */

/*
 * This file is used under Solaris 2.
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
#include <sys/cmn_err.h>
#include <net/ppp_defs.h>
#include <net/pppio.h>
#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <netinet/ip.h>
#include <net/vjcompress.h>

#define ALLOCATE(n)	kmem_alloc((n), KM_NOSLEEP)
#define FREE(p, n)	kmem_free((p), (n))

#define PACKETPTR	mblk_t *
#include <net/ppp-comp.h>

static int ppp_comp_open __P((queue_t *, dev_t *, int, int, cred_t *));
static int ppp_comp_close __P((queue_t *, int, cred_t *));
static int ppp_comp_rput __P((queue_t *, mblk_t *));
static int ppp_comp_rsrv __P((queue_t *));
static int ppp_comp_wput __P((queue_t *, mblk_t *));
static int ppp_comp_wsrv __P((queue_t *));
static void ppp_comp_ccp __P((queue_t *, mblk_t *, int));

static struct module_info minfo = {
    0xbadf, "ppp_comp", 0, INFPSZ, 16384, 4096,
};

static struct qinit r_init = {
    ppp_comp_rput, ppp_comp_rsrv, ppp_comp_open, ppp_comp_close,
    NULL, &minfo, NULL
};

static struct qinit w_init = {
    ppp_comp_wput, ppp_comp_wsrv, NULL, NULL, NULL, &minfo, NULL
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
    int		unit;
    int		ierrors;
    struct compressor *xcomp;
    void	*xstate;
    struct compressor *rcomp;
    void	*rstate;
    struct vjcompress vj_comp;
    int		vj_last_ierrors;
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
ppp_comp_open(q, devp, flag, sflag, credp)
    queue_t *q;
    dev_t *devp;
    int flag, sflag;
    cred_t *credp;
{
    struct ppp_comp_state *cp;

    if (q->q_ptr == NULL) {
	cp = (struct ppp_comp_state *) ALLOCATE(sizeof(struct ppp_comp_state));
	if (cp == NULL)
	    return ENOSR;
	WR(q)->q_ptr = q->q_ptr = cp;
	bzero((caddr_t)cp, sizeof(struct ppp_comp_state));
	cp->mru = PPP_MRU;
	cp->mtu = PPP_MRU;
	cp->xstate = NULL;
	cp->rstate = NULL;
	vj_compress_init(&cp->vj_comp, -1);
	qprocson(q);
    }
    return 0;
}

static int
ppp_comp_close(q, flag, credp)
    queue_t *q;
    int flag;
    cred_t *credp;
{
    struct ppp_comp_state *cp;

    qprocsoff(q);
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
    int error, len;
    int flags, mask;
    struct compressor **comp;
    struct ppp_comp_stats *pcp;
    unsigned char *opt_data;
    int nxslots, nrslots;

    cp = (struct ppp_comp_state *) q->q_ptr;
    switch (mp->b_datap->db_type) {

    case M_DATA:
	putq(q, mp);
	break;

    case M_IOCTL:
	iop = (struct iocblk *) mp->b_rptr;
	error = EINVAL;
	switch (iop->ioc_cmd) {

	case PPPIO_CFLAGS:
	    /* set/get CCP state */
	    if (iop->ioc_count != 2 * sizeof(int))
		break;
	    flags = ((int *) mp->b_cont->b_rptr)[0];
	    mask = ((int *) mp->b_cont->b_rptr)[1];
	    cp->flags = (cp->flags & ~mask) | (flags & mask);
	    if ((mask & CCP_ISOPEN) && (flags & CCP_ISOPEN) == 0) {
		if (cp->xstate != NULL) {
		    (*cp->xcomp->comp_free)(cp->xstate);
		    cp->xstate = NULL;
		}
		if (cp->rstate != NULL) {
		    (*cp->rcomp->decomp_free)(cp->rstate);
		    cp->rstate = NULL;
		}
		cp->flags &= ~CCP_ISUP;
	    }
	    error = 0;
	    iop->ioc_count = sizeof(int);
	    ((int *) mp->b_cont->b_rptr)[0] = cp->flags;
	    mp->b_cont->b_wptr = mp->b_cont->b_rptr + sizeof(int);
	    break;

	case PPPIO_VJINIT:
	    /*
	     * Initialize VJ compressor/decompressor
	     */
	    if (iop->ioc_count != 2)
		break;
	    nxslots = mp->b_cont->b_rptr[0] + 1;
	    nrslots = mp->b_cont->b_rptr[1] + 1;
	    if (nxslots > MAX_STATES || nrslots > MAX_STATES)
		break;
	    vj_compress_init(&cp->vj_comp, nxslots);
	    cp->vj_last_ierrors = cp->ierrors;
	    error = 0;
	    iop->ioc_count = 0;
	    break;

	case PPPIO_XCOMP:
	case PPPIO_RCOMP:
	    if (iop->ioc_count <= 0)
		break;
	    opt_data = mp->b_cont->b_rptr;
	    len = mp->b_cont->b_wptr - opt_data;
	    if (len > iop->ioc_count)
		len = iop->ioc_count;
	    if (opt_data[1] < 2 || opt_data[1] > len)
		break;
	    for (comp = ppp_compressors; *comp != NULL; ++comp)
		if ((*comp)->compress_proto == opt_data[0]) {
		    /* here's the handler! */
		    error = 0;
		    if (iop->ioc_cmd == PPPIO_XCOMP) {
			if (cp->xstate != NULL)
			    (*cp->xcomp->comp_free)(cp->xstate);
			cp->xcomp = *comp;
			cp->xstate = (*comp)->comp_alloc(opt_data, len);
			if (cp->xstate == NULL)
			    error = ENOSR;
		    } else {
			if (cp->rstate != NULL)
			    (*cp->rcomp->decomp_free)(cp->rstate);
			cp->rcomp = *comp;
			cp->rstate = (*comp)->decomp_alloc(opt_data, len);
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
	    error = -1;
	    break;

	default:
	    error = -1;
	    break;
	}

	if (error < 0)
	    putnext(q, mp);
	else if (error == 0) {
	    mp->b_datap->db_type = M_IOCACK;
	    qreply(q, mp);
	} else {
	    mp->b_datap->db_type = M_IOCNAK;
	    iop->ioc_error = error;
	    iop->ioc_count = 0;
	    qreply(q, mp);
	}
	break;

    case M_CTL:
	switch (*mp->b_rptr) {
	case PPPCTL_MTU:
	    cp->mtu = ((unsigned short *)mp->b_rptr)[1];
	    break;
	case PPPCTL_MRU:
	    cp->mru = ((unsigned short *)mp->b_rptr)[1];
	    break;
	case PPPCTL_UNIT:
	    cp->unit = mp->b_rptr[1];
	    break;
	}
	putnext(q, mp);
	break;

    default:
	putnext(q, mp);
    }
}

static int
ppp_comp_wsrv(q)
    queue_t *q;
{
    mblk_t *mp, *cmp;
    struct ppp_comp_state *cp;
    int len, proto, type;
    struct ip *ip;
    unsigned char *vjhdr, *dp;

    cp = (struct ppp_comp_state *) q->q_ptr;
    while ((mp = getq(q)) != 0) {
	/* assert(mp->b_datap->db_type == M_DATA) */
	if (!canputnext(q)) {
	    putbq(q, mp);
	    return;
	}

	/* first find out what the protocol is */
	if (mp->b_wptr - mp->b_rptr < PPP_HDRLEN
	    && !pullupmsg(mp, PPP_HDRLEN)) {
	    freemsg(mp);	/* give up on it */
	    continue;
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
				&cp->vj_comp, (cp->flags & COMP_VJCCID),
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
    }
}

static int
ppp_comp_rput(q, mp)
    queue_t *q;
    mblk_t *mp;
{
    struct ppp_comp_state *cp;

    cp = (struct ppp_comp_state *) q->q_ptr;
    switch (mp->b_datap->db_type) {

    case M_DATA:
	putq(q, mp);
	break;

    case M_CTL:
	switch (mp->b_rptr[0]) {
	case PPPCTL_IERROR:
	    ++cp->ierrors;
	    break;
	}
	putnext(q, mp);
	break;

    default:
	putnext(q, mp);
    }
}

static int
ppp_comp_rsrv(q)
    queue_t *q;
{
    int proto, rv;
    mblk_t *mp, *dmp, *np;
    unsigned char *dp, *iphdr;
    struct ppp_comp_state *cp;
    int len, hlen, vjlen, iphlen;
    int oldierrors;

    cp = (struct ppp_comp_state *) q->q_ptr;
    oldierrors = cp->ierrors;
    while ((mp = getq(q)) != 0) {
	/* assert(mp->b_datap->db_type == M_DATA) */
	if (!canputnext(q)) {
	    putbq(q, mp);
	    return;
	}

	/*
	 * First do address/control and protocol "decompression".
	 */
	len = msgdsize(mp);
	if (len > PPP_HDRLEN)
	    len = PPP_HDRLEN;
	if (mp->b_wptr - mp->b_rptr < len && !pullupmsg(mp, len)) {
	    ++cp->ierrors;
	    freemsg(mp);
	    continue;
	}
	dp = mp->b_rptr;
	if (PPP_ADDRESS(dp) == PPP_ALLSTATIONS && PPP_CONTROL(dp) == PPP_UI)
	    dp += 2;			/* skip address/control */
	proto = 0;
	if ((dp[0] & 1) == 0)
	    proto = *dp++ << 8;		/* grab high byte of protocol */
	proto += *dp++;			/* grab low byte of protocol */
	if (dp > mp->b_wptr) {
	    ++cp->ierrors;		/* short/bogus packet */
	    freemsg(mp);
	    continue;
	}
	if ((dp -= PPP_HDRLEN) < mp->b_datap->db_base) {
	    /* yucko, need a new message block */
	    mp->b_rptr = dp;
	    np = allocb(PPP_HDRLEN, BPRI_MED);
	    if (np == 0) {
		++cp->ierrors;
		freemsg(mp);
		continue;
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
			continue;
		    case DECOMP_ERROR:
			cp->flags |= CCP_ERROR;
			++cp->ierrors;
			break;
		    case DECOMP_FATALERROR:
			cp->flags |= CCP_FATALERROR;
			++cp->ierrors;
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
	proto = PPP_PROTOCOL(mp->b_rptr);
	if (proto == PPP_VJC_COMP || proto == PPP_VJC_UNCOMP) {
	    if ((cp->flags & DECOMP_VJC) == 0) {
		++cp->ierrors;	/* ? */
		freemsg(mp);
		continue;
	    }
	    if (cp->ierrors != cp->vj_last_ierrors) {
		vj_uncompress_err(&cp->vj_comp);
		cp->vj_last_ierrors = cp->ierrors;
	    }
	    len = msgdsize(mp);
	    hlen = (proto == PPP_VJC_COMP? MAX_VJHDR: MAX_IPHDR) + PPP_HDRLEN;
	    if (hlen > len)
		hlen = len;
	    if (mp->b_wptr - mp->b_rptr < hlen && !pullupmsg(mp, hlen)) {
		++cp->ierrors;
		freemsg(mp);
		continue;
	    }

	    if (proto == PPP_VJC_COMP) {
		mp->b_rptr += PPP_HDRLEN;
		vjlen = vj_uncompress_tcp(mp->b_rptr, mp->b_wptr - mp->b_rptr,
					  len - PPP_HDRLEN, &cp->vj_comp,
					  &iphdr, &iphlen);
		if (vjlen < 0
		    || (np = allocb(iphlen + PPP_HDRLEN + 4, BPRI_MED)) == 0) {
		    ++cp->ierrors;
		    freemsg(mp);
		    continue;
		}

		mp->b_rptr += vjlen;	/* drop off VJ header */
		dp = np->b_rptr;	/* prepend mblk with TCP/IP hdr */
		dp[0] = PPP_ALLSTATIONS; /* reconstruct PPP header */
		dp[1] = PPP_UI;
		dp[2] = PPP_IP >> 8;
		dp[3] = PPP_IP;
		bcopy(iphdr, dp + PPP_HDRLEN, iphlen);
		np->b_wptr = dp + iphlen + PPP_HDRLEN;
		np->b_cont = mp;

		/* XXX there seems to be a bug which causes panics in strread
		   if we make an mbuf with only the IP header in it :-( */
		if (mp->b_wptr - mp->b_rptr > 4) {
		    bcopy(mp->b_rptr, np->b_wptr, 4);
		    mp->b_rptr += 4;
		    np->b_wptr += 4;
		} else {
		    bcopy(mp->b_rptr, np->b_wptr, mp->b_wptr - mp->b_rptr);
		    np->b_wptr += mp->b_wptr - mp->b_rptr;
		    np->b_cont = mp->b_cont;
		    freeb(mp);
		}

		mp = np;

	    } else {
		if (!vj_uncompress_uncomp(mp->b_rptr + PPP_HDRLEN,
					  &cp->vj_comp)) {
		    ++cp->ierrors;
		    freemsg(mp);
		    continue;
		}
		mp->b_rptr[3] = PPP_IP;	/* fix up the PPP protocol field */
	    }
	}

	putnext(q, mp);
    }
#if DEBUG
    if (cp->ierrors != oldierrors)
	cmn_err(CE_CONT, "ppp_comp_rsrv ierrors now %d\n", cp->ierrors);
#endif
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
			 cp->unit, 0, 0))
		    cp->flags |= CCP_COMP_RUN;
	    } else {
		if (cp->rstate != NULL
		    && (*cp->rcomp->decomp_init)
		        (cp->rstate, dp + CCP_HDRLEN, clen - CCP_HDRLEN,
			 cp->unit, 0, cp->mru, 0))
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

#if DEBUG
dump_msg(mp)
    mblk_t *mp;
{
    dblk_t *db;

    while (mp != 0) {
	db = mp->b_datap;
	cmn_err(CE_CONT, "mp=%x cont=%x rptr=%x wptr=%x datap=%x\n",
		mp, mp->b_cont, mp->b_rptr, mp->b_wptr, db);
	cmn_err(CE_CONT, "  base=%x lim=%x ref=%d type=%d struioflag=%d\n",
		db->db_base, db->db_lim, db->db_ref, db->db_type,
		db->db_struioflag);
	mp = mp->b_cont;
    }
}
#endif
