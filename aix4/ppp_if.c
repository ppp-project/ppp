/*
  ppp_if.c - Streams PPP interface module

  top level module handles if_ and packetizing PPP packets.

  Copyright (C) 1990  Brad K. Clements, All Rights Reserved
  See copyright notice in NOTES

*/

#define	VJC	1
#include <sys/types.h>

#ifndef PPP_VD
#include "ppp.h"
#endif

#if NUM_PPP > 0

#define	STREAMS	1

#define	PPP_STATS	1	/* keep statistics */
#define	DEBUGS		1

#include <net/net_globals.h>
#include <sys/param.h>
#include <sys/stream.h>
#include <sys/stropts.h>
#include <sys/strconf.h>

#include <sys/device.h>
/*
#include <sys/user.h>
*/
/*
#include <sys/systm.h>
*/
#include <sys/mbuf.h>
#include <sys/socket.h>
#include <sys/errno.h>
#include <sys/ioctl.h>
#include <sys/file.h>
#include <sys/uio.h>
#include <net/if.h>
#include <net/route.h>
#include <net/netisr.h>
#include <netinet/in.h>
#include <netinet/in_var.h>
#define  _NETINET_IN_SYSTM_H_
typedef u_long  n_long;
#include <netinet/ip.h>

#include <net/ppp_defs.h>
#include <net/ppp_str.h>

#ifdef	VJC
#undef SPECIAL_I
#include <net/vjcompress.h>
#endif

#ifdef	PPP_STATS
#define	INCR(comp)	++p->pii_stats.comp
#else
#define	INCR(comp)
#endif

#define MAX_PKTSIZE	4096	/* max packet size including framing */
#define PPP_FRAMING	6	/* 4-byte header + 2-byte FCS */
#define MAX_IPHDR	128	/* max TCP/IP header size */
#define MAX_VJHDR	20	/* max VJ compressed header size (?) */

/*
 * Network protocols we support.
 */
#define NP_IP		0
#define NUM_NP		1	/* # protocols supported */

/*
 * Structure used within the ppp_if streams module.
 */
struct ppp_if_info {
    int			pii_flags;
    struct ifnet	pii_ifnet;
    queue_t		*pii_writeq;	/* used by ppp_output */
    enum NPmode		pii_npmode[NUM_NP];
    mblk_t		*pii_npq;	/* list of packets queued up */
    mblk_t		**pii_npq_tail;
#ifdef	VJC
    struct vjcompress	pii_sc_comp;	/* vjc control buffer */
#endif
#ifdef	PPP_STATS
    struct pppstat	pii_stats;
    struct ppp_comp_stats pii_cstats;
#endif
};

/*
 * Values for pii_flags.
 */
#define	PII_FLAGS_INUSE		0x1	/* in use by  a stream	*/
#define	PII_FLAGS_ATTACHED	0x8	/* already if_attached	*/
#define	PII_FLAGS_VJC_ON	0x10	/* VJ TCP header compression enabled */
#define PII_FLAGS_VJC_NOCCID	0x20	/* VJ: don't compress conn. id */
#define PII_FLAGS_VJC_REJ	0x40	/* receive: reject VJ comp */
#define PII_FLAGS_DEBUG		0x80	/* enable debug printout */

#ifdef	DEBUGS
#include <sys/syslog.h>
#define	DLOG(s,a) if (p->pii_flags&PII_FLAGS_DEBUG) bsdlog(LOG_INFO, s, a)
#else
#define	DLOG(s)	{}
#endif

#ifdef PPP_SNIT
#include <net/nit_if.h>
#include <netinet/if_ether.h>
/* Use a fake link level header to make etherfind and tcpdump happy. */
static struct ether_header header = {{1}, {2}, ETHERTYPE_IP};
static struct nit_if nif = {(caddr_t)&header, sizeof(header), 0, 0};
#endif

static	int	ppp_if_open(), ppp_if_close(), ppp_if_rput(), ppp_if_wput(),
		ppp_if_wsrv(), ppp_if_rsrv();

static 	struct	module_info	minfo ={
	0xbad,"ppp_if",0, INFPSZ, 16384, 4096
};

static	struct	qinit	r_init = {
	ppp_if_rput, ppp_if_rsrv, ppp_if_open, ppp_if_close, NULL, &minfo, NULL
};
static	struct	qinit	w_init = {
	ppp_if_wput, ppp_if_wsrv, ppp_if_open, ppp_if_close, NULL, &minfo, NULL
};
struct	streamtab	ppp_ifinfo = {
	&r_init, &w_init, NULL, NULL
};

typedef	struct ppp_if_info	PII;

PII	*pii;

int ppp_output(), ppp_ioctl();
static void if_release_addrs(), if_delete_route();

strconf_t pppconf = {
    "pppif", &ppp_ifinfo, STR_NEW_OPEN, 0, SQLVL_DEFAULT, (void *) 0
};

int ppp_load(int cmd, struct uio *uiop)
{
    int rc = 0;

    switch (cmd) {
        case CFG_INIT:
            rc = str_install(STR_LOAD_MOD, &pppconf);
            break;
        case CFG_TERM:
            rc = str_install(STR_UNLOAD_MOD, &pppconf);
            break;
        default:
            rc = EINVAL;
            break;
    }
    if ((rc == 0) && !(pii = xmalloc(sizeof(PII) * NUM_PPP, 0, pinned_heap)))
        rc = ENOMEM;
    else
	bzero(pii, sizeof(PII) * NUM_PPP);

    return(rc);
}

int
ppp_attach(unit)
    int	unit;
{
    register struct ifnet *ifp = &pii[unit].pii_ifnet;

    ifp->if_name = "ppp";
    ifp->if_type = IFT_PTPSERIAL;
    ifp->if_mtu  = PPP_MTU;
    ifp->if_flags = IFF_POINTOPOINT;
    ifp->if_unit  = unit;
    ifp->if_ioctl = ppp_ioctl;
    ifp->if_output = ppp_output;
    ifp->if_snd.ifq_maxlen = IFQ_MAXLEN;
    if_attach(ifp);
    if_nostat(ifp);
    pii[unit].pii_flags |= PII_FLAGS_ATTACHED;
}


int
ppp_unattach(unit)
    int	unit;
{
    struct ifnet *ifp = &pii[unit].pii_ifnet;
    struct ifnet **p;
    int s;

    if (!(pii[unit].pii_flags & PII_FLAGS_ATTACHED))
	return 0;

    /* remove interface from interface list */
    for (p = &ifp; *p; p = &((*p)->if_next)) {
	if (*p == ifp) {
	    *p = (*p)->if_next;

	    /* mark it down and flush it's que */
	    if_down(ifp);

	    /* free any addresses hanging off the intf */
	    if_release_addrs(ifp);

	    pii[unit].pii_flags &= ~PII_FLAGS_ATTACHED;

	    return 0;
	}
    }

    return -1;
}


static void
if_release_addrs(ifp)
register struct ifnet *ifp;
{
    register struct in_ifaddr **addr;
    register struct ifaddr *ifa, *ifanxt;
    register int s;
 
    if_delete_route(ifp);
 
    for (addr = &in_ifaddr; *addr; ) {
	if ((*addr)->ia_ifp == ifp)
	    *addr = (*addr)->ia_next;
	else
	    addr = &((*addr)->ia_next);
    }
 
    /*
     * Free all mbufs holding down this interface's address(es).
     */
    for (ifa = ifp->if_addrlist; ifa; ifa = ifanxt) {
	ifanxt = ifa->ifa_next;
	m_free(dtom(ifa));
    }
    ifp->if_addrlist = 0;
}

/*
 * Delete routes to the specified interface.
 * Hacked from rtrequest().
 */
static void
if_delete_route(ifp)
struct ifnet *ifp;
{
    extern int rttrash;		/* routes not in table but not freed */
    register struct mbuf **mprev, *m;
    register struct rtentry *route;
    register int i;
 
    /* search host rt tbl */
/*
    for (i = 0; i < RTHASHSIZ; i++) {
	mprev = &rthost[i];
	while (m = *mprev) {
	    route = mtod(m, struct rtentry *);
	    if (route->rt_ifp == ifp) {
		*mprev = m->m_next;
		if (route->rt_refcnt > 0) {
		    route->rt_flags &= ~RTF_UP;
		    rttrash++;
		    m->m_next = 0;
		} else {
		    m_free(m);
		}
	    } else
		mprev = &m->m_next;
	}
    }
*/
 
    /* search net rt tbl */
/*
    for (i = 0; i < RTHASHSIZ; i++) {
	mprev = &rtnet[i];
	while (m = *mprev) {
	    route = mtod(m, struct rtentry *);
	    if (route->rt_ifp == ifp) {
		*mprev = m->m_next;
		if (route->rt_refcnt > 0) {
		    route->rt_flags &= ~RTF_UP;
		    rttrash++;
		    m->m_next = 0;
		} else {
		    m_free(m);
		}
	    } else
		mprev = &m->m_next;
	}
    }
*/
} 

int
ppp_busy()
{
    int x;

    for (x = 0; x < NUM_PPP; x++) {
	if (pii[x].pii_flags & PII_FLAGS_INUSE)
	    return 1;
    }
    return 0;
}

static PII *
ppp_if_alloc()
{
    int s, x;
    PII *p;

    for (x = 0; x < NUM_PPP; x++)
	if (!(pii[x].pii_flags & PII_FLAGS_INUSE))
	    break;
    if (x == NUM_PPP) {		/* all buffers in use */
	return NULL;
    }
    p = &pii[x];
    p->pii_flags |= PII_FLAGS_INUSE;
    return p;
}

static void
ppp_if_init(q, p)
    queue_t *q;
    PII *p;
{
    int s, n;


#ifdef	VJC
    vj_compress_init(&p->pii_sc_comp, -1);
#endif
#ifdef	PPP_STATS
    bzero(&p->pii_stats, sizeof(p->pii_stats));
#endif
    if (!(p->pii_flags & PII_FLAGS_ATTACHED))
	ppp_attach(p - pii);			/* attach it */
    else
	p->pii_ifnet.if_mtu = PPP_MTU;
    p->pii_writeq = WR(q);
    /* set write Q and read Q to point here */
    WR(q)->q_ptr = q->q_ptr = (caddr_t) p;
    p->pii_ifnet.if_flags |= IFF_RUNNING;
    p->pii_flags &= PII_FLAGS_INUSE | PII_FLAGS_ATTACHED | PII_FLAGS_DEBUG;
    for (n = 0; n < NUM_NP; ++n)
	p->pii_npmode[n] = NPMODE_ERROR;
    p->pii_npmode[NP_IP] = NPMODE_PASS;	/* for backwards compatibility */
    p->pii_npq = NULL;
    p->pii_npq_tail = &p->pii_npq;

    DLOG("ppp_if%d: init\n", p - pii);
}

static int
ppp_if_open(q, dev, flag, sflag)
    queue_t	*q;
    dev_t	dev;
    int		flag, sflag;

{
    if (!suser()) {
	return(EPERM);
    }

    return (0);
}

static int
ppp_if_close(q)
    queue_t	*q;			/* queue info */
{
    PII	*p = (PII *) q->q_ptr;
    int	s, n;
    mblk_t *mp, *mq;

    if (p != NULL) {
	if_down(&p->pii_ifnet);
	p->pii_ifnet.if_flags &= ~IFF_RUNNING;
	p->pii_flags &= ~PII_FLAGS_INUSE;
	q->q_ptr = NULL;
	for (mp = p->pii_npq; mp != NULL; mp = mq) {
	    mq = mp->b_next;
	    freemsg(mp);
	}
	p->pii_npq = NULL;
	p->pii_npq_tail = &p->pii_npq;
	p->pii_writeq = NULL;
	DLOG("ppp_if%d: closed\n", p - pii);
    }
    return(0);			/* no work to be done */
}


static int
ppp_if_wput(q, mp)
    queue_t  *q;
    register mblk_t *mp;
{
    register struct iocblk *i;
    register PII *p;
    int bits, flags, error, unit, s;
    queue_t *oq;
    int npix;
    struct npioctl *npi;
    mblk_t *mq, **mqnext;
    struct ppp_stats *psp;

    switch (mp->b_datap->db_type) {

    case M_FLUSH:
	if (*mp->b_rptr & FLUSHW)
	    flushq(q, FLUSHDATA);
	putnext(q, mp);		/* send it along too */
	break;

    case M_DATA:
	putq(q, mp);	/* queue it for my service routine */
	break;

    case M_IOCTL:
	i = (struct iocblk *) mp->b_rptr;
	p = (PII *) q->q_ptr;
	switch ((unsigned int)i->ioc_cmd) {

	case SIOCSIFVJCOMP:	/* enable or disable VJ compression */
#ifdef	VJC
	    if (i->ioc_count == TRANSPARENT) {
		bits = *(u_int *) mp->b_cont->b_rptr;
		DLOG("ppp_if: SIFVJCOMP %d\n", bits);
		if (bits & 1) 
		    p->pii_flags |= PII_FLAGS_VJC_ON;
		else
		    p->pii_flags &= ~PII_FLAGS_VJC_ON;
		if (bits & 2)
		    p->pii_flags |= PII_FLAGS_VJC_NOCCID;
		else
		    p->pii_flags &= ~PII_FLAGS_VJC_NOCCID;
		if (bits & 4)
		    p->pii_flags |= PII_FLAGS_VJC_REJ;
		else
		    p->pii_flags &= ~PII_FLAGS_VJC_REJ;
		bits >>= 4;		/* now max conn id. */
		if (bits)
		    vj_compress_init(&p->pii_sc_comp, bits);
		mp->b_datap->db_type = M_IOCACK;
		i->ioc_count = 0;
		qreply(q, mp);
		break;
	    }
#endif
	    putnext(q, mp);
	    break;

	case SIOCGETU:	/* get unit number */
	    /*
	     * Allocate a unit if we don't already have one.
	     */
	    error = 0;
	    if (p == (PII *) 0) {
		p = ppp_if_alloc();
		if (p == NULL)
		    error = ENOBUFS;
		else
		    ppp_if_init(RD(q), p);
	    }
	    if (error == 0
		&& (mp->b_cont = allocb(sizeof(int), BPRI_MED)) == NULL)
		error = ENOSR;
	    if (error == 0) {
		*(int *) mp->b_cont->b_wptr = p->pii_ifnet.if_unit;
		mp->b_cont->b_wptr += i->ioc_count = sizeof(int);
		mp->b_datap->db_type = M_IOCACK;
	    } else {
		i->ioc_error = error;
		i->ioc_count = 0;
		mp->b_datap->db_type = M_IOCNAK;
	    }
	    qreply(q,mp);
	    break;

	case SIOCSETU:	/* set unit number */
	    if ((i->ioc_count == sizeof(int)) ||
		(i->ioc_count == TRANSPARENT)) {
		unit = *(int *)mp->b_cont->b_rptr;
		if (p != NULL || (unsigned) unit > NUM_PPP) {
		    mp->b_datap->db_type = M_IOCNAK;
		    i->ioc_error = EINVAL;
		    i->ioc_count = 0;
		    error = EINVAL;
		} else {
		    p = &pii[unit];
		    if (p->pii_flags & PII_FLAGS_INUSE) {
			oq = p->pii_writeq;
			oq->q_ptr = RD(oq)->q_ptr = NULL;
			q->q_ptr = RD(q)->q_ptr = (caddr_t) p;
			p->pii_writeq = q;
		    } else {
			ppp_if_init(RD(q), p);
		    }
		    mp->b_datap->db_type = M_IOCACK;
		}
		qreply(q, mp);
		break;
	    }
	    putnext(q, mp);
	    break;

	case SIOCSIFDEBUG :
	    /* catch it on the way past to set our debug flag as well */
	    if (i->ioc_count == TRANSPARENT) {
		flags = *(int *)mp->b_cont->b_rptr;
		if (flags & 1)
		    p->pii_flags |= PII_FLAGS_DEBUG;
		else
		    p->pii_flags &= ~PII_FLAGS_DEBUG;
	    }
	    putnext(q, mp);
	    break;

	case SIOCGETNPMODE:
	case SIOCSETNPMODE:
	    if (i->ioc_count == TRANSPARENT && p != NULL) {
		npi = *((struct npioctl **) mp->b_cont->b_rptr);
		switch (npi->protocol) {
		case PPP_IP:
		    npix = NP_IP;
		    break;
		default:
		    npix = -1;
		}
		if (npix < 0) {
		    i->ioc_error = EAFNOSUPPORT;
		    i->ioc_count = 0;
		    mp->b_datap->db_type = M_IOCNAK;
		    qreply(q, mp);
		    break;
		}
		if (i->ioc_cmd == SIOCSETNPMODE) {
		    if (p->pii_npmode[npix] == NPMODE_QUEUE
			&& npi->mode != NPMODE_QUEUE) {
			for (mqnext = &p->pii_npq; (mq = *mqnext) != NULL; ) {
			    if (PPP_PROTOCOL(mq->b_rptr) != npi->protocol){
				mqnext = &mq->b_next;
				continue;
			    }
			    *mqnext = mq->b_next;
			    if (npi->mode == NPMODE_PASS) {
				putq(q, mq); /* q it for service routine */
			    } else {
				freemsg(mq);
			    }
			}
			p->pii_npq_tail = mqnext;
		    }
		    p->pii_npmode[npix] = npi->mode;
		    i->ioc_count = 0;
		} else
		    npi->mode = p->pii_npmode[npix];
		mp->b_datap->db_type = M_IOCACK;
		qreply(q, mp);
		break;
	    }
	    putnext(q, mp);
	    break;

	default:		/* unknown IOCTL call */
	    putnext(q, mp);	/* pass it along */
	}
	break;

    default:
	putnext(q, mp);	/* don't know what to do with this, so send it along*/
    }
}

static int
ppp_if_wsrv(q)
    queue_t	*q;
{
    register mblk_t *mp;
    register PII *p;

    p = (PII *) q->q_ptr;

    while ((mp = getq(q)) != NULL) {
	/*
	 * we can only get M_DATA types into our Queue,
	 * due to our Put function
	 */
	if (!canput(q->q_next)) {
	    putbq(q, mp);
	    return;
	}

	/* increment count of outgoing packets */
	if (p != NULL)
	    INCR(ppp_opackets);

	/* just pass it along, nothing to do in this direction */
	putnext(q, mp);
    }	/* end while */
}


static int
ppp_if_rput(q, mp)
    queue_t *q;
    register mblk_t *mp;
{
    register PII	*p;

    switch (mp->b_datap->db_type) {

    case M_FLUSH:
	if (*mp->b_rptr & FLUSHR)
	    flushq(q, FLUSHDATA);
	putnext(q, mp);		/* send it along too */
	break;

    case M_DATA:
	putq(q, mp);		/* queue it for my service routine */
	break;

    case M_CTL:
	p = (PII *) q->q_ptr;
	if (p != NULL) {
	    switch (*(u_char *) mp->b_rptr) {
	    case IF_INPUT_ERROR :
		p->pii_ifnet.if_ierrors++;
		INCR(ppp_ierrors);
		DLOG("ppp_if: input error inc to %d\n",
		     p->pii_ifnet.if_ierrors);
		break;
	    case IF_OUTPUT_ERROR :
		p->pii_ifnet.if_oerrors++;
		INCR(ppp_oerrors);
		DLOG("ppp_if: output error inc to %d\n",
		     p->pii_ifnet.if_oerrors);
		break;
            case IF_CSTATS:
                bcopy(mp->b_rptr + sizeof(u_long), &p->pii_cstats,
                      sizeof(struct ppp_comp_stats));
                freemsg(mp);
                break;
            default:
                putnext(q, mp);         /* send it up to pppd */
                break;
            }
	}
	break;

    default:
	putnext(q, mp);		/* send along other message types */
    }
}

static int
ppp_if_rsrv(q)
    queue_t	*q;
{
    register mblk_t *mp,*m0;
#ifdef	VJC
    register mblk_t *mvjc;
    unsigned char *cp, *iphdr;
    u_int hlen;
#endif
    register PII *p;
    struct mbuf	*mb1, *mb2, *mbtail;
    struct ifnet	*ifp;
    int	len, xlen, count, s, pklen;
    u_char *rptr;
    int address, control;
    int dlen;

    p = (PII *) q->q_ptr;

    while ((mp = getq(q)) != NULL) {
	/*
	 * we can only get M_DATA types into our Queue,
	 * due to our Put function
	 */

	if (p == NULL) {
	    if (!canput(q->q_next)) {
		putbq(q, mp);
		return;
	    }
	    putnext(q, mp);
	    continue;
	}

	len = msgdsize(mp);
        dlen = len - PPP_HDRLEN;
#ifdef	PPP_STATS
	p->pii_stats.ppp_ibytes += len;
#endif

	/* make sure ppp_header is completely in first block */
	if (mp->b_wptr - mp->b_rptr < PPP_HDRLEN
	    && !pullupmsg(mp, PPP_HDRLEN)) {
	    DLOG("pullupmsg failed!\n", 0);
	    freemsg(mp);
	    p->pii_ifnet.if_ierrors++;
	    continue;
	}
	m0 = mp;	/* remember first message block */

#ifdef	VJC
	switch (PPP_PROTOCOL(mp->b_rptr)) {
	case PPP_VJC_COMP :
	    if ((p->pii_flags & PII_FLAGS_VJC_REJ)
		|| p->pii_npmode[NP_IP] != NPMODE_PASS) {
		DLOG("VJC rejected\n", 0);
		freemsg(mp);
		continue;				
	    }
	    address = PPP_ADDRESS(mp->b_rptr);
	    control = PPP_CONTROL(mp->b_rptr);
	    mp->b_rptr += PPP_HDRLEN;
	    len -= PPP_HDRLEN;

	    /*
	     * Make sure the VJ header is in one message block.
	     */
	    xlen = MIN(len, MAX_VJHDR);
	    if (mp->b_rptr + xlen > mp->b_wptr && !pullupmsg(mp, xlen)) {
		DLOG("pullupmsg vjc %d failed\n", xlen);
		freemsg(mp);
		continue;
	    }

	    /*
	     * Decompress it, then get a buffer and put the
	     * decompressed header in it.
	     */
	    xlen = vj_uncompress_tcp(mp->b_rptr, mp->b_wptr - mp->b_rptr,
				     len, &p->pii_sc_comp, &iphdr, &hlen);
	    if (xlen < 0) {
		DLOG("ppp: vj_uncompress failed on type Compressed\n", 0);
		freemsg(mp);
		continue;
	    }
	    if (!(mvjc = allocb(hlen + PPP_HDRLEN, BPRI_MED))) {
		DLOG("allocb mvjc failed (%d)\n", hlen + PPP_HDRLEN);
		freemsg(mp);
		continue;
	    }
	    dlen = len - xlen + hlen;
	    cp = mvjc->b_rptr;
	    cp[0] = address;
	    cp[1] = control;
	    cp[2] = 0;
	    cp[3] = PPP_IP;
	    bcopy(iphdr, cp + PPP_HDRLEN, hlen);
	    mvjc->b_wptr = cp + PPP_HDRLEN + hlen;
	    mvjc->b_cont = mp;
	    mp->b_rptr += xlen;
	    m0 = mp = mvjc;
	    break;

	case PPP_VJC_UNCOMP :
	    if ((p->pii_flags & PII_FLAGS_VJC_REJ)
		|| p->pii_npmode[NP_IP] != NPMODE_PASS) {
		DLOG("VJU rejected\n", 0);
		freemsg(mp);
		continue;
	    }

	    /*
	     * Make sure the IP header is in one message block.
	     */
	    xlen = MIN(len, MAX_IPHDR + PPP_HDRLEN);
	    if (mp->b_rptr + xlen > mp->b_wptr && !pullupmsg(mp, xlen)) {
		DLOG("pullupmsg vju %d failed\n", xlen);
		freemsg(mp);
		continue;
	    }

	    /*
	     * "Uncompress" it.  Basically this just copies information
	     * into p->pii_sc_comp and restores the protocol field of
	     * the IP header.
	     */
	    if (!vj_uncompress_uncomp(mp->b_rptr + PPP_HDRLEN,
				      &p->pii_sc_comp)) {
		DLOG("ppp: vj_uncompress failed on type Uncompresed\n", 0);
		freemsg(mp);
		continue;
	    }
	    mp->b_rptr[3] = PPP_IP;
	    break;
	}
#endif

	switch (PPP_PROTOCOL(mp->b_rptr)) {
	default:
	    if (!canput(q->q_next)) {
		putbq(q, mp);
		return;
	    }
	    INCR(ppp_ipackets);
	    p->pii_ifnet.if_ipackets++;
	    putnext(q, mp);
	    continue;

	case PPP_IP:
	    /*
	     * Don't let packets through until IPCP is up.
	     */
	    INCR(ppp_ipackets);
	    p->pii_ifnet.if_ipackets++;

	    if (!(p->pii_ifnet.if_flags & IFF_UP)
		|| p->pii_npmode[NP_IP] != NPMODE_PASS) {
		DLOG("pkt ignored - IP down\n", 0);
		freemsg(mp);
		continue;
	    }

	    /*
	     * Get the first mbuf and put the struct ifnet * in.
	     */
	    MGETHDR(mb1, M_DONTWAIT, MT_DATA);
	    mb1->m_len = 0;
	    if (mb1 == NULL) {
		p->pii_ifnet.if_ierrors++;
		freemsg(m0);
		continue;
	    }
	    len = MHLEN;
            mb1->m_pkthdr.rcvif = &(p->pii_ifnet);
            mb1->m_pkthdr.len = dlen;
	    mbtail = mb2 = mb1;
	    mb1->m_len = 0;

	    rptr = mp->b_rptr + PPP_HDRLEN;
	    xlen = mp->b_wptr - rptr;
	    for(;;) {
		if (xlen == 0) {	/* move to the next mblk */
		    mp = mp->b_cont;
		    if (mp == NULL)
			break;
		    xlen = mp->b_wptr - (rptr = mp->b_rptr);
		    continue;
		}
		if (len == 0) {
		    MGET(mb2, M_DONTWAIT, MT_DATA);
		    if (!mb2) {
			/* if we couldn't get a buffer, drop the packet */
			p->pii_ifnet.if_ierrors++;
			m_freem(mb1);	/* discard what we've used already */
			mb1 = NULL;
			break;
		    }
		    len = MLEN;
		    mb2->m_len = 0;
		    mbtail->m_next = mb2;
		    mbtail = mb2;
		}
		count = MIN(xlen, len);
		bcopy((char *) rptr, mtod(mb2, char *) + mb2->m_len, count);
		rptr += count;
		len -= count;
		xlen -= count;
		mb2->m_len += count;
	    }

	    freemsg(m0);
	    if (mb1 == NULL)
		continue;

#ifdef PPP_SNIT
	    if (p->pii_ifnet.if_flags & IFF_PROMISC) {
		struct mbuf *m = mb1;

		len = 0;
		do {
		    len += m->m_len;
		} while (m = m->m_next);
		nif.nif_bodylen = len - sizeof(struct ifnet *);
		mb1->m_off += sizeof(struct ifnet *);
		snit_intr(&p->pii_ifnet, mb1, &nif);
		mb1->m_off -= sizeof(struct ifnet *);
	    }
#endif
/*
	    if (IF_QFULL(&ipintrq)) {
		IF_DROP(&ipintrq);
		p->pii_ifnet.if_ierrors++;
		m_freem(mb1);
	    }
	    else {
*/
            find_input_type(0x0800, mb1, ifp, 0);
	}
    }	/* end while */
}

/* ifp output procedure */
int
ppp_output(ifp, m0, dst)
    struct ifnet *ifp;
    struct mbuf *m0;
    struct sockaddr *dst;
{
    register PII *p = &pii[ifp->if_unit];
    struct mbuf	*m1;
    int	error, s, len;
    u_short protocol;
#ifdef	VJC
    int	type;
    u_char *vjhdr;
#endif
    mblk_t *mp;
    enum NPmode npmode;

    error = 0;
    if (!(ifp->if_flags & IFF_UP)) {
	error = ENETDOWN;
	goto getout;
    }

    switch (dst->sa_family) {
#ifdef	INET
    case AF_INET:
#ifdef PPP_SNIT
	if (ifp->if_flags & IFF_PROMISC) {
	    struct mbuf *m = m0;

	    len = 0;
	    do {
		len += m->m_len;
	    } while (m = m->m_next);
	    nif.nif_bodylen = len;
	    snit_intr(ifp, m0, &nif);
	}
#endif
	protocol = PPP_IP;
	npmode = p->pii_npmode[NP_IP];
	break;
#endif

    default:
	DLOG("ppp: af%d not supported\n", dst->sa_family);
	error = EAFNOSUPPORT;
	goto getout;
    }

    if (!p->pii_writeq) {
	DLOG("ppp_if%d: no queue\n", p - pii);
	error = EHOSTUNREACH;
	goto getout;
    }

    switch (npmode) {
    case NPMODE_DROP:
	goto getout;
    case NPMODE_ERROR:
	error = ENETDOWN;
	goto getout;
    }

#ifdef	VJC
    if ((protocol == PPP_IP) && (p->pii_flags & PII_FLAGS_VJC_ON)) {
	register struct ip *ip;
	ip = mtod(m0, struct ip *);
	if (ip->ip_p == IPPROTO_TCP) {
	    type = vj_compress_tcp(ip, m0->m_len, &p->pii_sc_comp,
				   !(p->pii_flags & PII_FLAGS_VJC_NOCCID),
				   &vjhdr);
	    switch (type) {
	    case TYPE_UNCOMPRESSED_TCP :
		protocol = PPP_VJC_UNCOMP;
		break;
	    case TYPE_COMPRESSED_TCP :
		protocol = PPP_VJC_COMP;
		len = vjhdr - (u_char *) ip;
		m0->m_data += len;
		m0->m_len -= len;
		break;	
	    }
	}
    }
#endif

    len = PPP_HDRLEN;
    for (m1 = m0; m1; m1 = m1->m_next) 
	len += m1->m_len;

    if (!(mp = allocb(len, BPRI_MED))) {
	DLOG("ppp_if%d: allocb failed\n", p - pii);
	error = ENOBUFS;
	goto getout;
    }

#ifdef	PPP_STATS
    p->pii_stats.ppp_obytes += len;
#endif

    *mp->b_wptr++ = PPP_ALLSTATIONS;
    *mp->b_wptr++ = PPP_UI;
    *mp->b_wptr++ = 0;
    *mp->b_wptr++ = protocol;
    for (m1 = m0; m1; m1 = m1->m_next) {	/* copy all data */
	bcopy(mtod(m1, char *), (char *) mp->b_wptr, m1->m_len);
	mp->b_wptr += m1->m_len;
    }

    p->pii_ifnet.if_opackets++;
DLOG("ppp_output npmode is %d\n",npmode);
    if (npmode == NPMODE_PASS) {
	putq(p->pii_writeq, mp);
    } else {
	mp->b_next = NULL;
	*p->pii_npq_tail = mp;
	p->pii_npq_tail = &mp;
    }

 getout:
    m_freem(m0);
    if (error) {
	INCR(ppp_oerrors);
	p->pii_ifnet.if_oerrors++;
    }
    return (error);
}

/*
 * if_ ioctl requests 
*/
ppp_ioctl(ifp, cmd, data)
    register struct ifnet *ifp;
    unsigned int	cmd;
    caddr_t	data;
{
    register struct ifaddr *ifa = (struct ifaddr *) data;
    register struct ifreq *ifr = (struct ifreq *) data;
    struct ppp_stats *psp;
    struct ppp_comp_stats *pcp;
    PII *p;
    queue_t *q;
    int	error = 0;

    switch (cmd) {
    case SIOCSIFFLAGS :
	/* This happens every time IFF_PROMISC has been changed. */
	if (!ifr)
	    break;
	if (!suser()) {
	    error = EPERM;
	    break;
	}

	/* clear the flags that can be cleared */
	ifp->if_flags &= (IFF_CANTCHANGE);	
	/* or in the flags that can be changed */
	ifp->if_flags |= (ifr->ifr_flags & ~IFF_CANTCHANGE);
	break;

    case SIOCGIFFLAGS :
	ifr->ifr_flags = ifp->if_flags;
	break;

    case SIOCSIFADDR :
	if( ifa->ifa_addr->sa_family != AF_INET) 
	    error = EAFNOSUPPORT;
	break;

    case SIOCSIFDSTADDR :
	if (ifa->ifa_addr->sa_family != AF_INET)
	    error = EAFNOSUPPORT;
	break;

    case SIOCSIFMTU :
	if (!suser()) {
	    error = EPERM;
	    break;
	}
	if (ifr->ifr_mtu > MAX_PKTSIZE - PPP_FRAMING) {
	    error = EINVAL;
	    break;
	}
	ifp->if_mtu = ifr->ifr_mtu;
	break;

    case SIOCGIFMTU :
	ifr->ifr_mtu = ifp->if_mtu;
	break;

    case SIOCGPPPSTATS:
	p = &pii[ifp->if_unit];
	psp = (struct ppp_stats *) &((struct ifpppstatsreq *)data)->stats;
	bzero(psp, sizeof(struct ppp_stats));
#ifdef PPP_STATS
	psp->p = p->pii_stats;
#endif
#if defined(VJC) && !defined(VJ_NO_STATS)
	psp->vj = p->pii_sc_comp.stats;
#endif
	break;

    case SIOCGPPPCSTATS:
        p = &pii[ifp->if_unit];
        bzero(&p->pii_cstats, sizeof(struct ppp_comp_stats));

        /* Make a message to send on the interface's write stream */
        q = p->pii_writeq;
        if (q != NULL) {
            putctl1(q, M_CTL, IF_GET_CSTATS);
            /*
             * We assume the message gets passed along immediately, so
             * by the time the putctl1 returns, the request has been
             * processed, the values returned and p->pii_cstats has
             * been updated.  If not, we just get zeroes.
             */
        }
        pcp = (struct ppp_comp_stats *)&((struct ifpppcstatsreq *)data)->stats;
        bcopy(&p->pii_cstats, pcp, sizeof(struct ppp_comp_stats));
        break;

    default:
        error = EINVAL;
        break;
    }

    return(error);
}

#endif
