/*
 * ppp.c - STREAMS multiplexing pseudo-device driver for PPP.
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
 * $Id: ppp.c,v 1.4 1995/06/01 02:22:12 paulus Exp $
 */

/*
 * This file is used under Solaris 2.
 */

#include <sys/types.h>
#include <sys/param.h>
#include <sys/stat.h>
#include <sys/stream.h>
#include <sys/stropts.h>
#include <sys/errno.h>
#include <sys/cmn_err.h>
#include <sys/conf.h>
#include <sys/dlpi.h>
#include <sys/ioccom.h>
#include <sys/kmem.h>
#include <sys/ddi.h>
#ifdef sun
#include <sys/modctl.h>
#include <sys/kstat.h>
#include <sys/sunddi.h>
#endif
#include <net/ppp_defs.h>
#include <net/pppio.h>

#ifdef __STDC__
#define __P(x)	x
#else
#define __P(x)	()
#endif

/*
 * The IP module uses this SAP value for IP packets.
 */
#ifndef ETHERTYPE_IP
#define ETHERTYPE_IP	0x800
#endif

#ifndef PPP_MAXMTU
#define PPP_MAXMTU	65535
#endif

/*
 * Private information; one per upper stream.
 */
typedef struct upperstr {
    minor_t mn;			/* minor device number */
    struct upperstr *nextmn;	/* next minor device */
    queue_t *q;			/* read q associated with this upper stream */
    int flags;			/* flag bits, see below */
    int state;			/* current DLPI state */
    int sap;			/* service access point */
    int req_sap;		/* which SAP the DLPI client requested */
    struct upperstr *ppa;	/* control stream for our ppa */
    struct upperstr *next;	/* next stream for this ppa */
    uint ioc_id;		/* last ioctl ID for this stream */
    /*
     * There is exactly one control stream for each PPA.
     * The following fields are only used for control streams.
     */
    int ppa_id;
    queue_t *lowerq;		/* write queue attached below this PPA */
    struct upperstr *nextppa;	/* next control stream */
    int mru;
    int mtu;
    struct pppstat stats;	/* statistics */
#ifdef sun
    kstat_t *kstats;		/* stats for netstat */
#endif
} upperstr_t;

/* Values for flags */
#define US_PRIV		1	/* stream was opened by superuser */
#define US_CONTROL	2	/* stream is a control stream */
#define US_BLOCKED	4	/* flow ctrl has blocked lower write stream */
#define US_LASTMOD	8	/* no PPP modules below us */

static upperstr_t *minor_devs = NULL;
static upperstr_t *ppas = NULL;

#ifdef sun
static int ppp_identify __P((dev_info_t *));
static int ppp_attach __P((dev_info_t *, ddi_attach_cmd_t));
static int ppp_detach __P((dev_info_t *, ddi_detach_cmd_t));
static int ppp_devinfo __P((dev_info_t *, ddi_info_cmd_t, void *, void **));
#endif
static int pppopen __P((queue_t *, dev_t *, int, int, cred_t *));
static int pppclose __P((queue_t *, int, cred_t *));
static int pppuwput __P((queue_t *, mblk_t *));
static int pppursrv __P((queue_t *));
static int pppuwsrv __P((queue_t *));
static int ppplrput __P((queue_t *, mblk_t *));
static int ppplwput __P((queue_t *, mblk_t *));
static int ppplrsrv __P((queue_t *));
static int ppplwsrv __P((queue_t *));
static void dlpi_request __P((queue_t *, mblk_t *, upperstr_t *));
static void dlpi_error __P((queue_t *, int, int, int));
static void dlpi_ok __P((queue_t *, int));
static int send_data __P((mblk_t *, upperstr_t *));
static void new_ppa __P((queue_t *, mblk_t *));
static void attach_ppa __P((queue_t *, mblk_t *));
static void detach_ppa __P((queue_t *, mblk_t *));
static upperstr_t *find_dest __P((upperstr_t *, int));
static int putctl2 __P((queue_t *, int, int, int));
static int putctl4 __P((queue_t *, int, int, int));

static struct module_info ppp_info = {
    0xb1a6, "ppp", 0, 512, 512, 128
};

static struct qinit pppurint = {
    NULL, pppursrv, pppopen, pppclose, NULL, &ppp_info, NULL
};

static struct qinit pppuwint = {
    pppuwput, pppuwsrv, NULL, NULL, NULL, &ppp_info, NULL
};

static struct qinit ppplrint = {
    ppplrput, ppplrsrv, NULL, NULL, NULL, &ppp_info, NULL
};

static struct qinit ppplwint = {
    ppplwput, ppplwsrv, NULL, NULL, NULL, &ppp_info, NULL
};

static struct streamtab pppinfo = {
    &pppurint, &pppuwint,
    &ppplrint, &ppplwint
};

#ifdef sun
static dev_info_t *ppp_dip;

static struct cb_ops cb_ppp_ops = {
    nulldev, nulldev, nodev, nodev,	/* cb_open, ... */
    nodev, nodev, nodev, nodev,		/* cb_dump, ... */
    nodev, nodev, nodev, nochpoll,	/* cb_devmap, ... */
    ddi_prop_op,			/* cb_prop_op */
    &pppinfo,				/* cb_stream */
    D_NEW|D_MP|D_MTQPAIR|D_MTOUTPERIM|D_MTOCEXCL	/* cb_flag */
};

static struct dev_ops ppp_ops = {
    DEVO_REV,				/* devo_rev */
    0,					/* devo_refcnt */
    ppp_devinfo,			/* devo_getinfo */
    ppp_identify,			/* devo_identify */
    nulldev,				/* devo_probe */
    ppp_attach,				/* devo_attach */
    ppp_detach,				/* devo_detach */
    nodev,				/* devo_reset */
    &cb_ppp_ops,			/* devo_cb_ops */
    NULL				/* devo_bus_ops */
};

/*
 * Module linkage information
 */

static struct modldrv modldrv = {
    &mod_driverops,			/* says this is a pseudo driver */
    "PPP-2.2 multiplexing driver",
    &ppp_ops				/* driver ops */
};

static struct modlinkage modlinkage = {
    MODREV_1,
    (void *) &modldrv,
    NULL
};

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

static int
ppp_identify(dip)
    dev_info_t *dip;
{
    return strcmp(ddi_get_name(dip), "ppp") == 0? DDI_IDENTIFIED:
	DDI_NOT_IDENTIFIED;
}

static int
ppp_attach(dip, cmd)
    dev_info_t *dip;
    ddi_attach_cmd_t cmd;
{

    if (cmd != DDI_ATTACH)
	return DDI_FAILURE;
    if (ddi_create_minor_node(dip, "ppp", S_IFCHR, 0, DDI_PSEUDO, CLONE_DEV)
	== DDI_FAILURE) {
	ddi_remove_minor_node(dip, NULL);
	return DDI_FAILURE;
    }
    return DDI_SUCCESS;
}

static int
ppp_detach(dip, cmd)
    dev_info_t *dip;
    ddi_detach_cmd_t cmd;
{
    ddi_remove_minor_node(dip, NULL);
    return DDI_SUCCESS;
}

static int
ppp_devinfo(dip, cmd, arg, result)
    dev_info_t *dip;
    ddi_info_cmd_t cmd;
    void *arg;
    void **result;
{
    int error;

    error = DDI_SUCCESS;
    switch (cmd) {
    case DDI_INFO_DEVT2DEVINFO:
	if (ppp_dip == NULL)
	    error = DDI_FAILURE;
	else
	    *result = (void *) ppp_dip;
	break;
    case DDI_INFO_DEVT2INSTANCE:
	*result = NULL;
	break;
    default:
	error = DDI_FAILURE;
    }
    return error;
}
#endif /* sun */

#ifndef sun
# define qprocson(q)
# define qprocsoff(q)
# define canputnext(q)	canput((q)->q_next)
# define qwriter(q, mp, func, scope)	(func)((q), (mp))
#endif

static int
pppopen(q, devp, oflag, sflag, credp)
    queue_t *q;
    dev_t *devp;
    int oflag, sflag;
    cred_t *credp;
{
    upperstr_t *up;
    upperstr_t **prevp;
    minor_t mn;

    if (q->q_ptr)
	return 0;		/* device is already open */

    if (sflag == CLONEOPEN) {
	mn = 0;
	for (prevp = &minor_devs; (up = *prevp) != 0; prevp = &up->nextmn) {
	    if (up->mn != mn)
		break;
	    ++mn;
	}
    } else {
	mn = getminor(*devp);
	for (prevp = &minor_devs; (up = *prevp) != 0; prevp = &up->nextmn) {
	    if (up->mn >= mn)
		break;
	}
	if (up->mn == mn) {
	    /* this can't happen */
	    q->q_ptr = WR(q)->q_ptr = up;
	    return 0;
	}
    }

    /*
     * Construct a new minor node.
     */
    up = (upperstr_t *) kmem_zalloc(sizeof(upperstr_t), KM_SLEEP);
    if (up == 0) {
	cmn_err(CE_CONT, "pppopen: out of kernel memory\n");
	return ENXIO;
    }
    up->nextmn = *prevp;
    *prevp = up;
    up->mn = mn;
    *devp = makedevice(getmajor(*devp), mn);
    up->q = q;
    if (drv_priv(credp) == 0)
	up->flags |= US_PRIV;
    up->state = DL_UNATTACHED;
    up->sap = -1;
    q->q_ptr = up;
    WR(q)->q_ptr = up;
    noenable(WR(q));

    qprocson(q);
    return 0;
}

static int
pppclose(q, flag, credp)
    queue_t *q;
    int flag;
    cred_t *credp;
{
    upperstr_t *up, **upp;
    upperstr_t *as, *asnext;
    upperstr_t **prevp;

    qprocsoff(q);

    up = (upperstr_t *) q->q_ptr;
    if (up == 0)
	return 0;
    if (up->flags & US_CONTROL) {
	/*
	 * This stream represents a PPA:
	 * For all streams attached to the PPA, clear their
	 * references to this PPA.
	 * Then remove this PPA from the list of PPAs.
	 */
	for (as = up->next; as != 0; as = asnext) {
	    asnext = as->next;
	    as->next = 0;
	    as->ppa = 0;
	    if (as->flags & US_BLOCKED) {
		as->flags &= ~US_BLOCKED;
		flushq(WR(as->q), FLUSHDATA);
	    }
	}
	for (upp = &ppas; *upp != 0; upp = &(*upp)->nextppa)
	    if (*upp == up) {
		*upp = up->nextppa;
		break;
	    }

    } else {
	/*
	 * If this stream is attached to a PPA,
	 * remove it from the PPA's list.
	 */
	if ((as = up->ppa) != 0) {
	    for (; as->next != 0; as = as->next)
		if (as->next == up) {
		    as->next = up->next;
		    break;
		}
	}
    }

    if (up->kstats)
	kstat_delete(up->kstats);

    q->q_ptr = NULL;
    WR(q)->q_ptr = NULL;

    for (prevp = &minor_devs; *prevp != 0; prevp = &(*prevp)->nextmn) {
	if (*prevp == up) {
	    *prevp = up->nextmn;
	    break;
	}
    }
    kmem_free(up, sizeof(upperstr_t));

    return 0;
}

/*
 * A message from on high.  We do one of three things:
 *	- qreply()
 *	- put the message on the lower write stream
 *	- queue it for our service routine
 */
static int
pppuwput(q, mp)
    queue_t *q;
    mblk_t *mp;
{
    upperstr_t *us, *usnext, *ppa;
    struct iocblk *iop;
    struct linkblk *lb;
    queue_t *lq;
    int error, n;
    mblk_t *mq;

    us = (upperstr_t *) q->q_ptr;
    switch (mp->b_datap->db_type) {
    case M_PCPROTO:
    case M_PROTO:
	dlpi_request(q, mp, us);
	break;

    case M_DATA:
	if ((us->flags & US_CONTROL) == 0
	    || msgdsize(mp) > us->mtu + PPP_HDRLEN) {
#if DEBUG
	    cmn_err(CE_CONT, "pppuwput: junk data len=%d\n", msgdsize(mp));
#endif
	    freemsg(mp);
	    break;
	}
	if (!send_data(mp, us))
	    putq(q, mp);
	break;

    case M_IOCTL:
	iop = (struct iocblk *) mp->b_rptr;
	error = EINVAL;
	switch (iop->ioc_cmd) {
	case I_LINK:
	    if ((us->flags & US_CONTROL) == 0 || us->lowerq != 0)
		break;
	    lb = (struct linkblk *) mp->b_cont->b_rptr;
	    us->lowerq = lq = lb->l_qbot;
	    lq->q_ptr = us;
	    RD(lq)->q_ptr = us;
	    iop->ioc_count = 0;
	    error = 0;
	    us->flags &= ~US_LASTMOD;
	    /* Unblock upper streams which now feed this lower stream. */
	    qenable(lq);
	    /* Send useful information down to the modules which
	       are now linked below us. */
	    putctl2(lq, M_CTL, PPPCTL_UNIT, us->ppa_id);
	    putctl4(lq, M_CTL, PPPCTL_MRU, us->mru);
	    putctl4(lq, M_CTL, PPPCTL_MTU, us->mtu);
	    break;

	case I_UNLINK:
	    lb = (struct linkblk *) mp->b_cont->b_rptr;
#if DEBUG
	    if (us->lowerq != lb->l_qbot)
		cmn_err(CE_CONT, "ppp unlink: lowerq=%x qbot=%x\n",
			us->lowerq, lb->l_qbot);
#endif
	    us->lowerq = 0;
	    iop->ioc_count = 0;
	    error = 0;
	    /* Unblock streams which now feed back up the control stream. */
	    qenable(us->q);
	    break;

	case PPPIO_NEWPPA:
	    if (us->flags & US_CONTROL)
		break;
	    if ((us->flags & US_PRIV) == 0) {
		error = EPERM;
		break;
	    }
	    /* Arrange to return an int */
	    if ((mq = mp->b_cont) == 0
		|| mq->b_datap->db_lim - mq->b_rptr < sizeof(int)) {
		mq = allocb(sizeof(int), BPRI_HI);
		if (mq == 0) {
		    error = ENOSR;
		    break;
		}
		if (mp->b_cont != 0)
		    freemsg(mp->b_cont);
		mp->b_cont = mq;
		mq->b_cont = 0;
	    }
	    iop->ioc_count = sizeof(int);
	    mq->b_wptr = mq->b_rptr + sizeof(int);
	    qwriter(q, mp, new_ppa, PERIM_OUTER);
	    error = -1;
	    break;

	case PPPIO_ATTACH:
	    /* like dlpi_attach, for programs which can't write to
	       the stream (like pppstats) */
	    if (iop->ioc_count != sizeof(int) || us->ppa != 0)
		break;
	    n = *(int *)mp->b_cont->b_rptr;
	    for (ppa = ppas; ppa != 0; ppa = ppa->nextppa)
		if (ppa->ppa_id == n)
		    break;
	    if (ppa == 0)
		break;
	    us->ppa = ppa;
	    iop->ioc_count = 0;
	    qwriter(q, mp, attach_ppa, PERIM_OUTER);
	    error = -1;
	    break;

	case PPPIO_MRU:
	    if (iop->ioc_count != sizeof(int) || (us->flags & US_CONTROL) == 0)
		break;
	    n = *(int *)mp->b_cont->b_rptr;
	    if (n <= 0 || n > PPP_MAXMTU)
		break;
	    if (n < PPP_MRU)
		n = PPP_MRU;
	    us->mru = n;
	    if (us->lowerq)
		putctl4(us->lowerq, M_CTL, PPPCTL_MRU, n);
	    error = 0;
	    iop->ioc_count = 0;
	    break;

	case PPPIO_MTU:
	    if (iop->ioc_count != sizeof(int) || (us->flags & US_CONTROL) == 0)
		break;
	    n = *(int *)mp->b_cont->b_rptr;
	    if (n <= 0 || n > PPP_MAXMTU)
		break;
	    if (n < PPP_MRU)
		n = PPP_MRU;
	    us->mtu = n;
	    if (us->lowerq)
		putctl4(us->lowerq, M_CTL, PPPCTL_MTU, n);
	    error = 0;
	    iop->ioc_count = 0;
	    break;

	case PPPIO_LASTMOD:
	    us->flags |= US_LASTMOD;
	    error = 0;
	    break;

	default:
	    if (us->ppa == 0 || us->ppa->lowerq == 0)
		break;
	    us->ioc_id = iop->ioc_id;
	    error = -1;
	    switch (iop->ioc_cmd) {
	    case PPPIO_GETSTAT:
	    case PPPIO_GETCSTAT:
		if (us->flags & US_LASTMOD) {
		    error = EINVAL;
		    break;
		}
		putnext(us->ppa->lowerq, mp);
		break;
	    default:
		if (us->flags & US_PRIV)
		    putnext(us->ppa->lowerq, mp);
		else {
#if DEBUG
		    cmn_err(CE_CONT, "ppp ioctl %x rejected\n", iop->ioc_cmd);
#endif
		    error = EPERM;
		}
		break;
	    }
	    break;
	}

	if (error > 0) {
	    iop->ioc_error = error;
	    mp->b_datap->db_type = M_IOCNAK;
	    qreply(q, mp);
	} else if (error == 0) {
	    mp->b_datap->db_type = M_IOCACK;
	    qreply(q, mp);
	}
	break;

    case M_FLUSH:
	if (*mp->b_rptr & FLUSHW)
	    flushq(q, FLUSHDATA);
	if (*mp->b_rptr & FLUSHR) {
	    *mp->b_rptr &= ~FLUSHW;
	    qreply(q, mp);
	} else
	    freemsg(mp);
	break;

    default:
	freemsg(mp);
	break;
    }
    return 0;
}

static void
dlpi_request(q, mp, us)
    queue_t *q;
    mblk_t *mp;
    upperstr_t *us;
{
    union DL_primitives *d = (union DL_primitives *) mp->b_rptr;
    int size = mp->b_wptr - mp->b_rptr;
    mblk_t *reply, *np;
    upperstr_t *ppa, *os;
    int sap, *ip, len;
    dl_info_ack_t *info;
    dl_bind_ack_t *ackp;

    switch (d->dl_primitive) {
    case DL_INFO_REQ:
	if (size < sizeof(dl_info_req_t))
	    goto badprim;
	if ((reply = allocb(sizeof(dl_info_ack_t), BPRI_HI)) == 0)
	    break;		/* should do bufcall */
	reply->b_datap->db_type = M_PCPROTO;
	info = (dl_info_ack_t *) reply->b_wptr;
	reply->b_wptr += sizeof(dl_info_ack_t);
	bzero((caddr_t) info, sizeof(dl_info_ack_t));
	info->dl_primitive = DL_INFO_ACK;
	info->dl_max_sdu = PPP_MAXMTU;
	info->dl_min_sdu = 1;
	info->dl_addr_length = sizeof(ulong);
#ifdef DL_OTHER
	info->dl_mac_type = DL_OTHER;
#else
	info->dl_mac_type = DL_HDLC;	/* a lie */
#endif
	info->dl_current_state = us->state;
	info->dl_service_mode = DL_CLDLS;
	info->dl_provider_style = DL_STYLE2;
#if DL_CURRENT_VERSION >= 2
	info->dl_sap_length = sizeof(ulong);
	info->dl_version = DL_CURRENT_VERSION;
#endif
	qreply(q, reply);
	break;

    case DL_ATTACH_REQ:
	if (size < sizeof(dl_attach_req_t))
	    goto badprim;
	if (us->state != DL_UNATTACHED || us->ppa != 0) {
	    dlpi_error(q, DL_ATTACH_REQ, DL_OUTSTATE, 0);
	    break;
	}
	for (ppa = ppas; ppa != 0; ppa = ppa->nextppa)
	    if (ppa->ppa_id == d->attach_req.dl_ppa)
		break;
	if (ppa == 0) {
	    dlpi_error(q, DL_ATTACH_REQ, DL_BADPPA, 0);
	    break;
	}
	us->ppa = ppa;
	qwriter(q, mp, attach_ppa, PERIM_OUTER);
	break;

    case DL_DETACH_REQ:
	if (size < sizeof(dl_detach_req_t))
	    goto badprim;
	if (us->state != DL_UNBOUND || us->ppa == 0) {
	    dlpi_error(q, DL_DETACH_REQ, DL_OUTSTATE, 0);
	    break;
	}
	qwriter(q, mp, detach_ppa, PERIM_OUTER);
	break;

    case DL_BIND_REQ:
	if (size < sizeof(dl_bind_req_t))
	    goto badprim;
	if (us->state != DL_UNBOUND || us->ppa == 0) {
	    dlpi_error(q, DL_BIND_REQ, DL_OUTSTATE, 0);
	    break;
	}
	if (d->bind_req.dl_service_mode != DL_CLDLS) {
	    dlpi_error(q, DL_BIND_REQ, DL_UNSUPPORTED, 0);
	    break;
	}

	/* saps must be valid PPP network protocol numbers,
	   except that we accept ETHERTYPE_IP in place of PPP_IP. */
	sap = d->bind_req.dl_sap;
	us->req_sap = sap;
#if DEBUG
	cmn_err(CE_CONT, "ppp bind %x\n", sap);
#endif
	if (sap == ETHERTYPE_IP)
	    sap = PPP_IP;
	if (sap < 0x21 || sap > 0x3fff || (sap & 0x101) != 1) {
	    dlpi_error(q, DL_BIND_REQ, DL_BADADDR, 0);
	    break;
	}

	/* check that no other stream is bound to this sap already. */
	for (os = us->ppa; os != 0; os = os->next)
	    if (os->sap == sap)
		break;
	if (os != 0) {
	    dlpi_error(q, DL_BIND_REQ, DL_NOADDR, 0);
	    break;
	}

	us->sap = sap;
	us->state = DL_IDLE;

	if ((reply = allocb(sizeof(dl_bind_ack_t) + sizeof(ulong),
			    BPRI_HI)) == 0)
	    break;		/* should do bufcall */
	ackp = (dl_bind_ack_t *) reply->b_wptr;
	reply->b_wptr += sizeof(dl_bind_ack_t) + sizeof(ulong);
	reply->b_datap->db_type = M_PCPROTO;
	bzero((caddr_t) ackp, sizeof(dl_bind_ack_t));
	ackp->dl_primitive = DL_BIND_ACK;
	ackp->dl_sap = sap;
	ackp->dl_addr_length = sizeof(ulong);
	ackp->dl_addr_offset = sizeof(dl_bind_ack_t);
	*(ulong *)(ackp+1) = sap;
	qreply(q, reply);
	break;

    case DL_UNBIND_REQ:
	if (size < sizeof(dl_unbind_req_t))
	    goto badprim;
	if (us->state != DL_IDLE) {
	    dlpi_error(q, DL_UNBIND_REQ, DL_OUTSTATE, 0);
	    break;
	}
	us->sap = -1;
	us->state = DL_UNBOUND;
	dlpi_ok(q, DL_UNBIND_REQ);
	break;

    case DL_UNITDATA_REQ:
	if (size < sizeof(dl_unitdata_req_t))
	    goto badprim;
	if (us->state != DL_IDLE) {
	    dlpi_error(q, DL_UNITDATA_REQ, DL_OUTSTATE, 0);
	    break;
	}
	if (us->ppa == 0) {
	    cmn_err(CE_CONT, "ppp: in state dl_idle but ppa == 0?\n");
	    break;
	}
	len = mp->b_cont == 0? 0: msgdsize(mp->b_cont);
	if (len > us->ppa->mtu) {
#if DEBUG
	    cmn_err(CE_CONT, "dlpi data too large (%d > %d)\n", len, us->mtu);
#endif
	    break;
	}
	/* this assumes PPP_HDRLEN <= sizeof(dl_unitdata_req_t) */
	if (mp->b_datap->db_ref > 1) {
	    np = allocb(PPP_HDRLEN, BPRI_HI);
	    if (np == 0)
		break;		/* gak! */
	    np->b_cont = mp->b_cont;
	    mp->b_cont = 0;
	    freeb(mp);
	    mp = np;
	} else
	    mp->b_datap->db_type = M_DATA;
	/* XXX should use dl_dest_addr_offset/length here,
	   but we would have to translate ETHERTYPE_IP -> PPP_IP */
	mp->b_wptr = mp->b_rptr + PPP_HDRLEN;
	mp->b_rptr[0] = PPP_ALLSTATIONS;
	mp->b_rptr[1] = PPP_UI;
	mp->b_rptr[2] = us->sap >> 8;
	mp->b_rptr[3] = us->sap;
	if (!send_data(mp, us))
	    putq(q, mp);
	return;

#if DL_CURRENT_VERSION >= 2
    case DL_SUBS_BIND_REQ:
    case DL_SUBS_UNBIND_REQ:
    case DL_ENABMULTI_REQ:
    case DL_DISABMULTI_REQ:
    case DL_PROMISCON_REQ:
    case DL_PROMISCOFF_REQ:
    case DL_SET_PHYS_ADDR_REQ:
    case DL_XID_REQ:
    case DL_TEST_REQ:
    case DL_REPLY_UPDATE_REQ:
    case DL_REPLY_REQ:
    case DL_DATA_ACK_REQ:
#endif
    case DL_CONNECT_REQ:
    case DL_TOKEN_REQ:
	dlpi_error(q, d->dl_primitive, DL_NOTSUPPORTED, 0);
	break;

    case DL_CONNECT_RES:
    case DL_DISCONNECT_REQ:
    case DL_RESET_REQ:
    case DL_RESET_RES:
	dlpi_error(q, d->dl_primitive, DL_OUTSTATE, 0);
	break;

    case DL_UDQOS_REQ:
	dlpi_error(q, d->dl_primitive, DL_BADQOSTYPE, 0);
	break;

#if DL_CURRENT_VERSION >= 2
    case DL_TEST_RES:
    case DL_XID_RES:
	break;
#endif

    default:
	cmn_err(CE_CONT, "ppp: unknown dlpi prim 0x%x\n", d->dl_primitive);
	/* fall through */
    badprim:
	dlpi_error(q, d->dl_primitive, DL_BADPRIM, 0);
	break;
    }
    freemsg(mp);
}

static void
dlpi_error(q, prim, err, uerr)
    queue_t *q;
    int prim, err, uerr;
{
    mblk_t *reply;
    dl_error_ack_t *errp;

    reply = allocb(sizeof(dl_error_ack_t), BPRI_HI);
    if (reply == 0)
	return;			/* XXX should do bufcall */
    reply->b_datap->db_type = M_PCPROTO;
    errp = (dl_error_ack_t *) reply->b_wptr;
    reply->b_wptr += sizeof(dl_error_ack_t);
    errp->dl_primitive = DL_ERROR_ACK;
    errp->dl_error_primitive = prim;
    errp->dl_errno = err;
    errp->dl_unix_errno = uerr;
    qreply(q, reply);
}

static void
dlpi_ok(q, prim)
    queue_t *q;
    int prim;
{
    mblk_t *reply;
    dl_ok_ack_t *okp;

    reply = allocb(sizeof(dl_ok_ack_t), BPRI_HI);
    if (reply == 0)
	return;			/* XXX should do bufcall */
    reply->b_datap->db_type = M_PCPROTO;
    okp = (dl_ok_ack_t *) reply->b_wptr;
    reply->b_wptr += sizeof(dl_ok_ack_t);
    okp->dl_primitive = DL_OK_ACK;
    okp->dl_correct_primitive = prim;
    qreply(q, reply);
}

static int
send_data(mp, us)
    mblk_t *mp;
    upperstr_t *us;
{
    queue_t *q;
    upperstr_t *ppa;

    if (us->flags & US_BLOCKED)
	return 0;
    ppa = us->ppa;
    if (ppa == 0) {
	freemsg(mp);
	return 1;
    }
    if ((q = ppa->lowerq) == 0) {
	/* try to send it up the control stream */
	if (canputnext(ppa->q)) {
	    putnext(ppa->q, mp);
	    return 1;
	}
    } else {
	if (canputnext(ppa->lowerq)) {
	    /*
	     * The lower write queue's put procedure just updates counters
	     * and does a putnext.  We call it in order to enter the lower
	     * queues' perimeter so that the counter updates are serialized.
	     */
	    put(ppa->lowerq, mp);
	    return 1;
	}
    }
    us->flags |= US_BLOCKED;
    return 0;
}

/*
 * Allocate a new PPA id and link this stream into the list of PPAs.
 * This procedure is called with an exclusive lock on all queues in
 * this driver.
 */
static void
new_ppa(q, mp)
    queue_t *q;
    mblk_t *mp;
{
    upperstr_t *us, **usp;
    int ppa_id;

    usp = &ppas;
    ppa_id = 0;
    while ((us = *usp) != 0 && ppa_id == us->ppa_id) {
	++ppa_id;
	usp = &us->nextppa;
    }
    us = (upperstr_t *) q->q_ptr;
    us->ppa_id = ppa_id;
    us->ppa = us;
    us->next = 0;
    us->nextppa = *usp;
    *usp = us;
    us->flags |= US_CONTROL;

    us->mtu = PPP_MRU;
    us->mru = PPP_MRU;

#ifdef sun
    if (us->kstats == 0) {
	char unit[32];

	sprintf(unit, "ppp%d", us->ppa->ppa_id);
	us->kstats = kstat_create("ppp", us->ppa->ppa_id, unit,
				  "net", KSTAT_TYPE_NAMED, 4, 0);
	if (us->kstats != 0) {
	    kstat_named_t *kn = KSTAT_NAMED_PTR(us->kstats);

	    strcpy(kn[0].name, "ipackets");
	    kn[0].data_type = KSTAT_DATA_ULONG;
	    strcpy(kn[1].name, "ierrors");
	    kn[1].data_type = KSTAT_DATA_ULONG;
	    strcpy(kn[2].name, "opackets");
	    kn[2].data_type = KSTAT_DATA_ULONG;
	    strcpy(kn[3].name, "oerrors");
	    kn[3].data_type = KSTAT_DATA_ULONG;
	    kstat_install(us->kstats);
	}
    }
#endif

    *(int *)mp->b_cont->b_rptr = ppa_id;
    mp->b_datap->db_type = M_IOCACK;
    qreply(q, mp);
}

static void
attach_ppa(q, mp)
    queue_t *q;
    mblk_t *mp;
{
    upperstr_t *us, *t;

    us = (upperstr_t *) q->q_ptr;
    us->state = DL_UNBOUND;
    for (t = us->ppa; t->next != 0; t = t->next)
	;
    t->next = us;
    us->next = 0;
    if (mp->b_datap->db_type == M_IOCTL) {
	mp->b_datap->db_type = M_IOCACK;
	qreply(q, mp);
    } else {
	dlpi_ok(q, DL_ATTACH_REQ);
    }
}

static void
detach_ppa(q, mp)
    queue_t *q;
    mblk_t *mp;
{
    upperstr_t *us, *t;

    us = (upperstr_t *) q->q_ptr;
    for (t = us->ppa; t->next != 0; t = t->next)
	if (t->next == us) {
	    t->next = us->next;
	    break;
	}
    us->next = 0;
    us->ppa = 0;
    us->state = DL_UNATTACHED;
    dlpi_ok(q, DL_DETACH_REQ);
}

static int
pppuwsrv(q)
    queue_t *q;
{
    upperstr_t *us;
    struct lowerstr *ls;
    queue_t *lwq;
    mblk_t *mp;

    us = (upperstr_t *) q->q_ptr;
    while ((mp = getq(q)) != 0) {
	if (!send_data(mp, us)) {
	    putbq(q, mp);
	    break;
	}
    }
    if (mp == 0)
	us->flags &= ~US_BLOCKED;
    return 0;
}

static int
ppplwput(q, mp)
    queue_t *q;
    mblk_t *mp;
{
    upperstr_t *ppa;

    ppa = q->q_ptr;
    if (ppa != 0) {		/* why wouldn't it? */
	ppa->stats.ppp_opackets++;
	ppa->stats.ppp_obytes += msgdsize(mp);
	if (ppa->kstats != 0)
	    KSTAT_NAMED_PTR(ppa->kstats)[2].value.ul++;
    }
    putnext(q, mp);
    return 0;
}

static int
ppplwsrv(q)
    queue_t *q;
{
    upperstr_t *us;

    /*
     * Flow control has back-enabled this stream:
     * enable the write service procedures of all upper
     * streams feeding this lower stream.
     */
    for (us = (upperstr_t *) q->q_ptr; us != NULL; us = us->next)
	if (us->flags & US_BLOCKED)
	    qenable(WR(us->q));
    return 0;
}

static int
pppursrv(q)
    queue_t *q;
{
    upperstr_t *us, *as;
    mblk_t *mp, *hdr;
    dl_unitdata_ind_t *ud;
    int proto;

    /*
     * If this is a control stream and we don't have a lower queue attached,
     * run the write service routines of other streams attached to this PPA.
     */
    us = (upperstr_t *) q->q_ptr;
    if (us->flags & US_CONTROL) {
	/*
	 * A control stream.
	 * If there is no lower queue attached, run the write service
	 * routines of other upper streams attached to this PPA.
	 */
	if (us->lowerq == 0) {
	    as = us;
	    do {
		if (as->flags & US_BLOCKED)
		    qenable(WR(as->q));
		as = as->next;
	    } while (as != 0);
	}
    } else {
	/*
	 * A network protocol stream.  Put a DLPI header on each
	 * packet and send it on.
	 */
	while ((mp = getq(q)) != 0) {
	    if (!canputnext(q)) {
		putbq(q, mp);
		break;
	    }
	    proto = PPP_PROTOCOL(mp->b_rptr);
	    mp->b_rptr += PPP_HDRLEN;
	    hdr = allocb(sizeof(dl_unitdata_ind_t) + 2 * sizeof(ulong),
			 BPRI_MED);
	    if (hdr == 0) {
		/* XXX should put it back and use bufcall */
		freemsg(mp);
		continue;
	    }
	    ud = (dl_unitdata_ind_t *) hdr->b_wptr;
	    hdr->b_wptr += sizeof(dl_unitdata_ind_t) + 2 * sizeof(ulong);
	    hdr->b_cont = mp;
	    ud->dl_primitive = DL_UNITDATA_IND;
	    ud->dl_dest_addr_length = sizeof(ulong);
	    ud->dl_dest_addr_offset = sizeof(dl_unitdata_ind_t);
	    ud->dl_src_addr_length = sizeof(ulong);
	    ud->dl_src_addr_offset = ud->dl_dest_addr_offset + sizeof(ulong);
#if DL_CURRENT_VERSION >= 2
	    ud->dl_group_address = 0;
#endif
	    /* Send the DLPI client the data with the SAP they requested,
	       (e.g. ETHERTYPE_IP) rather than the PPP protocol number
	       (e.g. PPP_IP) */
	    ((ulong *)(ud + 1))[0] = us->req_sap;	/* dest SAP */
	    ((ulong *)(ud + 1))[1] = us->req_sap;	/* src SAP */
	    putnext(q, mp);
	}
    }
    return 0;
}

static upperstr_t *
find_dest(ppa, proto)
    upperstr_t *ppa;
    int proto;
{
    upperstr_t *us;

    for (us = ppa->next; us != 0; us = us->next)
	if (proto == us->sap)
	    break;
    return us;
}

static int
ppplrput(q, mp)
    queue_t *q;
    mblk_t *mp;
{
    upperstr_t *ppa, *us;
    queue_t *uq;
    int proto, len;
    mblk_t *np;
    struct iocblk *iop;

    ppa = (upperstr_t *) q->q_ptr;
    if (ppa == 0) {
#if DEBUG
	cmn_err(CE_CONT, "ppplrput: q = %x, ppa = 0??\n", q);
#endif
	freemsg(mp);
	return 0;
    }
    switch (mp->b_datap->db_type) {
    case M_FLUSH:
	if (*mp->b_rptr & FLUSHW) {
	    *mp->b_rptr &= ~FLUSHR;
	    qreply(q, mp);
	} else
	    freemsg(mp);
	break;

    case M_CTL:
	switch (*mp->b_rptr) {
	case PPPCTL_IERROR:
	    if (ppa->kstats != 0) {
		KSTAT_NAMED_PTR(ppa->kstats)[1].value.ul++;
	    }
	    ppa->stats.ppp_ierrors++;
	    break;
	case PPPCTL_OERROR:
	    if (ppa->kstats != 0) {
		KSTAT_NAMED_PTR(ppa->kstats)[3].value.ul++;
	    }
	    ppa->stats.ppp_oerrors++;
	    break;
	}
	freemsg(mp);
	break;

    case M_IOCACK:
    case M_IOCNAK:
	/*
	 * Attempt to match up the response with the stream
	 * that the request came from.
	 */
	iop = (struct iocblk *) mp->b_rptr;
	for (us = ppa; us != 0; us = us->next)
	    if (us->ioc_id == iop->ioc_id)
		break;
	if (us == 0)
	    freemsg(mp);
	else
	    putnext(us->q, mp);
	break;

    default:
	if (mp->b_datap->db_type == M_DATA) {
	    len = msgdsize(mp);
	    if (mp->b_wptr - mp->b_rptr < PPP_HDRLEN) {
		np = msgpullup(mp, PPP_HDRLEN);
		freemsg(mp);
		if (np == 0) {
#if DEBUG
		    cmn_err(CE_CONT, "ppp_lrput: msgpullup failed (len=%d)\n",
			    len);
#endif
		    break;
		}
		mp = np;
	    }
	    ppa->stats.ppp_ipackets++;
	    ppa->stats.ppp_ibytes += len;
	    if (ppa->kstats != 0) {
		KSTAT_NAMED_PTR(ppa->kstats)[0].value.ul++;
	    }
	    proto = PPP_PROTOCOL(mp->b_rptr);
	    if (proto < 0x8000 && (us = find_dest(ppa, proto)) != 0) {
		/*
		 * A data packet for some network protocol.
		 * Queue it on the upper stream for that protocol.
		 */
		if (canput(us->q))
		    putq(us->q, mp);
		else
		    putq(q, mp);
		break;
	    }
	}
	/*
	 * A control frame, a frame for an unknown protocol,
	 * or some other message type.
	 * Send it up to pppd via the control stream.
	 */
	if (queclass(mp) == QPCTL || canputnext(ppa->q))
	    putnext(ppa->q, mp);
	else
	    putq(q, mp);
	break;
    }

    return 0;
}

static int
ppplrsrv(q)
    queue_t *q;
{
    mblk_t *mp;
    upperstr_t *ppa, *us;
    int proto;

    /*
     * Packets only get queued here for flow control reasons.
     */
    ppa = (upperstr_t *) q->q_ptr;
    while ((mp = getq(q)) != 0) {
	if (mp->b_datap->db_type == M_DATA
	    && (proto = PPP_PROTOCOL(mp->b_rptr)) < 0x8000
	    && (us = find_dest(ppa, proto)) != 0) {
	    if (canput(us->q))
		putq(us->q, mp);
	    else {
		putbq(q, mp);
		break;
	    }
	} else {
	    if (canputnext(ppa->q))
		putnext(ppa->q, mp);
	    else {
		putbq(q, mp);
		break;
	    }
	}
    }
    return 0;
}

static int
putctl2(q, type, code, val)
    queue_t *q;
    int type, code, val;
{
    mblk_t *mp;

    mp = allocb(2, BPRI_HI);
    if (mp == 0)
	return 0;
    mp->b_datap->db_type = type;
    mp->b_wptr[0] = code;
    mp->b_wptr[1] = val;
    mp->b_wptr += 2;
    putnext(q, mp);
    return 1;
}

static int
putctl4(q, type, code, val)
    queue_t *q;
    int type, code, val;
{
    mblk_t *mp;

    mp = allocb(4, BPRI_HI);
    if (mp == 0)
	return 0;
    mp->b_datap->db_type = type;
    mp->b_wptr[0] = code;
    ((short *)mp->b_wptr)[1] = val;
    mp->b_wptr += 4;
    putnext(q, mp);
    return 1;
}
