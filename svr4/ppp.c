#include <sys/types.h>
#include <sys/param.h>
#include <sys/stat.h>
#include <sys/stream.h>
#include <sys/stropts.h>
#include <sys/errno.h>
#include <sys/cmn_err.h>
#include <sys/modctl.h>
#include <sys/conf.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/dlpi.h>
#include <sys/ioccom.h>
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
#define PPP_MAXMTU	65536
#endif

/*
 * Private information; one per upper stream.
 */
struct upperstr {
    minor_t mn;			/* minor device number */
    queue_t *q;			/* read q associated with this upper stream */
    int flags;			/* flag bits, see below */
    int state;			/* current DLPI state */
    int sap;			/* service access point */
    struct upperstr *ppa;	/* control stream for our ppa */
    struct upperstr *next;	/* next stream for this ppa */
    /*
     * There is exactly one control stream for each PPA.
     * The following fields are only used for control streams.
     */
    int ppa_id;
    queue_t *lowerq;		/* write queue attached below this PPA */
    struct upperstr *nextppa;	/* next control stream */
};

/* Values for flags */
#define US_PRIV		1	/* stream was opened by superuser */
#define US_CONTROL	2	/* stream is a control stream */
#define US_BLOCKED	4	/* flow ctrl has blocked lower stream */

static void *upper_states;
static struct upperstr *ppas;

static int ppp_identify __P((dev_info_t *));
static int ppp_attach __P((dev_info_t *, ddi_attach_cmd_t));
static int ppp_detach __P((dev_info_t *, ddi_detach_cmd_t));
static int ppp_devinfo __P((dev_info_t *, ddi_info_cmd_t, void *, void **));
static int pppopen __P((queue_t *, dev_t *, int, int, cred_t *));
static int pppclose __P((queue_t *, int, cred_t *));
static int pppuwput __P((queue_t *, mblk_t *));
static int pppursrv __P((queue_t *));
static int pppuwsrv __P((queue_t *));
static int ppplrput __P((queue_t *, mblk_t *));
static int ppplrsrv __P((queue_t *));
static int ppplwsrv __P((queue_t *));
static void dlpi_request __P((queue_t *, mblk_t *, struct upperstr *));
static void dlpi_error __P((queue_t *, int, int, int));
static void dlpi_ok __P((queue_t *, int));
static int send_data __P((mblk_t *, struct upperstr *));
static void new_ppa __P((queue_t *, mblk_t *));
static struct upperstr *find_dest __P((struct upperstr *, int));

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
    NULL, ppplwsrv, NULL, NULL, NULL, &ppp_info, NULL
};

static struct streamtab pppinfo = {
    &pppurint, &pppuwint,
    &ppplrint, &ppplwint
};

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
    int error;

    error = ddi_soft_state_init(&upper_states, sizeof(struct upperstr), 4);
    if (!error) {
	error = mod_install(&modlinkage);
	if (!error)
	    return 0;
	ddi_soft_state_fini(&upper_states);
    }
    return error;
}

int
_fini(void)
{
    int error;

    error = mod_remove(&modlinkage);
    if (error)
	return error;
    ddi_soft_state_fini(&upper_states);
    return 0;
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

static int
pppopen(q, devp, oflag, sflag, credp)
    queue_t *q;
    dev_t *devp;
    int oflag, sflag;
    cred_t *credp;
{
    struct upperstr *up;
    minor_t mn;

    if (q->q_ptr)
	return 0;		/* device is already open */

    if (sflag == CLONEOPEN) {
	for (mn = 0; ddi_get_soft_state(upper_states, mn) != NULL; ++mn)
	    ;
    } else {
	mn = getminor(*devp);
    }
    cmn_err(CE_CONT, "pppopen: minor %d\n", mn);

    /*
     * Construct a new minor node.
     */
    if (ddi_soft_state_zalloc(upper_states, mn) != DDI_SUCCESS)
	return ENXIO;
    up = ddi_get_soft_state(upper_states, mn);
    *devp = makedevice(getmajor(*devp), mn);
    up->q = q;
    up->mn = mn;
    up->flags = 0;
    if (drv_priv(credp) == 0)
	up->flags |= US_PRIV;
    up->state = DL_UNATTACHED;
    up->sap = -1;
    up->ppa = 0;
    up->next = 0;
    up->lowerq = 0;
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
    struct upperstr *up, **upp;
    struct upperstr *as, *asnext;
    struct lowerstr *ls;

    qprocsoff(q);

    up = (struct upperstr *) q->q_ptr;
    cmn_err(CE_CONT, "pppclose: minor %d\n", up->mn);
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

    q->q_ptr = NULL;
    WR(q)->q_ptr = NULL;
    ddi_soft_state_free(upper_states, up->mn);

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
    struct upperstr *us, *usnext;
    struct iocblk *iop;
    struct linkblk *lb;
    queue_t *lq;
    int error;
    mblk_t *mq;

    us = (struct upperstr *) q->q_ptr;
    switch (mp->b_datap->db_type) {
    case M_PCPROTO:
    case M_PROTO:
	dlpi_request(q, mp, us);
	break;

    case M_DATA:
	if (!send_data(mp, us))
	    putq(q, mp);
	break;

    case M_IOCTL:
	iop = (struct iocblk *) mp->b_rptr;
	cmn_err(CE_CONT, "ppp%d ioctl %x count=%d\n", us->mn, iop->ioc_cmd,
		iop->ioc_count);
	switch (iop->ioc_cmd) {
	case I_LINK:
	    if ((us->flags & US_CONTROL) == 0 || us->lowerq != 0)
		goto iocnak;
	    lb = (struct linkblk *) mp->b_cont->b_rptr;
	    us->lowerq = lq = lb->l_qbot;
	    lq->q_ptr = us;
	    WR(lq)->q_ptr = us;
	    iop->ioc_count = 0;
	    mp->b_datap->db_type = M_IOCACK;
	    qreply(q, mp);
	    /* Unblock upper streams which now feed this lower stream. */
	    qenable(lq);
	    break;

	case I_UNLINK:
	    lb = (struct linkblk *) mp->b_cont->b_rptr;
	    if (us->lowerq != lb->l_qbot)
		cmn_err(CE_CONT, "ppp unlink: lowerq=%x qbot=%x\n",
			us->lowerq, lb->l_qbot);
	    us->lowerq = 0;
	    iop->ioc_count = 0;
	    mp->b_datap->db_type = M_IOCACK;
	    qreply(q, mp);
	    /* Unblock streams which now feed back up the control stream. */
	    qenable(us->q);
	    break;

	case PPPIO_NEWPPA:
	    if (us->flags & US_CONTROL)
		goto iocnak;
	    if ((us->flags & US_PRIV) == 0) {
		iop->ioc_error = EPERM;
		goto iocnak;
	    }
	    /* Arrange to return an int */
	    if ((mq = mp->b_cont) == 0
		|| mq->b_datap->db_lim - mq->b_rptr < sizeof(int)) {
		mq = allocb(sizeof(int), BPRI_HI);
		if (mq == 0) {
		    iop->ioc_error = ENOSR;
		    goto iocnak;
		}
		if (mp->b_cont != 0)
		    freemsg(mp->b_cont);
		mp->b_cont = mq;
		mq->b_cont = 0;
	    }
	    iop->ioc_count = sizeof(int);
	    mq->b_wptr = mq->b_rptr + sizeof(int);
	    qwriter(q, mp, new_ppa, PERIM_OUTER);
	    break;

	default:
	    if (us->ppa == 0 || us->ppa->lowerq == 0)
		goto iocnak;
	    switch (iop->ioc_cmd) {
	    case PPPIO_GETSTAT:
	    case PPPIO_GETCSTAT:
		break;
	    default:
		if ((us->flags & US_PRIV) == 0) {
		    iop->ioc_error = EPERM;
		    goto iocnak;
		}
	    }
	    putnext(us->ppa->lowerq, mp);
	    break;

	iocnak:
	    mp->b_datap->db_type = M_IOCNAK;
	    qreply(q, mp);
	    break;
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
    struct upperstr *us;
{
    union DL_primitives *d = (union DL_primitives *) mp->b_rptr;
    int size = mp->b_wptr - mp->b_rptr;
    mblk_t *reply, *np;
    struct upperstr *t, *ppa;
    int sap;
    dl_info_ack_t *info;
    dl_bind_ack_t *ackp;
    dl_phys_addr_ack_t *adrp;

    cmn_err(CE_CONT, "ppp%d dlpi prim %x, state=%x\n", us->mn,
	    d->dl_primitive, us->state);
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
	info->dl_mac_type = DL_OTHER;
	info->dl_current_state = us->state;
	info->dl_sap_length = sizeof(ulong);
	info->dl_service_mode = DL_CLDLS;
	info->dl_provider_style = DL_STYLE2;
	info->dl_version = DL_CURRENT_VERSION;
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
	us->state = DL_UNBOUND;
	for (t = ppa; t->next != 0; t = t->next)
	    ;
	t->next = us;
	us->next = 0;
	dlpi_ok(q, DL_ATTACH_REQ);
	break;

    case DL_DETACH_REQ:
	if (size < sizeof(dl_detach_req_t))
	    goto badprim;
	if (us->state != DL_UNBOUND || us->ppa == 0) {
	    dlpi_error(q, DL_DETACH_REQ, DL_OUTSTATE, 0);
	    break;
	}
	for (t = us->ppa; t->next != 0; t = t->next)
	    if (t->next == us) {
		t->next = us->next;
		break;
	    }
	us->next = 0;
	us->ppa = 0;
	us->state = DL_UNATTACHED;
	dlpi_ok(q, DL_DETACH_REQ);
	break;

    case DL_BIND_REQ:
	if (size < sizeof(dl_bind_req_t))
	    goto badprim;
	if (us->state != DL_UNBOUND) {
	    dlpi_error(q, DL_BIND_REQ, DL_OUTSTATE, 0);
	    break;
	}
	if (d->bind_req.dl_service_mode != DL_CLDLS) {
	    dlpi_error(q, DL_BIND_REQ, DL_UNSUPPORTED, 0);
	    break;
	}
	/* saps must be valid PPP network protocol numbers */
	sap = d->bind_req.dl_sap;
	cmn_err(CE_CONT, "ppp bind %x\n", sap);
	if (sap == ETHERTYPE_IP)
	    sap = PPP_IP;
	if (sap < 0x21 || sap > 0x3fff
	    || (sap & 1) == 0 || (sap & 0x100) != 0) {
	    dlpi_error(q, DL_BIND_REQ, DL_BADADDR, 0);
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
	/* this assumes PPP_HDRLEN <= sizeof(dl_unitdata_req_t) */
	if (mp->b_datap->db_ref > 1) {
	    np = allocb(PPP_HDRLEN, BPRI_HI);
	    if (np == 0)
		break;		/* gak! */
	    np->b_cont = mp->b_cont;
	    mp->b_cont = 0;
	    freeb(mp);
	    mp = np;
	}
	/* XXX should use dl_dest_addr_offset/length here */
	mp->b_wptr = mp->b_rptr + PPP_HDRLEN;
	mp->b_rptr[0] = PPP_ALLSTATIONS;
	mp->b_rptr[1] = PPP_UI;
	mp->b_rptr[2] = us->sap >> 8;
	mp->b_rptr[3] = us->sap;
	if (!send_data(mp, us))
	    putq(q, mp);
	return;

    case DL_SUBS_BIND_REQ:
    case DL_SUBS_UNBIND_REQ:
    case DL_ENABMULTI_REQ:
    case DL_DISABMULTI_REQ:
    case DL_PROMISCON_REQ:
    case DL_PROMISCOFF_REQ:
    case DL_PHYS_ADDR_REQ:
    case DL_SET_PHYS_ADDR_REQ:
    case DL_XID_REQ:
    case DL_TEST_REQ:
    case DL_CONNECT_REQ:
    case DL_TOKEN_REQ:
    case DL_REPLY_UPDATE_REQ:
    case DL_GET_STATISTICS_REQ:
    case DL_REPLY_REQ:
    case DL_DATA_ACK_REQ:
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

    case DL_TEST_RES:
    case DL_XID_RES:
	break;

    default:
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
    struct upperstr *us;
{
    queue_t *q;
    struct upperstr *ppa;

    if (us->flags & US_BLOCKED)
	return 0;
    ppa = us->ppa;
    if (ppa == 0) {
	freemsg(mp);
	return 1;
    }
    if ((q = ppa->lowerq) == 0) {
	/* try to send it up the control stream */
	q = ppa->q;
    }
    if (canputnext(q)) {
	putnext(q, mp);
	return 1;
    }
    us->flags |= US_BLOCKED;
    return 0;
}

static void
new_ppa(q, mp)
    queue_t *q;
    mblk_t *mp;
{
    struct upperstr *us, **usp;
    int ppa_id;

    /*
     * Allocate a new PPA id and link this stream into
     * the list of PPAs.
     */
    usp = &ppas;
    ppa_id = 0;
    while ((us = *usp) != 0 && ppa_id == us->ppa_id) {
	++ppa_id;
	usp = &us->nextppa;
    }
    us = (struct upperstr *) q->q_ptr;
    us->ppa_id = ppa_id;
    us->ppa = us;
    us->next = 0;
    us->nextppa = *usp;
    *usp = us;
    us->flags |= US_CONTROL;

    *(int *)mp->b_cont->b_rptr = ppa_id;
    mp->b_datap->db_type = M_IOCACK;
    qreply(q, mp);
}

static int
pppuwsrv(q)
    queue_t *q;
{
    struct upperstr *us;
    struct lowerstr *ls;
    queue_t *lwq;
    mblk_t *mp;

    us = (struct upperstr *) q->q_ptr;
    while ((mp = getq(q)) != 0) {
	if (!send_data(mp, us)) {
	    putbq(q, mp);
	    break;
	}
    }
    return 0;
}

static int
ppplwsrv(q)
    queue_t *q;
{
    struct upperstr *us;

    /*
     * Flow control has back-enabled this stream:
     * enable the write service procedures of all upper
     * streams feeding this lower stream.
     */
    for (us = (struct upperstr *) q->q_ptr; us != NULL; us = us->next)
	if (us->flags & US_BLOCKED)
	    qenable(WR(us->q));
    return 0;
}

static int
pppursrv(q)
    queue_t *q;
{
    struct upperstr *us, *as;
    mblk_t *mp, *hdr;
    dl_unitdata_ind_t *ud;
    int proto;

    /*
     * If this is a control stream and we don't have a lower queue attached,
     * run the write service routines of other streams attached to this PPA.
     */
    us = (struct upperstr *) q->q_ptr;
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
	    ud->dl_group_address = 0;
	    ((ulong *)(ud + 1))[0] = proto;	/* dest SAP */
	    ((ulong *)(ud + 1))[1] = proto;	/* src SAP */
	    putnext(q, mp);
	}
    }
    return 0;
}

static struct upperstr *
find_dest(ppa, proto)
    struct upperstr *ppa;
    int proto;
{
    struct upperstr *us;

    for (us = ppa->next; us != 0; us = us->next)
	if (proto == us->sap)
	    return us;
    return 0;
}

static int
ppplrput(q, mp)
    queue_t *q;
    mblk_t *mp;
{
    struct upperstr *ppa, *us;
    queue_t *uq;
    int proto;

    ppa = (struct upperstr *) q->q_ptr;
    switch (mp->b_datap->db_type) {
    case M_FLUSH:
	if (*mp->b_rptr & FLUSHW) {
	    *mp->b_rptr &= ~FLUSHR;
	    qreply(q, mp);
	} else
	    freemsg(mp);
	break;

    default:
	if (mp->b_datap->db_type == M_DATA
	    && (proto = PPP_PROTOCOL(mp->b_rptr)) < 0x8000
	    && (us = find_dest(ppa, proto)) != 0) {
	    /*
	     * A data packet for some network protocol.
	     * Queue it on the upper stream for that protocol.
	     */
	    if (canput(us->q))
		putq(us->q, mp);
	    else
		putq(q, mp);
	    break;
	} else {
	    /*
	     * A control frame, a frame for an unknown protocol,
	     * or some other message type.
	     * Send it up to pppd via the control stream.
	     */
	    if (mp->b_datap->db_type >= QPCTL || canputnext(ppa->q))
		putnext(ppa->q, mp);
	    else
		putq(q, mp);
	}
	break;
    }

    return 0;
}

static int
ppplrsrv(q)
    queue_t *q;
{
    mblk_t *mp;
    struct upperstr *ppa, *us;
    int proto;

    /*
     * Packets only get queued here for flow control reasons.
     */
    ppa = (struct upperstr *) q->q_ptr;
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
