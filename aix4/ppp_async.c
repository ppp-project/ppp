/*
  ppp_async.c - Streams async functions Also does FCS

  Copyright (C) 1990  Brad K. Clements, All Rights Reserved
  fcstab and some ideas nicked from if_ppp.c from cmu.
  See copyright notice in if_ppp.h and NOTES

  $Id: ppp_async.c,v 1.2 1994/12/05 00:54:58 paulus Exp $
*/

#include <sys/types.h>

#ifndef PPP_VD
#include "ppp.h"
#endif

#if NUM_PPP > 0

#define	STREAMS	1
#define	DEBUGS	1
#include <net/net_globals.h>
#include <sys/param.h>
#include <sys/stream.h>
#include <sys/stropts.h>
#include <sys/strconf.h>
#include <sys/device.h>
#include <sys/dir.h>
#include <sys/signal.h>
#include <sys/user.h>
#include <sys/mbuf.h>
#include <sys/socket.h>
#include <net/if.h>
#include <netinet/in.h>

#include <net/ppp_defs.h>
#include <net/ppp_str.h>

/* how big of a buffer block to allocate for each chunk of the input chain */
#define       ALLOCBSIZE      64

#ifdef	DEBUGS
#include <sys/syslog.h>
#define	DLOG(s,a) if (p->pai_flags&PAI_FLAGS_DEBUG) bsdlog(LOG_INFO, s, a)

int	ppp_async_max_dump_bytes = 28;
#define MAX_DUMP_BYTES	1504

static void ppp_dump_frame();

#else
#define	DLOG(s)	{}
#endif

static	int	ppp_async_open(), ppp_async_close(), ppp_async_rput(),
	ppp_async_wput(), ppp_async_wsrv(), ppp_async_rsrv();

static 	struct	module_info	minfo ={
	0xabcd,"ppp_async",0, INFPSZ, 16384, 4096
};

static	struct	qinit	r_init = {
	ppp_async_rput, ppp_async_rsrv, ppp_async_open, ppp_async_close,
	NULL, &minfo, NULL
};
static	struct	qinit	w_init = {
	ppp_async_wput, ppp_async_wsrv, ppp_async_open, ppp_async_close,
	NULL, &minfo, NULL
};
struct	streamtab	ppp_asyncinfo = {
	&r_init, &w_init, NULL, NULL
};

/*
 * FCS lookup table as calculated by genfcstab.
 */
static u_short fcstab[256] = {
	0x0000,	0x1189,	0x2312,	0x329b,	0x4624,	0x57ad,	0x6536,	0x74bf,
	0x8c48,	0x9dc1,	0xaf5a,	0xbed3,	0xca6c,	0xdbe5,	0xe97e,	0xf8f7,
	0x1081,	0x0108,	0x3393,	0x221a,	0x56a5,	0x472c,	0x75b7,	0x643e,
	0x9cc9,	0x8d40,	0xbfdb,	0xae52,	0xdaed,	0xcb64,	0xf9ff,	0xe876,
	0x2102,	0x308b,	0x0210,	0x1399,	0x6726,	0x76af,	0x4434,	0x55bd,
	0xad4a,	0xbcc3,	0x8e58,	0x9fd1,	0xeb6e,	0xfae7,	0xc87c,	0xd9f5,
	0x3183,	0x200a,	0x1291,	0x0318,	0x77a7,	0x662e,	0x54b5,	0x453c,
	0xbdcb,	0xac42,	0x9ed9,	0x8f50,	0xfbef,	0xea66,	0xd8fd,	0xc974,
	0x4204,	0x538d,	0x6116,	0x709f,	0x0420,	0x15a9,	0x2732,	0x36bb,
	0xce4c,	0xdfc5,	0xed5e,	0xfcd7,	0x8868,	0x99e1,	0xab7a,	0xbaf3,
	0x5285,	0x430c,	0x7197,	0x601e,	0x14a1,	0x0528,	0x37b3,	0x263a,
	0xdecd,	0xcf44,	0xfddf,	0xec56,	0x98e9,	0x8960,	0xbbfb,	0xaa72,
	0x6306,	0x728f,	0x4014,	0x519d,	0x2522,	0x34ab,	0x0630,	0x17b9,
	0xef4e,	0xfec7,	0xcc5c,	0xddd5,	0xa96a,	0xb8e3,	0x8a78,	0x9bf1,
	0x7387,	0x620e,	0x5095,	0x411c,	0x35a3,	0x242a,	0x16b1,	0x0738,
	0xffcf,	0xee46,	0xdcdd,	0xcd54,	0xb9eb,	0xa862,	0x9af9,	0x8b70,
	0x8408,	0x9581,	0xa71a,	0xb693,	0xc22c,	0xd3a5,	0xe13e,	0xf0b7,
	0x0840,	0x19c9,	0x2b52,	0x3adb,	0x4e64,	0x5fed,	0x6d76,	0x7cff,
	0x9489,	0x8500,	0xb79b,	0xa612,	0xd2ad,	0xc324,	0xf1bf,	0xe036,
	0x18c1,	0x0948,	0x3bd3,	0x2a5a,	0x5ee5,	0x4f6c,	0x7df7,	0x6c7e,
	0xa50a,	0xb483,	0x8618,	0x9791,	0xe32e,	0xf2a7,	0xc03c,	0xd1b5,
	0x2942,	0x38cb,	0x0a50,	0x1bd9,	0x6f66,	0x7eef,	0x4c74,	0x5dfd,
	0xb58b,	0xa402,	0x9699,	0x8710,	0xf3af,	0xe226,	0xd0bd,	0xc134,
	0x39c3,	0x284a,	0x1ad1,	0x0b58,	0x7fe7,	0x6e6e,	0x5cf5,	0x4d7c,
	0xc60c,	0xd785,	0xe51e,	0xf497,	0x8028,	0x91a1,	0xa33a,	0xb2b3,
	0x4a44,	0x5bcd,	0x6956,	0x78df,	0x0c60,	0x1de9,	0x2f72,	0x3efb,
	0xd68d,	0xc704,	0xf59f,	0xe416,	0x90a9,	0x8120,	0xb3bb,	0xa232,
	0x5ac5,	0x4b4c,	0x79d7,	0x685e,	0x1ce1,	0x0d68,	0x3ff3,	0x2e7a,
	0xe70e,	0xf687,	0xc41c,	0xd595,	0xa12a,	0xb0a3,	0x8238,	0x93b1,
	0x6b46,	0x7acf,	0x4854,	0x59dd,	0x2d62,	0x3ceb,	0x0e70,	0x1ff9,
	0xf78f,	0xe606,	0xd49d,	0xc514,	0xb1ab,	0xa022,	0x92b9,	0x8330,
	0x7bc7,	0x6a4e,	0x58d5,	0x495c,	0x3de3,	0x2c6a,	0x1ef1,	0x0f78
};


struct  ppp_async_info {
    u_int	pai_flags;
    int		pai_buffsize;	/* how big of an input buffer to alloc */
    int		pai_buffcount;	/* how many chars currently in input buffer */
    u_short	pai_fcs;	/* the current fcs */
    mblk_t	*pai_buffer;	/* pointer to the current buffer list */
    mblk_t	*pai_bufftail;	/* pointer to the current input block */
    ext_accm	pai_asyncmap;	/* current outgoing asyncmap */
    u_int32_t	pai_rasyncmap;	/* current receive asyncmap */
};

/* Values for pai_flags */
#define	PAI_FLAGS_INUSE		0x1
#define	PAI_FLAGS_FLUSH		0x2
#define	PAI_FLAGS_ESCAPED 	0x4
#define	PAI_FLAGS_COMPPROT	0x8
#define	PAI_FLAGS_COMPAC	0x10
#define	PAI_FLAGS_RCV_COMPPROT	0x20
#define	PAI_FLAGS_RCV_COMPAC	0x40

#define PAI_FLAGS_DEBUG		0x1000
#define PAI_FLAGS_LOG_INPKT	0x2000
#define PAI_FLAGS_LOG_OUTPKT	0x4000
#define PAI_FLAGS_ALL_DEBUG	0x7000

typedef	struct ppp_async_info	PAI;

static PAI pai[NUM_PPP*2];		/* our private cache of async ctrl structs */

static strconf_t pppasync_conf = {
        "pppasync", &ppp_asyncinfo, STR_NEW_OPEN, 0, SQLVL_DEFAULT, (void *) 0
};

int ppp_async_load(int cmd, struct uio *uiop)
{
    int rc;

    switch (cmd) {
        case CFG_INIT:
            rc = str_install(STR_LOAD_MOD, &pppasync_conf);
            break;
        case CFG_TERM:
            rc = str_install(STR_UNLOAD_MOD, &pppasync_conf);
            break;
        default:
            rc = EINVAL;
            break;
    }
    return(rc);
}

/* open might fail if we don't have any more pai elements left free */
static int
ppp_async_open(q, dev, flag, sflag)
    queue_t	*q;
    dev_t	dev;
    int	flag;
    int sflag;
{
    register PAI *p;
    register int x;
    int	s;
  
    /* only let the superuser or setuid root ppl open this module */
    if (!suser()) {
	return(EPERM);	
    }

    if (!q->q_ptr) {
	for (x=0; x < NUM_PPP; x++)	/* search for an empty PAI */
	    if (!(pai[x].pai_flags & PAI_FLAGS_INUSE))
		break;
	if (x == NUM_PPP) {		/* all buffers in use */
	    return(ENOBUFS);
	}
	p = &pai[x];
	DLOG("ppp_async%d: opening\n",x);

	/* initialize the unit to default values */
	WR(q)->q_ptr = q->q_ptr =  (caddr_t) p;
	bzero(p, sizeof(*p));
	p->pai_flags = PAI_FLAGS_INUSE | PAI_FLAGS_RCV_COMPAC
	    | PAI_FLAGS_RCV_COMPPROT;
	p->pai_asyncmap[0] = 0xffffffff;	/* default async map */
	p->pai_asyncmap[3] = 0x60000000;	/* escape 7d, 7e */
	p->pai_buffsize = PPP_MTU + PPP_HDRLEN + PPP_FCSLEN;
    }
    else {
	p = (PAI *) q->q_ptr;
	DLOG("ppp_async%d: reopen\n", p - pai);
    }
    return(0);
}

static int
ppp_async_close(q)
    queue_t	*q;			/* queue info */
{
    int	s;
    register PAI *p;
  
    if ((p = (PAI *) q->q_ptr) != NULL) {
	p->pai_flags = 0;		/* clear all flags */
	if (p->pai_buffer) {
	    /* currently receiving some chars, discard the buffer */
	    freemsg(p->pai_buffer);
	    p->pai_buffer = NULL;
	}
	DLOG("ppp_async%d: closing\n", p - pai);
    }
    return(0);			
}


/* M_IOCTL processing is performed at this level. There is some 
   weirdness here, but I couldn't think of an easier way to handle it.
   
   SIOC{G,S}IF{,R,X}ASYNCMAP are handled here.
   
   SIOCSIFCOMPAC and SIOCSIFCOMPPROT are both handled here. 
   
   SIOCSIFMRU and SIOCGIFMRU (Max Receive Unit) are both handled here.
   Rather than using the MTU to set the MRU, we have a seperate IOCTL for it.
*/

static int
ppp_async_wput(q, mp)
    queue_t  *q;
    register mblk_t *mp;
{
    register struct iocblk	*i;
    register PAI	*p;
    int	x, flags;
  
    switch (mp->b_datap->db_type) {
    
    case M_FLUSH :
	if (*mp->b_rptr & FLUSHW)
	    flushq(q, FLUSHDATA);
	putnext(q, mp);			/* send it along too */
	break;
    
    case M_DATA :
	putq(q, mp);			/* queue it for my service routine */
	break;
    
    case M_IOCTL :
	i = (struct iocblk *) mp->b_rptr;
	p = (PAI *) q->q_ptr;
	switch ((unsigned int)i->ioc_cmd) {
      
	case SIOCSIFCOMPAC :	/* enable or disable AC compression */
	    if (i->ioc_count != TRANSPARENT) {
		i->ioc_error = EINVAL;
		goto iocnak;
	    }
	    x = *(u_int *) mp->b_cont->b_rptr;
	    DLOG("ppp_async: SIFCOMPAC %d\n", x);
	    flags = (x & 2)? PAI_FLAGS_RCV_COMPAC: PAI_FLAGS_COMPAC;
	    if (x & 1) 
		p->pai_flags |= flags;
	    else
		p->pai_flags &= ~flags;
	    i->ioc_count = 0;
	    goto iocack;

	case SIOCSIFCOMPPROT:	/* enable or disable PROT  compression */
	    if (i->ioc_count != TRANSPARENT) {
		i->ioc_error = EINVAL;
		goto iocnak;
	    }
	    x = *(u_int *) mp->b_cont->b_rptr;
	    DLOG("ppp_async: SIFCOMPPROT %d\n", x);
	    flags = (x & 2)? PAI_FLAGS_RCV_COMPPROT: PAI_FLAGS_COMPPROT;
	    if (x & 1) 
		p->pai_flags |= flags;
	    else
		p->pai_flags &= ~flags;
	    i->ioc_count = 0;
	    goto iocack;
      
      
	case SIOCSIFMRU :
	    if ((i->ioc_count != TRANSPARENT) &&
		(i->ioc_count != sizeof(int))) {
		i->ioc_error = EINVAL;
		goto iocnak;
	    }
	    x = *(int *) mp->b_cont->b_rptr;
	    if (x < PPP_MTU)
		x = PPP_MTU;
	    x += PPP_HDRLEN + PPP_FCSLEN;
	    if (x > 4096) {	/* couldn't allocb something this big */
		i->ioc_error = EINVAL;
		goto iocnak;
	    }
	    p->pai_buffsize = x;
      	    i->ioc_count  = 0;
	    goto iocack;

	case SIOCGIFMRU :
	    if ((mp->b_cont = allocb(sizeof(int), BPRI_MED)) != NULL) {
		*(int *) mp->b_cont->b_wptr = 
		    p->pai_buffsize - (PPP_HDRLEN + PPP_FCSLEN);
		mp->b_cont->b_wptr += i->ioc_count  = sizeof(int);
		goto iocack;
	    }
	    i->ioc_error = ENOSR;
	    goto iocnak;
      
	case SIOCGIFASYNCMAP :
	    if ((mp->b_cont = allocb(sizeof(u_int32_t), BPRI_MED)) != NULL) {
		*(u_int32_t *) mp->b_cont->b_wptr = p->pai_asyncmap[0];
		mp->b_cont->b_wptr += i->ioc_count = sizeof(u_int32_t);
		goto iocack;
	    }
	    i->ioc_error = ENOSR;
	    goto iocnak;

	case SIOCSIFASYNCMAP :
	    if ((i->ioc_count != TRANSPARENT) &&
		(i->ioc_count != sizeof(u_int32_t))) {
		i->ioc_error = EINVAL;
		goto iocnak;	/* ugh, goto */
	    }
	    p->pai_asyncmap[0] = *(u_int32_t *) mp->b_cont->b_rptr;
	    DLOG("ppp_async: SIFASYNCMAP %lx\n", p->pai_asyncmap[0]);
	    i->ioc_count = 0;
	    goto iocack;

	case SIOCGIFRASYNCMAP :
	    if ((mp->b_cont = allocb(sizeof(u_int32_t), BPRI_MED)) != NULL) {
		*(u_int32_t *) mp->b_cont->b_wptr = p->pai_rasyncmap;
		mp->b_cont->b_wptr += i->ioc_count = sizeof(u_int32_t);
		goto iocack;
	    }
	    i->ioc_error = ENOSR;
	    goto iocnak;

	case SIOCSIFRASYNCMAP :
	    if ((i->ioc_count != TRANSPARENT) &&
		(i->ioc_count != sizeof(u_int32_t))) {
		i->ioc_error = EINVAL;
		goto iocnak;	/* ugh, goto */
	    }
	    p->pai_rasyncmap = *(u_int32_t *) mp->b_cont->b_rptr;
	    DLOG("ppp_async: SIFRASYNCMAP %lx\n", p->pai_rasyncmap);
	    i->ioc_count = 0;
	    goto iocack;

	case SIOCGIFXASYNCMAP :
	    if ((mp->b_cont = allocb(sizeof(ext_accm), BPRI_MED)) != NULL) {
		bcopy(p->pai_asyncmap, mp->b_cont->b_wptr, sizeof(ext_accm));
		mp->b_cont->b_wptr += i->ioc_count = sizeof(ext_accm);
		goto iocack;
	    }
	    i->ioc_error = ENOSR;
	    goto iocnak;

	case SIOCSIFXASYNCMAP :
	    if ((i->ioc_count != TRANSPARENT) &&
		(i->ioc_count != sizeof(ext_accm))) {
		i->ioc_error = EINVAL;
		goto iocnak;	/* ugh, goto */
	    }
	    bcopy(*mp->b_cont->b_rptr, p->pai_asyncmap, sizeof(ext_accm));
	    p->pai_asyncmap[1] = 0; 		/* can't escape 20-3f */
	    p->pai_asyncmap[2] &= ~0x40000000;	/* can't escape 5e */
	    p->pai_asyncmap[3] |= 0x60000000;	/* must escape 7d, 7e */
	    i->ioc_count = 0;
	    goto iocack;

	case SIOCGIFDEBUG :
	    if ((mp->b_cont = allocb(sizeof(int), BPRI_MED)) != NULL) {
		*(int *)mp->b_cont->b_wptr =
		    (unsigned)(p->pai_flags & PAI_FLAGS_ALL_DEBUG)
			/ PAI_FLAGS_DEBUG |
		    (p->pai_flags & PAI_FLAGS_HIBITS);
		mp->b_cont->b_wptr += i->ioc_count = sizeof(int);
		goto iocack;
	    }
	    i->ioc_error = ENOSR;
	    goto iocnak;

	case SIOCSIFDEBUG :
	    if ((i->ioc_count != TRANSPARENT) &&
		(i->ioc_count != sizeof(int))) {
		i->ioc_error = EINVAL;
		goto iocnak;	/* ugh, goto */
	    }
	    flags = *(int *)mp->b_cont->b_rptr;
	    DLOG("ppp_async: SIFIFDEBUG %x\n", flags);
	    p->pai_flags &= ~PAI_FLAGS_ALL_DEBUG | PAI_FLAGS_HIBITS;
	    p->pai_flags |= ((unsigned) flags * PAI_FLAGS_DEBUG)
		& PAI_FLAGS_ALL_DEBUG;
	    i->ioc_count = 0;
	    goto iocack;

	iocack:;
	    mp->b_datap->db_type = M_IOCACK;
	    qreply(q,mp);
	    break;
	iocnak:;
	    i->ioc_count = 0;
	    mp->b_datap->db_type = M_IOCNAK;
	    qreply(q, mp);
	    break;
	default:				/* unknown IOCTL call */
	    putnext(q,mp);		/* pass it along */
	}
	break;

    default:
	putnext(q, mp);	/* don't know what to do with this, so send it along*/
    }
}

static int
ppp_async_wsrv(q)
    queue_t	*q;
{
    register u_char	*cp, *wp;
    register PAI	*p;
    register u_short	fcs;
    register mblk_t	*mp, *m0;
    mblk_t	*cop, *outgoing;
    int proto, len, olen, c;

    p = (PAI *) q->q_ptr;

    while ((mp = getq(q)) != NULL) {
	/*
	 * we can only get M_DATA types into our Queue,
	 * due to our Put function
	 */
	if (!canput(q->q_next)) {
	    putbq(q, mp);
	    return;
	}

	/* at least a header required */
	len = msgdsize(mp);
	if (len < PPP_HDRLEN
	    || (mp->b_wptr - mp->b_rptr < PPP_HDRLEN
		&& !pullupmsg(mp, PPP_HDRLEN))) {	
	    freemsg(mp);		/* discard the message */
	    DLOG("ppp_async: short message (%d)\n", len);
	    /* indicate output err */
	    putctl1(OTHERQ(q), M_CTL, IF_OUTPUT_ERROR);
	    continue;
	}

	/* Do address/control and protocol compression */
	proto = (mp->b_rptr[2] << 8) + mp->b_rptr[3];
	if (p->pai_flags & PAI_FLAGS_COMPAC && proto != PPP_LCP
	    && mp->b_rptr[0] == PPP_ALLSTATIONS && mp->b_rptr[1] == PPP_UI) {
	    mp->b_rptr += 2;
	    if (p->pai_flags & PAI_FLAGS_COMPPROT && proto < 0xff)
		++mp->b_rptr;
	} else if (p->pai_flags & PAI_FLAGS_COMPPROT && proto < 0xff) {
	    mp->b_rptr[2] = mp->b_rptr[1];
	    mp->b_rptr[1] = mp->b_rptr[0];
	    ++mp->b_rptr;
	}

	m0 = mp;		/* remember first message block */
	fcs = PPP_INITFCS;

	/*
	 * Estimate the required buffer length as 1.25 * message length
	 * to allow for escaped characters.  If this isn't enough, we
	 * allocate another buffer later.
	 */
	olen = len + (len >> 2) + 5;
	if (olen < 32)
	    olen = 32;
	else if (olen > 2048)
	    olen = 2048;
	outgoing = cop = allocb(olen, BPRI_MED);
	if (outgoing == NULL) {
	    DLOG("allocb(%d) failed!\n", olen);
	    /* should do something tricky here */
	    goto nobuffs;
	}
	wp = cop->b_wptr;

	/* Put the initial flag in (we'll take it out later if we don't
	   need it). */
	*wp++ = PPP_FLAG;
	--olen;

#define	SPECIAL(p, c)	(p->pai_asyncmap[(c) >> 5] & (1 << ((c) & 0x1F)))

	/*
	 * Copy the message to the output block, escaping characters
	 * as needed.
	 */
	while (mp) {
	    for (cp = mp->b_rptr; cp < mp->b_wptr; ) {
		c = *cp++;
		if (olen < 2) {
		    /* grab another message block and put it on the end */
		    cop->b_wptr = wp;
		    olen = 256;
		    cop = allocb(olen, BPRI_MED);
		    if (cop == NULL)
			goto nobuffs;
		    linkb(outgoing, cop);
		    wp = cop->b_wptr;
		}
		if (SPECIAL(p, c)) {
		    *wp++ = PPP_ESCAPE;
		    *wp++ = c ^ PPP_TRANS;
		    olen -= 2;
		} else {
		    *wp++ = c;
		    --olen;
		}
		fcs = PPP_FCS(fcs, c);
	    }
	    mp = mp->b_cont; /* look at the next block */
	}					/* end while(mp) */

	/*
	 * Add the FCS and the trailing flag.
	 */
	if (olen < 5) {
	    /* grab another message block for FCS and trailing flag */
	    cop->b_wptr = wp;
	    cop = allocb(5, BPRI_MED);
	    if (cop == NULL)
		goto nobuffs;
	    linkb(outgoing, cop);
	    wp = cop->b_wptr;
	}
	fcs ^= 0xffff;				/* XOR the resulting FCS */
	c = fcs & 0xff;
	if (SPECIAL(p, c)) {
	    *wp++ = PPP_ESCAPE;
	    *wp++ = c ^ PPP_TRANS;
	} else
	    *wp++ = c;
	c = fcs >> 8;
	if (SPECIAL(p, c)) {
	    *wp++ = PPP_ESCAPE;
	    *wp++ = c ^ PPP_TRANS;
	} else
	    *wp++  = c;
	*wp++ = PPP_FLAG;	/* add trailing PPP_FLAG */

	cop->b_wptr = wp;
	freemsg(m0);

	/*
	 * now we check to see if the lower queue has entries, if so,
	 * we assume that we don't need a leading PPP_FLAG because
	 * these packets will be sent back to back.
	 */
	if (qsize(q->q_next) > 0) {
	    /* entries in next queue, remove the leading PPP_FLAG */
	    ++outgoing->b_rptr;
	}

#if DEBUGS
	if (p->pai_flags & PAI_FLAGS_LOG_OUTPKT)
	    ppp_dump_frame(p, outgoing, " sent output");
#endif
	putnext(q, outgoing);
	continue;

    nobuffs:	/* well, we ran out of memory somewhere */
	if (outgoing)
	    freemsg(outgoing);		/* throw away what we have already */
	putbq(q, m0);			/* put back the original message */
	putctl1(OTHERQ(q), M_CTL, IF_OUTPUT_ERROR);
	qenable(q);			/* reschedule ourselves for later */
	return;
    } /* end while(getq()) */
}	/* end function */					

static int
ppp_async_rput(q, mp)
    queue_t *q;
    register mblk_t *mp;
{
    switch (mp->b_datap->db_type) {
    
    case M_FLUSH:
	if(*mp->b_rptr & FLUSHR)
	    flushq(q, FLUSHDATA);
	putnext(q, mp);		/* send it along too */
	break;
    
    case M_DATA:
	putq(q, mp);		/* queue it for my service routine */
	break;
    
    default:
	putnext(q,mp);	/* don't know what to do with this, so send it along */
    }
}

static u_int32_t paritytab[8] = {
    0x96696996, 0x69969669, 0x69969669, 0x96696996,
    0x69969669, 0x96696996, 0x96696996, 0x69969669,
};

static int
ppp_async_rsrv(q)
    queue_t	*q;
{
    register mblk_t *mp, *bp;
    register PAI	*p;
    register u_char	*cp,c;
    mblk_t	*m0;
    register u_char *wptr;
    int bcount;
  
    p = (PAI *) q->q_ptr;

#define	INPUT_ERROR(q)	putctl1(q, M_CTL, IF_INPUT_ERROR)
#define	STUFF_CHAR(p,c)	(*wptr++ = (c), (p)->pai_buffcount++)
#define	FLUSHEM(q, p)	(INPUT_ERROR(q), (p)->pai_flags |= PAI_FLAGS_FLUSH)
  
    while ((mp = getq(q)) != NULL) {
	/* we can only get M_DATA types into our Queue,
	   due to our Put function */
	if (!canput(q->q_next)) {
	    putbq(q, mp);
	    return;
	}
	m0 = mp;	/* remember first message block */
	for (; mp != NULL; mp = mp->b_cont) {	/* for each message block */
	    cp = mp->b_rptr;
	    while (cp < mp->b_wptr) {
		c = *cp++;

		/* Accumulate info to help with detecting
		   non 8-bit clean links. */
		if (c & 0x80)
		    p->pai_flags |= PAI_FLAGS_B7_1;
		else
		    p->pai_flags |= PAI_FLAGS_B7_0;
		if (paritytab[c >> 5] & (1 << (c & 0x1F)))
		    p->pai_flags |= PAI_FLAGS_PAR_ODD;
		else
		    p->pai_flags |= PAI_FLAGS_PAR_EVEN;

		/* Throw out chars in the receive asyncmap. */
		if (c < 0x20 && (p->pai_rasyncmap & (1 << c)))
		    continue;

		/* A flag marks the end of a frame. */
		if (c == PPP_FLAG) {
		    bp = p->pai_buffer;
		    bcount = p->pai_buffcount;
		    p->pai_buffer = NULL;
		    p->pai_buffcount = 0;

		    /* if the escape indicator is set, then we have
		       seen the packet abort sequence "}~". */
		    if (p->pai_flags & (PAI_FLAGS_ESCAPED | PAI_FLAGS_FLUSH)) {
			if ((p->pai_flags & PAI_FLAGS_FLUSH) == 0)
			    DLOG("ppp_async: packet abort\n", 0);
			p->pai_flags &= ~(PAI_FLAGS_ESCAPED | PAI_FLAGS_FLUSH);
			if (bp)
			    freemsg(bp);
			continue;
		    }

		    if (bcount > PPP_FCSLEN) {	/* discard FCS */
			adjmsg(bp, -PPP_FCSLEN);
			bcount -= PPP_FCSLEN;
		    }

		    if (bcount < PPP_HDRLEN) {
			if (bcount) {
			    INPUT_ERROR(q);
			    DLOG("ppp_async: short input packet (%d)\n",
				 bcount);
			}
			if (bp)
			    freemsg(bp);
			continue;
		    }

		    if (bp) {
			if (p->pai_fcs == PPP_GOODFCS) {
#if DEBUGS
			    if (p->pai_flags & PAI_FLAGS_LOG_INPKT)
				ppp_dump_frame(p, bp, " got input");
#endif /*DEBUGS*/
			    putnext(q, bp);
			}
			else {
			    INPUT_ERROR(q);
			    freemsg(bp);
			    DLOG("ppp_async: FCS Error\n", 0);
			}
		    }
		    continue;
		}

		/* here c != PPP_FLAG */
		if (p->pai_flags & PAI_FLAGS_FLUSH) {
		    while (cp < mp->b_wptr && *cp != PPP_FLAG)
			++cp;
		    continue;
		}

		if (p->pai_flags & PAI_FLAGS_ESCAPED) {
		    p->pai_flags &= ~PAI_FLAGS_ESCAPED; /* clear esc flag */
		    c ^= PPP_TRANS;
		} else if (c == PPP_ESCAPE) {
		    if (cp >= mp->b_wptr || (c = *cp) == PPP_FLAG
			|| c < 0x20 && (p->pai_rasyncmap & (1 << c))) {
			p->pai_flags |= PAI_FLAGS_ESCAPED;
			continue;
		    }
		    c ^= PPP_TRANS;
		    ++cp;
		}

		/* here we check to see if we have a buffer.
		   If we don't, we assume that this is the first char
		   for the buffer, and we allocb one */
	
		if (!p->pai_buffer) {
		    /* we allocate buffer chains in blocks of ALLOCBSIZE */
	  
		    if (!(p->pai_buffer = allocb(ALLOCBSIZE, BPRI_MED))) {
			FLUSHEM(q, p);
			continue;
			/* if we don't get a buffer, is there some way
			   to recover and requeue later? rather than flushing
			   the current packet... ? */
		    }
		    p->pai_bufftail = p->pai_buffer;
		}
		wptr = p->pai_bufftail->b_wptr;

		if (!p->pai_buffcount) {
		    p->pai_fcs = PPP_INITFCS;
		    if (c != PPP_ALLSTATIONS) {
			if (p->pai_flags & PAI_FLAGS_RCV_COMPAC) {
			    STUFF_CHAR(p, PPP_ALLSTATIONS);
			    STUFF_CHAR(p, PPP_UI);
			}
			else {
			    DLOG("ppp_async: missed ALLSTATIONS (0xff), got 0x%x\n", c);
			    FLUSHEM(q, p);
			    continue;
			}
		    }
		} /* end if !p->pai_buffcount */

		if (p->pai_buffcount == 1 && c != PPP_UI) {
		    DLOG("ppp_async: missed UI (0x3), got 0x%x\n", c);
		    FLUSHEM(q,p);
		    continue;
		}

		if (p->pai_buffcount == 2 && (c & 1) == 1) {
		    if (p->pai_flags & PAI_FLAGS_RCV_COMPPROT)
			STUFF_CHAR(p, 0);
		    else {
			DLOG("ppp_async: bad protocol high byte %x\n", c);
			FLUSHEM(q, p);
			continue;
		    }
		}

		if (p->pai_buffcount == 3 && (c & 1) == 0) {
		    DLOG("ppp_async: bad protocol low byte %x\n", c);
		    FLUSHEM(q, p);
		    continue;
		}

		if (p->pai_buffcount >= p->pai_buffsize) {	/* overrun */
		    DLOG("ppp_async: too many chars in input buffer %d\n",
			 p->pai_buffcount);
		    FLUSHEM(q, p);
		    continue;
		}

		/* determine if we have enough space in the buffer */
		if (wptr >= p->pai_bufftail->b_datap->db_lim) {
		    p->pai_bufftail->b_wptr = wptr;
		    if (!(p->pai_bufftail = allocb(ALLOCBSIZE, BPRI_MED))) {
			DLOG("ppp_async: couldn't get buffer for tail\n", 0);
			FLUSHEM(q, p);	/* discard all of it */
			continue;
		    }
		    linkb(p->pai_buffer, p->pai_bufftail);
		    wptr = p->pai_bufftail->b_wptr;
		}

		STUFF_CHAR(p, c);
		p->pai_fcs = PPP_FCS(p->pai_fcs, c);

		if (p->pai_buffcount >= PPP_HDRLEN) {
		    while (cp < mp->b_wptr
			   && wptr < p->pai_bufftail->b_datap->db_lim
			   && (c = *cp) != PPP_FLAG && c != PPP_ESCAPE) {
			if (c >= 0x20 || (p->pai_rasyncmap & (1 << c)) == 0) {
			    STUFF_CHAR(p, c);
			    p->pai_fcs = PPP_FCS(p->pai_fcs, c);
			}
			++cp;
		    }
		}

		p->pai_bufftail->b_wptr = wptr;

	    } /* end while cp < wptr */
	}	/* end for each block */
	/* discard this message now */
	freemsg(m0);
    }	/* end while  getq */
  
}

#if DEBUGS
/*
 * here is where we will dump out a frame in hex using the log() 
 * function if ppp_async_input_debug is non-zero. As this function is
 * a pig, we only print up to the number of bytes specified by the value of
 * the ppp_async_max_dump_bytes variable so as to not cause too many
 * timeouts.   <gmc@quotron.com> 
 */

static void
ppp_dump_frame(p, mptr, msg)
    register PAI *p;
    register mblk_t *mptr;
    char *msg;
{
    register u_char *rptr;
    register u_int i, mlen, frame_length;
    char buf[2*MAX_DUMP_BYTES+4];	/* tmp buffer */
    char *bp = buf;
    static char digits[] = "0123456789abcdef";

    frame_length = i = msgdsize(mptr);
    bsdlog(LOG_INFO, "ppp_async%d:%s frame of %d bytes\n", p - pai,
	msg, frame_length); 
    rptr = mptr->b_rptr; /* get pointer to beginning  */
    mlen = mptr->b_wptr - rptr; /* get length of this dblock */

    /* only dump up to MAX_DUMP_BYTES */
    if (i > ppp_async_max_dump_bytes)
	i = ppp_async_max_dump_bytes;   

    while (i--) {			/* convert to ascii hex */
	while (mlen == 0) {		/* get next dblock */
	    mptr = mptr->b_cont;
	    if (mptr) { /* are we done? */
		rptr = mptr->b_rptr;	/* nope, get next dblock */
		mlen = mptr->b_wptr - rptr;
	    }
	    else {			/* no more dblocks */
		if (i != 0)
		    bsdlog(LOG_ERR, "ppp_async: ran out of data! (this shouldn't happen\n");
		break;
	    }
	}
	--mlen;
	*bp++ = digits[*rptr >> 4]; /* convert byte to ascii hex */
	*bp++ = digits[*rptr++ & 0xf];
    }

    /* add a '>' to show that frame was truncated*/
    if (ppp_async_max_dump_bytes < frame_length)
	*bp++ = '>';
    *bp = 0;
    bsdlog(LOG_INFO,"ppp_async: %s\n", buf); 
}
#endif /* DEBUGS */

#endif /* NUM_PPP > 0 */
