/*
 * ppp_ahdlc.c - STREAMS module for doing PPP asynchronous HDLC.
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
 * THE AUSTRALIAN NATIONAL UNIVERSITY HAS BEEN ADVISED OF THE POSSIBILITY
 * OF SUCH DAMAGE.
 *
 * THE AUSTRALIAN NATIONAL UNIVERSITY SPECIFICALLY DISCLAIMS ANY WARRANTIES,
 * INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY
 * AND FITNESS FOR A PARTICULAR PURPOSE.  THE SOFTWARE PROVIDED HEREUNDER IS
 * ON AN "AS IS" BASIS, AND THE AUSTRALIAN NATIONAL UNIVERSITY HAS NO
 * OBLIGATION TO PROVIDE MAINTENANCE, SUPPORT, UPDATES, ENHANCEMENTS,
 * OR MODIFICATIONS.
 *
 * $Id: ppp_ahdlc.c,v 1.3 1996/08/28 06:35:50 paulus Exp $
 */

/*
 * This file is used under Solaris 2, SVR4, SunOS 4, and Digital UNIX.
 */
#include <sys/types.h>
#include <sys/param.h>
#include <sys/stream.h>
#include <sys/errno.h>

#ifdef SVR4
#include <sys/conf.h>
#include <sys/kmem.h>
#include <sys/cmn_err.h>
#include <sys/ddi.h>
#else
#include <sys/user.h>
#endif /* SVR4 */

#include <net/ppp_defs.h>
#include <net/pppio.h>
#include "ppp_mod.h"

#define IFRAME_BSIZE	512	/* Block size to allocate for input */
#define OFRAME_BSIZE	4096	/* Don't allocb more than this for output */

MOD_OPEN_DECL(ahdlc_open);
MOD_CLOSE_DECL(ahdlc_close);
static int ahdlc_wput __P((queue_t *, mblk_t *));
static int ahdlc_rput __P((queue_t *, mblk_t *));
static void stuff_frame __P((queue_t *, mblk_t *));
static void unstuff_chars __P((queue_t *, mblk_t *));
static int msg_byte __P((mblk_t *, unsigned int));

/* Extract byte i of message mp. */
#define MSG_BYTE(mp, i)	((i) < (mp)->b_wptr - (mp)->b_rptr? (mp)->b_rptr[i]: \
			 msg_byte((mp), (i)))

/* Is this LCP packet one we have to transmit using LCP defaults? */
#define LCP_USE_DFLT(mp)	(1 <= (code = MSG_BYTE((mp), 4)) && code <= 7)

#define PPP_AHDL_ID 0x7d23
static struct module_info minfo = {
    PPP_AHDL_ID, "ppp_ahdl", 0, INFPSZ, 4096, 128
};

static struct qinit rinit = {
    ahdlc_rput, NULL, ahdlc_open, ahdlc_close, NULL, &minfo, NULL
};

static struct qinit winit = {
    ahdlc_wput, NULL, NULL, NULL, NULL, &minfo, NULL
};

struct streamtab ppp_ahdlcinfo = {
    &rinit, &winit, NULL, NULL
};

int ppp_ahdlc_count;

typedef struct ahdlc_state {
    int flags;
    mblk_t *cur_frame;
    mblk_t *cur_blk;
    int inlen;
    ushort infcs;
    u_int32_t xaccm[8];
    u_int32_t raccm;
    int mtu;
    int mru;
    int unit;
    struct pppstat stats;
} ahdlc_state_t;

/* Values for flags */
#define ESCAPED		0x100	/* last saw escape char on input */
#define IFLUSH		0x200	/* flushing input due to error */

/* RCV_B7_1, etc., defined in net/pppio.h, are stored in flags also. */
#define RCV_FLAGS	(RCV_B7_1|RCV_B7_0|RCV_ODDP|RCV_EVNP)

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

/*
 * STREAMS module entry points.
 */
MOD_OPEN(ahdlc_open)
{
    ahdlc_state_t *sp;

    if (q->q_ptr == 0) {
	sp = (ahdlc_state_t *) ALLOC_SLEEP(sizeof(ahdlc_state_t));
	if (sp == 0)
	    OPEN_ERROR(ENOSR);
	bzero((caddr_t) sp, sizeof(ahdlc_state_t));
	q->q_ptr = (caddr_t) sp;
	WR(q)->q_ptr = (caddr_t) sp;
	sp->xaccm[0] = ~0;
	sp->xaccm[3] = 0x60000000;
	sp->mru = 1500;
	++ppp_ahdlc_count;
	qprocson(q);
    }
    return 0;
}

MOD_CLOSE(ahdlc_close)
{
    ahdlc_state_t *state;

    qprocsoff(q);
    if (q->q_ptr != 0) {
	state = (ahdlc_state_t *) q->q_ptr;
	if (state->cur_frame != 0) {
	    freemsg(state->cur_frame);
	    state->cur_frame = 0;
	}
	FREE(q->q_ptr, sizeof(ahdlc_state_t));
	--ppp_ahdlc_count;
    }
    return 0;
}

static int
ahdlc_wput(q, mp)
    queue_t *q;
    mblk_t *mp;
{
    ahdlc_state_t *state;
    struct iocblk *iop;
    int error;
    mblk_t *np;
    struct ppp_stats *psp;

    state = (ahdlc_state_t *) q->q_ptr;
    switch (mp->b_datap->db_type) {
    case M_DATA:
	/*
	 * A data packet - do character-stuffing and FCS, and
	 * send it onwards.
	 */
	stuff_frame(q, mp);
	freemsg(mp);
	break;

    case M_IOCTL:
	iop = (struct iocblk *) mp->b_rptr;
	error = EINVAL;
	switch (iop->ioc_cmd) {
	case PPPIO_XACCM:
	    if (iop->ioc_count < sizeof(u_int32_t)
		|| iop->ioc_count > sizeof(ext_accm))
		break;
	    bcopy((caddr_t)mp->b_cont->b_rptr, (caddr_t)state->xaccm,
		  iop->ioc_count);
	    state->xaccm[2] &= ~0x40000000;	/* don't escape 0x5e */
	    state->xaccm[3] |= 0x60000000;	/* do escape 0x7d, 0x7e */
	    iop->ioc_count = 0;
	    error = 0;
	    break;

	case PPPIO_RACCM:
	    if (iop->ioc_count != sizeof(u_int32_t))
		break;
	    bcopy((caddr_t)mp->b_cont->b_rptr, (caddr_t)&state->raccm,
		  sizeof(u_int32_t));
	    iop->ioc_count = 0;
	    error = 0;
	    break;

	case PPPIO_GCLEAN:
	    np = allocb(sizeof(int), BPRI_HI);
	    if (np == 0) {
		error = ENOSR;
		break;
	    }
	    if (mp->b_cont != 0)
		freemsg(mp->b_cont);
	    mp->b_cont = np;
	    *(int *)np->b_wptr = state->flags & RCV_FLAGS;
	    np->b_wptr += sizeof(int);
	    iop->ioc_count = sizeof(int);
	    error = 0;
	    break;

	case PPPIO_GETSTAT:
	    np = allocb(sizeof(struct ppp_stats), BPRI_HI);
	    if (np == 0) {
		error = ENOSR;
		break;
	    }
	    if (mp->b_cont != 0)
		freemsg(mp->b_cont);
	    mp->b_cont = np;
	    psp = (struct ppp_stats *) np->b_wptr;
	    np->b_wptr += sizeof(struct ppp_stats);
	    bzero((caddr_t)psp, sizeof(struct ppp_stats));
	    psp->p = state->stats;
	    iop->ioc_count = sizeof(struct ppp_stats);
	    error = 0;
	    break;

	case PPPIO_LASTMOD:
	    /* we knew this anyway */
	    error = 0;
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
	    iop->ioc_count = 0;
	    iop->ioc_error = error;
	    qreply(q, mp);
	}
	break;

    case M_CTL:
	switch (*mp->b_rptr) {
	case PPPCTL_MTU:
	    state->mtu = ((unsigned short *)mp->b_rptr)[1];
	    freemsg(mp);
	    break;
	case PPPCTL_MRU:
	    state->mru = ((unsigned short *)mp->b_rptr)[1];
	    freemsg(mp);
	    break;
	case PPPCTL_UNIT:
	    state->unit = mp->b_rptr[1];
	    break;
	default:
	    putnext(q, mp);
	}
	break;

    default:
	putnext(q, mp);
    }
    return 0;
}

static int
ahdlc_rput(q, mp)
    queue_t *q;
    mblk_t *mp;
{
    mblk_t *np;
    uchar_t *cp;
    ahdlc_state_t *state;

    switch (mp->b_datap->db_type) {
    case M_DATA:
	unstuff_chars(q, mp);
	freemsg(mp);
	break;

    case M_HANGUP:
	state = (ahdlc_state_t *) q->q_ptr;
	if (state->cur_frame != 0) {
	    /* XXX would like to send this up for debugging */
	    freemsg(state->cur_frame);
	    state->cur_frame = 0;
	    state->cur_blk = 0;
	}
	state->inlen = 0;
	state->flags = IFLUSH;
	putnext(q, mp);
	break;

    default:
	putnext(q, mp);
    }
    return 0;
}

/* Extract bit c from map m, to determine if c needs to be escaped. */
#define ESCAPE(c, m)	((m)[(c) >> 5] & (1 << ((c) & 0x1f)))

static void
stuff_frame(q, mp)
    queue_t *q;
    mblk_t *mp;
{
    ahdlc_state_t *state;
    int ilen, olen, c, extra, i, code;
    mblk_t *omsg, *op, *np;
    uchar_t *sp, *sp0, *dp, *dp0, *spend;
    ushort_t fcs;
    u_int32_t *xaccm, lcp_xaccm[8];
    static uchar_t lcphdr[PPP_HDRLEN] = { 0xff, 0x03, 0xc0, 0x21 };
    uchar_t ppphdr[PPP_HDRLEN];

    state = (ahdlc_state_t *) q->q_ptr;
    ilen = msgdsize(mp);

    /*
     * We estimate the length of the output packet as
     * 1.25 * input length + 16 (for initial flag, FCS, final flag, slop).
     */
    olen = ilen + (ilen >> 2) + 16;
    if (olen > OFRAME_BSIZE)
	olen = OFRAME_BSIZE;
    omsg = op = allocb(olen, BPRI_MED);
    if (omsg == 0)
	goto bomb;

    /*
     * Put in an initial flag for now.  We'll remove it later
     * if we decide we don't need it.
     */
    dp = op->b_wptr;
    *dp++ = PPP_FLAG;
    --olen;

    /*
     * For LCP packets with code values between 1 and 7 (Conf-Req
     * to Code-Rej), we must escape all control characters.
     */
    xaccm = state->xaccm;
    if (MSG_BYTE(mp, 0) == PPP_ALLSTATIONS
	&& MSG_BYTE(mp, 1) == PPP_UI
	&& MSG_BYTE(mp, 2) == (PPP_LCP >> 8)
	&& MSG_BYTE(mp, 3) == (PPP_LCP & 0xFF)
	&& LCP_USE_DFLT(mp)) {
	bcopy((caddr_t) state->xaccm, (caddr_t) lcp_xaccm, sizeof(lcp_xaccm));
	lcp_xaccm[0] = ~0;
	xaccm = lcp_xaccm;
    }

    sp = mp->b_rptr;
    fcs = PPP_INITFCS;
    for (;;) {
	spend = mp->b_wptr;
	extra = sp + olen - spend;
	if (extra < 0) {
	    spend = sp + olen;
	    extra = 0;
	}
	/*
	 * We can safely process the input up to `spend'
	 * without overrunning the output, provided we don't
	 * hit more than `extra' characters which need to be escaped.
	 */
	sp0 = sp;
	dp0 = dp;
	while (sp < spend) {
	    c = *sp;
	    if (ESCAPE(c, xaccm)) {
		if (extra > 0)
		    --extra;
		else if (sp < spend - 1)
		    --spend;
		else
		    break;
		fcs = PPP_FCS(fcs, c);
		*dp++ = PPP_ESCAPE;
		c ^= PPP_TRANS;
	    } else
		fcs = PPP_FCS(fcs, c);
	    *dp++ = c;
	    ++sp;
	}
	ilen -= sp - sp0;
	olen -= dp - dp0;

	/*
	 * At this point, we have emptied an input block
	 * and/or filled an output block.
	 */
	if (sp >= mp->b_wptr) {
	    /*
	     * We've emptied an input block.  Advance to the next.
	     */
	    mp = mp->b_cont;
	    if (mp == 0)
		break;		/* all done */
	    sp = mp->b_rptr;
	}
	if (olen < 2) {
	    /*
	     * The output block is full.  Allocate a new one.
	     */
	    op->b_wptr = dp;
	    olen = 2 * ilen + 5;
	    if (olen > OFRAME_BSIZE)
		olen = OFRAME_BSIZE;
	    np = allocb(olen, BPRI_MED);
	    if (np == 0)
		goto bomb;
	    op->b_cont = np;
	    op = np;
	    dp = op->b_wptr;
	}
    }

    /*
     * Append the FCS and closing flag.
     * This could require up to 5 characters.
     */
    if (olen < 5) {
	/* Sigh.  Need another block. */
	op->b_wptr = dp;
	np = allocb(5, BPRI_MED);
	if (np == 0)
	    goto bomb;
	op->b_cont = np;
	op = np;
	dp = op->b_wptr;
    }
    c = ~fcs & 0xff;
    if (ESCAPE(c, xaccm)) {
	*dp++ = PPP_ESCAPE;
	c ^= PPP_TRANS;
    }
    *dp++ = c;
    c = (~fcs >> 8) & 0xff;
    if (ESCAPE(c, xaccm)) {
	*dp++ = PPP_ESCAPE;
	c ^= PPP_TRANS;
    }
    *dp++ = c;
    *dp++ = PPP_FLAG;
    op->b_wptr = dp;

    /*
     * Remove the initial flag, if possible.
     */
    if (qsize(q->q_next) > 0)
	++omsg->b_rptr;

    /*
     * Update statistics.
     */
    state->stats.ppp_obytes += msgdsize(omsg);
    state->stats.ppp_opackets++;

    /*
     * Send it on.
     */
    putnext(q, omsg);
    return;

 bomb:
    if (omsg != 0)
	freemsg(omsg);
    state->stats.ppp_oerrors++;
    putctl1(RD(q)->q_next, M_CTL, PPPCTL_OERROR);
}

#define UPDATE_FLAGS(c)	{				\
    if ((c) & 0x80)					\
	state->flags |= RCV_B7_1;			\
    else						\
	state->flags |= RCV_B7_0;			\
    if (0x6996 & (1 << ((((c) >> 4) ^ (c)) & 0xf)))	\
	state->flags |= RCV_ODDP;			\
    else						\
	state->flags |= RCV_EVNP;			\
}

/*
 * Process received characters.
 */
static void
unstuff_chars(q, mp)
    queue_t *q;
    mblk_t *mp;
{
    ahdlc_state_t *state;
    mblk_t *om;
    uchar_t *cp, *cpend, *dp, *dp0;
    int c, len, extra, offset;
    ushort_t fcs;

    state = (ahdlc_state_t *) q->q_ptr;
    state->stats.ppp_ibytes += msgdsize(mp);
    cp = mp->b_rptr;
    for (;;) {
	/*
	 * Advance to next input block if necessary.
	 */
	if (cp >= mp->b_wptr) {
	    mp = mp->b_cont;
	    if (mp == 0)
		break;
	    cp = mp->b_rptr;
	    continue;
	}

	if ((state->flags & (IFLUSH|ESCAPED)) == 0
	    && state->inlen > 0 && (om = state->cur_blk) != 0) {
	    /*
	     * Process bulk chars as quickly as possible.
	     */
	    dp = om->b_wptr;
	    len = om->b_datap->db_lim - dp; /* max # output bytes */
	    extra = (mp->b_wptr - cp) - len;/* #input chars - #output bytes */
	    if (extra < 0) {
		len += extra;		    /* we'll run out of input first */
		extra = 0;
	    }
	    cpend = cp + len;
	    dp0 = dp;
	    fcs = state->infcs;
	    while (cp < cpend) {
		c = *cp;
		if (c == PPP_FLAG)
		    break;
		++cp;
		UPDATE_FLAGS(c);
		if (c == PPP_ESCAPE) {
		    if (extra > 0) {
			--extra;
			++cpend;
		    }
		    if (cp >= cpend || (c = *cp) == PPP_FLAG) {
			state->flags |= ESCAPED;
			break;
		    }
		    ++cp;
		    UPDATE_FLAGS(c);
		    c ^= PPP_TRANS;
		}
		*dp++ = c;
		fcs = PPP_FCS(fcs, c);
	    }
	    state->inlen += dp - dp0;
	    state->infcs = fcs;
	    om->b_wptr = dp;
	    if (cp >= mp->b_wptr)
		continue;	/* advance to the next mblk */
	}

	c = *cp++;
	UPDATE_FLAGS(c);
	if (c == PPP_FLAG) {
	    /*
	     * End of a frame.
	     * If the ESCAPE flag is set, the frame ended with
	     * the frame abort sequence "}~".
	     */
	    om = state->cur_frame;
	    len = state->inlen;
	    state->cur_frame = 0;
	    state->inlen = 0;
	    if (len == 0 && (state->flags & IFLUSH) == 0)
		continue;
	    state->stats.ppp_ipackets++;
	    if (om != 0 && (state->flags & (IFLUSH|ESCAPED)) == 0
		&& len > PPP_FCSLEN) {
		if (state->infcs == PPP_GOODFCS) {
		    adjmsg(om, -PPP_FCSLEN);	/* chop off fcs */
		    putnext(q, om);		/* bombs away! */
		    continue;
		}
		DPRINT2("ppp%d: bad fcs (len=%d)\n", state->unit, len);
	    }
	    if (om != 0)
		freemsg(om);
	    state->flags &= ~(IFLUSH|ESCAPED);
	    state->stats.ppp_ierrors++;
	    putctl1(q->q_next, M_CTL, PPPCTL_IERROR);
	    continue;
	}

	if (state->flags & IFLUSH)
	    continue;
	if (state->flags & ESCAPED) {
	    c ^= PPP_TRANS;
	    state->flags &= ~ESCAPED;
	} else if (c == PPP_ESCAPE) {
	    state->flags |= ESCAPED;
	    continue;
	}
	if (state->inlen == 0) {
	    /*
	     * First byte of the frame: allocate the first message block.
	     */
	    om = allocb(IFRAME_BSIZE, BPRI_MED);
	    if (om == 0) {
		state->flags |= IFLUSH;
		continue;
	    }
	    state->cur_frame = om;
	    state->cur_blk = om;
	    state->infcs = PPP_INITFCS;
	} else {
	    om = state->cur_blk;
	    if (om->b_wptr >= om->b_datap->db_lim) {
		/*
		 * Current message block is full.  Allocate another one,
		 * unless we have run out of MRU.
		 */
		if (state->inlen >= state->mru + PPP_HDRLEN + PPP_FCSLEN) {
		    state->flags |= IFLUSH;
		    DPRINT2("ppp%d: frame too long (%d)\n",
			    state->unit, state->inlen);
		    continue;
		}
		om = allocb(IFRAME_BSIZE, BPRI_MED);
		if (om == 0) {
		    state->flags |= IFLUSH;
		    continue;
		}
		state->cur_blk->b_cont = om;
		state->cur_blk = om;
	    }
	}

	if (state->inlen == 0) {
	    /*
	     * We don't do address/control & protocol decompression here,
	     * but we try to put the first byte at an offset such that
	     * the info field starts on a word boundary.  The code here
	     * will do this except for packets with protocol compression
	     * but not address/control compression.
	     */
	    if (c != PPP_ALLSTATIONS) {
		om->b_wptr += 2;
		if (c & 1)
		    ++om->b_wptr;
		om->b_rptr = om->b_wptr;
	    }
	}

	*om->b_wptr++ = c;
	++state->inlen;
	state->infcs = PPP_FCS(state->infcs, c);
    }
}

static int
msg_byte(mp, i)
    mblk_t *mp;
    unsigned int i;
{
    while (mp != 0 && i >= mp->b_wptr - mp->b_rptr)
	mp = mp->b_cont;
    if (mp == 0)
	return -1;
    return mp->b_rptr[i];
}
