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
 * $Id: ppp_ahdlc.c,v 1.2 1995/05/19 02:18:34 paulus Exp $
 */

/*
 * This file is used under Solaris 2.
 */

#include <sys/types.h>
#include <sys/param.h>
#include <sys/stream.h>
#include <sys/modctl.h>
#include <sys/conf.h>
#include <sys/kmem.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/errno.h>
#include <sys/cmn_err.h>
#include <net/ppp_defs.h>
#include <net/pppio.h>

#define IFRAME_BSIZE	512	/* Block size to allocate for input */
#define OFRAME_BSIZE	4096	/* Don't allocb more than this for output */

static int ahdlc_open __P((queue_t *, dev_t *, int, int, cred_t *));
static int ahdlc_close __P((queue_t *, int, cred_t *));
static int ahdlc_wput __P((queue_t *, mblk_t *));
static int ahdlc_rput __P((queue_t *, mblk_t *));
static void stuff_frame __P((queue_t *, mblk_t *));
static void unstuff_chars __P((queue_t *, mblk_t *));

static struct module_info minfo = {
    0x7d23, "ppp_ahdl", 0, INFPSZ, 4096, 128
};

static struct qinit rinit = {
    ahdlc_rput, NULL, ahdlc_open, ahdlc_close, NULL, &minfo, NULL
};

static struct qinit winit = {
    ahdlc_wput, NULL, NULL, NULL, NULL, &minfo, NULL
};

static struct streamtab ahdlc_info = {
    &rinit, &winit, NULL, NULL
};
    
static struct fmodsw fsw = {
    "ppp_ahdl",
    &ahdlc_info,
    D_NEW | D_MP | D_MTQPAIR
};

extern struct mod_ops mod_strmodops;

static struct modlstrmod modlstrmod = {
    &mod_strmodops,
    "PPP async HDLC module",
    &fsw
};

static struct modlinkage modlinkage = {
    MODREV_1,
    (void *) &modlstrmod,
    NULL
};

struct ahdlc_state {
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
};

/* Values for flags */
#define ESCAPED		1	/* last saw escape char on input */
#define IFLUSH		2	/* flushing input due to error */

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
ahdlc_open(q, devp, flag, sflag, credp)
    queue_t *q;
    dev_t *devp;
    int flag, sflag;
    cred_t *credp;
{
    struct ahdlc_state *sp;

    if (q->q_ptr == 0) {
	sp = (struct ahdlc_state *) kmem_zalloc(sizeof(struct ahdlc_state),
						KM_SLEEP);
	if (sp == 0)
	    return ENOSR;
	q->q_ptr = sp;
	WR(q)->q_ptr = sp;
	sp->xaccm[0] = ~0;
	sp->xaccm[3] = 0x60000000;
	sp->mru = 1500;
	qprocson(q);
    }
    return 0;
}

static int
ahdlc_close(q, flag, credp)
    queue_t *q;
    int flag;
    cred_t *credp;
{
    struct ahdlc_state *state;

    qprocsoff(q);
    if (q->q_ptr != 0) {
	state = (struct ahdlc_state *) q->q_ptr;
	if (state->cur_frame != 0) {
	    freemsg(state->cur_frame);
	    state->cur_frame = 0;
	}
	kmem_free(q->q_ptr, sizeof(struct ahdlc_state));
    }
    return 0;
}

static int
ahdlc_wput(q, mp)
    queue_t *q;
    mblk_t *mp;
{
    struct ahdlc_state *state;
    struct iocblk *iop;
    int error;

    state = (struct ahdlc_state *) q->q_ptr;
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
	    bcopy(mp->b_cont->b_rptr, (caddr_t)state->xaccm, iop->ioc_count);
	    state->xaccm[2] &= 0x40000000;	/* don't escape 0x5e */
	    state->xaccm[3] |= 0x60000000;	/* do escape 0x7d, 0x7e */
	    iop->ioc_count = 0;
	    error = 0;
	    break;

	case PPPIO_RACCM:
	    if (iop->ioc_count != sizeof(u_int32_t))
		break;
	    bcopy(mp->b_cont->b_rptr, (caddr_t)&state->raccm,
		  sizeof(u_int32_t));
	    iop->ioc_count = 0;
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
    struct ahdlc_state *state;

    switch (mp->b_datap->db_type) {
    case M_DATA:
	unstuff_chars(q, mp);
	freemsg(mp);
	break;

    case M_HANGUP:
	state = (struct ahdlc_state *) q->q_ptr;
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
    struct ahdlc_state *state;
    int ilen, olen, c, extra;
    mblk_t *omsg, *np, *op;
    uchar_t *sp, *sp0, *dp, *dp0, *spend;
    ushort_t fcs;
    u_int32_t *xaccm, lcp_xaccm[8];

    /*
     * We estimate the length of the output packet as
     * 1.25 * input length + 16 (for initial flag, FCS, final flag, slop).
     */
    state = (struct ahdlc_state *) q->q_ptr;
    ilen = msgdsize(mp);
    olen = ilen + (ilen >> 2) + 16;
    if (olen > OFRAME_BSIZE)
	olen = OFRAME_BSIZE;
    omsg = op = allocb(olen, BPRI_MED);
    if (omsg == 0)
	return;

    /*
     * Put in an initial flag for now.  We'll remove it later
     * if we decide we don't need it.
     */
    dp = op->b_wptr;
    *dp++ = PPP_FLAG;
    --olen;

    /*
     * For LCP packets, we must escape all control characters.
     * LCP packets must not be A/C or protocol compressed.
     */
    xaccm = state->xaccm;
    if (ilen >= PPP_HDRLEN) {
	if (mp->b_wptr - mp->b_rptr >= PPP_HDRLEN
	    || pullupmsg(mp, PPP_HDRLEN)) {
	    if (PPP_ADDRESS(mp->b_rptr) == PPP_ALLSTATIONS
		&& PPP_CONTROL(mp->b_rptr) == PPP_UI
		&& PPP_PROTOCOL(mp->b_rptr) == PPP_LCP) {
		bcopy((caddr_t) state->xaccm, (caddr_t) lcp_xaccm,
		      sizeof(lcp_xaccm));
		lcp_xaccm[0] = ~0;
		xaccm = lcp_xaccm;
	    }
	}
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
	    if (np == 0) {
		freemsg(omsg);
		return;
	    }
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
	if (np == 0) {
	    freemsg(omsg);
	    return;
	}
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

    putnext(q, omsg);
}

static void
unstuff_chars(q, mp)
    queue_t *q;
    mblk_t *mp;
{
    struct ahdlc_state *state;
    mblk_t *om;
    uchar_t *cp, *cpend, *dp, *dp0;
    int c, len, extra, offset;
    ushort_t fcs;

    state = (struct ahdlc_state *) q->q_ptr;
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
	    && state->inlen >= PPP_HDRLEN
	    && (om = state->cur_blk) != 0) {
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
		if (c == PPP_ESCAPE) {
		    if (extra > 0) {
			--extra;
			++cpend;
		    } else if (cp >= cpend) {
			state->flags |= ESCAPED;
			break;
		    }
		    c = *cp;
		    if (c == PPP_FLAG)
			break;
		    ++cp;
		    c ^= PPP_TRANS;
		}
		*dp++ = c;
		fcs = PPP_FCS(fcs, c);
	    }
	    state->inlen += dp - dp0;
	    state->infcs = fcs;
	    om->b_wptr = dp;
	    if (cp >= cpend)
		continue;	/* go back and check cp again */
	}

	c = *cp++;
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
	    if (om == 0)
		continue;
	    if (!(state->flags & (IFLUSH|ESCAPED) || len < PPP_FCSLEN)) {
		if (state->infcs == PPP_GOODFCS) {
		    adjmsg(om, -PPP_FCSLEN);	/* chop off fcs */
		    putnext(q, om);		/* bombs away! */
		    continue;
		}
		/* incr bad fcs stats */
#if DEBUG
		cmn_err(CE_CONT, "ppp_ahdl: bad fcs %x\n", state->infcs);
#endif
	    }
	    freemsg(om);
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
#if DEBUG
		    cmn_err(CE_CONT, "ppp_ahdl: frame too long (%d)\n",
			    state->inlen);
#endif
		    state->flags |= IFLUSH;
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
	*om->b_wptr++ = c;
	++state->inlen;
	state->infcs = PPP_FCS(state->infcs, c);

	if (state->inlen == PPP_HDRLEN) {
	    /*
	     * We don't do address/control & protocol decompression here,
	     * but we do leave space for the decompressed fields and
	     * arrange for the info field to start on a word boundary.
	     */
	    dp = om->b_rptr;
	    if (PPP_ADDRESS(dp) == PPP_ALLSTATIONS
		&& PPP_CONTROL(dp) == PPP_UI)
		dp += 2;
	    if ((*dp & 1) == 0)
		++dp;
	    /* dp is now pointing at the last byte of the ppp protocol field */
	    offset = 3 - ((unsigned)dp & 3);
	    if (offset > 0) {
		dp = om->b_wptr;
		do {
		    --dp;
		    dp[offset] = dp[0];
		} while (dp > om->b_rptr);
		om->b_rptr += offset;
		om->b_wptr += offset;
	    }
	}
    }
}

