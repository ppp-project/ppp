/*	$ID: ppp_tty.c,v 1.4 1994/12/13 03:42:17 paulus Exp paulus $	*/

/*
 * ppp_tty.c - Point-to-Point Protocol (PPP) driver for asynchronous
 *	       tty devices.
 *
 * Copyright (c) 1989 Carnegie Mellon University.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms are permitted
 * provided that the above copyright notice and this paragraph are
 * duplicated in all such forms and that any documentation,
 * advertising materials, and other materials related to such
 * distribution and use acknowledge that the software was developed
 * by Carnegie Mellon University.  The name of the
 * University may not be used to endorse or promote products derived
 * from this software without specific prior written permission.
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND WITHOUT ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, WITHOUT LIMITATION, THE IMPLIED
 * WARRANTIES OF MERCHANTIBILITY AND FITNESS FOR A PARTICULAR PURPOSE.
 *
 * Drew D. Perkins
 * Carnegie Mellon University
 * 4910 Forbes Ave.
 * Pittsburgh, PA 15213
 * (412) 268-8576
 * ddp@andrew.cmu.edu
 *
 * Based on:
 *	@(#)if_sl.c	7.6.1.2 (Berkeley) 2/15/89
 *
 * Copyright (c) 1987 Regents of the University of California.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms are permitted
 * provided that the above copyright notice and this paragraph are
 * duplicated in all such forms and that any documentation,
 * advertising materials, and other materials related to such
 * distribution and use acknowledge that the software was developed
 * by the University of California, Berkeley.  The name of the
 * University may not be used to endorse or promote products derived
 * from this software without specific prior written permission.
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND WITHOUT ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, WITHOUT LIMITATION, THE IMPLIED
 * WARRANTIES OF MERCHANTIBILITY AND FITNESS FOR A PARTICULAR PURPOSE.
 *
 * Serial Line interface
 *
 * Rick Adams
 * Center for Seismic Studies
 * 1300 N 17th Street, Suite 1450
 * Arlington, Virginia 22209
 * (703)276-7900
 * rick@seismo.ARPA
 * seismo!rick
 *
 * Pounded on heavily by Chris Torek (chris@mimsy.umd.edu, umcp-cs!chris).
 * Converted to 4.3BSD Beta by Chris Torek.
 * Other changes made at Berkeley, based in part on code by Kirk Smith.
 *
 * Converted to 4.3BSD+ 386BSD by Brad Parker (brad@cayman.com)
 * Added VJ tcp header compression; more unified ioctls
 *
 * Extensively modified by Paul Mackerras (paulus@cs.anu.edu.au).
 * Cleaned up a lot of the mbuf-related code to fix bugs that
 * caused system crashes and packet corruption.  Changed pppstart
 * so that it doesn't just give up with a collision if the whole
 * packet doesn't fit in the output ring buffer.
 *
 * Added priority queueing for interactive IP packets, following
 * the model of if_sl.c, plus hooks for bpf.
 * Paul Mackerras (paulus@cs.anu.edu.au).
 *
 * Rewritten for NextStep's funky kernel functions, I/O threads,
 * and netbufs (instead of real mbufs).  Also, ifnets don't install
 * into the kernel under NS as they do under BSD.  We have tried to
 * make the code remain as similar to the NetBSD version without
 * incurring too much hassle.  This code is the merge of 
 * Philip Prindeville's <philipp@res.enst.fr>/Pete French's <pete@ohm.york.ac.uk>
 * and Stephen Perkins'  <perkins@cps.msu.edu> independent ports.
 *
 */

/* from if_sl.c,v 1.11 84/10/04 12:54:47 rick Exp */
/* from NetBSD: if_ppp.c,v 1.15.2.2 1994/07/28 05:17:59 cgd Exp */

/* #include "ppp.h" */
#if NUM_PPP > 0

#define KERNEL 1
#define KERNEL_FEATURES 1
#define INET 1

#include <sys/param.h>
#include <sys/proc.h>
#include <sys/user.h>
#include "netbuf.h"
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/file.h>
#include <sys/tty.h>
#include <sys/conf.h>
#include <sys/dk.h>
#include <sys/uio.h>
#include <sys/errno.h>
#include <machine/param.h>


#include <kernserv/prototypes.h>
/* NeXT broke spl.h in 3.2/m68k. Thanks EPS! */

#if defined(m68k)
#import "spl.h"
#else
#include <driverkit/generalFuncs.h>
#import <kernserv/machine/spl.h>
#endif

#include <kernserv/kern_server_types.h>

#include <net/if.h>
#include <net/route.h>

#ifdef VJC
#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <netinet/ip.h>
#endif

#include <net/ppp_defs.h>
#ifdef VJC
#include <net/vjcompress.h>
#endif
#include <net/if_ppp.h>
#include "if_pppvar.h"

#include "inlines.h"

int	pppopen __P((dev_t dev, struct tty *tp));
void	pppclose __P((struct tty *tp));
int	pppread __P((struct tty *tp, struct uio *uio));
int	pppwrite __P((struct tty *tp, struct uio *uio));
int	ppptioctl __P((struct tty *tp, int cmd, void *data, int flag));
void	pppinput __P((int c, struct tty *tp));
void	pppstart __P((struct tty *tp));

netbuf_t	pppgetbuf __P((netif_t));
int     	pppoutput __P((netif_t ifp, netbuf_t m, void *arg));
void		pppintr __P((void *));

static u_int16_t pppfcs __P((u_int16_t fcs, u_char *cp, int len));
static void	pppasyncstart __P((struct ppp_softc *));
static void	pppasyncctlp __P((struct ppp_softc *));
static void	pppasyncrelinq __P((struct ppp_softc *));
static int	ppp_timeout __P((void *));
void		pppgetm __P((struct ppp_softc *sc));
static void	pppdumpb __P((u_char *b, int l));
void	        ppplogchar __P((struct ppp_softc *, int));

extern kern_server_t instance;

#ifdef ADD_ERRORS

static int in_error_pkt_count = 0;   /* Number of packets received */
static int in_error_limit = -1;      /* Insert error at this limit */
static int in_error_max_sep  = 50;  /* Max range of random number */

static int out_error_pkt_count = 0;   /* Number of packets sent */
static int out_error_limit = -1;      /* Insert error at this limit */
static int out_error_max_sep  = 50;  /* Max range of random number */

#endif /* ADD_ERRORS */


/*
 * Does c need to be escaped?
 */
#define	ESCAPE_P(c)	(sc->sc_asyncmap[(c) >> 5] & (1 << ((c) & 0x1F)))

#define CCOUNT(q)	((q)->c_cc)

#define	PPP_HIWAT	400	/* Don't start a new packet if HIWAT on que */

#include "linedisc.h"  


extern int ttymodem(struct tty*, int);
extern int ttselect(struct tty *tp, int rw);


static netbuf_t
pppgetinbuf(netif_t ifp)
{
    register struct ppp_softc *sc = &ppp_softc[if_unit(ifp)];
    netbuf_t nb;
    int len = MAX(sc->sc_mru, PPP_MTU) + sizeof (struct ifnet *) +
#ifdef VJC
	      VJ_HDRLEN +
#endif
	      PPP_HDRLEN + PPP_FCSLEN;
    nb =  ppp_nb_alloc(len);
    if (nb != NULL)
      {
#ifdef VJC
	ppp_nb_shrink_top(nb, VJ_HDRLEN + PPP_HDRLEN);
#else
	ppp_nb_shrink_top(nb, PPP_HDRLEN);
#endif
      }

    return nb;
}

/*
 * I was a bit worried about reentrancy here.  +++SJP
 */

void
pppfillfreeq(void *arg)
{
    struct ppp_softc *sc = (struct ppp_softc *)arg;
    netbuf_t nb;
    volatile static int in = 0;

    if (in)
      return;
    in = 1;

    while(!nbq_high(&sc->sc_freeq)) {
	nb = pppgetinbuf(sc->sc_if);
	if (! nb) break;
#if 0
	/*
	 * we no longer reset the length to 0 and then advance the
	 * packet length bit by bit; instead we write into it whenever
	 * we want, and at the end resize the packet before handing-off.
	 */
	nb_shrink_bot(nb, nb_size(nb));
#endif
	nbq_enqueue(&sc->sc_freeq, nb);
    }

    in = 0;
}

/*
 * Line specific open routine for async tty devices.
 * Attach the given tty to the first available ppp unit.
 */
/* ARGSUSED */
int
pppopen(dev, tp)
    dev_t dev;
    register struct tty *tp;
{
    struct proc *p = curproc;		/* XXX */
    register struct ppp_softc *sc;
    int s;

    if (! suser())
	return EPERM;

    if (tp->t_line == PPPDISC) {
	sc = (struct ppp_softc *) tp->t_sc;
	if (sc != NULL && sc->sc_devp == (void *) tp)
	    return (0);
    }

    if ((sc = pppalloc(p->p_pid)) == NULL)
	return ENXIO;

    if (sc->sc_relinq)
	(*sc->sc_relinq)(sc);	/* get previous owner to relinquish the unit */

    pppfillfreeq((void *) sc);   /* fill the free queue - we may block */

    s = splimp();
    sc->sc_ilen = 0;
    sc->sc_m = NULL;
    bzero(sc->sc_asyncmap, sizeof(sc->sc_asyncmap));
    sc->sc_asyncmap[0] = 0xffffffff;
    sc->sc_asyncmap[3] = 0x60000000;
    sc->sc_rasyncmap = 0;
    sc->sc_devp = (void *) tp;
    sc->sc_start = pppasyncstart;
    sc->sc_ctlp = pppasyncctlp;
    sc->sc_relinq = pppasyncrelinq;
    sc->sc_outm = NULL;
    pppgetm(sc);
    if_flags_set(sc->sc_if, if_flags(sc->sc_if) | IFF_RUNNING);

    tp->t_sc = (caddr_t) sc;
    ttyflush(tp, FREAD | FWRITE);
    splx(s);

    return (0);
}

/*
 * Line specific close routine.
 * Detach the tty from the ppp unit.
 * Mimics part of ttyclose().
 */
void
pppclose(tp)
    struct tty *tp;
{
    register struct ppp_softc *sc;
    int s;

    ttywflush(tp);
    s = splimp();		/* paranoid; splnet probably ok */
    tp->t_line = 0;
    sc = (struct ppp_softc *) tp->t_sc;
    if (sc != NULL) {
	tp->t_sc = NULL;
	if (tp == (struct tty *) sc->sc_devp) {
	    pppasyncrelinq(sc);
	    pppdealloc(sc);
	}
    }
    splx(s);
    return;
}

/*
 * Relinquish the interface unit to another device.
 */
static void
pppasyncrelinq(sc)
    struct ppp_softc *sc;
{
    int s;

    s = splimp();
    if (sc->sc_outm) {
	nb_free(sc->sc_outm);
	sc->sc_outm = NULL;
    }
    if (sc->sc_m) {
	nb_free(sc->sc_m);
	sc->sc_m = NULL;
    }
    if (sc->sc_flags & SC_TIMEOUT) {
	ns_untimeout(ppp_timeout, (void *) sc);
	sc->sc_flags &= ~SC_TIMEOUT;
    }
    splx(s);
}

/*
 * Line specific (tty) read routine.
 */
int
pppread(tp, uio)
    register struct tty *tp;
    struct uio *uio;
{
    register struct ppp_softc *sc = (struct ppp_softc *)tp->t_sc;
    netbuf_t m;
    register int s;
    int error = 0;

    if ((tp->t_state & TS_CARR_ON) == 0 && (tp->t_flags & CLOCAL) == 0)
	return 0;		/* end of file */
    if (sc == NULL || tp != (struct tty *) sc->sc_devp)
	return 0;
    s = splimp();
    while (nbq_empty(&sc->sc_inq) && tp->t_line == PPPDISC) {
	if (tp->t_state & (TS_ASYNC | TS_NBIO)) {
	    splx(s);
	    return (EWOULDBLOCK);
	}
#if 0
	/* NetBSD version... */
	error = ttysleep(tp, (caddr_t)&tp->t_rawq, TTIPRI|PCATCH, ttyin, 0);
	if (error) {
	    splx(s);
	    return error;
	}
#else
	sleep((caddr_t)&tp->t_rawq, TTIPRI);
#endif
    }
    if (tp->t_line != PPPDISC) {
	splx(s);
	return (-1);
    }

    /* Pull place-holder byte out of canonical queue */
    getc(&tp->t_canq);

    /* Get the packet from the input queue */
    m = nbq_dequeue(&sc->sc_inq);
    splx(s);
    if (nbuf == NULL){
      if (sc->sc_flags & SC_DEBUG)
	IOLogDbg("Read didn't get a buffer at %s %d\n", __FILE__, __LINE__);
      return -1;
    }
    error = uiomove(nb_map(m), nb_size(m), UIO_READ, uio);
    nb_free(m);
    return (error);
}

/*
 * Line specific (tty) write routine.
 */
int
pppwrite(tp, uio)
    register struct tty *tp;
    struct uio *uio;
{
    register struct ppp_softc *sc = (struct ppp_softc *)tp->t_sc;
    netbuf_t m;
    struct sockaddr dst;
    int len, error;

    if ((tp->t_state & TS_CARR_ON) == 0 && (tp->t_flags & CLOCAL) == 0)
	return 0;		/* wrote 0 bytes */
    if (tp->t_line != PPPDISC)
	return (EINVAL);
    if (sc == NULL || tp != (struct tty *) sc->sc_devp)
	return EIO;
    if (uio->uio_resid > if_mtu(sc->sc_if) + PPP_HDRLEN ||
      uio->uio_resid < PPP_HDRLEN)
	return (EMSGSIZE);
    m = pppgetbuf(sc->sc_if);
    if (m == NULL){
      if (sc->sc_flags & SC_DEBUG)
	IOLogDbg("No buffers available for user level write()\n");
      return(ENOBUFS);
    }
    ppp_nb_grow_top(m, PPP_HDRLEN);
    len = uio->uio_resid;
    if (error = uiomove(nb_map(m), nb_size(m), UIO_WRITE, uio)) {
	nb_free(m);
	return error;
    }
    nb_shrink_bot(m, nb_size(m) - len);
    dst.sa_family = AF_UNSPEC;
    bcopy(mtod(m, u_char *), dst.sa_data, PPP_HDRLEN);
    ppp_nb_shrink_top(m, PPP_HDRLEN);
    return (pppoutput(sc->sc_if, m, &dst));
}

/*
 * Line specific (tty) ioctl routine.
 * This discipline requires that tty device drivers call
 * the line specific l_ioctl routine from their ioctl routines.
 */
/* ARGSUSED */
int
ppptioctl(tp, cmd, data, flag)
    struct tty *tp;
    void *data;
    int cmd, flag;
{
    struct ppp_softc *sc = (struct ppp_softc *) tp->t_sc;
    int error, s;

    if (sc == NULL || tp != (struct tty *) sc->sc_devp)
	return -1;

    error = 0;
    switch (cmd) {
    case PPPIOCSASYNCMAP:
	if (! suser())
	    return EPERM;
#if 0
	IOLogDbg("ppp%d: set async map to 0x%08x\n", if_unit(sc->sc_if),
		 *(u_long *)data);
#endif
	sc->sc_asyncmap[0] = *(u_int *)data;
	break;

    case PPPIOCGASYNCMAP:
	*(u_int *)data = sc->sc_asyncmap[0];
#if 0
	IOLogDbg("ppp%d: asyncmap gets 0x%x\n", if_unit(sc->sc_if), *(u_int *)data);
#endif
	break;

    case PPPIOCSRASYNCMAP:
	if (! suser())
	    return EPERM;
	sc->sc_rasyncmap = *(u_int *)data;
#if 0
	IOLogDbg("ppp%d: setting rasyncmap 0x%x\n", if_unit(sc->sc_if), sc->sc_rasyncmap);
#endif
	break;

    case PPPIOCGRASYNCMAP:
	*(u_int *)data = sc->sc_rasyncmap;
#if 0
	IOLogDbg("ppp%d: rasyncmap gets 0x%x\n", if_unit(sc->sc_if), *(u_int *)data);
#endif
	break;

    case PPPIOCSXASYNCMAP:
	if (! suser())
	    return EPERM;
	s = spltty();
	bcopy(data, sc->sc_asyncmap, sizeof(sc->sc_asyncmap));
	sc->sc_asyncmap[1] = 0;			/* mustn't escape 0x20 - 0x3f */
	sc->sc_asyncmap[2] &= ~0x40000000;	/* mustn't escape 0x5e */
	sc->sc_asyncmap[3] |= 0x60000000;	/* must escape 0x7d, 0x7e */
	splx(s);
	break;

    case PPPIOCGXASYNCMAP:
	bcopy(sc->sc_asyncmap, data, sizeof(sc->sc_asyncmap));
#if 0
	IOLogDbg("ppp%d: xasyncmap gets 0x%x/0x%x/0x%x/0x%x\n", if_unit(sc->sc_if), ((u_int *)data)[0], ((u_int *)data)[1], ((u_int *)data)[2], ((u_int *)data)[3]);
#endif
	break;

    default:
	error = pppioctl(sc, cmd, data, flag);
	if (error == 0 && cmd == PPPIOCSMRU)
	    pppgetm(sc);
    }

#ifdef	i386
    if (! error && (cmd & IOC_OUT)) {
	struct uthread *_u = uthread_from_thread(current_thread());

	/* third arg is destination in ioctl() call... */
	copyout(data, (caddr_t) _u->uu_arg[2], (cmd >> 16) & IOCPARM_MASK);
    }
#endif

    return error;
}

/*
 * FCS lookup table as calculated by genfcstab.
 */
static const u_int16_t fcstab[256] = {
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
 * Calculate a new FCS given the current FCS and the new data.
 */
static u_int16_t
pppfcs(fcs, cp, len)
    register u_int16_t fcs;
    register u_char *cp;
    register int len;
{
    while (len--)
	fcs = PPP_FCS(fcs, *cp++);
    return (fcs);
}

/*
 * This gets called from pppoutput when a new packet is
 * put on a queue.
 */
static void
pppasyncstart(sc)
    register struct ppp_softc *sc;
{
    register struct tty *tp = (struct tty *) sc->sc_devp;
    int s;

    s = splimp();
    pppstart(tp);
    splx(s);
}

/*
 * This gets called when a received packet is placed on
 * the inq.
 */
static void
pppasyncctlp(sc)
    struct ppp_softc *sc;
{
    struct tty *tp;

    /* Put a placeholder byte in canq for ttselect()/ttnread(). */
    tp = (struct tty *) sc->sc_devp;
    putc(0, &tp->t_canq);
    ttwakeup(tp);
}

/*
 * Start output on async tty interface.  Get another datagram
 * to send from the interface queue and start sending it.
 */
void
pppstart(tp)
    register struct tty *tp;
{
    register struct ppp_softc *sc = (struct ppp_softc *) tp->t_sc;
    register netbuf_t m;
    register int len;
    register u_char *start, *stop, *cp;
    int n, ndone, done, idle;

    if ((tp->t_state & TS_CARR_ON) == 0 && (tp->t_flags & CLOCAL) == 0
	|| sc == NULL || tp != (struct tty *) sc->sc_devp) {
	if (tp->t_oproc != NULL)
	    (*tp->t_oproc)(tp);
	return;
    }

    idle = 0;
#ifdef	OLD_MUX
    while (CCOUNT(&tp->t_outq) == 0) {
#else
    while (CCOUNT(&tp->t_outq) < PPP_HIWAT) {
#endif
	/*
	 * See if we have an existing packet partly sent.
	 * If not, get a new packet and start sending it.
	 */
	m = sc->sc_outm;
	if (m == NULL) {
	    /*
	     * Get another packet to be sent.
	     */
	    m = ppp_dequeue(sc);
	    if (m == NULL) {
		idle = 1;
		break;
	    }

	    /*
	     * The extra PPP_FLAG will start up a new packet, and thus
	     * will flush any accumulated garbage.  We do this whenever
	     * the line may have been idle for some time.
	     */
	    if (CCOUNT(&tp->t_outq) == 0) {
		++sc->sc_bytessent;
		(void) putc(PPP_FLAG, &tp->t_outq);
	    }

	    /* Calculate the FCS for the first netbuf's worth. */
	    sc->sc_outfcs = pppfcs(PPP_INITFCS, mtod(m, u_char *), nb_size(m));
	    sc->sc_outfcs ^= 0xffff;

#ifdef ADD_ERRORS
      /*
       * This section will adds random errors to 
       * outgoing packets.
       */

      if (out_error_limit == -1)  /* Initial time through */
	{
	  out_error_limit = rand() % out_error_max_sep;
	  IOLog("Introducing outgoing random error after %d more packets\n",
		 out_error_limit);
	}	

      if (out_error_pkt_count >=  out_error_limit)
	{
	  sc->sc_outfcs ^= 0x99;   /* Munge with some noise */
	  out_error_pkt_count = 0;
	  out_error_limit = rand() % out_error_max_sep;
	  IOLog("Introducing outgoing random error after %d more packets\n",
		 out_error_limit);
	}
      else
	++out_error_pkt_count;
      

#endif /* ADD_ERRORS */      

	    cp = mtod(m, u_char *) + nb_size(m);
	    nb_grow_bot(m, PPP_FCSLEN);
	    *cp++ = sc->sc_outfcs & 0xFF;
	    *cp++ = (sc->sc_outfcs >> 8) & 0xFF;
	}

	start = mtod(m, u_char *);
	len = nb_size(m);
	stop = start + len;
	while (len > 0) {
	    /*
	     * Find out how many bytes in the string we can
	     * handle without doing something special.
	     */
	    for (cp = start; cp < stop; cp++)
		if (ESCAPE_P(*cp))
		    break;
	    n = cp - start;
	    if (n) {
		/* NetBSD (0.9 or later), 4.3-Reno or similar. */
		ndone = n - b_to_q(start, n, &tp->t_outq);
		len -= ndone;
		start += ndone;
		sc->sc_bytessent += ndone;

		if (ndone < n)
		    break;	/* packet doesn't fit */
	    }

	    /*
	     * If there are characters left in the netbuf,
	     * the first one must be special..
	     * Put it out in a different form.
	     */
	    if (len) {
		if (putc(PPP_ESCAPE, &tp->t_outq))
		    break;
		if (putc(*start ^ PPP_TRANS, &tp->t_outq)) {
		    (void) unputc(&tp->t_outq);
		    break;
		}
		sc->sc_bytessent += 2;
		start++;
		len--;
	    }
	}
	/*
	 * If we didn't empty this netbuf, remember where we're up to.
	 */
	done = len == 0;

	if (!done) {
	    /* remember where we got to */
	    ppp_nb_shrink_top(m, start - mtod(m, u_char *));
	    break;	/* can't do any more at the moment */
	}

	/*
	 * Output trailing PPP flag and finish packet.
	 * We make the length zero in case the flag
	 * cannot be output immediately.
	 */
	ppp_nb_shrink_top(m, nb_size(m));
	if (putc(PPP_FLAG, &tp->t_outq))
	    break;
	sc->sc_bytessent++;

	/* Finished with this netbuf; free it and move on. */
	nb_free(m);
	m = NULL;
	incr_cnt(sc->sc_if, if_opackets);

	sc->sc_outm = m;
    }

    /*
     * If there is stuff in the output queue, send it now.
     * We are being called in lieu of ttstart and must do what it would.
     */
    if (tp->t_oproc != NULL)
	(*tp->t_oproc)(tp);

    /*
     * This timeout is needed for operation on a pseudo-tty,
     * because the pty code doesn't call pppstart after it has
     * drained the t_outq.
     */
    if (!idle && (sc->sc_flags & SC_TIMEOUT) == 0) {
	ns_timeout(ppp_timeout, (void *) sc, 1 * (1000000000L / HZ), CALLOUT_PRI_SOFTINT0);
	sc->sc_flags |= SC_TIMEOUT;
    }

    return;
}

/*
 * Timeout routine - try to start some more output.
 */
static int
ppp_timeout(x)
    void *x;
{
    struct ppp_softc *sc = (struct ppp_softc *) x;
    struct tty *tp = (struct tty *) sc->sc_devp;
    int s;

    s = splimp();
    sc->sc_flags &= ~SC_TIMEOUT;
    pppstart(tp);
    splx(s);
    return 0;
}

/*
 * Allocate enough netbuf to handle current MRU.
 *
 * Warning Will Robinson:  pppgetm() can get called at interrupt-level!
 */
void
pppgetm(sc)
    register struct ppp_softc *sc;
{
    int s;

    s = splimp();
    /*
     * When the MRU is being changed, we could conceivably end up
     * nuking a packet being received, but I doubt it, since the
     * hand-shake is lock-step (ie. single packet).
     */
    if (sc->sc_m != NULL)
	nb_free(sc->sc_m);
    sc->sc_m = nbq_dequeue(&sc->sc_freeq);
    splx(s);
}

/*
 * 4.3 says this is an unused function.  However,
 * it appears to be returning a NULL terminated string
 * of several characters.  My guess is that the serial
 * driver is doing a little buffering so that we don't
 * get burdend with interrupts.
 *
 * This function gets called when you use the NeXT
 * supplied serial drivers.  It does not get called
 * with the MuX driver.  
 *
 * In order to expedite the work done here, we
 * handle most things here that don't require
 * processing of a PPP_FLAG.
 *
 */

void
ppprend(cp, n, tp)
    unsigned char *cp;
    int n;
    struct tty *tp;
{

#ifndef OPTIMIZE_PPPREND	
  while (n--) pppinput((u_char) *cp++, tp);
#else
#warning OPTIMIZE_PPPREND in effect

  register struct ppp_softc *sc = (struct ppp_softc *)tp->t_sc;
  register int ret;

  if (sc == NULL || tp != (struct tty *) sc->sc_devp)
    {
      printf("Warning, bad softc structure at %s %d\n", __FILE__, __LINE__);
      return;
    }

  /*
   * We can handle FLUSHs, ESCAPES, and non PPP_FLAG characters
   */
  
  while (n)
    {
      if (sc->sc_flags & SC_FLUSH)
	{
	  do
	    {
	      if (*(cp++) == PPP_FLAG)
		{
		  pppinput(PPP_FLAG, tp);
		  --n;
		  break;
		}
	      else if (sc->sc_flags & SC_LOG_FLUSH)
		ppplogchar(sc, *cp);
	    }
	  while(--n);
	}
      else if (sc->sc_ilen > 3 &&
		       (nb_size(sc->sc_m) - sc->sc_ilen) > n &&
		 *cp != PPP_FLAG &&
		 *cp != PPP_ESCAPE)         /* Dont really handle escapes properly...should */
	{
	    unsigned char* cp1 = cp;
	    if (sc->sc_flags & SC_ESCAPED)
	    {
		sc->sc_flags &= ~SC_ESCAPED;
		*cp ^= PPP_TRANS;
	      }
	    
	    do
	    {
		sc->sc_fcs = PPP_FCS(sc->sc_fcs, *(cp++));
		if (sc->sc_flags & SC_LOG_RAWIN)
		  ppplogchar(sc, *cp);

	    } while(--n && *cp != PPP_FLAG && *cp != PPP_ESCAPE);
	    

	    bcopy(cp1, sc->sc_mp, (cp-cp1));

	    sc->sc_bytesrcvd += (cp - cp1);
	    sc->sc_ilen += (cp-cp1);
	    sc->sc_mp += (cp-cp1);
	}
	else
	{
	    --n;
	    pppinput(*(cp++), tp);
	}
    }

#endif /* OPTIMIZE_PPPREND */
}

/*
 * tty interface receiver interrupt.
 */
static const unsigned paritytab[8] = {
    0x96696996, 0x69969669, 0x69969669, 0x96696996,
    0x69969669, 0x96696996, 0x96696996, 0x69969669
};

void
pppinput(c, tp)
    int c;
    register struct tty *tp;
{
    register struct ppp_softc *sc;
    netbuf_t m;
    int ilen, s;

    sc = (struct ppp_softc *) tp->t_sc;
    if (sc == NULL || tp != (struct tty *) sc->sc_devp)
	return;

    ++tk_nin;
    ++sc->sc_bytesrcvd;

    if (c & TTY_FE) {
	/* framing error or overrun on this char - abort packet */
	IOLogDbg("ppp%d: bad char 0x%x\n", if_unit(sc->sc_if), c);
	goto flush;
    }

    c &= 0xff;

    if (c & 0x80)
	sc->sc_flags |= SC_RCV_B7_1;
    else
	sc->sc_flags |= SC_RCV_B7_0;
    if (paritytab[c >> 5] & (1 << (c & 0x1F)))
	sc->sc_flags |= SC_RCV_ODDP;
    else
	sc->sc_flags |= SC_RCV_EVNP;

    if (sc->sc_flags & SC_LOG_RAWIN)
	ppplogchar(sc, c);

    if (c == PPP_FLAG) {


	ilen = sc->sc_ilen;
	sc->sc_ilen = 0;

	if (sc->sc_rawin_count > 0)
	    ppplogchar(sc, -1);

#ifdef ADD_ERRORS
      /*
       * This section will adds random packet
       * errors if defined.
       */

      /*
       * Initial time through
       */
      if (in_error_limit == -1) 
	{
	  in_error_limit = rand() % in_error_max_sep;
	  IOLog("Introducing incoming random error after %d more packets\n",
		 in_error_limit);
	}	

      if ((in_error_pkt_count >= in_error_limit) && (ilen != 0))
	{
	  sc->sc_fcs = !PPP_GOODFCS;
	  in_error_pkt_count = 0;
	  in_error_limit = rand() % in_error_max_sep;
	  IOLog("Introducing incoming random error after %d more packets\n",
		 in_error_limit);
	}

	if (ilen != 0)
	  ++in_error_pkt_count;
      

#endif /* ADD_ERRORS */      

	/*
	 * From the RFC:
	 *  Each Control Escape octet is also
         *  removed, and the following octet is exclusive-or'd with hexadecimal
         *  0x20, unless it is the Flag Sequence (which aborts a frame).
         *
	 * So, if SC_ESCAPED is set, then we've seen the packet
	 * abort sequence "}~".
	 */

	if (sc->sc_flags & (SC_FLUSH | SC_ESCAPED)
	    || ilen > 0 && sc->sc_fcs != PPP_GOODFCS) {
	    sc->sc_flags |= SC_PKTLOST;	/* note the dropped packet */
	    if ((sc->sc_flags & (SC_FLUSH | SC_ESCAPED)) == 0){
		IOLogDbg("ppp%d: bad fcs 0x%04x\n", if_unit(sc->sc_if), sc->sc_fcs);
		incr_cnt(sc->sc_if, if_ierrors);
	    } else
		sc->sc_flags &= ~(SC_FLUSH | SC_ESCAPED);
	    return;
	}

	if (ilen < PPP_HDRLEN + PPP_FCSLEN) {
	    if (ilen) {
		IOLogDbg("ppp%d: too short (%d)\n", if_unit(sc->sc_if), ilen);
		incr_cnt(sc->sc_if, if_ierrors);
		sc->sc_flags |= SC_PKTLOST;
	    }
	    return;
	}

	/*
	 * Remove FCS trailer.  Set packet length...
	 */
	ilen -= PPP_FCSLEN;
	nb_shrink_bot(sc->sc_m, nb_size(sc->sc_m) - ilen);

	/* excise this netbuf */
	m = sc->sc_m;
	sc->sc_m = NULL;

	ppppktin(sc, m, sc->sc_flags & SC_PKTLOST);
	sc->sc_flags &= ~SC_PKTLOST;

	pppgetm(sc);
	return;
    }

    if (sc->sc_flags & SC_FLUSH) {
	if (sc->sc_flags & SC_LOG_FLUSH)
	    ppplogchar(sc, c);
	return;
    }

/*
 * From the RFC:
 *  On reception, prior to FCS computation, each octet with value less
 *  than hexadecimal 0x20 is checked.  If it is flagged in the receiving
 *  ACCM, it is simply removed (it may have been inserted by intervening
 *  data communications equipment).  Each Control Escape octet is also
 *  removed, and the following octet is exclusive-or'd with hexadecimal
 *  0x20, unless it is the Flag Sequence (which aborts a frame).
 */

    if (c < 0x20 && (sc->sc_rasyncmap & (1 << c))) {
	return;
    }

    if (sc->sc_flags & SC_ESCAPED) {
	sc->sc_flags &= ~SC_ESCAPED;
	c ^= PPP_TRANS;
    } else if (c == PPP_ESCAPE) {
	sc->sc_flags |= SC_ESCAPED;
/*	splx(s); */
	return;
    }

    /*
     * Initialize buffer on first octet received.
     * First octet could be address or protocol (when compressing
     * address/control).
     * Second octet is control.
     * Third octet is first or second (when compressing protocol)
     * octet of protocol.
     * Fourth octet is second octet of protocol.
     */
    if (sc->sc_ilen == 0) {
	/* reset the input netbuf */
	if (sc->sc_m == NULL) {
	    pppgetm(sc);
	    if (sc->sc_m == NULL) {
		/*
		 * We schedule a call here as pppindrain will
		 * not get scheduled and we need the free buffers
		 */
		IOLog("ppp%d: no input netbufs!\n", if_unit(sc->sc_if));
		(void)pppsched(pppfillfreeq, sc);
		goto flush;
	    }
	}
	m = sc->sc_m;
	sc->sc_mp = mtod(m, char *);
	sc->sc_fcs = PPP_INITFCS;
	if (c != PPP_ALLSTATIONS) {
	    if (sc->sc_flags & SC_REJ_COMP_AC) {
		IOLogDbg("ppp%d: garbage received: 0x%02x (need 0x%02x)\n",
			   if_unit(sc->sc_if), c, PPP_ALLSTATIONS);
		goto flush;
	    }
	    *sc->sc_mp++ = PPP_ALLSTATIONS;
	    *sc->sc_mp++ = PPP_UI;
	    sc->sc_ilen += 2;
	}
    }
    if (sc->sc_ilen == 1 && c != PPP_UI) {
	IOLogDbg("ppp%d: missing UI (0x%02x), got 0x%02x\n",
		   if_unit(sc->sc_if), PPP_UI, c);
	goto flush;
    }
    if (sc->sc_ilen == 2 && (c & 1) == 1) {
	/* a compressed protocol */
	*sc->sc_mp++ = 0;
	sc->sc_ilen++;
    }
    if (sc->sc_ilen == 3 && (c & 1) == 0) {
	IOLogDbg("ppp%d: bad protocol %x\n", if_unit(sc->sc_if),
		   (sc->sc_mp[-1] << 8) + c);
	goto flush;
    }

    /* packet beyond configured mru? */
    if (++sc->sc_ilen > sc->sc_mru + PPP_HDRLEN + PPP_FCSLEN) {
	IOLogDbg("ppp%d: packet too big (%d bytes)\n", if_unit(sc->sc_if),
		sc->sc_ilen);
	goto flush;
    }

    /* ilen was incremented above... */
    *sc->sc_mp++ = c;
    sc->sc_fcs = PPP_FCS(sc->sc_fcs, c);
    return;

 flush:
    if (!(sc->sc_flags & SC_FLUSH)) {
	incr_cnt(sc->sc_if, if_ierrors);
	sc->sc_flags |= SC_FLUSH;
	if (sc->sc_flags & SC_LOG_FLUSH)
	    ppplogchar(sc, c);
    }
    return;
}

int
install_ppp_ld(void)
{
    return tty_ld_install(PPPDISC, NORMAL_LDISC, pppopen,
			  pppclose, pppread, pppwrite, ppptioctl,
			  pppinput, ppprend, pppstart, ttymodem,
			  ttselect);
}

#define MAX_DUMP_BYTES	128

void
ppplogchar(sc, c)
    struct ppp_softc *sc;
    int c;
{
    if (c >= 0)
	sc->sc_rawin[sc->sc_rawin_count++] = c;
    if (sc->sc_rawin_count >= sizeof(sc->sc_rawin)
	|| c < 0 && sc->sc_rawin_count > 0) {
	IOLog("ppp%d input:\n", if_unit(sc->sc_if));
	pppdumpb(sc->sc_rawin, sc->sc_rawin_count);
	sc->sc_rawin_count = 0;
    }
}

static void
pppdumpb(b, l)
    u_char *b;
    int l;
{
    char buf[3*MAX_DUMP_BYTES+4];
    char *bp = buf;
    static char digits[] = "0123456789abcdef";

    while (l--) {
	if (bp >= buf + sizeof(buf) - 3) {
	    *bp++ = '>';
	    break;
	}
	*bp++ = digits[*b >> 4]; /* convert byte to ascii hex */
	*bp++ = digits[*b++ & 0xf];
	*bp++ = ' ';
    }

    *bp = 0;
    IOLog("%s\n", buf);
}
#endif	/* NUM_PPP > 0 */
