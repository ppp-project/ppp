/*
 * if_ppp.c - Point-to-Point Protocol (PPP) Asynchronous driver.
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

#if !defined(lint)
static char sccsid[] = "$Revision: 1.12 $ ($Date: 1999/12/23 01:48:44 $)";
#endif /* not lint*/

#define KERNEL 1
#define KERNEL_FEATURES 1
#define INET 1

#if NS_TARGET >= 40
#if NS_TARGET >= 41
#include <kernserv/clock_timer.h>
#include <kernserv/lock.h>
#else
#include <kern/lock.h>
#endif /* NS_TARGET */
#endif /* NS_TARGET */

#include <sys/param.h>
#if NS_TARGET >= 41
typedef simple_lock_data_t lock_data_t;		/* XXX */
#endif /* NS_TARGET */
#include <sys/proc.h>
#include "netbuf.h"
#include <sys/socket.h>
#include <sys/conf.h>
#include <sys/time.h>
#include <sys/ioctl.h>
#include <sys/errno.h>
#if !(NS_TARGET >= 40)
#include <kernserv/prototypes.h>
#endif
#if defined(m68k)
#import "spl.h"
#else
#include <driverkit/generalFuncs.h>
#import <kernserv/machine/spl.h>
#endif
#if defined(sparc) || defined(m68k)
#include <machine/psl.h>
#endif
#include <kernserv/kern_server_types.h>

#include <net/if.h>
#include <net/route.h>

#if INET
#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <netinet/in_var.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#endif

#include <net/ppp_defs.h>
#ifdef	VJC
#include <net/vjcompress.h>
#endif
#include <net/if_ppp.h>
#include "NeXT_Version.h"
#include "if_pppvar.h"


struct	ppp_softc ppp_softc[NUM_PPP];


#ifdef	PPP_COMPRESS
#define	PACKETPTR	NETBUF_T
#include <net/ppp-comp.h>
#endif

/*
 * The max number of NETBUF_Ts we wish to compress and cache for
 * sending.
 */
#define COMPRESS_CACHE_LEN 1

#include "inlines.h"

/*
 * Necessary to avoid redefinition warnings or bogus type casts later.
 */
int	pppoutput __P((netif_t ifp, netbuf_t m, void *arg));
int	pppsioctl __P((netif_t ifp, int cmd, caddr_t data));
int	pppcontrol __P((netif_t ifp, const char *cmd, void *data));
void	pppintr_comp __P((void *arg));
void	pppintr_decomp __P((void *arg));
void	pppfillfreeq __P((void *arg));
void	pppgetm __P((register struct ppp_softc *sc));

static void	ppp_requeue __P((struct ppp_softc *));
static void	ppp_outpkt __P((struct ppp_softc *));
static void	ppp_ccp __P((struct ppp_softc *, NETBUF_T, int rcvd));
static void	ppp_ccp_closed __P((struct ppp_softc *));
static void	ppp_inproc __P((struct ppp_softc *, NETBUF_T));
static void	pppdumpm __P((NETBUF_T));

extern int	install_ppp_ld __P((void));
extern int	tty_ld_remove __P((int));

/*
 * We steal two bits in the mbuf m_flags, to mark high-priority packets
 * for output, and received packets following lost/corrupted packets.
 */
#define	M_HIGHPRI	0x2000	/* output packet for sc_fastq */
#define	M_ERRMARK	0x4000	/* steal a bit in mbuf m_flags */

/*
 * The following disgusting hack gets around the problem that IP TOS
 * can't be set yet.  We want to put "interactive" traffic on a high
 * priority queue.  To decide if traffic is interactive, we check that
 * a) it is TCP and b) one of its ports is telnet, rlogin or ftp control.
 */
static u_short interactive_ports[8] = {
	0,	513,	0,	0,
	0,	21,	0,	23,
};

enum { QFREE, QRAW, QFAST, QSLOW, QIN, QNP, QCACHE };

static struct qparms qparms[] = {
	{20, 40, 50, "free"},		/* freeq */
	{5, 20, 25, "raw"},		/* rawq */
	{5, 20, 25, "fast"},		/* fastq */
	{5, 20, 25, "slow"},		/* slowq */
	{5, 20, 25, "in"},		/* inq */
	{5, 20, 25, "np"},		/* npq */
	{0, COMPRESS_CACHE_LEN, COMPRESS_CACHE_LEN, "cache"}	/* cache */
};

#define INTERACTIVE(p)	(interactive_ports[(p) & 7] == (p))

#ifndef	IPTOS_LOWDELAY
#define	IPTOS_LOWDELAY	0x10
#endif

#ifdef PPP_COMPRESS
/*
 * List of compressors we know about.
 * We leave some space so maybe we can modload compressors.
 */

extern struct compressor ppp_bsd_compress;

struct compressor *ppp_compressors[8] = {
#if DO_BSD_COMPRESS
    &ppp_bsd_compress,
#endif
    NULL
};
#endif /* PPP_COMPRESS */

/* yeah, we sometimes have to change the MTU after having created the
 * device.  Let's hope this doesn't break anything!!!
 */
#define	if_mtu_set(ifn,mtu)  (((struct ifnet *)ifn)->if_mtu = mtu)

extern int ipforwarding;
extern int ipsendredirects;

kern_server_t instance;

/*
 * Sigh.  Should be defined in <net/if.h> but isn't...
 */
union ifr_ifru {
	short	ifru_flags;
	short   ifru_mtu;
	u_long  ifru_asyncmap;
	int     ifru_metric;
	caddr_t ifru_data;
};


/*
 * Returns a new "outgoing" netbuf.
 *  
 * Must return an actual netbuf_t since other protocols
 * use this to get our buffers.  Before releasing, save
 * any space we may need when the buffer returns.
 */

netbuf_t
pppgetbuf(netif_t ifp)
{
    NETBUF_T nb;

    int len = MAX(if_mtu(ifp), PPP_MTU) + PPP_HDRLEN + PPP_FCSLEN;
    nb = NB_ALLOC(len);
    if (nb != NULL)
      {
	NB_SHRINK_TOP(nb, PPP_HDRLEN);
	NB_SHRINK_BOT(nb, PPP_FCSLEN);          /* grown by pppstart() */
      }
    return NB_TO_nb(nb);
}

/*
 * Called from boot code to establish ppp interfaces.
 */
void
pppattach()
{
    register struct ppp_softc *sc;
    register int i = 0;
    
    IOLog("\nPPP version 2.3.11-%s for NeXTSTEP and OPENSTEP\n", PPPVERSION);
    IOLog("by  Stephen Perkins, Philip Prindeville, and Pete French\n");
    if (install_ppp_ld() < 0) {
	IOLog("ppp: Could not install line discipline\n");
    }
    
    for (sc = ppp_softc; i < NUM_PPP; sc++, i++) {
	sc->sc_if = if_attach(NULL, NULL, pppoutput, 
			      pppgetbuf, pppcontrol, "ppp", i, "Serial line PPP", 
			      PPP_MTU, IFF_POINTOPOINT, NETIFCLASS_VIRTUAL, (void *) sc);
	nbq_init(&sc->sc_freeq, &qparms[QFREE]);
	nbq_init(&sc->sc_rawq, &qparms[QRAW]);
	nbq_init(&sc->sc_fastq, &qparms[QFAST]);
	nbq_init(&sc->sc_slowq, &qparms[QSLOW]);
	nbq_init(&sc->sc_inq, &qparms[QIN]);
	nbq_init(&sc->sc_npq, &qparms[QNP]);
	nbq_init(&sc->sc_compq, &qparms[QCACHE]);
	IOLog("     ppp%d successfully attached.\n", i);
    }

    ipforwarding = 1;
    ipsendredirects = 1;

    IOLog("PPP Successfully Installed.\n\n");
}

int
pppdetach()
{
    struct ppp_softc *sc;
    int i;

    IOLog("Removing PPP on Line Discipline %d\n", PPPDISC);
    if (!tty_ld_remove(PPPDISC))
	IOLog("ppp: Could not remove line discipline\n");

    IOLog("Removing interfaces:\n");
    for (sc = ppp_softc, i = 0; i < NUM_PPP; sc++, i++) {
	nbq_free(&sc->sc_freeq);
	nbq_free(&sc->sc_rawq);
	nbq_free(&sc->sc_fastq);
	nbq_free(&sc->sc_slowq);
	nbq_free(&sc->sc_inq);
	nbq_free(&sc->sc_npq);
	nbq_free(&sc->sc_compq);
	if_detach(sc->sc_if);
	/* no idea why we need this, but... */
	bzero(sc->sc_if, sizeof(netif_t));
	IOLog("     ppp%d successfully detached.\n", i);
    }
    IOLog("PPP-2.3 Successfully Removed.\n\n");
    return 0;
}

/*
 * Allocate a ppp interface unit and initialize it.
 */
struct ppp_softc *
pppalloc(pid)
    pid_t pid;
{
    int nppp, i;
    struct ppp_softc *sc;
#if NS_TARGET >= 40
    struct timeval tv_time;
#endif /* NS_TARGET */

    for (nppp = 0, sc = ppp_softc; nppp < NUM_PPP; nppp++, sc++)
	if (sc->sc_xfer == pid) {
	    IOLogDbg("ppp%d: alloc'ing unit %d to proc %d\n", nppp, nppp, pid);
	    sc->sc_xfer = 0;
	    return sc;
	}
    for (nppp = 0, sc = ppp_softc; nppp < NUM_PPP; nppp++, sc++)
	if (sc->sc_devp == NULL)
	    break;
    if (nppp >= NUM_PPP)
	return NULL;

    sc->sc_flags = 0;
    sc->sc_mru = PPP_MRU;
    sc->sc_relinq = NULL;
#ifdef VJC
    vj_compress_init(&sc->sc_comp, -1);
#endif
#ifdef PPP_COMPRESS
    sc->sc_xc_state = NULL;
    sc->sc_rc_state = NULL;
#endif /* PPP_COMPRESS */
    for (i = 0; i < NUM_NP; ++i)
	sc->sc_npmode[i] = NPMODE_ERROR;
    /* XXX - I'm not sure why the npqueue was zapped here... */

#if NS_TARGET >= 40
    ns_time_to_timeval(clock_value(System), &tv_time);
    sc->sc_last_sent = sc->sc_last_recv = tv_time.tv_sec;
#else
    sc->sc_last_sent = sc->sc_last_recv = time.tv_sec;
#endif

    sc->sc_compsched = 0;
    sc->sc_decompsched = 0;

    /*
     * XXX -- We need to get packets here, and we don't care if we do block...
     * We do this after we set the sc_mru.
     */
    pppfillfreeq((void *) sc);

    return sc;
}

/*
 * Deallocate a ppp unit.  Must be called at splnet or higher.
 */
void
pppdealloc(sc)
    struct ppp_softc *sc;
{

    if_flags_set(sc->sc_if, if_flags(sc->sc_if) & ~(IFF_UP|IFF_RUNNING));
    sc->sc_devp = NULL;
    sc->sc_xfer = 0;
    nbq_flush(&sc->sc_freeq);
    nbq_flush(&sc->sc_rawq);
    nbq_flush(&sc->sc_inq);
    nbq_flush(&sc->sc_fastq);
    nbq_flush(&sc->sc_slowq);
    nbq_flush(&sc->sc_npq);
    nbq_flush(&sc->sc_compq);
#ifdef PPP_COMPRESS
    ppp_ccp_closed(sc);
    sc->sc_xc_state = NULL;
    sc->sc_rc_state = NULL;
#endif /* PPP_COMPRESS */


}

/*
 * Ioctl routine for generic ppp devices.
 */
int
pppioctl(sc, cmd, data, flag)
    struct ppp_softc *sc;
    void *data;
    u_long cmd;
    int flag;
{
    struct proc *p = curproc;
    int s, error, flags, mru, nb, npx, oldflags;
    struct ppp_option_data *odp;
    struct compressor **cp;
    struct npioctl *npi;
    time_t t;
#ifdef	PPP_COMPRESS
    u_char ccp_option[CCP_MAX_OPTION_LENGTH];
#endif
    NETBUF_T m;
#ifdef	HAS_BROKEN_TIOCSPGRP
    struct tty *tp = sc->sc_devp;
#endif
#if NS_TARGET >= 40
	struct timeval tv_time;
#endif /* NS_TARGET */


    switch (cmd) {
    case FIONREAD:
	s = splimp();		/* paranoid; splnet probably ok */
	if ((m = nbq_peek(&sc->sc_inq)) != NULL)
	    *(int *)data = NB_SIZE(m);
	else
	    *(int *)data = 0;
	splx(s);
	break;

    case PPPIOCGUNIT:
	*(int *)data = if_unit(sc->sc_if);
	break;

     case PPPIOCGFLAGS:
	*(u_int *)data = sc->sc_flags;
	break;

    case PPPIOCSFLAGS:
	if (! suser())
	    return EPERM;
	flags = *(int *)data & SC_MASK;
	s = splnet();
#ifdef PPP_COMPRESS
	if (sc->sc_flags & SC_CCP_OPEN && !(flags & SC_CCP_OPEN))
	    ppp_ccp_closed(sc);
#endif
	splimp();
	oldflags = sc->sc_flags;
	sc->sc_flags = (sc->sc_flags & ~SC_MASK) | flags;
	splx(s);
	break;

    case PPPIOCSMRU:
	if (! suser())
	    return EPERM;
	mru = *(int *)data;

	IOLogDbg("ppp%d: setting mru %d\n", if_unit(sc->sc_if), mru);

	if (mru >= PPP_MRU && mru <= PPP_MAXMRU) {

	    /* To make sure we handle the received packet
	     * correctly, we do two things.  First, we
	     * empty out the free_q.  We then remove
	     * the current input buffer, set the input length
	     * to zero, and set the flush flag.
	     */
	    s = splimp();
	    nbq_flush(&sc->sc_freeq);	/* get rid of old buffers */
	    sc->sc_mru = mru;
	    if (sc->sc_m){
	      NB_FREE(sc->sc_m);
	      sc->sc_m = NULL;
	      if (sc->sc_ilen != 0)
		sc->sc_flags |= SC_FLUSH;
	    }
	    sc->sc_ilen = 0;
	    splx(s);
    	    pppfillfreeq((void *) sc);	/* and make a queue of new ones */
	    pppgetm(sc);
	}
	break;

    case PPPIOCGMRU:
	*(int *)data = sc->sc_mru;
	break;

#ifdef	VJC
    case PPPIOCSMAXCID:
	if (! suser())
	    return EPERM;
	s = splnet();
	vj_compress_init(&sc->sc_comp, *(int *)data);
	splx(s);
	break;
#endif

    case PPPIOCXFERUNIT:
	if (! suser())
	    return EPERM;
	sc->sc_xfer = p->p_pid;
	break;

#ifdef PPP_COMPRESS
    case PPPIOCSCOMPRESS:
	if (! suser())
	    return EPERM;
	odp = (struct ppp_option_data *) data;
	nb = odp->length;
	if (nb > sizeof(ccp_option))
	    nb = sizeof(ccp_option);
	if (error = copyin(odp->ptr, ccp_option, nb))
	    return (error);
	if (ccp_option[1] < 2)	/* preliminary check on the length byte */
	    return (EINVAL);
	for (cp = ppp_compressors; *cp != NULL; ++cp)
	    if ((*cp)->compress_proto == ccp_option[0]) {
		/*
		 * Found a handler for the protocol - try to allocate
		 * a compressor or decompressor.
		 */
		error = 0;
		s = splnet();
		if (odp->transmit) {
		    if (sc->sc_xc_state != NULL)
			(*sc->sc_xcomp->comp_free)(sc->sc_xc_state);
		    sc->sc_xcomp = *cp;  /* entry points for compressor */
		    sc->sc_xc_state = (*cp)->comp_alloc(ccp_option, nb);
		    if (sc->sc_xc_state == NULL) {
			IOLogDbg("ppp%d: comp_alloc failed", if_unit(sc->sc_if));
			error = ENOBUFS;
		    }
		    splimp();
		    sc->sc_flags &= ~SC_COMP_RUN;
		} else {
		    if (sc->sc_rc_state != NULL)
			(*sc->sc_rcomp->decomp_free)(sc->sc_rc_state);
		    sc->sc_rcomp = *cp; /* entry points for compressor */
		    sc->sc_rc_state = (*cp)->decomp_alloc(ccp_option, nb);
		    if (sc->sc_rc_state == NULL) {
			IOLogDbg("ppp%d: decomp_alloc failed", if_unit(sc->sc_if));
			error = ENOBUFS;
		    }
		    splimp();
		    sc->sc_flags &= ~SC_DECOMP_RUN;
		}
		splx(s);
		return (error);
	    }
	IOLogDbg("ppp%d: no compressor for [%x %x %x], %x", if_unit(sc->sc_if),
		 ccp_option[0], ccp_option[1], ccp_option[2], nb);
	return (EINVAL);	/* no handler found */
#endif /* PPP_COMPRESS */

#ifdef	HAS_BROKEN_TIOCSPGRP
    case TIOCSPGRP:
	tp->t_pgrp = *(int *)data;
	break;
#endif

    case PPPIOCGNPMODE:
    case PPPIOCSNPMODE:
	npi = (struct npioctl *) data;
	switch (npi->protocol) {
	case PPP_IP:
	    npx = NP_IP;
	    break;
	default:
	    return EINVAL;
	}
	if (cmd == PPPIOCGNPMODE) {
	    npi->mode = sc->sc_npmode[npx];
	} else {
	    if (! suser())
		return EPERM;
	    if (npi->mode != sc->sc_npmode[npx]) {
		s = splimp();
		sc->sc_npmode[npx] = npi->mode;
		if (npi->mode != NPMODE_QUEUE) {
		    ppp_requeue(sc);
		    (*sc->sc_start)(sc);
		}
		splx(s);
	    }
	}
	break;

    case PPPIOCGIDLE:
	s = splimp();
#if NS_TARGET >= 40
	ns_time_to_timeval(clock_value(System), &tv_time);
	t = tv_time.tv_sec;
#else
	t = time.tv_sec;
#endif /* NS_TARGET */
	((struct ppp_idle *)data)->xmit_idle = t - sc->sc_last_sent;
	((struct ppp_idle *)data)->recv_idle = t - sc->sc_last_recv;
	splx(s);
	break;

    default:
	return (-1);
    }
    return (0);
}

int
pppcontrol(ifp, cmd, data)
    netif_t ifp;
    const char *cmd;
    void *data;
{

    if (!strcmp(cmd, IFCONTROL_UNIXIOCTL)) {
	if_ioctl_t* ctl = (if_ioctl_t*)data;
	return pppsioctl(ifp,
			ctl->ioctl_command,
			ctl->ioctl_data);
    } else if (!strcmp(cmd, IFCONTROL_SETADDR)) {
	struct sockaddr_in *sin = (struct sockaddr_in *)data;
	if (sin->sin_family != AF_INET)
		return EAFNOSUPPORT;
	if_flags_set(ifp, if_flags(ifp) | IFF_UP);
	return 0;
    }
    /*
     * We implement this to allow iftab
     * to contain -AUTOMATIC- entries
     * without generating errors at boot time.
     * We do not, however, mark it as UP.
     */
    else if (!strcmp(cmd, IFCONTROL_AUTOADDR)) {
	struct sockaddr_in *sin = (struct sockaddr_in *) data;
	if (sin->sin_family != AF_INET)
	    return EAFNOSUPPORT;
	return 0;
    } else if (!strcmp(cmd, IFCONTROL_SETFLAGS)) {
	register union ifr_ifru *ifr = (union ifr_ifru *)data;
	if (!suser())
	    return EPERM;
	if_flags_set(ifp, ifr->ifru_flags);
	return 0;
    }
    /*
     * Under 3.2 developer, I don't know the symbol for this
     * new 3.3 command.  So it is a constant for now. I don't
     * believe I need to do anything to support this at the moment.
     */
    else if (strcmp(cmd, "add-multicast") == 0) {
      struct sockaddr_in *sin = (struct sockaddr_in *) data;
      if (sin->sin_family != AF_INET)
	return EAFNOSUPPORT;
    } else {
	IOLog("ppp%d: Invalid ppp control %s\n", if_unit(ifp), cmd);
	return EINVAL;
    }
}

/*
 * Process an ioctl request to the ppp network interface.
 */
int
pppsioctl(ifp, cmd, data)
    register netif_t ifp;
    int cmd;
    caddr_t data;
{
    register struct ppp_softc *sc = &ppp_softc[if_unit(ifp)];
    register struct ifaddr *ifa = (struct ifaddr *)data;
    register struct ifreq *ifr = (struct ifreq *)data;
    struct ppp_stats *psp;
#ifdef	PPP_COMPRESS
    struct ppp_comp_stats *pcp;
#endif
    int s = splimp(), error = 0;

    switch (cmd) {
    case SIOCSIFFLAGS:
	IOLog("ppp%d: pppioctl: SIOCSIFFLAGS called!\n", if_unit(ifp));
	break;

    case SIOCSIFADDR:
	if (ifa->ifa_addr.sa_family != AF_INET)
	    error = EAFNOSUPPORT;
	break;

    case SIOCSIFDSTADDR:
	if (ifa->ifa_addr.sa_family != AF_INET)
	    error = EAFNOSUPPORT;
	break;

    case SIOCSIFMTU:
	if (!suser()) {
	    error = EPERM;
	    break;
	}
	if_mtu_set(sc->sc_if, ifr->ifr_mtu);
	nbq_flush(&sc->sc_freeq);		/* get rid of old buffers */
	pppsched(pppfillfreeq, sc);             /* and make a queue of new ones */
	pppgetm(sc);
	break;

    case SIOCGIFMTU:
	ifr->ifr_mtu = if_mtu(sc->sc_if);
	break;

    case SIOCGPPPSTATS:
	psp = &((struct ifpppstatsreq *) data)->stats;
	bzero(psp, sizeof(*psp));
	psp->p.ppp_ibytes = sc->sc_bytesrcvd;
	psp->p.ppp_ipackets = if_ipackets(sc->sc_if);
	psp->p.ppp_ierrors = if_ierrors(sc->sc_if);
	psp->p.ppp_obytes = sc->sc_bytessent;
	psp->p.ppp_opackets = if_opackets(sc->sc_if);
	psp->p.ppp_oerrors = if_oerrors(sc->sc_if);
#ifdef VJC
	psp->vj.vjs_packets = sc->sc_comp.stats.vjs_packets;
	psp->vj.vjs_compressed = sc->sc_comp.stats.vjs_compressed;
	psp->vj.vjs_searches = sc->sc_comp.stats.vjs_searches;
	psp->vj.vjs_misses = sc->sc_comp.stats.vjs_misses;
	psp->vj.vjs_uncompressedin = sc->sc_comp.stats.vjs_uncompressedin;
	psp->vj.vjs_compressedin = sc->sc_comp.stats.vjs_compressedin;
	psp->vj.vjs_errorin = sc->sc_comp.stats.vjs_errorin;
	psp->vj.vjs_tossed = sc->sc_comp.stats.vjs_tossed;
#endif /* VJC */
	break;

#ifdef PPP_COMPRESS
    case SIOCGPPPCSTATS:
	pcp = &((struct ifpppcstatsreq *) data)->stats;
	bzero(pcp, sizeof(*pcp));
	if (sc->sc_xc_state != NULL)
	    (*sc->sc_xcomp->comp_stat)(sc->sc_xc_state, &pcp->c);
	if (sc->sc_rc_state != NULL)
	    (*sc->sc_rcomp->decomp_stat)(sc->sc_rc_state, &pcp->d);
	break;
#endif /* PPP_COMPRESS */

    default:
	error = EINVAL;
    }
    splx(s);
    return (error);
}

/*
 * Queue a packet.  Start transmission if not active.
 * Packet is placed in Information field of PPP frame.
 *
 * This procedure MUST take an actual netbuf_t as input
 * since it may be called by procedures outside of us.
 * The buffer received must be in the same format as that
 * returned by pppgetbuf().
 */
int
pppoutput(ifp, in_nb, arg)
    netif_t ifp;
    netbuf_t in_nb;
    void *arg;
{
    register struct ppp_softc *sc = &ppp_softc[if_unit(ifp)];
    struct sockaddr *dst = (struct sockaddr *) arg;
    int protocol, address, control;
    u_char *cp;
    int s, error;
    mark_t flags = 0;
    struct ip *ip;
    struct nb_queue *ifq;
    enum NPmode mode;
    NETBUF_T m0;

    m0 = nb_TO_NB(in_nb);

    if (sc->sc_devp == NULL || (if_flags(ifp) & IFF_RUNNING) == 0
	|| (if_flags(ifp) & IFF_UP) == 0 && dst->sa_family != AF_UNSPEC) {
	error = ENETDOWN;	/* sort of */
	goto bad;
    }


    /*
     * Compute PPP header.
     */
    flags &= ~M_HIGHPRI;
    switch (dst->sa_family) {
#ifdef INET
    case AF_INET:
	address = PPP_ALLSTATIONS;
	control = PPP_UI;
	protocol = PPP_IP;
	mode = sc->sc_npmode[NP_IP];

	/*
	 * If this packet has the "low delay" bit set in the IP header,
	 * or TCP and to an interactive port, put it on the fastq instead
	 */
	ip = mtod(m0, struct ip *);
	if (ip->ip_tos & IPTOS_LOWDELAY || ip->ip_p == IPPROTO_ICMP)
	    goto urgent;
	else if (ip->ip_p == IPPROTO_TCP) {
	    register u_short *p = (u_short *) &(((caddr_t) ip)[ip->ip_hl << 2]);
	    if (INTERACTIVE(ntohs(p[0])) || INTERACTIVE(ntohs(p[1])))
urgent:		flags |= M_HIGHPRI;
	}
	break;
#endif
#ifdef NS
    case AF_NS:
	address = PPP_ALLSTATIONS;
	control = PPP_UI;
	protocol = PPP_XNS;
	mode = NPMODE_PASS;
	break;
#endif
    case AF_UNSPEC:
	address = PPP_ADDRESS(dst->sa_data);
	control = PPP_CONTROL(dst->sa_data);
	protocol = PPP_PROTOCOL(dst->sa_data);
	mode = NPMODE_PASS;
	break;
    default:
	IOLog("ppp%d: af%d not supported\n", if_unit(ifp), dst->sa_family);
	error = EAFNOSUPPORT;
	goto bad;
    }

    /*
     * Drop this packet, or return an error, if necessary.
     */
    if (mode == NPMODE_ERROR) {
	error = ENETDOWN;
	goto bad;
    }
    if (mode == NPMODE_DROP) {
	error = 0;
	goto bad;
    }

    /*
     * Add PPP header.
     */
    NB_GROW_TOP(m0, PPP_HDRLEN);

    cp = mtod(m0, u_char *);
    *cp++ = address;
    *cp++ = control;
    *cp++ = protocol >> 8;
    *cp++ = protocol & 0xff;


    if (sc->sc_flags & SC_LOG_OUTPKT) {
	IOLog("ppp%d: output:\n", if_unit(ifp));	/* XXX */
	pppdumpm(m0);
    }


    /*
     * Put the packet on the appropriate queue.
     */
    s = splimp();		/* splnet should be OK now */
    if (mode == NPMODE_QUEUE) {
	NB_SET_MARK(m0,flags);			/* save priority */
	/* XXX we should limit the number of packets on this queue */
	nbq_enqueue(&sc->sc_npq, m0);		/* XXX is this correct? */
    } else {
	ifq = (flags & M_HIGHPRI)? &sc->sc_fastq: &sc->sc_slowq;
	if (nbq_full(ifq) < 0) {
	    nbq_drop(ifq);
	    IOLog("ppp%d: output queue full\n", if_unit(sc->sc_if));
	    splx(s);
	    incr_cnt(sc->sc_if, if_oerrors);
	    error = ENOBUFS;
	    goto bad;
	}
	nbq_enqueue(ifq, m0);
    }

    /*
     * If we don't have some compressed packets already
     * and we are not at interrupt priority, then do some compression. 
     *
     * We need to be especially careful here.  pppouput() is typically
     * called at 2 different priority levels.  On a NeXT, neither of these
     * is the interrupt priority level.  However, on Intel, one of them is.
     * I don't know about HPPA or Sparc. Simple fix is to just check.
     */
    
    if(!sc->sc_compsched && s != ipltospl(IPLIMP)) {
	sc->sc_compsched = 1;
	splx(s);
	pppintr_comp(sc);    /* Calls pppstart() */
    }
    else {
      (*sc->sc_start)(sc);
      splx(s);
    }

    return (0);

bad:
    NB_FREE(m0);
    return (error);
}

/*
 * After a change in the NPmode for some NP, move packets from the
 * npqueue to the send queue or the fast queue as appropriate.
 * Should be called at splimp (actually splnet would probably suffice).
 * Due to some of the uglies in the packet queueing system I have
 * implemented this without the mpp stuff.
 * PCF
 */

static void
ppp_requeue(sc)
    struct ppp_softc *sc;
{
    NETBUF_T m, lm, nm;
    struct nb_queue *ifq;
    enum NPmode mode;
    mark_t flags;

    lm = nm = NULL;
    for (m = sc->sc_npq.head; m; ) {
	NB_GET_NEXT(m,&nm);

	switch (PPP_PROTOCOL(mtod(m, u_char *))) {
	case PPP_IP:
	    mode = sc->sc_npmode[NP_IP];
	    break;
	default:
	    mode = NPMODE_PASS;
	}

	switch (mode) {
	case NPMODE_PASS:
	    /*
	     * This packet can now go on one of the queues to be sent.
	     */
	    if(lm)
		NB_SET_NEXT(lm,nm);
	    else
		sc->sc_npq.head = nm;
	    NB_SET_NEXT(m,NULL);
	    NB_GET_MARK(m,&flags);
	    ifq = (flags & M_HIGHPRI)? &sc->sc_fastq: &sc->sc_slowq;
	    if (nbq_full(ifq)) {
		nbq_drop(ifq);
		incr_cnt(sc->sc_if, if_oerrors);
		NB_FREE(m);
	    } else 
		nbq_enqueue(ifq, m);
	    sc->sc_npq.len--;
	    break;

	case NPMODE_DROP:
	case NPMODE_ERROR:
	    sc->sc_npq.len--;
	    NB_FREE(m);
	    break;

	case NPMODE_QUEUE:
	    lm = m;
	    break;
	}
	m = nm;
    }
    sc->sc_npq.tail = lm;	/*  anything further on has been sent ! */
}

/*
 * Get a packet to send.  This procedure is intended to be called
 * at spltty()/splimp(), so it takes little time.  If there isn't
 * a packet waiting to go out, it schedules a software interrupt
 * to prepare a new packet; the device start routine gets called
 * again when a packet is ready.
 */
NETBUF_T
ppp_dequeue(sc)
    struct ppp_softc *sc;
{
  NETBUF_T m;
  int error;
  
  m = nbq_dequeue(&sc->sc_compq);


  if (!sc->sc_compsched && 
      (! nbq_empty(&sc->sc_slowq) || ! nbq_empty(&sc->sc_fastq)))
    {
      
      if ((error = pppsched(pppintr_comp, sc)) == KERN_SUCCESS)
	sc->sc_compsched = 1;
      else
	{
	  IOLogDbg("ppp%d: compression callout failed returning %d\n",
		   if_unit(sc->sc_if), error);
	}
    }
  
  return m;
}

/*
 * Takes all received input packets and uncompresses/hands_off.
 * Must not be reentrant and is called at normal priority.
 * Guaranteed Non-Reentrancy means we don't need to be at splnet().
 *
 */

void
pppintr_decomp(arg)
    void *arg;
{
    struct ppp_softc *sc = (struct ppp_softc *)arg;
    int s;
    NETBUF_T m;

    if (nbq_low(&sc->sc_freeq))
      pppfillfreeq((void *) sc);

  decomp:
    for (;;) {
      m = nbq_dequeue(&sc->sc_rawq);
      if (m == NULL)
	break;
      ppp_inproc(sc, m);
    }

  /*
   * Now we have aparently emptied the queue.  So, we try to reset the
   * synchronization flag that schedules callbacks.  We check for the
   * possibility that an interrupt occurred before we finish this check.
   */
  s = splimp();
  if (!nbq_empty(&sc->sc_rawq))
    {
      splx(s);
      goto decomp;
    }
  else
    {
      sc->sc_decompsched = 0;
      splx(s);
    }
}



/*
 * Readies the next few output packet from
 * the sc_fastq/sc_slowq.  Will try to
 * precompress all packets on the fast
 * queue and at most one from the slow queue.
 */
void
pppintr_comp(arg)
    void *arg;
{
  struct ppp_softc *sc = (struct ppp_softc *)arg;
  int s;
  NETBUF_T m;
  
  if (nbq_low(&sc->sc_freeq))
    pppfillfreeq((void *) sc);

  
  while (!nbq_full(&sc->sc_compq) && !nbq_empty(&sc->sc_fastq))
    ppp_outpkt(sc);

  if (!nbq_full(&sc->sc_compq) && !nbq_empty(&sc->sc_slowq))
    ppp_outpkt(sc);
      
  sc->sc_compsched = 0;
}

/*
 * Grab another packet off a queue and apply VJ compression,
 * packet compression, address/control and/or protocol compression
 * if enabled.  Should be called at splnet.
 */
static void
ppp_outpkt(sc)
    struct ppp_softc *sc;
{
    int s;
    NETBUF_T m;
    u_char *cp;
    int address, control, protocol;
#if NS_TARGET >= 40
    struct timeval tv_time;
#endif

    /*
     * Grab a packet to send: first try the fast queue, then the
     * normal queue.
     */
    m = nbq_dequeue(&sc->sc_fastq);
    if (m == NULL)
	m = nbq_dequeue(&sc->sc_slowq);
    if (m == NULL)
	return;

    /*
     * Extract the ppp header of the new packet.
     * The ppp header will be in one netbuf.
     */
    cp = mtod(m, u_char *);
    address = PPP_ADDRESS(cp);
    control = PPP_CONTROL(cp);
    protocol = PPP_PROTOCOL(cp);

#if NS_TARGET >= 40
	ns_time_to_timeval(clock_value(System), &tv_time);
#endif /* NS_TARGET */

    switch (protocol) {
    case PPP_IP:
	/*
	 * Update the time we sent the most recent packet.
	 */
#if NS_TARGET >= 40
	sc->sc_last_sent = tv_time.tv_sec;
#else
        sc->sc_last_sent = time.tv_sec;
#endif /* NS_TARGET */

#ifdef VJC
	/*
	 * If the packet is a TCP/IP packet, see if we can compress it.
	 */
	if (sc->sc_flags & SC_COMP_TCP) {
	    struct ip *ip;
	    int type;
	    u_char *vjhdr;

	    ip = (struct ip *) (cp + PPP_HDRLEN);
	    /* this code assumes the IP/TCP header is in one netbuf */
	    if (ip->ip_p == IPPROTO_TCP) {
		type = vj_compress_tcp(ip, NB_SIZE(m) - PPP_HDRLEN,
				       &sc->sc_comp,
				       !(sc->sc_flags & SC_NO_TCP_CCID), &vjhdr);
		switch (type) {
		case TYPE_UNCOMPRESSED_TCP:
		    protocol = PPP_VJC_UNCOMP;
		    break;
		case TYPE_COMPRESSED_TCP:
		    NB_SHRINK_TOP(m, vjhdr - (u_char *) ip);
		    protocol = PPP_VJC_COMP;
		    cp = mtod(m, u_char *);
		    cp[0] = address;	/* header has moved */
		    cp[1] = control;
		    cp[2] = 0;
		    break;
		}
		cp[3] = protocol;	/* update protocol in PPP header */
	    }
	}

#endif	/* VJC */

	break;

#ifdef PPP_COMPRESS
    case PPP_CCP:
	ppp_ccp(sc, m, 0);
	break;
#endif	/* PPP_COMPRESS */
    }


#ifdef PPP_COMPRESS
    if (protocol != PPP_LCP && protocol != PPP_CCP
	&& sc->sc_xc_state && (sc->sc_flags & SC_COMP_RUN)) {
	NETBUF_T mcomp;
	int slen, clen;

	slen = NB_SIZE(m);

	clen = (*sc->sc_xcomp->compress)
	    (sc->sc_xc_state, &mcomp, m, slen,
	     sc->sc_flags & SC_CCP_UP? if_mtu(sc->sc_if): 0);


	if (mcomp && (NB_SIZE(mcomp) >= slen))
	    IOLog("BSD Warning... packet growth: Orig=%d New=%d.\n",
		  slen, NB_SIZE(mcomp));

	if (mcomp != NULL) {

	    NB_FREE(m);
	    m = mcomp;
	    cp = mtod(m, u_char *);
	    protocol = cp[3];
	}
    }
#endif	/* PPP_COMPRESS */

    /*
     * Compress the address/control and protocol, if possible.
     */
    if (sc->sc_flags & SC_COMP_AC && address == PPP_ALLSTATIONS &&
	control == PPP_UI && protocol != PPP_ALLSTATIONS &&
	protocol != PPP_LCP) {
	/* can compress address/control */
	NB_SHRINK_TOP(m, 2);
    }
    if (sc->sc_flags & SC_COMP_PROT && protocol < 0xFF) {
	/* can compress protocol */
	if (mtod(m, u_char *) == cp) {
	    cp[2] = cp[1];	/* move address/control up */
	    cp[1] = cp[0];
	}
	NB_SHRINK_TOP(m, 1);
    }


    s = splimp();
    nbq_enqueue(&sc->sc_compq, m);
    (*sc->sc_start)(sc);
    splx(s);
}

#ifdef PPP_COMPRESS
/*
 * Handle a CCP packet.  `rcvd' is 1 if the packet was received,
 * 0 if it is about to be transmitted.
 */
static void
ppp_ccp(sc, m, rcvd)
    struct ppp_softc *sc;
    NETBUF_T m;
    int rcvd;
{
    u_char *dp, *ep;
    int slen, s;

    /*
     * Get a pointer to the data after the PPP header.
     */
    dp = mtod(m, u_char *) + PPP_HDRLEN;

    ep = mtod(m, u_char *) + NB_SIZE(m);
    if (dp + CCP_HDRLEN > ep)
	return;
    slen = CCP_LENGTH(dp);
    if (dp + slen > ep) {
	IOLogDbg("ppp%d: ccp: not enough data in netbuf (%x+%x > %x+%x)\n",
		 if_unit(sc->sc_if), dp, slen, mtod(m, u_char *), NB_SIZE(m));
	return;
    }

    switch (CCP_CODE(dp)) {
    case CCP_CONFREQ:
    case CCP_TERMREQ:
    case CCP_TERMACK:
	/* CCP must be going down - disable compression */
	if (sc->sc_flags & SC_CCP_UP) {
	    s = splimp();
	    sc->sc_flags &= ~(SC_CCP_UP | SC_COMP_RUN | SC_DECOMP_RUN);
	    splx(s);
	}
	break;

    case CCP_CONFACK:
	if (sc->sc_flags & SC_CCP_OPEN && !(sc->sc_flags & SC_CCP_UP)
	    && slen >= CCP_HDRLEN + CCP_OPT_MINLEN
	    && slen >= CCP_OPT_LENGTH(dp + CCP_HDRLEN) + CCP_HDRLEN) {
	    if (!rcvd) {
		/* we're agreeing to send compressed packets. */
		if (sc->sc_xc_state != NULL
		    && (*sc->sc_xcomp->comp_init)
			(sc->sc_xc_state, dp + CCP_HDRLEN, slen - CCP_HDRLEN,
			 if_unit(sc->sc_if), 0, sc->sc_flags & SC_DEBUG)) {
		    s = splimp();
		    sc->sc_flags |= SC_COMP_RUN;
		    splx(s);
		}
	    } else {
		/* peer is agreeing to send compressed packets. */
		if (sc->sc_rc_state != NULL
		    && (*sc->sc_rcomp->decomp_init)
			(sc->sc_rc_state, dp + CCP_HDRLEN, slen - CCP_HDRLEN,
			 if_unit(sc->sc_if),
#ifdef VJC
			 VJ_HDRLEN +
#endif
			 0, sc->sc_mru, sc->sc_flags & SC_DEBUG)) {
		    s = splimp();
		    sc->sc_flags |= SC_DECOMP_RUN;
		    sc->sc_flags &= ~(SC_DC_ERROR | SC_DC_FERROR);
		    splx(s);
		}
	    }
	}
	break;

    case CCP_RESETACK:
	if (sc->sc_flags & SC_CCP_UP) {
	    if (!rcvd) {
		if (sc->sc_xc_state && (sc->sc_flags & SC_COMP_RUN)) {
		    (*sc->sc_xcomp->comp_reset)(sc->sc_xc_state);
		    nbq_flush(&sc->sc_compq);  /* Flush pre-compressed packets */
		  }
	    } else {
		if (sc->sc_rc_state && (sc->sc_flags & SC_DECOMP_RUN)) {
		    (*sc->sc_rcomp->decomp_reset)(sc->sc_rc_state);
		    s = splimp();
		    sc->sc_flags &= ~SC_DC_ERROR;
		    splx(s);
		}
	    }
	}
	break;
    }
}

/*
 * CCP is down; free (de)compressor state if necessary.
 */
static void
ppp_ccp_closed(sc)
    struct ppp_softc *sc;
{
    if (sc->sc_xc_state) {
	(*sc->sc_xcomp->comp_free)(sc->sc_xc_state);
	sc->sc_xc_state = NULL;
    }
    if (sc->sc_rc_state) {
	(*sc->sc_rcomp->decomp_free)(sc->sc_rc_state);
	sc->sc_rc_state = NULL;
    }
}
#endif /* PPP_COMPRESS */

/*
 * PPP packet input routine.
 * The caller has checked and removed the FCS and has inserted
 * the address/control bytes and the protocol high byte if they
 * were omitted.
 */
void
ppppktin(sc, m, lost)
    struct ppp_softc *sc;
    NETBUF_T m;
    int lost;
{
  int error, s = splimp();
  
  NB_SET_MARK(m,(lost ? M_ERRMARK : 0));
  
  /* XXX - we should check for the raw queue overflowing... */
  nbq_enqueue(&sc->sc_rawq, m);
  if (!sc->sc_decompsched)
    {
      if ((error = pppsched(pppintr_decomp, sc)) == KERN_SUCCESS)
	sc->sc_decompsched = 1;
      else
	IOLogDbg("ppp%d: decompression callout failed returning %d\n",
		 if_unit(sc->sc_if), error);
    }
  
  splx(s);
}

/*
 * Process a received PPP packet, doing decompression as necessary.
 */
#define COMPTYPE(proto)	((proto) == PPP_VJC_COMP? TYPE_COMPRESSED_TCP: \
			 TYPE_UNCOMPRESSED_TCP)

static void
ppp_inproc(sc, m)
    struct ppp_softc *sc;
    NETBUF_T m;
{
    struct nb_queue *inq;
    int s, ilen, xlen, proto, rv;
    mark_t flags;
    u_char *cp, adrs, ctrl;
    NETBUF_T dmp;
    u_char *iphdr;
    u_int hlen;
#if NS_TARGET >= 40
    struct timeval tv_time;
#endif /* NS_TARGET */


    incr_cnt(sc->sc_if, if_ipackets);

    NB_GET_MARK(m,&flags);

    if (sc->sc_flags & SC_LOG_INPKT) {
	IOLog("ppp%d: got %d bytes\n", if_unit(sc->sc_if), NB_SIZE(m));
	pppdumpm(m);
    }

    cp = mtod(m, u_char *);
    adrs = PPP_ADDRESS(cp);
    ctrl = PPP_CONTROL(cp);
    proto = PPP_PROTOCOL(cp);

    if (flags & M_ERRMARK) {
	s = splimp();
	sc->sc_flags |= SC_VJ_RESET;
	splx(s);
    }

#ifdef PPP_COMPRESS
    /*
     * Decompress this packet if necessary, update the receiver's
     * dictionary, or take appropriate action on a CCP packet.
     */
    if (proto == PPP_COMP && sc->sc_rc_state && (sc->sc_flags & SC_DECOMP_RUN)
	&& !(sc->sc_flags & SC_DC_ERROR) && !(sc->sc_flags & SC_DC_FERROR)) {
	/* decompress this packet */
	rv = (*sc->sc_rcomp->decompress)(sc->sc_rc_state, m, &dmp);
	if (rv == DECOMP_OK){

	  NB_FREE(m);
	  if (dmp == NULL){
	    /* No error, but no decompressed packet returned */
	    return;
	  }
	    m = dmp;
	    cp = mtod(m, u_char *);
	    proto = PPP_PROTOCOL(cp);
	} else {
	    /*
	     * An error has occurred in decompression.
	     * Pass the compressed packet up to pppd, which may take
	     * CCP down or issue a Reset-Req.
	     */
	    IOLogDbg("ppp%d: decompress failed %d\n", if_unit(sc->sc_if), rv);
	    s = splimp();
	    sc->sc_flags |= SC_VJ_RESET;

	    if (rv == DECOMP_ERROR)
	      sc->sc_flags |= SC_DC_ERROR;
	    else
	      sc->sc_flags |= SC_DC_FERROR;
	    splx(s);
	}

    } else {
	if (sc->sc_rc_state && (sc->sc_flags & SC_DECOMP_RUN))
	  {

	    (*sc->sc_rcomp->incomp)(sc->sc_rc_state, m);
	}
	if (proto == PPP_CCP) {
	    ppp_ccp(sc, m, 1);
	}
    }
#endif

    ilen = NB_SIZE(m);

#ifdef VJC
    if (sc->sc_flags & SC_VJ_RESET) {
	/*
	 * If we've missed a packet, we must toss subsequent compressed
	 * packets which don't have an explicit connection ID.
	 */

/*	IOLog("SC_VJ_RESET was set!\n"); */

	vj_uncompress_err(&sc->sc_comp);
	s = splimp();
	sc->sc_flags &= ~SC_VJ_RESET;
	splx(s);
    }

    /*
     * See if we have a VJ-compressed packet to uncompress.
     */
    if (proto == PPP_VJC_COMP) {
	if (sc->sc_flags & SC_REJ_COMP_TCP)
	    goto bad;


	xlen = vj_uncompress_tcp(cp + PPP_HDRLEN, ilen - PPP_HDRLEN,
				 ilen - PPP_HDRLEN,
				 &sc->sc_comp, &iphdr, &hlen);

	if (xlen <= 0) {
/*
   IOLogDbg("ppp%d: VJ uncompress failed on type comp\n", 
			if_unit(sc->sc_if));
*/
	    goto bad;
	}

	/*
	 * Write the IP/TCP header back into the datagram.
	 * The pointers point to the stored copy in the VJ
	 * compression table.
	 */
   
	NB_GROW_TOP(m, hlen - xlen);
	NB_WRITE(m, PPP_HDRLEN, hlen, iphdr);

	cp = mtod(m, u_char *);

#ifdef TCP_CHECKSUM
    {
#define getip_hl(base)	((base).ip_hl)

      u_short mytcpcksum (struct ip *pip);
      struct tcphdr *ptcp;
      struct ip *iphdr;
      u_short thecksum;
      u_long hlen;

      iphdr = (struct ip*) (cp + PPP_HDRLEN);
      hlen = getip_hl(*iphdr) << 2;  /* Length is in words */
      ptcp = (struct tcphdr *)&((u_char *)iphdr)[hlen];

      thecksum = (u_short)mytcpcksum(iphdr);

      if(ptcp->th_sum != thecksum)
	{
#ifdef NEWVJ_RESYNC
	  set_newvj_error_mode();
#endif
	  IOLog("NEWVJ: Warning... TCP checksum failed Received=%u, Calculated=%u)\n",
		(ptcp->th_sum)&0xffff, thecksum&0xffff);
	}
    }	    	    
#endif


	cp[0] = adrs;
	cp[1] = ctrl;
	cp[2] = 0;
	cp[3] = PPP_IP;
	proto = PPP_IP;

	ilen += hlen - xlen;

    } else if (proto == PPP_VJC_UNCOMP) {
	if (sc->sc_flags & SC_REJ_COMP_TCP)
	    goto bad;


	vj_uncompress_uncomp(cp + PPP_HDRLEN, ilen-PPP_HDRLEN, &sc->sc_comp);

	proto = PPP_IP;
	cp[3] = PPP_IP;
    }
#endif /* VJC */


    rv = 0;
    switch (proto) {
#ifdef INET
    case PPP_IP:
	/*
	 * IP packet - take off the ppp header and pass it up to IP.
	 */
	if ((if_flags(sc->sc_if) & IFF_UP) == 0
	    || sc->sc_npmode[NP_IP] != NPMODE_PASS) {
	    /* interface is down - drop the packet. */
	    NB_FREE(m);
	    IOLogDbg("ppp%d: IP packed dropped (NPmode)\n", if_unit(sc->sc_if));
	    return;
	}
	NB_SHRINK_TOP(m, PPP_HDRLEN);
	inet_queue(sc->sc_if, NB_TO_nb(m));
#if NS_TARGET >= 40
	/*  I am assuming the time is different here than above. */
	ns_time_to_timeval(clock_value(System), &tv_time);
	sc->sc_last_recv = tv_time.tv_sec; /* update time of last pkt rcvd */
#else
	sc->sc_last_recv = time.tv_sec; /* update time of last pkt rcvd */
#endif
	return;
#endif

    default:
	/*
	 * Some other protocol - place on input queue for read().
	 */
	inq = &sc->sc_inq;
	rv = 1;
	break;
    }

    /*
     * Put the packet on the appropriate input queue.
     */
    s = splimp();
    if (nbq_full(inq)) {
	nbq_drop(inq);
	splx(s);
	IOLog("ppp%d: input queue full\n", if_unit(sc->sc_if));
	goto bad;
    }
    nbq_enqueue(inq, m);
    splx(s);

    if (rv)
	(*sc->sc_ctlp)(sc);

    return;

 bad:
    NB_FREE(m);
    incr_cnt(sc->sc_if, if_ierrors);
}

#define MAX_DUMP_BYTES	128

static void
pppdumpm(m0)
    NETBUF_T m0;
{
    char buf[3*MAX_DUMP_BYTES+4];
    char *bp = buf;
    static char digits[] = "0123456789abcdef";
    int l = NB_SIZE(m0);
    u_char *rptr = mtod(m0, u_char *);

    while (l--) {
	if (bp > buf + sizeof(buf) - 4)
	    goto done;
	*bp++ = digits[*rptr >> 4]; /* convert byte to ascii hex */
	*bp++ = digits[*rptr++ & 0xf];
    }

    *bp++ = ' ';
done:
    if (l)
	*bp++ = '>';
    *bp = 0;
    IOLog("%s\n", buf);
}


