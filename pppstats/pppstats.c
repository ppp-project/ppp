/*
 * print PPP statistics:
 * 	pppstats [-i interval] [-v] [interface] [system] [core] 
 *
 *	Brad Parker (brad@cayman.com) 6/92
 *
 * from the original "slstats" by Van Jaconson
 *
 * Copyright (c) 1989 Regents of the University of California.
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
 *	Van Jacobson (van@helios.ee.lbl.gov), Dec 31, 1989:
 *	- Initial distribution.
 */

#ifndef lint
static char rcsid[] = "$Id: pppstats.c,v 1.2 1993/12/15 05:00:47 paulus Exp $";
#endif

#include <sys/param.h>
#include <sys/mbuf.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/file.h>
#ifdef sun
#include <kvm.h>
#endif
#include <ctype.h>
#include <errno.h>
#include <nlist.h>
#include <stdio.h>
#include <signal.h>
#ifndef sun
#include <paths.h>
#endif

#include <net/if.h>
#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <netinet/ip.h>
#include <netinet/ip_var.h>

#define	VJC	1
#include <net/slcompress.h>
#include <net/if_ppp.h>

#ifdef STREAMS
#include <sys/stream.h>
#include <net/ppp_str.h>
#endif

#ifdef STREAMS
struct nlist nl[] = {
#define N_SOFTC 0
	{ "_pii" },
	"",
};
#else
struct nlist nl[] = {
#define N_SOFTC 0
	{ "_ppp_softc" },
	"",
};
#endif

#ifdef sun
kvm_t	*kd;
#endif

#ifdef sun
char	*system = "/vmunix";
#else
char	*system = _PATH_UNIX;
#endif

char	*kmemf;
int	kflag;
int	vflag;
unsigned interval = 5;
int	unit;

extern	char *malloc();

main(argc, argv)
	int argc;
	char *argv[];
{
	--argc; ++argv;
	while (argc > 0) {
		if (strcmp(argv[0], "-v") == 0) {
			++vflag;
			++argv, --argc;
			continue;
		}
		if (strcmp(argv[0], "-i") == 0 && argv[1] &&
		    isdigit(argv[1][0])) {
			interval = atoi(argv[1]);
			if (interval <= 0)
				usage();
			++argv, --argc;
			++argv, --argc;
			continue;
		}
		if (isdigit(argv[0][0])) {
			unit = atoi(argv[0]);
			if (unit < 0)
				usage();
			++argv, --argc;
			continue;
		}
		if (kflag)
			usage();

		system = *argv;
		++argv, --argc;
		if (argc > 0) {
			kmemf = *argv++;
			--argc;
			kflag++;
		}
	}
#ifdef sun
	/* SunOS */
	if ((kd = kvm_open(system, kmemf, (char *)0, O_RDONLY, NULL)) == NULL) {
	  perror("kvm_open");
	  exit(1);
	}
#else
	/* BSD4.3+ */
	if (kvm_openfiles(system, kmemf, (char *)0) == -1) {
	  fprintf(stderr, "kvm_openfiles: %s", kvm_geterr());
	  exit(1);
	}
#endif

#ifdef sun
	if (kvm_nlist(kd, nl)) {
#else
	if (kvm_nlist(nl)) {
#endif
	  fprintf(stderr, "pppstats: can't find symbols in nlist\n");
	  exit(1);
	}
	intpr();
	exit(0);
}

usage()
{
	fprintf(stderr,"usage: pppstats [-i interval] [-v] [unit] [system] [core]\n");
	exit(1);
}

u_char	signalled;			/* set if alarm goes off "early" */

#define V(offset) ((line % 20)? sc->offset - osc->offset : sc->offset)

/*
 * Print a running summary of interface statistics.
 * Repeat display every interval seconds, showing statistics
 * collected over that interval.  Assumes that interval is non-zero.
 * First line printed at top of screen is always cumulative.
 */
intpr()
{
	register int line = 0;
	int oldmask;
#ifdef __STDC__
	void catchalarm(int);
#else
	void catchalarm();
#endif

#ifdef STREAMS
#define STRUCT struct ppp_if_info
#else
#define STRUCT struct ppp_softc
#endif

	STRUCT *sc, *osc;

	nl[N_SOFTC].n_value += unit * sizeof(struct ppp_softc);
	sc = (STRUCT *)malloc(sizeof(STRUCT));
	osc = (STRUCT *)malloc(sizeof(STRUCT));

	bzero((char *)osc, sizeof(STRUCT));

	while (1) {
#ifdef sun
		if (kvm_read(kd, nl[N_SOFTC].n_value,
#else
		if (kvm_read(nl[N_SOFTC].n_value,
#endif
			     sc, sizeof(STRUCT)) !=
		    sizeof(STRUCT))
		  perror("kvm_read");

		(void)signal(SIGALRM, catchalarm);
		signalled = 0;
		(void)alarm(interval);

		if ((line % 20) == 0) {
			printf("%6.6s %6.6s %6.6s %6.6s %6.6s",
				"in", "pack", "comp", "uncomp", "err");
			if (vflag)
				printf(" %6.6s %6.6s", "toss", "ip");
			printf(" | %6.6s %6.6s %6.6s %6.6s %6.6s",
				"out", "pack", "comp", "uncomp", "ip");
			if (vflag)
				printf(" %6.6s %6.6s", "search", "miss");
			putchar('\n');
		}

#ifdef STREAMS
#define	COMP	pii_sc_comp
#define	STATS	pii_ifnet
#else
#define	COMP	sc_comp
#define	STATS	sc_if
#endif

		printf("%6d %6d %6d %6d %6d",
#if BSD > 43
			V(STATS.if_ibytes),
#else
			0,
#endif
			V(STATS.if_ipackets),
			V(COMP.sls_compressedin),
			V(COMP.sls_uncompressedin),
			V(COMP.sls_errorin));
		if (vflag)
			printf(" %6d %6d",
				V(COMP.sls_tossed),
				V(STATS.if_ipackets) -
				  V(COMP.sls_compressedin) -
				  V(COMP.sls_uncompressedin) -
				  V(COMP.sls_errorin));
		printf(" | %6d %6d %6d %6d %6d",
#if BSD > 43
			V(STATS.if_obytes),
#else
			0,
#endif
			V(STATS.if_opackets),
			V(COMP.sls_compressed),
			V(COMP.sls_packets) - V(COMP.sls_compressed),
			V(STATS.if_opackets) - V(COMP.sls_packets));
		if (vflag)
			printf(" %6d %6d",
				V(COMP.sls_searches),
				V(COMP.sls_misses));

		putchar('\n');
		fflush(stdout);
		line++;
		oldmask = sigblock(sigmask(SIGALRM));
		if (! signalled) {
			sigpause(0);
		}
		sigsetmask(oldmask);
		signalled = 0;
		(void)alarm(interval);
		bcopy((char *)sc, (char *)osc, sizeof(STRUCT));
	}
}

/*
 * Called if an interval expires before sidewaysintpr has completed a loop.
 * Sets a flag to not wait for the alarm.
 */
void catchalarm(arg)
int arg;
{
	signalled = 1;
}
