/*
 * print PPP statistics:
 * 	pppstats [-i interval] [-v] [-r] [-c] [interface]
 *
 *   -i <update interval in seconds>
 *   -v Verbose mode for default display
 *   -r Show compression ratio in default display
 *   -c Show Compression statistics instead of default display
 *
 *
 * History:
 *      perkins@cps.msu.edu: Added compression statistics and alternate 
 *                display. 11/94

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
static char rcsid[] = "$Id: pppstats.c,v 1.7 1995/05/02 04:18:40 paulus Exp $";
#endif

#include <ctype.h>
#include <errno.h>
#include <nlist.h>
#include <stdio.h>
#include <signal.h>
#include <sys/param.h>
#include <sys/mbuf.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/file.h>
#include <net/if.h>
#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <netinet/ip.h>
#include <netinet/ip_var.h>

#include <net/ppp_defs.h>

#ifndef STREAMS
#include <net/if_ppp.h>
#endif

#ifdef STREAMS
#define PPP_STATS	1	/* should be defined iff it is in ppp_if.c */
#include <sys/stream.h>
#include <net/ppp_str.h>
#endif

int	vflag, rflag, cflag;
unsigned interval = 5;
int	unit;
int	s;			/* socket file descriptor */
int	signalled;		/* set if alarm goes off "early" */

extern	char *malloc();
void catchalarm __P((int));

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
	if (strcmp(argv[0], "-r") == 0) {
	  ++rflag;
	  ++argv, --argc;
	  continue;
	}
	if (strcmp(argv[0], "-c") == 0) {
	  ++cflag;
	  ++argv, --argc;
	  continue;
	}
	if (strcmp(argv[0], "-i") == 0 && argv[1] &&
	    isdigit(argv[1][0])) {
	    interval = atoi(argv[1]);
	    if (interval < 0)
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
	usage();
    }

    if ((s = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
	perror("couldn't create IP socket");
	exit(1);
    }
    intpr();
    exit(0);
}

usage()
{
    fprintf(stderr, "Usage: pppstats [-v] [-r] [-c] [-i interval] [unit]\n");
    exit(1);
}

#define V(offset) (line % 20? req.stats.offset - osc.offset: req.stats.offset)
#define W(offset) (line % 20? creq.stats.offset - csc.offset: creq.stats.offset)

#define CRATE(comp, inc, unc)	((unc) == 0? 0.0: \
				 1.0 - (double)((comp) + (inc)) / (unc))

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
    struct ifpppstatsreq req;
    struct ifpppcstatsreq creq;
    struct ppp_stats osc;
    struct ppp_comp_stats csc;

    bzero(&osc, sizeof(osc));
    bzero(&csc, sizeof(csc));

    sprintf(req.ifr_name, "ppp%d", unit);
    sprintf(creq.ifr_name, "ppp%d", unit);
    while (1) {
	if (ioctl(s, SIOCGPPPSTATS, &req) < 0) {
	    if (errno == ENOTTY)
		fprintf(stderr, "pppstats: kernel support missing\n");
	    else
		perror("ioctl(SIOCGPPPSTATS)");
	    exit(1);
	}
	if ((cflag || rflag) && ioctl(s, SIOCGPPPCSTATS, &creq) < 0) {
	    if (errno == ENOTTY) {
		fprintf(stderr, "pppstats: no kernel compression support\n");
		if (cflag)
		    exit(1);
		rflag = 0;
	    } else {
		perror("ioctl(SIOCGPPPCSTATS)");
		exit(1);
	    }
	}
	(void)signal(SIGALRM, catchalarm);
	signalled = 0;
	(void)alarm(interval);
    
	if ((line % 20) == 0) {
	    if (line > 0)
		putchar('\n');
	    if (cflag) {
	    
		printf("%6.6s %6.6s %6.6s %6.6s %6.6s %6.6s %6.6s",
		       "ubyte", "upack", "cbyte", "cpack", "ibyte", "ipack", "ratio");
		printf(" | %6.6s %6.6s %6.6s %6.6s %6.6s %6.6s %6.6s",
		       "ubyte", "upack", "cbyte", "cpack", "ibyte", "ipack", "ratio");
		putchar('\n');
	    } else {

		printf("%6.6s %6.6s %6.6s %6.6s %6.6s",
		       "in", "pack", "comp", "uncomp", "err");
		if (vflag)
		    printf(" %6.6s %6.6s", "toss", "ip");
		if (rflag)
		    printf("   %6.6s %6.6s", "ratio", "ubyte");
		printf("  | %6.6s %6.6s %6.6s %6.6s %6.6s",
		       "out", "pack", "comp", "uncomp", "ip");
		if (vflag)
		    printf(" %6.6s %6.6s", "search", "miss");
		if(rflag)
		    printf("   %6.6s %6.6s", "ratio", "ubyte");
		putchar('\n');
	    }
	    bzero(&osc, sizeof(osc));
	    bzero(&csc, sizeof(csc));
	}
	
	if (cflag) {
	    printf("%6d %6d %6d %6d %6d %6d %6.2f",
		   W(d.unc_bytes),
		   W(d.unc_packets),
		   W(d.comp_bytes),
		   W(d.comp_packets),
		   W(d.inc_bytes),
		   W(d.inc_packets),
		   W(d.ratio) / 256.0);

	    printf(" | %6d %6d %6d %6d %6d %6d %6.2f",
		   W(c.unc_bytes),
		   W(c.unc_packets),
		   W(c.comp_bytes),
		   W(c.comp_packets),
		   W(c.inc_bytes),
		   W(c.inc_packets),
		   W(c.ratio) / 256.0);
	
	    putchar('\n');
	} else {

	    printf("%6d %6d %6d %6d %6d",
		   V(p.ppp_ibytes),
		   V(p.ppp_ipackets), V(vj.vjs_compressedin),
		   V(vj.vjs_uncompressedin), V(vj.vjs_errorin));
	    if (vflag)
		printf(" %6d %6d", V(vj.vjs_tossed),
		       V(p.ppp_ipackets) - V(vj.vjs_compressedin) -
		       V(vj.vjs_uncompressedin) - V(vj.vjs_errorin));
	    if (rflag)
		printf("   %6.2f %6d",
		       CRATE(W(d.comp_bytes), W(d.unc_bytes), W(d.unc_bytes)),
		       W(d.unc_bytes));
	    printf("  | %6d %6d %6d %6d %6d", V(p.ppp_obytes),
		   V(p.ppp_opackets), V(vj.vjs_compressed),
		   V(vj.vjs_packets) - V(vj.vjs_compressed),
		   V(p.ppp_opackets) - V(vj.vjs_packets));
	    if (vflag)
		printf(" %6d %6d", V(vj.vjs_searches), V(vj.vjs_misses));

	    if (rflag)
		printf("   %6.2f %6d",
		       CRATE(W(d.comp_bytes), W(d.unc_bytes), W(d.unc_bytes)),
		       W(c.unc_bytes));
	    
	    putchar('\n');
	}

	fflush(stdout);
	line++;
	if (interval == 0)
	    exit(0);
    
	oldmask = sigblock(sigmask(SIGALRM));
	if (! signalled) {
	    sigpause(0);
	}
	sigsetmask(oldmask);
	signalled = 0;
	(void)alarm(interval);
	osc = req.stats;
	csc = creq.stats;
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
