/*
 * if_ppp.h - Point-to-Point Protocol definitions.
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
 */

/* Portions Copyright (C) 1990 Brad K. Clements (streams support)
 */

#if !(NS_TARGET >= 40)
#import <kernserv/prototypes.h>
#endif /* NS_TARGET */

/*
 * Supported network protocols.  These values are used for
 * indexing sc_npmode.
 */
#define NP_IP	0		/* Internet Protocol */
#define NUM_NP	1		/* Number of NPs. */

#include "nbq.h"


/* only defined in the posix universe... */
/*typedef	int pid_t; */

struct ppp_softc {
	netif_t	sc_if;		/* network-visible interface */
	u_int	sc_flags;	/* control/status bits; see if_ppp.h */
	struct	tty *sc_devp;	/* pointer to device-dep structure */
	void	(*sc_start) __P((struct ppp_softc *));	/* start output proc */
	void	(*sc_ctlp) __P((struct ppp_softc *));	/* rcvd control pkt */
	void	(*sc_relinq) __P((struct ppp_softc *));	/* relinquish ifunit */
	u_int16_t sc_mru;	/* max receive unit */
	pid_t	sc_xfer;	/* used in transferring unit */
	NETBUF_T sc_m;		/* Current TTY input netbuf */
	struct nb_queue sc_freeq; /* reserve netbufs */
	struct nb_queue sc_rawq;  /* Raw input buffers */
	struct nb_queue sc_fastq; /* For telnet, rlogin, and ftp control */
	struct nb_queue sc_slowq; /* Everything else */
	struct nb_queue sc_inq;	/* Input available to user ppp */
	struct nb_queue sc_npq;	/* output packets not to be sent yet */
	struct nb_queue sc_compq; /* Cache of compressed bufs to be sent */
#ifdef VJC
	struct vjcompress sc_comp;
#endif
	u_int	sc_bytessent;	/* count of octets sent */
	u_int	sc_bytesrcvd;	/* count of octets received */
	enum NPmode sc_npmode[NUM_NP]; /* what to do with each NP */
#ifdef	PPP_COMPRESS
	struct compressor *sc_xcomp; /* transmit compressor */
	void	*sc_xc_state;	/* transmit compressor state */
	struct compressor *sc_rcomp; /* receive decompressor */
	void	*sc_rc_state;	/* receive decompressor state */
#endif
	time_t	sc_last_sent;	/* time (secs) last NP pkt sent */
	time_t	sc_last_recv;	/* time (secs) last NP pkt rcvd */

	short sc_compsched;     /* synchronize compression callouts */
	short sc_decompsched;   /* synchronize decompression callouts */

	/* Device-dependent part for async lines. */
	ext_accm sc_asyncmap;	/* async control character map */
	u_int32_t sc_rasyncmap;	/* receive async control char map */
	NETBUF_T sc_outm;	/* netbuf currently being output */
	char	*sc_mp;		/* ptr to next char in input netbuf */
	u_int16_t sc_ilen;      /* length of input packet so far */
	u_int16_t sc_fcs;	/* FCS so far (input) */
	u_int16_t sc_outfcs;	/* FCS so far for output packet */
	u_char	sc_rawin[16];	/* chars as received */
	int	sc_rawin_count;	/* # in sc_rawin */
};

extern struct	ppp_softc ppp_softc[];

struct	ppp_softc *pppalloc __P((pid_t pid));
void	pppdealloc __P((struct ppp_softc *sc));
int	pppioctl __P((struct ppp_softc *sc, u_long cmd, void *data, int flag));
void	ppppktin __P((struct ppp_softc *sc, NETBUF_T m, int lost));
NETBUF_T ppp_dequeue __P((struct ppp_softc *sc));

#define t_sc T_LINEP

#define incr_cnt(ifp,field) field##_set(ifp, field(ifp) + 1)

#ifdef VJC
#define VJ_HDRLEN	128
#endif
