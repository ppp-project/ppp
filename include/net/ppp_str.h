/*
  ppp_str.h - streams version include file

  defines ioctl calls for MRU, COMPPROT and ASYNCMAP

  Copyright (C) 1990 Brad K. Clements, All Rights Reserved,
  See copyright statement in NOTES
*/

#include	<sys/ioccom.h>

#ifdef	__STDC__
#define	SIOCSIFCOMPAC	_IOW('p', 130, char)
#define	SIOCSIFCOMPPROT	_IOW('p', 131, char)
#define	SIOCSIFMRU	_IOW('p', 132, int)
#define	SIOCGIFMRU	_IOR('p', 133, int)
#define	SIOCGIFASYNCMAP	_IOR('p', 134, long)
#define	SIOCSIFASYNCMAP	_IOW('p', 135, long)
#define	SIOCGETU	_IOR('p', 136, int)	/* get unit number */
#define	SIOCSIFVJCOMP	_IOW('p', 137, char)	/* enable/disable VJ Compression */
#define	SIOCGIFDEBUG	_IOR('p', 138, int)	/* get debug flags */
#define	SIOCSIFDEBUG	_IOW('p', 139, int)	/* set debug flags */

#else
/* traditional C compiler */
#define	SIOCSIFCOMPAC	_IOW(p, 130, char)
#define	SIOCSIFCOMPPROT	_IOW(p, 131, char)
#define	SIOCSIFMRU	_IOW(p, 132, int)
#define	SIOCGIFMRU	_IOR(p, 133, int)
#define	SIOCGIFASYNCMAP	_IOR(p, 134, long)
#define	SIOCSIFASYNCMAP	_IOW(p, 135, long)
#define	SIOCGETU	_IOR(p, 136, int)	/* get unit number */
#define	SIOCSIFVJCOMP	_IOW(p, 137, char)	/* enable/disable VJ Compression */
#define	SIOCGIFDEBUG	_IOR(p, 138, int)	/* get debug flags */
#define	SIOCSIFDEBUG	_IOW(p, 139, int)	/* set debug flags */
#endif

struct	ppp_if_info {
	int	pii_flags;
#define	PII_FLAGS_INUSE		0x1		/* in use by  a stream	*/
#define	PII_FLAGS_COMPAC	0x2
#define	PII_FLAGS_COMPPROT	0x4
#define	PII_FLAGS_ATTACHED	0x8		/* already if_attached	*/
#define	PII_FLAGS_VJC_ON	0x10		/* VJ TCP header compression enabled */
	struct	ifnet	pii_ifnet;
	queue_t		*pii_writeq;		/* used by ppp_output 	*/
#ifdef	VJC
	struct 	slcompress	pii_sc_comp;	/* vjc control buffer */
#endif
#ifdef	PPP_STATS
	struct	pppstat	{
		u_int	ppp_ibytes;
		u_int	ppp_ipackets;
		u_int	ppp_ierrors;
		u_int	ppp_obytes;
		u_int	ppp_opackets;
		u_int	ppp_oerrors;
	} pii_stats;
#endif
};

#ifdef        STREAMS
/* defines for streams modules */
#define       IF_INPUT_ERROR  0xe1
#define       IF_OUTPUT_ERROR 0xe2

#define       ALLOCBSIZE      64              /* how big of a buffer block to
allocate for each chunk of the input chain */
#endif
