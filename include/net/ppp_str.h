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
#define	SIOCSIFMRU	_IOW('p', 132, int)	/* set max receive unit */
#define	SIOCGIFMRU	_IOR('p', 133, int)	/* get max receive unit */
#define	SIOCGIFASYNCMAP	_IOR('p', 134, long)	/* get transmit async map */
#define	SIOCSIFASYNCMAP	_IOW('p', 135, long)	/* set transmit async map */
#define	SIOCGETU	_IOR('p', 136, int)	/* get unit number */
#define	SIOCSIFVJCOMP	_IOW('p', 137, char)	/* enable/disable VJ comp */
#define	SIOCGIFDEBUG	_IOR('p', 138, int)	/* get debug flags */
#define	SIOCSIFDEBUG	_IOW('p', 139, int)	/* set debug flags */
#define	SIOCGIFRASYNCMAP _IOR('p', 140, long)	/* get receive async map */
#define	SIOCSIFRASYNCMAP _IOW('p', 141, long)	/* set receive async map */
#define	SIOCGIFXASYNCMAP _IOR('p', 142, ext_accm)  /* get extended xmit map */
#define	SIOCSIFXASYNCMAP _IOW('p', 143, ext_accm)  /* set extended xmit map */

#else
/* traditional C compiler */
#define	SIOCSIFCOMPAC	_IOW(p, 130, char)
#define	SIOCSIFCOMPPROT	_IOW(p, 131, char)
#define	SIOCSIFMRU	_IOW(p, 132, int)	/* set max receive unit */
#define	SIOCGIFMRU	_IOR(p, 133, int)	/* get max receive unit */
#define	SIOCGIFASYNCMAP	_IOR(p, 134, long)	/* get transmit async map */
#define	SIOCSIFASYNCMAP	_IOW(p, 135, long)	/* set transmit async map */
#define	SIOCGETU	_IOR(p, 136, int)	/* get unit number */
#define	SIOCSIFVJCOMP	_IOW(p, 137, char)	/* enable/disable VJ comp */
#define	SIOCGIFDEBUG	_IOR(p, 138, int)	/* get debug flags */
#define	SIOCSIFDEBUG	_IOW(p, 139, int)	/* set debug flags */
#define	SIOCGIFRASYNCMAP _IOR(p, 140, long)	/* get receive async map */
#define	SIOCSIFRASYNCMAP _IOW(p, 141, long)	/* set receive async map */
#define	SIOCGIFXASYNCMAP _IOR(p, 142, ext_accm)  /* get extended xmit map */
#define	SIOCSIFXASYNCMAP _IOW(p, 143, ext_accm)  /* set extended xmit map */
#endif

/*
 * Note on SIOCSIFVJCOMP: the parameter is now encoded as follows.
 * Bit 0 = overall VJ enable, bit 1 = don't compress connection ID,
 * bit 2 = receiver rejects VJ compression,
 * bits 4--7 = maximum slot ID (0 => use default (15)).
 */

/*
 * Structure used within the ppp_if streams module.
 */
struct	ppp_if_info {
	int			pii_flags;
#define	PII_FLAGS_INUSE		0x1	/* in use by  a stream	*/
#define	PII_FLAGS_ATTACHED	0x8	/* already if_attached	*/
#define	PII_FLAGS_VJC_ON	0x10	/* VJ TCP header compression enabled */
#define PII_FLAGS_VJC_NOCCID	0x20	/* VJ: don't compress conn. id */
#define PII_FLAGS_VJC_REJ	0x40	/* receive: reject VJ comp */
#define PII_FLAGS_DEBUG		0x80	/* enable debug printout */

	struct	ifnet		pii_ifnet;
	queue_t			*pii_writeq;	/* used by ppp_output 	*/
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
	}			pii_stats;
#endif
};

#ifdef        STREAMS
/* defines for streams modules */
#define       IF_INPUT_ERROR  0xe1
#define       IF_OUTPUT_ERROR 0xe2

#define       ALLOCBSIZE      64              /* how big of a buffer block to
allocate for each chunk of the input chain */
#endif
