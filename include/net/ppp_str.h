/*
  ppp_str.h - streams version include file

  Copyright (C) 1990 Brad K. Clements, All Rights Reserved,
  See copyright statement in NOTES
*/

#include	<sys/ioccom.h>

#define PPP_HDRLEN	4	/* octets for standard ppp header */
#define PPP_FCSLEN	2	/* octets for FCS */

#define PPP_ADDRESS(cp)		((cp)[0])
#define PPP_CONTROL(cp)		((cp)[1])
#define PPP_PROTOCOL(cp)	(((cp)[2] << 8) + (cp)[3])

#define	PPP_ALLSTATIONS	0xff	/* All-Stations broadcast address */
#define	PPP_UI		0x03	/* Unnumbered Information */
#define	PPP_FLAG	0x7e	/* Flag Sequence */
#define	PPP_ESCAPE	0x7d	/* Asynchronous Control Escape */
#define	PPP_TRANS	0x20	/* Asynchronous transparency modifier */

/*
 * Protocol field values.
 */
#define PPP_IP		0x21	/* Internet Protocol */
#define	PPP_XNS		0x25	/* Xerox NS */
#define	PPP_VJC_COMP	0x2d	/* VJ compressed TCP */
#define	PPP_VJC_UNCOMP	0x2f	/* VJ uncompressed TCP */
#define PPP_COMP	0xfd	/* compressed packet */
#define PPP_LCP		0xc021	/* Link Control Protocol */
#define PPP_CCP		0x80fd	/* Compression Control Protocol */

/*
 * Important FCS values.
 */
#define PPP_INITFCS	0xffff	/* Initial FCS value */
#define PPP_GOODFCS	0xf0b8	/* Good final FCS value */
#define PPP_FCS(fcs, c)	(((fcs) >> 8) ^ fcstab[((fcs) ^ (c)) & 0xff])

/*
 * Packet sizes
 */
#define	PPP_MTU		1500	/* Default MTU (size of Info field) */
#define PPP_MRU		1500	/* Default MRU (max receive unit) */
#define PPP_MAXMRU	65000	/* Largest MRU we allow */

/* Extended asyncmap - allows any character to be escaped. */
typedef u_long	ext_accm[8];

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

/* defines for streams modules */
#define       IF_INPUT_ERROR  0xe1
#define       IF_OUTPUT_ERROR 0xe2

#define       ALLOCBSIZE      64              /* how big of a buffer block to
allocate for each chunk of the input chain */

#define	PPP_MTU		1500	/* Default MTU (size of Info field) */
#define PPP_HDRLEN	4	/* sizeof(struct ppp_header) must be 4 */
