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
#define PPP_HDRLEN	4	/* sizeof(struct ppp_header) must be 4 */

/*
 * A 32-bit unsigned integral type.
 */
#ifdef	UINT32_T
typedef UINT32_T	u_int32_t;
#else
typedef unsigned long	u_int32_t;
#endif

/* Extended asyncmap - allows any character to be escaped. */
typedef u_int32_t	ext_accm[8];

/*
 * Statistics.
 */
struct pppstat	{
    u_int	ppp_ibytes;	/* bytes received */
    u_int	ppp_ipackets;	/* packets received */
    u_int	ppp_ierrors;	/* receive errors */
    u_int	ppp_obytes;	/* bytes sent */
    u_int	ppp_opackets;	/* packets sent */
    u_int	ppp_oerrors;	/* transmit errors */
};

struct vjstat {
    u_int	sls_packets;	/* outbound packets */
    u_int	sls_compressed;	/* outbound compressed packets */
    u_int	sls_searches;	/* searches for connection state */
    u_int	sls_misses;	/* times couldn't find conn. state */
    u_int	sls_uncompressedin; /* inbound uncompressed packets */
    u_int	sls_compressedin;   /* inbound compressed packets */
    u_int	sls_errorin;	/* inbound unknown type packets */
    u_int	sls_tossed;	/* inbound packets tossed because of error */
};

struct ppp_stats {
    struct pppstat	p;
    struct vjstat	vj;
};

/*
 * What to do with network protocol (NP) packets.
 */

enum NPmode {
    NPMODE_PASS,		/* pass the packet through */
    NPMODE_DROP,		/* silently drop the packet */
    NPMODE_ERROR,		/* return an error */
    NPMODE_QUEUE		/* save it up for later. */
};

struct npioctl {
    int		protocol;	/* PPP procotol, e.g. PPP_IP */
    enum NPmode	mode;
};

/* Structure describing a CCP configuration option, for SIOCSCOMPRESS */
#define MAX_PPP_OPTION	32
struct ppp_option_data {
	u_int	length;
	int	transmit;
	u_char	opt_data[MAX_PPP_OPTION];
};

/* Bit definitions for SIOC[GS]IFCOMP. */
#define CCP_ISOPEN	1
#define CCP_ISUP	2
#define CCP_COMP_RUN	4
#define CCP_DECOMP_RUN	8
#define CCP_ERROR	0x10
#define CCP_FATALERROR	0x20

/*
 * Ioctl definitions.
 */

#ifdef	__STDC__
#define	SIOCSIFCOMPAC	_IOW('p', 130, char)
#define	SIOCSIFCOMPPROT	_IOW('p', 131, char)
#define	SIOCSIFMRU	_IOW('p', 132, int)	/* set max receive unit */
#define	SIOCGIFMRU	_IOR('p', 133, int)	/* get max receive unit */
#define	SIOCGIFASYNCMAP	_IOR('p', 134, u_int32_t) /* get transmit async map */
#define	SIOCSIFASYNCMAP	_IOW('p', 135, u_int32_t) /* set transmit async map */
#define	SIOCGETU	_IOR('p', 136, int)	/* get unit number */
#define	SIOCSIFVJCOMP	_IOW('p', 137, char)	/* enable/disable VJ comp */
#define	SIOCGIFDEBUG	_IOR('p', 138, int)	/* get debug flags */
#define	SIOCSIFDEBUG	_IOW('p', 139, int)	/* set debug flags */
#define	SIOCGIFRASYNCMAP _IOR('p', 140, u_int32_t) /* get receive async map */
#define	SIOCSIFRASYNCMAP _IOW('p', 141, u_int32_t) /* set receive async map */
#define	SIOCGIFXASYNCMAP _IOR('p', 142, ext_accm)  /* get extended xmit map */
#define	SIOCSIFXASYNCMAP _IOW('p', 143, ext_accm)  /* set extended xmit map */
#define	SIOCSETU	_IOW('p', 144, int)	/* set unit number */
#define SIOCSETNPMODE	_IOW('p', 145, struct npioctl)	/* set NP mode */
#define SIOCGETNPMODE	_IOWR('p', 146, struct npioctl)	/* get NP mode */
#define SIOCGETSTATS	_IOR('p', 147, struct ppp_stats)
#define SIOCGIFCOMP	_IOR('p', 148, int)	/* get CCP kernel flags */
#define SIOCSIFCOMP	_IOW('p', 149, int)	/* set CCP closed/open/up */
#define SIOCSCOMPRESS	_IOW('p', 150, struct ppp_option_data)

#else
/* traditional C compiler */
#define	SIOCSIFCOMPAC	_IOW(p, 130, char)
#define	SIOCSIFCOMPPROT	_IOW(p, 131, char)
#define	SIOCSIFMRU	_IOW(p, 132, int)	/* set max receive unit */
#define	SIOCGIFMRU	_IOR(p, 133, int)	/* get max receive unit */
#define	SIOCGIFASYNCMAP	_IOR(p, 134, u_int32_t)	/* get transmit async map */
#define	SIOCSIFASYNCMAP	_IOW(p, 135, u_int32_t)	/* set transmit async map */
#define	SIOCGETU	_IOR(p, 136, int)	/* get unit number */
#define	SIOCSIFVJCOMP	_IOW(p, 137, char)	/* enable/disable VJ comp */
#define	SIOCGIFDEBUG	_IOR(p, 138, int)	/* get debug flags */
#define	SIOCSIFDEBUG	_IOW(p, 139, int)	/* set debug flags */
#define	SIOCGIFRASYNCMAP _IOR(p, 140, u_int32_t) /* get receive async map */
#define	SIOCSIFRASYNCMAP _IOW(p, 141, u_int32_t) /* set receive async map */
#define	SIOCGIFXASYNCMAP _IOR(p, 142, ext_accm) /* get extended xmit map */
#define	SIOCSIFXASYNCMAP _IOW(p, 143, ext_accm) /* set extended xmit map */
#define	SIOCSETU	_IOW(p, 144, int)	/* set unit number */
#define SIOCSETNPMODE	_IOW(p, 145, struct npioctl)	/* set NP mode */
#define SIOCGETNPMODE	_IOWR(p, 146, struct npioctl)	/* get NP mode */
#define SIOCGETSTATS	_IOR(p, 147, struct ppp_stats)
#define SIOCGIFCOMP	_IOR(p, 148, int)	/* get CCP kernel flags */
#define SIOCSIFCOMP	_IOW(p, 149, int)	/* set CCP closed/open/up */
#define SIOCSCOMPRESS	_IOW(p, 150, struct ppp_option_data)
#endif

/*
 * Note on SIOCSIFVJCOMP: the parameter is now encoded as follows.
 * Bit 0 = overall VJ enable, bit 1 = don't compress connection ID,
 * bit 2 = receiver rejects VJ compression,
 * bits 4--7 = maximum slot ID (0 => use default (15)).
 */

/* Bits for SIOCGIFDEBUG */
#define PAI_FLAGS_B7_0		0x100
#define PAI_FLAGS_B7_1		0x200
#define PAI_FLAGS_PAR_EVEN	0x400
#define PAI_FLAGS_PAR_ODD	0x800
#define PAI_FLAGS_HIBITS	0xF00

/* defines for streams modules */
#define       IF_INPUT_ERROR  0xe1
#define       IF_OUTPUT_ERROR 0xe2

#define       ALLOCBSIZE      64              /* how big of a buffer block to
allocate for each chunk of the input chain */

#ifndef __P
#ifdef __STDC__
#define __P(x)	x
#else
#define __P(x)	()
#endif
#endif
