/*
  ppp_str.h - streams version include file

  Copyright (C) 1990 Brad K. Clements, All Rights Reserved,
  See copyright statement in NOTES
*/

/*
 * Packet sizes
 */
#define	PPP_MTU		1500	/* Default MTU (size of Info field) */
#define PPP_MAXMRU	65000	/* Largest MRU we allow */

/*
 * Definitions for ioctls.
 */
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

struct ifpppstatsreq {
    char ifr_name[IFNAMSIZ];
    struct ppp_stats stats;
};

struct ifpppcstatsreq {
    char ifr_name[IFNAMSIZ];
    struct ppp_comp_stats stats;
};

/*
 * Ioctl definitions.
 */

#if defined(__STDC__) || defined(__osf__)
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
#define SIOCGIFCOMP	_IOR('p', 148, int)	/* get CCP kernel flags */
#define SIOCSIFCOMP	_IOW('p', 149, int)	/* set CCP closed/open/up */
#define SIOCSCOMPRESS	_IOW('p', 150, struct ppp_option_data)

#define SIOCGPPPSTATS	_IOWR('i', 123, struct ifpppstatsreq)
#define SIOCGPPPCSTATS	_IOWR('i', 124, struct ifpppcstatsreq)

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
#define SIOCGIFCOMP	_IOR(p, 148, int)	/* get CCP kernel flags */
#define SIOCSIFCOMP	_IOW(p, 149, int)	/* set CCP closed/open/up */
#define SIOCSCOMPRESS	_IOW(p, 150, struct ppp_option_data)

#define SIOCGPPPSTATS	_IOWR(i, 123, struct ifpppstatsreq)
#define SIOCGPPPCSTATS	_IOWR(i, 124, struct ifpppcstatsreq)
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

/* Bit definitions for SIOC[GS]IFCOMP. */
#define CCP_ISOPEN	1
#define CCP_ISUP	2
#define CCP_COMP_RUN	4
#define CCP_DECOMP_RUN	8
#define CCP_ERROR	0x10
#define CCP_FATALERROR	0x20

/* defines for streams modules */
#define IF_INPUT_ERROR	0xe1
#define IF_OUTPUT_ERROR	0xe2
#define IF_GET_CSTATS	0xe3
#define IF_CSTATS	0xe4
