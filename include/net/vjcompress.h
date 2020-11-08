/*
 * Definitions for tcp compression routines.
 *
 * $Id: vjcompress.h,v 1.3 1996/05/28 00:55:33 paulus Exp $
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

#ifndef _VJCOMPRESS_H_
#define _VJCOMPRESS_H_

#define MAX_STATES 16		/* must be > 2 and < 256 */
#define MAX_HDR	   128

/*
 * Compressed packet format:
 *
 * The first octet contains the packet type (top 3 bits), TCP
 * 'push' bit, and flags that indicate which of the 4 TCP sequence
 * numbers have changed (bottom 5 bits).  The next octet is a
 * conversation number that associates a saved IP/TCP header with
 * the compressed packet.  The next two octets are the TCP checksum
 * from the original datagram.  The next 0 to 15 octets are
 * sequence number changes, one change per bit set in the header
 * (there may be no changes and there are two special cases where
 * the receiver implicitly knows what changed -- see below).
 * 
 * There are 5 numbers which can change (they are always inserted
 * in the following order): TCP urgent pointer, window,
 * acknowlegement, sequence number and IP ID.  (The urgent pointer
 * is different from the others in that its value is sent, not the
 * change in value.)  Since typical use of SLIP links is biased
 * toward small packets (see comments on MTU/MSS below), changes
 * use a variable length coding with one octet for numbers in the
 * range 1 - 255 and 3 octets (0, MSB, LSB) for numbers in the
 * range 256 - 65535 or 0.  (If the change in sequence number or
 * ack is more than 65535, an uncompressed packet is sent.)
 */

/*
 * Packet types (must not conflict with IP protocol version)
 *
 * The top nibble of the first octet is the packet type.  There are
 * three possible types: IP (not proto TCP or tcp with one of the
 * control flags set); uncompressed TCP (a normal IP/TCP packet but
 * with the 8-bit protocol field replaced by an 8-bit connection id --
 * this type of packet syncs the sender & receiver); and compressed
 * TCP (described above).
 *
 * LSB of 4-bit field is TCP "PUSH" bit (a worthless anachronism) and
 * is logically part of the 4-bit "changes" field that follows.  Top
 * three bits are actual packet type.  For backward compatibility
 * and in the interest of conserving bits, numbers are chosen so the
 * IP protocol version number (4) which normally appears in this nibble
 * means "IP packet".
 */

/* packet types */
#define TYPE_IP 0x40
#define TYPE_UNCOMPRESSED_TCP 0x70
#define TYPE_COMPRESSED_TCP 0x80
#define TYPE_ERROR 0x00

/* Bits in first octet of compressed packet */
#define NEW_C	0x40	/* flag bits for what changed in a packet */
#define NEW_I	0x20
#define NEW_S	0x08
#define NEW_A	0x04
#define NEW_W	0x02
#define NEW_U	0x01

/* reserved, special-case values of above */
#define SPECIAL_I (NEW_S|NEW_W|NEW_U)		/* echoed interactive traffic */
#define SPECIAL_D (NEW_S|NEW_A|NEW_W|NEW_U)	/* unidirectional data */
#define SPECIALS_MASK (NEW_S|NEW_A|NEW_W|NEW_U)

#define TCP_PUSH_BIT 0x10


/*
 * "state" data for each active tcp conversation on the wire.  This is
 * basically a copy of the entire IP/TCP header from the last packet
 * we saw from the conversation together with a small identifier
 * the transmit & receive ends of the line use to locate saved header.
 */
struct cstate {
    struct cstate *cs_next;	/* next most recently used state (xmit only) */
    u_short cs_hlen;		/* size of hdr (receive only) */
    u_char cs_id;		/* connection # associated with this state */
    u_char cs_filler;
    union {
	char csu_hdr[MAX_HDR];
	struct ip csu_ip;	/* ip/tcp hdr from most recent packet */
    } vjcs_u;
};
#define cs_ip vjcs_u.csu_ip
#define cs_hdr vjcs_u.csu_hdr

/*
 * all the state data for one serial line (we need one of these per line).
 */
struct vjcompress {
    struct cstate *last_cs;	/* most recently used tstate */
    u_char last_recv;		/* last rcvd conn. id */
    u_char last_xmit;		/* last sent conn. id */
    u_short flags;
#ifndef VJ_NO_STATS
    struct vjstat stats;
#endif
    struct cstate tstate[MAX_STATES];	/* xmit connection states */
    struct cstate rstate[MAX_STATES];	/* receive connection states */
};

/* flag values */
#define VJF_TOSS 1		/* tossing rcvd frames because of input err */

extern void  vj_compress_init(struct vjcompress *comp, int max_state);
extern u_int vj_compress_tcp(struct ip *ip, u_int mlen,
				struct vjcompress *comp, int compress_cid_flag,
				u_char **vjhdrp);
extern void  vj_uncompress_err(struct vjcompress *comp);
extern int   vj_uncompress_uncomp(u_char *buf, int buflen,
				struct vjcompress *comp);
extern int   vj_uncompress_tcp(u_char *buf, int buflen, int total_len,
				struct vjcompress *comp, u_char **hdrp,
				u_int *hlenp);

#endif /* _VJCOMPRESS_H_ */
