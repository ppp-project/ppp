#ifndef _LINUX_PPP_H
#define _LINUX_PPP_H

/* definitions for kernel PPP module
   Michael Callahan <callahan@maths.ox.ac.uk>
   Nov. 4 1993 */

/* $Id: ppp.h,v 1.3 1994/05/27 00:59:24 paulus Exp $ */

/* how many PPP units? */
#define PPP_NRUNIT     4

#define PPP_VERSION  "0.2.7"

/* line discipline number */
#define N_PPP	       3

/* Extended asyncmap - allows any character to be escaped. */
typedef u_long	ext_accm[8];

/* Magic value for the ppp structure */
#define PPP_MAGIC 0x5002

#define	PPPIOCGFLAGS	 0x5490	/* get configuration flags */
#define	PPPIOCSFLAGS	 0x5491	/* set configuration flags */
#define	PPPIOCGASYNCMAP	 0x5492	/* get async map */
#define	PPPIOCSASYNCMAP	 0x5493	/* set async map */
#define	PPPIOCGUNIT	 0x5494	/* get ppp unit number */
#define PPPIOCSINPSIG	 0x5495	/* set input ready signal */
#define PPPIOCSDEBUG	 0x5497	/* set debug level */
#define PPPIOCGDEBUG	 0x5498	/* get debug level */
#define PPPIOCGSTAT	 0x5499	/* read PPP statistic information */
#define PPPIOCGTIME	 0x549A	/* read time delta information */
#define	PPPIOCGXASYNCMAP 0x549B	/* get async table */
#define	PPPIOCSXASYNCMAP 0x549C	/* set async table */
#define PPPIOCSMRU	 0x549D	/* set receive unit size for PPP */
#define PPPIOCRASYNCMAP	 0x549E	/* set receive async map */
#define PPPIOCSMAXCID    0x549F /* set the maximum compression slot id */

/* special characters in the framing protocol */
#define	PPP_ALLSTATIONS	0xff	/* All-Stations broadcast address */
#define	PPP_UI		0x03	/* Unnumbered Information */
#define PPP_FLAG	0x7E	/* frame delimiter -- marks frame boundaries */
#define PPP_ADDRESS	0xFF	/* first character of frame   <--  (may be   */
#define PPP_CONTROL	0x03	/* second character of frame  <-- compressed)*/
#define	PPP_TRANS	0x20	/* Asynchronous transparency modifier */
#define PPP_ESC		0x7d	/* escape charecter -- next character is
				   data, and the PPP_TRANS bit should be
				   toggled. PPP_ESC PPP_FLAG is illegal */

/* protocol numbers */
#define PROTO_IP       0x0021
#define PROTO_VJCOMP   0x002d
#define PROTO_VJUNCOMP 0x002f

/* FCS support */
#define PPP_FCS_INIT   0xffff
#define PPP_FCS_GOOD   0xf0b8

/* initial MTU */
#define PPP_MTU	       1500

/* initial MRU */
#define PPP_MRU	       PPP_MTU

/* flags */
#define SC_COMP_PROT	0x00000001	/* protocol compression (output) */
#define SC_COMP_AC	0x00000002	/* header compression (output) */
#define	SC_COMP_TCP	0x00000004	/* TCP (VJ) compression (output) */
#define SC_NO_TCP_CCID	0x00000008	/* disable VJ connection-id comp. */
#define SC_REJ_COMP_AC	0x00000010	/* reject adrs/ctrl comp. on input */
#define SC_REJ_COMP_TCP	0x00000020	/* reject TCP (VJ) comp. on input */
#define SC_ENABLE_IP	0x00000100	/* IP packets may be exchanged */
#define SC_IP_DOWN	0x00000200	/* give ip frames to pppd */
#define SC_IP_FLUSH	0x00000400	/* "next time" flag for IP_DOWN */
#define SC_DEBUG	0x00010000	/* enable debug messages */
#define SC_LOG_INPKT	0x00020000	/* log contents of good pkts recvd */
#define SC_LOG_OUTPKT	0x00040000	/* log contents of pkts sent */
#define SC_LOG_RAWIN	0x00080000	/* log all chars received */
#define SC_LOG_FLUSH	0x00100000	/* log all chars flushed */

/* Flag bits to determine state of input characters */
#define SC_RCV_B7_0	0x01000000	/* have rcvd char with bit 7 = 0 */
#define SC_RCV_B7_1	0x02000000	/* have rcvd char with bit 7 = 0 */
#define SC_RCV_EVNP	0x04000000	/* have rcvd char with even parity */
#define SC_RCV_ODDP	0x08000000	/* have rcvd char with odd parity */

#define	SC_MASK		0x0fffffff	/* bits that user can change */

/* flag for doing transmitter lockout */
#define SC_XMIT_BUSY	0x10000000	/* ppp_write_wakeup is active */

/*
 * This is the format of the data buffer of a LQP packet. The packet data
 * is sent/received to the peer.
 */

struct ppp_lqp_packet_hdr {
  unsigned long		LastOutLQRs;	/* Copied from PeerOutLQRs	 */
  unsigned long		LastOutPackets; /* Copied from PeerOutPackets	 */
  unsigned long		LastOutOctets;	/* Copied from PeerOutOctets	 */
  unsigned long		PeerInLQRs;	/* Copied from SavedInLQRs	 */
  unsigned long		PeerInPackets;	/* Copied from SavedInPackets	 */
  unsigned long		PeerInDiscards; /* Copied from SavedInDiscards	 */
  unsigned long		PeerInErrors;	/* Copied from SavedInErrors	 */
  unsigned long		PeerInOctets;	/* Copeid from SavedInOctets	 */
  unsigned long		PeerOutLQRs;	/* Copied from OutLQRs, plus 1	 */
  unsigned long		PeerOutPackets; /* Current ifOutUniPackets, + 1	 */
  unsigned long		PeerOutOctets;	/* Current ifOutOctets + LQR	 */
  };

/*
 * This data is not sent to the remote. It is updated by the driver when
 * a packet is received.
 */

struct ppp_lqp_packet_trailer {
  unsigned long		SaveInLQRs;	/* Current InLQRs on receiption	 */
  unsigned long		SaveInPackets;	/* Current ifInUniPackets	 */
  unsigned long		SaveInDiscards; /* Current ifInDiscards		 */
  unsigned long		SaveInErrors;	/* Current ifInErrors		 */
  unsigned long		SaveInOctets;	/* Current ifInOctects		 */
};

/*
 * PPP LQP packet. The packet is changed by the driver immediately prior
 * to transmission and updated upon receiption with the current values.
 * So, it must be known to the driver as well as the pppd software.
 */

struct ppp_lpq_packet {
  unsigned long			magic;	/* current magic value		 */
  struct ppp_lqp_packet_hdr	hdr;	/* Header fields for structure	 */
  struct ppp_lqp_packet_trailer tail;	/* Trailer fields (not sent)	 */
};

/*
 * PPP interface statistics. (used by LQP / pppstats)
 */

struct ppp_stats {
  unsigned long		rbytes;		/* bytes received		 */
  unsigned long		rcomp;		/* compressed packets received	 */
  unsigned long		runcomp;	/* uncompressed packets received */
  unsigned long		rothers;	/* non-ip frames received	 */
  unsigned long		rerrors;	/* received errors		 */
  unsigned long		roverrun;	/* "buffer overrun" counter	 */
  unsigned long		tossed;		/* packets discarded		 */
  unsigned long		runts;		/* frames too short to process	 */
  unsigned long		rgiants;	/* frames too large to process	 */
  unsigned long		sbytes;		/* bytes sent			 */
  unsigned long		scomp;		/* compressed packets sent	 */
  unsigned long		suncomp;	/* uncompressed packets sent	 */
  unsigned long		sothers;	/* non-ip frames sent		 */
  unsigned long		serrors;	/* transmitter errors		 */
  unsigned long		sbusy;		/* "transmitter busy" counter	 */
};

/*
 * Demand dial fields
 */

struct ppp_ddinfo {
  unsigned long		ip_sjiffies;	/* time when last IP frame sent */
  unsigned long		ip_rjiffies;	/* time when last IP frame recvd*/
  unsigned long		nip_sjiffies;	/* time when last NON-IP sent	*/
  unsigned long		nip_rjiffies;	/* time when last NON-IP recvd	*/
};

#ifdef __KERNEL__

struct ppp {
  int			magic;		/* magic value for structure	*/

  /* Bitmapped flag fields. */
  char			inuse;		/* are we allocated?		*/
  char			sending;	/* "channel busy" indicator	*/
  char			escape;		/* 0x20 if prev char was PPP_ESC*/
  char			toss;		/* toss this frame		*/

  unsigned int		flags;		/* miscellany			*/

  ext_accm		xmit_async_map; /* 1 bit means that given control 
					   character is quoted on output*/

  unsigned long		recv_async_map; /* 1 bit means that given control 
					   character is ignored on input*/
  int			mtu;		/* maximum xmit frame size	*/
  int			mru;		/* maximum receive frame size	*/
  unsigned short	fcs;		/* FCS field of current frame	*/

  /* Various fields. */
  int			line;		/* PPP channel number		*/
  struct tty_struct	*tty;		/* ptr to TTY structure		*/
  struct device		*dev;		/* easy for intr handling	*/
  struct slcompress	*slcomp;	/* for header compression	*/
  unsigned long		last_xmit;	/* time of last transmission	*/

  /* These are pointers to the malloc()ed frame buffers.
     These buffers are used while processing a packet.	If a packet
     has to hang around for the user process to read it, it lingers in
     the user buffers below. */
  unsigned char		*rbuff;		/* receiver buffer		*/
  unsigned char		*xbuff;		/* transmitter buffer		*/
  unsigned char		*cbuff;		/* compression buffer		*/

  /* These are the various pointers into the buffers. */
  unsigned char		*rhead;		/* RECV buffer pointer (head)	*/
  unsigned char		*rend;		/* RECV buffer pointer (end)	*/
  int			rcount;		/* PPP receive counter		*/
  unsigned char		*xhead;		/* XMIT buffer pointer (head)	*/
  unsigned char 	*xtail;		/* XMIT buffer pointer (end) 	*/

  /* Structures for interfacing with the user process. */
#define RBUFSIZE 4000
  unsigned char		*us_rbuff;	/* circular incoming packet buf.*/
  unsigned char		*us_rbuff_end;	/* end of allocated space	*/
  unsigned char		*us_rbuff_head; /* head of waiting packets	*/
  unsigned char		*us_rbuff_tail; /* tail of waiting packets	*/
  unsigned char		us_rbuff_lock;	/* lock: bit 0 head bit 1 tail	*/
  int			inp_sig;	/* input ready signal for pgrp	*/
  int			inp_sig_pid;	/* process to get notified	*/

  /* items to support the select() function */
  struct wait_queue	*write_wait;	/* queue for reading processes	*/
  struct wait_queue	*read_wait;	/* queue for writing processes	*/

  /* PPP interface statistics. */
  struct ppp_stats	stats;		/* statistic information	*/

  /* PPP demand dial information. */
  struct ppp_ddinfo	ddinfo;		/* demand dial information	*/
};

#endif	/* __KERNEL__ */
#endif	/* _LINUX_PPP_H */


