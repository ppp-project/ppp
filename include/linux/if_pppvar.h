/*	From: if_pppvar.h,v 1.2 1995/06/12 11:36:51 paulus Exp */
/*
 * if_pppvar.h - private structures and declarations for PPP.
 *
 * Copyright (c) 1994 The Australian National University.
 * All rights reserved.
 *
 * Permission to use, copy, modify, and distribute this software and its
 * documentation is hereby granted, provided that the above copyright
 * notice appears in all copies.  This software is provided without any
 * warranty, express or implied. The Australian National University
 * makes no representations about the suitability of this software for
 * any purpose.
 *
 * IN NO EVENT SHALL THE AUSTRALIAN NATIONAL UNIVERSITY BE LIABLE TO ANY
 * PARTY FOR DIRECT, INDIRECT, SPECIAL, INCIDENTAL, OR CONSEQUENTIAL DAMAGES
 * ARISING OUT OF THE USE OF THIS SOFTWARE AND ITS DOCUMENTATION, EVEN IF
 * THE AUSTRALIAN NATIONAL UNIVERSITY HAVE BEEN ADVISED OF THE POSSIBILITY
 * OF SUCH DAMAGE.
 *
 * THE AUSTRALIAN NATIONAL UNIVERSITY SPECIFICALLY DISCLAIMS ANY WARRANTIES,
 * INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY
 * AND FITNESS FOR A PARTICULAR PURPOSE.  THE SOFTWARE PROVIDED HEREUNDER IS
 * ON AN "AS IS" BASIS, AND THE AUSTRALIAN NATIONAL UNIVERSITY HAS NO
 * OBLIGATION TO PROVIDE MAINTENANCE, SUPPORT, UPDATES, ENHANCEMENTS,
 * OR MODIFICATIONS.
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

/*
 *  ==FILEVERSION 971001==
 *
 *  NOTE TO MAINTAINERS:
 *     If you modify this file at all, please set the above date.
 *     if_pppvar.h is shipped with a PPP distribution as well as with the kernel;
 *     if everyone increases the FILEVERSION number above, then scripts
 *     can do the right thing when deciding whether to install a new if_pppvar.h
 *     file.  Don't change the format of that line otherwise, so the
 *     installation script can recognize it.
 */

/*
 * Supported network protocols.  These values are used for
 * indexing sc_npmode.
 */

#define NP_IP	0		/* Internet Protocol */
#define NUM_NP	1		/* Number of NPs. */

/*
 * Buffers for the PPP process have the following structure
 */

#define RBUFSIZE  2048		 /* MUST be a power of 2 and be <= 4095 */

struct ppp_buffer {
	__s32		size;		/* Size of the buffer area	*/
        __s32		count;		/* Count of characters in bufr	*/
        __s32		head;		/* index to head of list	*/
        __s32		tail;		/* index to tail of list	*/
        unsigned long	locked;		/* Buffer is being sent		*/
        __s32		type;		/* Type of the buffer		*/
					/* =0, device read buffer	*/
					/* =1, device write buffer	*/
					/* =2, daemon write buffer	*/
					/* =3, daemon read buffer	*/
        __u16		fcs;		/* Frame Check Sequence (CRC)	*/
        __u16		magic;		/* Extra space if needed	*/
};

/* Given a pointer to the ppp_buffer then return base address of buffer */
#define buf_base(buf) ((__u8 *) (&buf[1]))

/*
 * Structure describing each ppp unit.
 */

struct ppp {
	__s32		magic;		/* magic value for structure	*/
	struct ppp	*next;		/* unit with next index		*/

	/* Bitmapped flag fields. */
	unsigned long	inuse;		/* are we allocated?		*/
	__u8		escape;		/* 0x20 if prev char was PPP_ESC*/
	__u8		toss;		/* toss this frame		*/

	__u32		flags;		/* miscellany			*/

	__u32		xmit_async_map[8]; /* 1 bit means that given control 
					   character is quoted on output*/

	__u32		recv_async_map; /* 1 bit means that given control 
					   character is ignored on input*/
	__s32		mtu;		/* maximum xmit frame size	*/
	__s32		mru;		/* maximum receive frame size	*/

	/* Information about the current tty data */
	__s32		line;		/* PPP channel number	*/
	struct tty_struct *tty;		/* ptr to TTY structure	*/
	struct tty_struct *backup_tty;	/* TTY to use if tty gets closed */
	__s32		bytes_sent;	/* Bytes sent on frame	*/
	__s32		bytes_rcvd;	/* Bytes recvd on frame	*/

	/* VJ Header compression data */
	struct slcompress *slcomp;	/* for header compression	*/

	/* Transmission information */
	struct ppp_buffer *xbuf;	/* Buffer currently being sent	*/
	struct ppp_buffer *s1buf;	/* Pointer to daemon buffer	*/
	struct ppp_buffer *s2buf;	/* Pointer to device buffer	*/

	unsigned long	last_xmit;	/* time of last transmission	*/
	unsigned long	last_recv;	/* time last packet received    */

  /* These are pointers to the malloc()ed frame buffers.
     These buffers are used while processing a packet.	If a packet
     has to hang around for the user process to read it, it lingers in
     the user buffers below. */

	struct ppp_buffer *wbuf;	  /* Transmission information	*/
	struct ppp_buffer *tbuf;	  /* daemon transmission buffer	*/
	struct ppp_buffer *rbuf;	  /* Receive information	*/
	struct ppp_buffer *ubuf;	  /* User buffer information	*/
	struct ppp_buffer *cbuf;	  /* compression buffer		*/

	/* Queues for select() functionality */
	struct wait_queue *write_wait;	  /* queue for reading processes */
	struct wait_queue *read_wait;	  /* queue for writing processes */

	/* Statistic information */
	struct pppstat	stats;		  /* statistic information	*/

	/* PPP compression protocol information */
	__u32	sc_bytessent;		  /* count of octets sent */
	__u32	sc_bytesrcvd;		  /* count of octets received */
	enum	NPmode sc_npmode[NUM_NP]; /* what to do with each NP */
	struct	compressor *sc_xcomp;	  /* transmit compressor */
	void	*sc_xc_state;		  /* transmit compressor state */
	struct	compressor *sc_rcomp;	  /* receive decompressor */
	void	*sc_rc_state;		  /* receive decompressor state */
	__s32	 sc_xfer;		  /* PID of reserved PPP table */
	char	name[8];
	struct device	dev;		/* net device structure */
	struct enet_statistics estats;	/* more detailed stats */
};
