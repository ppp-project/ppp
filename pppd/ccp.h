/*
 * ccp.h - Definitions for PPP Compression Control Protocol.
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
 * $Id: ccp.h,v 1.3 1994/10/18 02:07:33 paulus Exp $
 */

/*
 * Compression algorithms = configuration options
 */
#define CI_BSD_COMPRESS	0x21	/* BSD Compress */

/*
 * Extra codes for CCP.
 */
#define RESETREQ	14
#define RESETACK	15

typedef struct ccp_options {
    u_int bsd_compress: 1;	/* do BSD Compress? */
    u_short bsd_bits;		/* # bits/code for BSD Compress */
} ccp_options;

#define MIN_BSD_BITS	9
#define MAX_BSD_BITS	15

extern fsm ccp_fsm[];
extern ccp_options ccp_wantoptions[];
extern ccp_options ccp_gotoptions[];
extern ccp_options ccp_allowoptions[];
extern ccp_options ccp_hisoptions[];

void ccp_init __P((int unit));
void ccp_open __P((int unit));
void ccp_close __P((int unit));
void ccp_lowerup __P((int unit));
void ccp_lowerdown __P((int));
void ccp_input __P((int unit, u_char *pkt, int len));
void ccp_protrej __P((int unit));
int  ccp_printpkt __P((u_char *pkt, int len,
			  void (*printer) __P((void *, char *, ...)),
			  void *arg));
void ccp_datainput __P((int unit, u_char *pkt, int len));
