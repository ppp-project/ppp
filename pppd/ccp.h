/*
 * ccp.h - Definitions for PPP Compression Control Protocol.
 *
 * $Id: ccp.h,v 1.1 1994/08/11 01:44:32 paulus Exp $
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
    u_short bsd_compress: 1;	/* do BSD Compress? */
    u_short bsd_bits;		/* # bits/code for BSD Compress */
} ccp_options;

#define MIN_BSD_BITS	9
#define MAX_BSD_BITS	15

extern fsm ccp_fsm[];
extern ccp_options ccp_wantoptions[];
extern ccp_options ccp_gotoptions[];
extern ccp_options ccp_allowoptions[];
extern ccp_options ccp_hisoptions[];

void ccp_init __ARGS((int unit));
void ccp_open __ARGS((int unit));
void ccp_close __ARGS((int unit));
void ccp_lowerup __ARGS((int unit));
void ccp_lowerdown __ARGS((int));
void ccp_input __ARGS((int unit, u_char *pkt, int len));
void ccp_protrej __ARGS((int unit));
int  ccp_printpkt __ARGS((u_char *pkt, int len,
			  void (*printer) __ARGS((void *, char *, ...)),
			  void *arg));
void ccp_datainput __ARGS((int unit, u_char *pkt, int len));
