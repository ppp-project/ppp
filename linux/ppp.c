/*
 *  PPP for Linux
 *
 *  ==PPPVERSION 2.1.3==
 *
 *  NOTE TO MAINTAINERS:
 *     If you modify this file at all, increment the last number above.
 *     ppp.c is shipped with a PPP distribution as well as with the kernel;
 *     if everyone increases the PPPVERSION number above, then scripts
 *     can do the right thing when deciding whether to install a new ppp.c
 *     file.  Don't change the format of that line otherwise, so the
 *     installation script can recognize it.
 *
 */

/*
   Sources:

   slip.c

   RFC1331: The Point-to-Point Protocol (PPP) for the Transmission of
   Multi-protocol Datagrams over Point-to-Point Links

   RFC1332: IPCP

   ppp-2.0

   Flags for this module (any combination is acceptable for testing.):

   OPTIMIZE_FLAG_TIME - Number of jiffies to force sending of leading flag
			character. This is normally set to ((HZ * 3) / 2).
			This is 1.5 seconds. If not defined then the leading
			flag is always sent.

   CHECK_CHARACTERS   - Enable the checking on all received characters for
			8 data bits, no parity. This adds a small amount of
			processing for each received character.

   PPP_COMPRESS	      - Enable the PPP compression protocol. This protocol
			is under contention with Motorolla's patent, so use
			with caution.
			
   NEW_SKBUFF	      - Use NET3.020 sk_buff's
*/

/* #define NEW_SKBUFF		1 */
#define OPTIMIZE_FLAG_TIME	((HZ * 3)/2)
#define CHECK_CHARACTERS	1
#define PPP_COMPRESS		1

/* $Id: ppp.c,v 1.5 1995/06/12 11:36:53 paulus Exp $
 * Added dynamic allocation of channels to eliminate
 *   compiled-in limits on the number of channels.
 *
 * Dynamic channel allocation code Copyright 1995 Caldera, Inc.,
 *   released under the GNU General Public License Version 2.
 */

#include <linux/kernel.h>
#include <linux/sched.h>
#include <linux/types.h>
#include <linux/fcntl.h>
#include <linux/interrupt.h>
#include <linux/ptrace.h>
#include <linux/ioport.h>
#include <linux/in.h>
#include <linux/malloc.h>
#include <linux/tty.h>
#include <linux/errno.h>
#include <linux/sched.h>	/* to get the struct task_struct */
#include <linux/string.h>	/* used in new tty drivers */
#include <linux/signal.h>	/* used in new tty drivers */
#include <asm/system.h>
#include <asm/bitops.h>
#include <asm/segment.h>
#include <net/if.h>
#include <net/if_arp.h>
#include <net/if_route.h>
#include <linux/if_ether.h>
#include <linux/netdevice.h>
#include <linux/skbuff.h>
#include <linux/inet.h>
#include <linux/ioctl.h>

#ifdef NEW_SKBUFF
#include <linux/netprotocol.h>
#else
#define skb_data(skb)	((unsigned char *) (skb)->data)
typedef struct sk_buff	sk_buff;
#endif

#include <ip.h>
#include <tcp.h>
#include <linux/if_arp.h>
#include "slhc.h"
#include <net/ppp_defs.h>
#include <linux/socket.h>
#include <net/if_ppp.h>
#include <net/if_pppvar.h>

#ifdef MODULE
#include <linux/module.h>
#include <linux/version.h>
#define STATIC static
#else
#define MOD_INC_USE_COUNT while(0) { }
#define MOD_DEC_USE_COUNT while(0) { }
#endif /* def MODULE */

#ifdef PPP_COMPRESS
#undef   PACKETPTR
#define  PACKETPTR 1
#include <net/ppp-comp.h>
#undef   PACKETPTR

#define bsd_decompress	(*ppp->sc_rcomp->decompress)
#define bsd_compress	(*ppp->sc_xcomp->compress)
#endif

#ifndef PPP_IPX
#define PPP_IPX 0x2b  /* IPX protocol over PPP */
#endif

#ifndef PPP_LQR
#define PPP_LQR 0xc025  /* Link Quality Reporting Protocol */
#endif

/*
 * Local functions
 */

static void ppp_init_ctrl_blk (register struct ppp *);
static void ppp_kick_tty (struct ppp *, struct ppp_buffer *bfr);
static int ppp_doframe (struct ppp *);
static struct ppp *ppp_alloc (void);
static void ppp_print_buffer (const u_char *, u_char *, int);
extern inline void ppp_stuff_char (struct ppp *ppp,
				   register struct ppp_buffer *buf,
				   register u_char chr);
extern inline int lock_buffer (register struct ppp_buffer *buf);
static void ppp_proto_ccp (struct ppp *ppp, u_char *dp, int len, int rcvd);

static int rcv_proto_ip         (struct ppp *, u_short, u_char *, int);
static int rcv_proto_ipx        (struct ppp *, u_short, u_char *, int);
static int rcv_proto_vjc_comp   (struct ppp *, u_short, u_char *, int);
static int rcv_proto_vjc_uncomp (struct ppp *, u_short, u_char *, int);
static int rcv_proto_unknown    (struct ppp *, u_short, u_char *, int);
static int rcv_proto_ccp        (struct ppp *, u_short, u_char *, int);
static int rcv_proto_lqr        (struct ppp *, u_short, u_char *, int);
static void ppp_doframe_lower   (struct ppp *, u_char *, int);
static int ppp_doframe          (struct ppp *);

/*
 * List of compressors we know about.
 * We leave some space so maybe we can modload compressors.
 */

#ifdef PPP_COMPRESS
extern struct compressor ppp_bsd_compress;

struct compressor *ppp_compressors[8] = {
    &ppp_bsd_compress,
    NULL
};
#endif /* PPP_COMPRESS */

#define ins_char(pbuf,c) (buf_base(pbuf) [(pbuf)->count++] = (u_char)(c))

/*
 * The "main" procedure to the ppp device
 */

int ppp_init (struct device *);

/*
 * Network device driver callback routines
 */

static int ppp_dev_open (struct device *);
static int ppp_dev_ioctl (struct device *dev, struct ifreq *ifr, int cmd);
static int ppp_dev_close (struct device *);
static int ppp_dev_xmit (sk_buff *, struct device *);
static struct enet_statistics *ppp_dev_stats (struct device *);

#ifdef NEW_SKBUFF
static int ppp_dev_input (struct protocol *self, struct protocol *lower,
			  sk_buff *skb, void *saddr, void *daddr);
static int ppp_dev_output (struct protocol *self, sk_buff *skb, int type,
			   int subid, void *saddr, void *daddr, void *opt);
static int ppp_dev_getkey(int protocol, int subid, unsigned char *key);
#else
static int ppp_dev_header (u_char *, struct device *, unsigned short,
			   void *, void *, unsigned, sk_buff *);
static int ppp_dev_rebuild (void *, struct device *, unsigned long,
			    sk_buff *);
static unsigned short ppp_dev_type (sk_buff *, struct device *);
#endif

/*
 * TTY callbacks
 */

static int ppp_tty_read (struct tty_struct *, struct file *, u_char *,
			 unsigned int);
static int ppp_tty_write (struct tty_struct *, struct file *, u_char *,
			  unsigned int);
static int ppp_tty_ioctl (struct tty_struct *, struct file *, unsigned int,
			  unsigned long);
static int ppp_tty_select (struct tty_struct *tty, struct inode *inode,
		      struct file *filp, int sel_type, select_table * wait);
static int ppp_tty_open (struct tty_struct *);
static void ppp_tty_close (struct tty_struct *);
static int ppp_tty_room (struct tty_struct *tty);
static void ppp_tty_receive (struct tty_struct *tty, u_char * cp,
			     char *fp, int count);
static void ppp_tty_wakeup (struct tty_struct *tty);

#define PRINTK(p) printk p ;
#define CHECK_PPP(a)  if (!ppp->inuse) { PRINTK ((ppp_warning, __LINE__)) return a;}
#define CHECK_PPP_VOID()  if (!ppp->inuse) { PRINTK ((ppp_warning, __LINE__)) return;}

#define in_xmap(ppp,c)	(ppp->xmit_async_map[(c) >> 5] & (1 << ((c) & 0x1f)))
#define in_rmap(ppp,c)	((((unsigned int) (u_char) (c)) < 0x20) && \
			ppp->recv_async_map & (1 << (c)))

#define bset(p,b)	((p)[(b) >> 5] |= (1 << ((b) & 0x1f)))

#define tty2ppp(tty)	((struct ppp *) (tty->disc_data))
#define dev2ppp(dev)	((struct ppp *) (dev->priv))
#define ppp2tty(ppp)	((struct tty_struct *) ppp->tty)
#define ppp2dev(ppp)	((struct device *) ppp->dev)

struct ppp_hdr {
	unsigned char address;
	unsigned char control;
	unsigned char protocol[2];
};

#define PPP_HARD_HDR_LEN	(sizeof (struct ppp_hdr))

#if 1
typedef struct  ppp_ctrl {
	struct ppp_ctrl *next;		/* Next structure in the list	*/
	char            name [8];	/* Name of the device		*/
	struct ppp      ppp;		/* PPP control table		*/
	struct device   dev;		/* Device information table	*/
} ppp_ctrl_t;

static ppp_ctrl_t *ppp_list = NULL;

#define ctl2ppp(ctl) (struct ppp *)    &ctl->ppp
#define ctl2dev(ctl) (struct device *) &ctl->dev
#undef  PPP_NRUNIT

#else

#define PPP_NRUNIT 4
static struct ppp ppp_ctrl[PPP_NRUNIT];
#undef  dev2ppp
#define dev2ppp(dev)	((struct ppp *) &ppp_ctrl[dev->base_addr])
#endif

/* Buffer types */
#define BUFFER_TYPE_DEV_RD	0  /* ppp read buffer       */
#define BUFFER_TYPE_TTY_WR	1  /* tty write buffer      */
#define BUFFER_TYPE_DEV_WR	2  /* ppp write buffer      */
#define BUFFER_TYPE_TTY_RD	3  /* tty read buffer       */
#define BUFFER_TYPE_VJ		4  /* vj compression buffer */

/* Define this string only once for all macro envocations */
static char ppp_warning[] = KERN_WARNING "PPP: ALERT! not INUSE! %d\n";

static char szVersion[]         = PPP_VERSION;
 
#ifdef NEW_SKBUFF
static struct protocol proto_ppp;
#endif

/*
 * Information for the protocol decoder
 */

typedef int (*pfn_proto)  (struct ppp *, u_short, u_char *, int);

typedef struct ppp_proto_struct {
	int		proto;
	pfn_proto	func;
} ppp_proto_type;

ppp_proto_type proto_list[] = {
	{ PPP_IP,         rcv_proto_ip         },
	{ PPP_IPX,        rcv_proto_ipx        },
	{ PPP_VJC_COMP,   rcv_proto_vjc_comp   },
	{ PPP_VJC_UNCOMP, rcv_proto_vjc_uncomp },
	{ PPP_LQR,        rcv_proto_lqr       },
#ifdef PPP_COMPRESS
	{ PPP_CCP,        rcv_proto_ccp        },
#endif
	{ 0,              rcv_proto_unknown    }  /* !!! MUST BE LAST !!! */
};

/* FCS table from RFC1331 */

static unsigned short fcstab[256] =
{
	0x0000, 0x1189, 0x2312, 0x329b, 0x4624, 0x57ad, 0x6536, 0x74bf,
	0x8c48, 0x9dc1, 0xaf5a, 0xbed3, 0xca6c, 0xdbe5, 0xe97e, 0xf8f7,
	0x1081, 0x0108, 0x3393, 0x221a, 0x56a5, 0x472c, 0x75b7, 0x643e,
	0x9cc9, 0x8d40, 0xbfdb, 0xae52, 0xdaed, 0xcb64, 0xf9ff, 0xe876,
	0x2102, 0x308b, 0x0210, 0x1399, 0x6726, 0x76af, 0x4434, 0x55bd,
	0xad4a, 0xbcc3, 0x8e58, 0x9fd1, 0xeb6e, 0xfae7, 0xc87c, 0xd9f5,
	0x3183, 0x200a, 0x1291, 0x0318, 0x77a7, 0x662e, 0x54b5, 0x453c,
	0xbdcb, 0xac42, 0x9ed9, 0x8f50, 0xfbef, 0xea66, 0xd8fd, 0xc974,
	0x4204, 0x538d, 0x6116, 0x709f, 0x0420, 0x15a9, 0x2732, 0x36bb,
	0xce4c, 0xdfc5, 0xed5e, 0xfcd7, 0x8868, 0x99e1, 0xab7a, 0xbaf3,
	0x5285, 0x430c, 0x7197, 0x601e, 0x14a1, 0x0528, 0x37b3, 0x263a,
	0xdecd, 0xcf44, 0xfddf, 0xec56, 0x98e9, 0x8960, 0xbbfb, 0xaa72,
	0x6306, 0x728f, 0x4014, 0x519d, 0x2522, 0x34ab, 0x0630, 0x17b9,
	0xef4e, 0xfec7, 0xcc5c, 0xddd5, 0xa96a, 0xb8e3, 0x8a78, 0x9bf1,
	0x7387, 0x620e, 0x5095, 0x411c, 0x35a3, 0x242a, 0x16b1, 0x0738,
	0xffcf, 0xee46, 0xdcdd, 0xcd54, 0xb9eb, 0xa862, 0x9af9, 0x8b70,
	0x8408, 0x9581, 0xa71a, 0xb693, 0xc22c, 0xd3a5, 0xe13e, 0xf0b7,
	0x0840, 0x19c9, 0x2b52, 0x3adb, 0x4e64, 0x5fed, 0x6d76, 0x7cff,
	0x9489, 0x8500, 0xb79b, 0xa612, 0xd2ad, 0xc324, 0xf1bf, 0xe036,
	0x18c1, 0x0948, 0x3bd3, 0x2a5a, 0x5ee5, 0x4f6c, 0x7df7, 0x6c7e,
	0xa50a, 0xb483, 0x8618, 0x9791, 0xe32e, 0xf2a7, 0xc03c, 0xd1b5,
	0x2942, 0x38cb, 0x0a50, 0x1bd9, 0x6f66, 0x7eef, 0x4c74, 0x5dfd,
	0xb58b, 0xa402, 0x9699, 0x8710, 0xf3af, 0xe226, 0xd0bd, 0xc134,
	0x39c3, 0x284a, 0x1ad1, 0x0b58, 0x7fe7, 0x6e6e, 0x5cf5, 0x4d7c,
	0xc60c, 0xd785, 0xe51e, 0xf497, 0x8028, 0x91a1, 0xa33a, 0xb2b3,
	0x4a44, 0x5bcd, 0x6956, 0x78df, 0x0c60, 0x1de9, 0x2f72, 0x3efb,
	0xd68d, 0xc704, 0xf59f, 0xe416, 0x90a9, 0x8120, 0xb3bb, 0xa232,
	0x5ac5, 0x4b4c, 0x79d7, 0x685e, 0x1ce1, 0x0d68, 0x3ff3, 0x2e7a,
	0xe70e, 0xf687, 0xc41c, 0xd595, 0xa12a, 0xb0a3, 0x8238, 0x93b1,
	0x6b46, 0x7acf, 0x4854, 0x59dd, 0x2d62, 0x3ceb, 0x0e70, 0x1ff9,
	0xf78f, 0xe606, 0xd49d, 0xc514, 0xb1ab, 0xa022, 0x92b9, 0x8330,
	0x7bc7, 0x6a4e, 0x58d5, 0x495c, 0x3de3, 0x2c6a, 0x1ef1, 0x0f78
};

#ifdef CHECK_CHARACTERS
static unsigned paritytab[8] =
{
	0x96696996, 0x69969669, 0x69969669, 0x96696996,
	0x69969669, 0x96696996, 0x96696996, 0x69969669
};
#endif

/* local function to store a value into the LQR frame */
extern inline u_char * store_long (register u_char *p, register int value) {
	*p++ = (u_char) (value >> 24);
	*p++ = (u_char) (value >> 16);
	*p++ = (u_char) (value >>  8);
	*p++ = (u_char) value;
	return p;
}

/*************************************************************
 * INITIALIZATION
 *************************************************************/

/* This procedure is called once and once only to define who we are to
 * the operating system and the various procedures that it may use in
 * accessing the ppp protocol.
 */

static int
ppp_first_time (void)
{
	static struct tty_ldisc	ppp_ldisc;
	int    status;

#ifdef PPP_NRUNIT
#define PPP_UNITS3(x) #x
#define PPP_UNITS2(x) PPP_UNITS3(x)
#define PPP_UNITS1(x) PPP_UNITS2(x)
#define PPP_UNITS   "(" PPP_UNITS1(PPP_NRUNIT) " devices)"
#else
#define PPP_UNITS   "(dynamic channel allocation)"
#endif
	printk (KERN_INFO
		"PPP: version %s " PPP_UNITS
#ifdef NEW_SKBUFF
		" NEW_SKBUFF"
#endif
		"\n", szVersion);
#undef PPP_UNITS
#undef PPP_UNITS1
#undef PPP_UNITS2
#undef PPP_UNITS3

	printk (KERN_INFO
		"TCP compression code copyright 1989 Regents of the "
		"University of California\n");
	
#ifndef PPP_NRUNIT
	printk (KERN_INFO
		"PPP Dynamic channel allocation code copyright 1995 "
		"Caldera, Inc.\n");
#endif

/*
 * Register the protocol for the device
 */

#ifdef NEW_SKBUFF  
	memset (&proto_ppp, 0, sizeof (proto_ppp));

	proto_ppp.name          = "PPP";
	proto_ppp.output        = ppp_dev_output;
	proto_ppp.input         = ppp_dev_input;
	proto_ppp.bh_input      = ppp_dev_input;
	proto_ppp.control_event = default_protocol_control;
	proto_ppp.get_binding   = ppp_dev_getkey;
	proto_ppp.header_space  = 0; /* PPP_HARD_HDR_LEN; */

	protocol_register(&proto_ppp);
#endif

/*
 * Register the tty dicipline
 */	
	(void) memset (&ppp_ldisc, 0, sizeof (ppp_ldisc));
	ppp_ldisc.magic		= TTY_LDISC_MAGIC;
	ppp_ldisc.open		= ppp_tty_open;
	ppp_ldisc.close		= ppp_tty_close;
	ppp_ldisc.read		= ppp_tty_read;
	ppp_ldisc.write		= ppp_tty_write;
	ppp_ldisc.ioctl		= ppp_tty_ioctl;
	ppp_ldisc.select	= ppp_tty_select;
	ppp_ldisc.receive_room	= ppp_tty_room;
	ppp_ldisc.receive_buf	= ppp_tty_receive;
	ppp_ldisc.write_wakeup	= ppp_tty_wakeup;
	
	status = tty_register_ldisc (N_PPP, &ppp_ldisc);
	if (status == 0)
		printk (KERN_INFO "PPP line discipline registered.\n");
	else
		printk (KERN_ERR "error registering line discipline: %d\n",
			status);
	return status;
}

/*************************************************************
 * INITIALIZATION
 *************************************************************/

/* called when the device is actually created */

static int
ppp_init_dev (struct device *dev)
{
	int    indx;
#ifdef NEW_SKBUFF  
	dev->default_protocol = &proto_ppp;	/* Our protocol layer is PPP */
#else
	dev->hard_header      = ppp_dev_header;
	dev->type_trans       = ppp_dev_type;
	dev->rebuild_header   = ppp_dev_rebuild;
	dev->hard_header_len  = 0; /* PPP_HARD_HDR_LEN; */
#endif

	/* device INFO */
	dev->mtu              = PPP_MTU;
	dev->hard_start_xmit  = ppp_dev_xmit;
	dev->open             = ppp_dev_open;
	dev->stop             = ppp_dev_close;
	dev->get_stats        = ppp_dev_stats;
	dev->do_ioctl         = ppp_dev_ioctl;
	dev->addr_len         = 0;
	dev->type             = ARPHRD_PPP;

	for (indx = 0; indx < DEV_NUMBUFFS; indx++)
		skb_queue_head_init (&dev->buffs[indx]);

	/* New-style flags */
	dev->flags      = IFF_POINTOPOINT;
	dev->family     = AF_INET;
	dev->pa_addr    = 0;
	dev->pa_brdaddr = 0;
	dev->pa_mask    = 0;
	dev->pa_alen    = sizeof (unsigned long);

	return 0;
}

/*
 * Local procedure to initialize the ppp structure
 */

static void
ppp_init_ctrl_blk (register struct ppp *ppp)
{
	ppp->magic  = PPP_MAGIC;
	ppp->toss   = 0xE0;
	ppp->escape = 0;

	ppp->flags  = 0;
	ppp->mtu    = PPP_MTU;
	ppp->mru    = PPP_MRU;

	memset (ppp->xmit_async_map, 0, sizeof (ppp->xmit_async_map));
	ppp->xmit_async_map[0] = 0xffffffff;
	ppp->xmit_async_map[3] = 0x60000000;
	ppp->recv_async_map    = 0x00000000;

	ppp->rbuf       = NULL;
	ppp->wbuf       = NULL;
	ppp->ubuf       = NULL;
	ppp->cbuf       = NULL;
	ppp->slcomp     = NULL;
	ppp->read_wait  = NULL;
	ppp->write_wait = NULL;

#ifdef OPTIMIZE_FLAG_TIME   /* ensure flag will always be sent first time */
	ppp->last_xmit = jiffies - OPTIMIZE_FLAG_TIME;
#else
	ppp->last_xmit = 0;
#endif

	/* clear statistics */
	memset (&ppp->stats, '\0', sizeof (struct pppstat));

	/* Reset the demand dial information */
	ppp->ddinfo.ip_sjiffies  =
	ppp->ddinfo.ip_rjiffies  =
	ppp->ddinfo.nip_sjiffies =
	ppp->ddinfo.nip_rjiffies = jiffies;

#ifdef PPP_COMPRESS
	ppp->sc_xc_state =
	ppp->sc_rc_state = NULL;
#endif /* PPP_COMPRESS */
}

/* called at boot/load time for each ppp device defined in the kernel */

#ifndef MODULE
int
ppp_init (struct device *dev)
{
	static int first_time = 1;
	int    answer = 0;

	if (first_time) {
		first_time = 0;
		answer     = ppp_first_time();
	}
/*
 * Un-register the devices defined at the start of the system. They will
 * be added when they are needed again. The first device just gets us into
 * this code to register the handlers.
 */
#if 1
	unregister_netdev (dev);
#else
	ppp_init_dev (dev);
	ppp_init_ctrl_blk (dev2ppp (dev));
	dev2ppp (dev) -> inuse = 0;
	dev2ppp (dev) -> dev   = dev;
#endif
	return answer;
}
#endif

/*
 * Routine to allocate a buffer for later use by the driver.
 */

static struct ppp_buffer *
ppp_alloc_buf (int size, int type)
{
	struct ppp_buffer *buf;

	buf = (struct ppp_buffer *) kmalloc (size + sizeof (struct ppp_buffer),
					     GFP_ATOMIC);

	if (buf != NULL) {
		buf->size   = size - 1;	/* Mask for the buffer size */
		buf->type   = type;
		buf->locked = 0;
		buf->count  = 0;
		buf->head   = 0;
		buf->tail   = 0;
		buf->fcs    = PPP_INITFCS;
	}
	return (buf);
}

/*
 * Routine to release the allocated buffer.
 */

static void
ppp_free_buf (struct ppp_buffer *ptr)
{
	if (ptr != NULL)
		kfree (ptr);
}

/*
 * Lock the indicated transmit buffer
 */

extern inline int
lock_buffer (register struct ppp_buffer *buf)
{
	register int state;
	int flags;
/*
 * Save the current state and if free then set it to the "busy" state
 */
	save_flags (flags);
	cli ();
	state = buf->locked;
	if (state == 0)
		buf->locked = 2;
/*
 * Restore the flags and return the previous state. 0 implies success.
 */
	restore_flags (flags);
	return (state);
}

/*
 * MTU has been changed by the IP layer. Unfortunately we are not told
 * about this, but we spot it ourselves and fix things up. We could be
 * in an upcall from the tty driver, or in an ip packet queue.
 */

static int
ppp_changedmtu (struct ppp *ppp, int new_mtu, int new_mru)
{
	struct device *dev;

	struct ppp_buffer *new_rbuf;
	struct ppp_buffer *new_wbuf;
	struct ppp_buffer *new_cbuf;
	struct ppp_buffer *new_tbuf;

	struct ppp_buffer *old_rbuf;
	struct ppp_buffer *old_wbuf;
	struct ppp_buffer *old_cbuf;
	struct ppp_buffer *old_tbuf;

	int mtu, mru;
/*
 *  Allocate the buffer from the kernel for the data
 */
	dev = ppp2dev (ppp);
	mru = new_mru;
	/* allow for possible escapement of every character */
	mtu = (new_mtu * 2) + 20;

	/* RFC 1331, section 7.2 says the minimum value is 1500 bytes */
	if (mru < PPP_MRU)
		mru = PPP_MRU;

	mru += 10;
	
	if (ppp->flags & SC_DEBUG)
		printk (KERN_INFO "ppp: channel %s mtu = %d, mru = %d\n",
			dev->name, new_mtu, new_mru);

	new_wbuf = ppp_alloc_buf (mtu+PPP_HARD_HDR_LEN,	BUFFER_TYPE_DEV_WR);
	new_tbuf = ppp_alloc_buf ((PPP_MTU * 2) + 24,	BUFFER_TYPE_TTY_WR);
	new_rbuf = ppp_alloc_buf (mru + 84,		BUFFER_TYPE_DEV_RD);
	new_cbuf = ppp_alloc_buf (mru+PPP_HARD_HDR_LEN,	BUFFER_TYPE_VJ);
/*
 *  If the buffers failed to allocate then complain and release the partial
 *  allocations.
 */
	if (new_wbuf == NULL || new_tbuf == NULL ||
	    new_rbuf == NULL || new_cbuf == NULL) {
		if (ppp->flags & SC_DEBUG)
			printk (KERN_ERR
				"ppp: failed to allocate new buffers\n");

		ppp_free_buf (new_wbuf);
		ppp_free_buf (new_tbuf);
		ppp_free_buf (new_rbuf);
		ppp_free_buf (new_cbuf);
		return 0;
	}
/*
 *  Update the pointers to the new buffer structures.
 */
	cli ();
	old_wbuf = ppp->wbuf;
	old_rbuf = ppp->rbuf;
	old_cbuf = ppp->cbuf;
	old_tbuf = ppp->tbuf;

	ppp->wbuf = new_wbuf;
	ppp->rbuf = new_rbuf;
	ppp->cbuf = new_cbuf;
	ppp->tbuf = new_tbuf;

	ppp->rbuf->size -= 80;  /* reserve space for vj header expansion */

	dev->mem_start  = (unsigned long) buf_base (new_wbuf);
	dev->mem_end    = (unsigned long) (dev->mem_start + mtu);
	dev->rmem_start = (unsigned long) buf_base (new_rbuf);
	dev->rmem_end   = (unsigned long) (dev->rmem_start + mru);
/*
 *  Update the parameters for the new buffer sizes
 */
	ppp->toss   = 0xE0;	/* To ignore characters until new FLAG */
	ppp->escape = 0;	/* No pending escape character */

	dev->mtu    =
	ppp->mtu    = new_mtu;
	ppp->mru    = new_mru;

	ppp->s1buf  = NULL;
	ppp->s2buf  = NULL;
	ppp->xbuf   = NULL;

	ppp->tty->flags &= ~TTY_DO_WRITE_WAKEUP;
	ppp->flags      &= ~SC_XMIT_BUSY;

	sti ();
/*
 *  Release old buffer pointers
 */
	ppp_free_buf (old_rbuf);
	ppp_free_buf (old_wbuf);
	ppp_free_buf (old_cbuf);
	ppp_free_buf (old_tbuf);
	return 1;
}

/*
 * CCP is down; free (de)compressor state if necessary.
 */

#ifdef PPP_COMPRESS
static void
ppp_ccp_closed (struct ppp *ppp)
{
    if (ppp->sc_xc_state) {
	(*ppp->sc_xcomp->comp_free) (ppp->sc_xc_state);
	ppp->sc_xc_state = NULL;
    }

    if (ppp->sc_rc_state) {
	(*ppp->sc_rcomp->decomp_free) (ppp->sc_rc_state);
	ppp->sc_rc_state = NULL;
    }
}
#endif /* PPP_COMPRESS */

/*
 * Called to release all of the information in the current PPP structure.
 *
 * It is called when the ppp device goes down or if it is unable to go
 * up.
 */

static void
ppp_release (struct ppp *ppp)
{
	struct tty_struct *tty;
	struct device *dev;

	tty = ppp2tty (ppp);
	dev = ppp2dev (ppp);

#ifdef PPP_COMPRESS
	ppp_ccp_closed (ppp);
	ppp->sc_xc_state =
	ppp->sc_rc_state = NULL;
#endif /* PPP_COMPRESS */

	if (tty != NULL && tty->disc_data == ppp)
		tty->disc_data = NULL;	/* Break the tty->ppp link */

	if (dev && dev->flags & IFF_UP) {
		dev_close (dev); /* close the device properly */
		dev->flags = 0;  /* prevent recursion */
	}

	ppp_free_buf (ppp->rbuf);
	ppp_free_buf (ppp->wbuf);
	ppp_free_buf (ppp->cbuf);
	ppp_free_buf (ppp->ubuf);
	ppp_free_buf (ppp->tbuf);

	ppp->rbuf  =
	ppp->wbuf  =
	ppp->cbuf  =
	ppp->tbuf  =
	ppp->xbuf  =
	ppp->s1buf =
	ppp->s2buf =
	ppp->ubuf  = NULL;

	if (ppp->slcomp) {
		slhc_free (ppp->slcomp);
		ppp->slcomp = NULL;
	}

	ppp->inuse = 0;
	ppp->tty   = NULL;
}

/*
 * Device callback.
 *
 * Called when the PPP device goes down in response to an ifconfig request.
 */

static void
ppp_tty_close (struct tty_struct *tty)
{
	struct ppp *ppp = tty2ppp (tty);

	if (ppp == NULL || ppp->magic != PPP_MAGIC) {
		if (ppp->flags & SC_DEBUG)
			printk (KERN_WARNING
				"ppp: trying to close unopened tty!\n");
	} else {
		CHECK_PPP_VOID();
		if (ppp->flags & SC_DEBUG)
			printk (KERN_INFO "ppp: channel %s closing.\n",
				ppp2dev(ppp) -> name);
		ppp_release (ppp);
		MOD_DEC_USE_COUNT;
	}
}

/*
 * TTY callback.
 *
 * Called when the tty discipline is switched to PPP.
 */

static int
ppp_tty_open (struct tty_struct *tty)
{
	struct ppp *ppp = tty2ppp (tty);
/*
 * There should not be an existing table for this slot.
 */
	if (ppp) {
		if (ppp->flags & SC_DEBUG)
			printk (KERN_ERR
			"ppp_tty_open: gack! tty already associated to %s!\n",
			ppp->magic == PPP_MAGIC ? ppp2dev(ppp)->name
						: "unknown");
		return -EEXIST;
	}
/*
 * Allocate the structure from the system
 */
	ppp = ppp_alloc ();
	if (ppp == NULL) {
		if (ppp->flags & SC_DEBUG)
			printk (KERN_ERR
			"ppp_tty_open: couldn't allocate ppp channel\n");
		return -ENFILE;
	}
/*
 * Initialize the control block
 */
	ppp_init_ctrl_blk (ppp);
	ppp->tty       = tty;
	tty->disc_data = ppp;
/*
 * Flush any pending characters in the driver and discipline.
 */
	if (tty->ldisc.flush_buffer)
		tty->ldisc.flush_buffer (tty);

	if (tty->driver.flush_buffer)
		tty->driver.flush_buffer (tty);
/*
 * Allocate space for the default VJ header compression slots (16)
 */
	ppp->slcomp = slhc_init (16, 16);
	if (ppp->slcomp == NULL) {
		if (ppp->flags & SC_DEBUG)
			printk (KERN_ERR
			"ppp_tty_open: no space for compression buffers!\n");
		ppp_release (ppp);
		return -ENOMEM;
	}
/*
 * Allocate space for the MTU and MRU buffers
 */
	if (ppp_changedmtu (ppp, ppp2dev(ppp)->mtu, ppp->mru) == 0) {
		ppp_release (ppp);
		return -ENOMEM;
	}
/*
 * Allocate space for a user level buffer
 */
	ppp->ubuf = ppp_alloc_buf (RBUFSIZE, BUFFER_TYPE_TTY_RD);
	if (ppp->ubuf == NULL) {
		if (ppp->flags & SC_DEBUG)
			printk (KERN_ERR
		       "ppp_tty_open: no space for user receive buffer\n");
		ppp_release (ppp);
		return -ENOMEM;
	}

	if (ppp->flags & SC_DEBUG)
		printk (KERN_INFO "ppp: channel %s open\n",
			ppp2dev(ppp)->name);

	MOD_INC_USE_COUNT;
	return (ppp->line);
}

/*
 * Local function to send the next portion of the buffer.
 *
 * Called by the tty driver's tty_wakeup function should it be entered
 * because the partial buffer was transmitted.
 *
 * Called by kick_tty to send the initial portion of the buffer.
 *
 * Completion processing of the buffer transmission is handled here.
 */

static void
ppp_tty_wakeup_code (struct ppp *ppp, struct tty_struct *tty,
		     struct ppp_buffer *xbuf)
{
	register int count, actual;
/*
 * Prevent re-entrancy by ensuring that this routine is called only once.
 */
	cli ();
	if (ppp->flags & SC_XMIT_BUSY) {
		sti ();
		return;
	}
	ppp->flags |= SC_XMIT_BUSY;
	sti ();
/*
 * Send the next block of data to the modem
 */
	count = xbuf->count - xbuf->tail;
	actual = tty->driver.write (tty, 0,
				    buf_base (xbuf) + xbuf->tail, count);
/*
 * Terminate transmission of any block which may have an error.
 * This could occur should the carrier drop.
 */
	if (actual < 0) {
	        ppp->stats.ppp_oerrors++;
		actual = count;
	} else
		ppp->bytes_sent += actual;
/*
 * If the buffer has been transmitted then clear the indicators.
 */
	xbuf->tail += actual;
	if (actual == count) {
		xbuf = NULL;
		ppp->flags &= ~SC_XMIT_BUSY;
/*
 * Complete the transmission on the current buffer.
 */
		xbuf = ppp->xbuf;
		if (xbuf != NULL) {
			tty->flags  &= ~TTY_DO_WRITE_WAKEUP;
			xbuf->locked = 0;
			ppp->xbuf    = NULL;
/*
 * If the completed buffer came from the device write, then complete the
 * transmission block.
 */
			if (ppp2dev (ppp) -> flags & IFF_UP) {
			        ppp2dev (ppp)->tbusy = 0;
				mark_bh (NET_BH);
				dev_tint (ppp2dev (ppp));
			}
/*
 * Wake up the transmission queue for all completion events.
 */
			wake_up_interruptible (&ppp->write_wait);
/*
 * Look at the priorities. Choose a daemon write over the device driver.
 */
			xbuf = ppp->s1buf;
			ppp->s1buf = NULL;
			if (xbuf == NULL) {
				xbuf = ppp->s2buf;
				ppp->s2buf = NULL;
			}
/*
 * If there is a pending buffer then transmit it now.
 */
			if (xbuf != NULL) {
				ppp->flags &= ~SC_XMIT_BUSY;
				ppp_kick_tty (ppp, xbuf);
			}
		}
	}
/*
 * Clear the re-entry flag
 */
	ppp->flags &= ~SC_XMIT_BUSY;
}

/*
 * This function is called by the tty driver when the transmit buffer has
 * additional space. It is used by the ppp code to continue to transmit
 * the current buffer should the buffer have been partially sent.
 *
 * In addition, it is used to send the first part of the buffer since the
 * logic and the inter-locking would be identical.
 */

static void
ppp_tty_wakeup (struct tty_struct *tty)
{
	struct ppp_buffer *xbuf;
	struct ppp *ppp = tty2ppp (tty);

	if (!ppp || ppp->magic != PPP_MAGIC) {
		if (ppp->flags & SC_DEBUG)
			printk (KERN_DEBUG "PPP: write_wakeup called but "
				"couldn't find PPP struct.\n");
		return;
	}
/*
 * Ensure that there is a transmission pending. Clear the re-entry flag if
 * there is no pending buffer. Otherwise, send the buffer.
 */
	xbuf = ppp->xbuf;
	if (xbuf == NULL)
		tty->flags &= ~(1 << TTY_DO_WRITE_WAKEUP);
	else
		ppp_tty_wakeup_code (ppp, tty, xbuf);
}

/*
 * This function is called to transmit a buffer to the remote. The buffer
 * is placed on the pending queue if there is presently a buffer being
 * sent or it is transmitted with the aid of ppp_tty_wakeup.
 */

static void
ppp_kick_tty (struct ppp *ppp, struct ppp_buffer *xbuf)
{
	register int flags;
/*
 * Hold interrupts.
 */
	save_flags (flags);
	cli ();
/*
 * Control the flags which are best performed with the interrupts masked.
 */
	xbuf->locked     = 1;
	xbuf->tail       = 0;
/*
 * If the transmitter is busy then place the buffer on the appropriate
 * priority queue.
 */
	if (ppp->xbuf != NULL) {
		if (xbuf->type == BUFFER_TYPE_TTY_WR)
			ppp->s1buf = xbuf;
		else
			ppp->s2buf = xbuf;
		restore_flags (flags);
		return;
	}
/*
 * If the transmitter is not busy then this is the highest priority frame
 */
	ppp->flags      &= ~SC_XMIT_BUSY;
	ppp->tty->flags |= (1 << TTY_DO_WRITE_WAKEUP);
	ppp->xbuf        = xbuf;
	restore_flags (flags);
/*
 * Do the "tty wakeup_code" to actually send this buffer.
 */
	ppp_tty_wakeup_code (ppp, ppp2tty (ppp), xbuf);
}

/*************************************************************
 * TTY INPUT
 *    The following functions handle input that arrives from
 *    the TTY.	It recognizes PPP frames and either hands them
 *    to the network layer or queues them for delivery to a
 *    user process reading this TTY.
 *************************************************************/

/*
 * Callback function from tty driver. Return the amount of space left
 * in the receiver's buffer to decide if remote transmitter is to be
 * throttled.
 */

static int
ppp_tty_room (struct tty_struct *tty)
{
	return 65536;	    /* We can handle an infinite amount of data. :-) */
}

/*
 * Callback function when data is available at the tty driver.
 */

static void
ppp_tty_receive (struct tty_struct *tty, u_char * data, char *flags, int count)
{
	register struct ppp *ppp = tty2ppp (tty);
	register struct ppp_buffer *buf = ppp->rbuf;
	u_char chr;
/*
 * Verify the table pointer and ensure that the line is
 * still in PPP discipline.
 */
	if (!ppp || ppp->magic != PPP_MAGIC) {
		if (ppp->flags & SC_DEBUG)
			printk (KERN_DEBUG
				"PPP: handler called but couldn't find "
				"PPP struct.\n");
		return;
	}
	CHECK_PPP_VOID ();
/*
 * Print the buffer if desired
 */
	if (ppp->flags & SC_LOG_RAWIN)
		ppp_print_buffer ("receive buffer", data, count);
/*
 * Collect the character and error condition for the character. Set the toss
 * flag for the first character error.
 */
	while (count-- > 0) {
		ppp->bytes_rcvd++;
		chr = *data++;
		if (flags) {
			if (*flags && ppp->toss == 0)
				ppp->toss = *flags;
			++flags;
		}
/*
 * Set the flags for 8 data bits and no parity.
 *
 * Actually, it sets the flags for d7 being 0/1 and parity being even/odd
 * so that the normal processing would have all flags set at the end of the
 * session. A missing flag bit would denote an error condition.
 */

#ifdef CHECK_CHARACTERS
		if (chr & 0x80)
			ppp->flags |= SC_RCV_B7_1;
		else
			ppp->flags |= SC_RCV_B7_0;

		if (paritytab[chr >> 5] & (1 << (chr & 0x1F)))
			ppp->flags |= SC_RCV_ODDP;
		else
			ppp->flags |= SC_RCV_EVNP;
#endif
/*
 * Branch on the character. Process the escape character. The sequence ESC ESC
 * is defined to be ESC.
 */
		switch (chr) {
		case PPP_ESCAPE: /* PPP_ESCAPE: invert bit in next character */
			ppp->escape = PPP_TRANS;
			break;
/*
 * FLAG. This is the end of the block. If the block terminated by ESC FLAG,
 * then the block is to be ignored. In addition, characters before the very
 * first FLAG are also tossed by this procedure.
 */
		case PPP_FLAG:	/* PPP_FLAG: end of frame */
			ppp->stats.ppp_ibytes = ppp->bytes_rcvd;
			if (ppp->escape)
				ppp->toss |= 0x80;
/*
 * Process frames which are not to be ignored. If the processing failed,
 * then clean up the VJ tables.
 */
			if ((ppp->toss & 0x80) != 0 ||
			    ppp_doframe (ppp) == 0) {
				slhc_toss (ppp->slcomp);
			}
/*
 * Reset all indicators for the new frame to follow.
 */
			buf->count  = 0;
			buf->fcs    = PPP_INITFCS;
			ppp->escape = 0;
			ppp->toss   = 0;
			break;
/*
 * All other characters in the data come here. If the character is in the
 * receive mask then ignore the character.
 */
		default:
			if (in_rmap (ppp, chr))
				break;
/*
 * Adjust the character and if the frame is to be discarded then simply
 * ignore the character until the ending FLAG is received.
 */
			chr ^= ppp->escape;
			ppp->escape = 0;

			if (ppp->toss != 0)
				break;
/*
 * If the count sent is within reason then store the character, bump the
 * count, and update the FCS for the character.
 */
			if (buf->count < buf->size) {
				buf_base (buf)[buf->count++] = chr;
				buf->fcs = PPP_FCS (buf->fcs, chr);
				break;
			}
/*
 * The peer sent too much data. Set the flags to discard the current frame
 * and wait for the re-synchronization FLAG to be sent.
 */
			ppp->stats.ppp_ierrors++;
			ppp->toss |= 0xC0;
			break;
		}
	}
}

/*
 * Put the input frame into the networking system for the indicated protocol
 */

static int
ppp_rcv_rx (struct ppp *ppp, unsigned short proto, u_char * data, int count)
{
	sk_buff *skb = alloc_skb (count, GFP_ATOMIC);
/*
 * Generate a skb buffer for the new frame.
 */
	if (skb == NULL) {
		if (ppp->flags & SC_DEBUG)
			printk (KERN_ERR
			 "ppp_do_ip: packet dropped on %s (no memory)!\n",
			 ppp2dev (ppp)->name);
		return 0;
	}
/*
 * Move the received data from the input buffer to the skb buffer.
 */
	skb->len = count;		/* Store the length */
	skb->dev = ppp2dev (ppp);	/* We are the device */
#ifdef NEW_SKBUF
	skb->protocol = proto;
#endif
	memcpy ((u_char *) skb_data(skb), data, count);	/* move data */
/*
 * Tag the frame and kick it to the proper receive routine
 */
	skb->free = 1;
	ppp->ddinfo.ip_rjiffies = jiffies;
	netif_rx (skb);
	return 1;
}

/*
 * Process the receipt of an IP frame
 */

static int
rcv_proto_ip (struct ppp *ppp, unsigned short proto, u_char * data, int count)
{
	if (ppp2dev (ppp)->flags & IFF_UP) {
		if (count > 0)
			return ppp_rcv_rx (ppp, htons (ETH_P_IP), data, count);
	}
	return 0;
}

/*
 * Process the receipt of an IPX frame
 */

static int
rcv_proto_ipx (struct ppp *ppp, unsigned short proto, u_char * data, int count)
{
#ifdef NEW_SKBUF
	if (ppp2dev (ppp)->flags & IFF_UP) {
		if (count > 0)
			return ppp_rcv_rx (ppp, htons (ETH_P_IPX), data, count);
	} else
#endif
	return 0;
}

/*
 * Process the receipt of an VJ Compressed frame
 */

static int
rcv_proto_vjc_comp (struct ppp *ppp, unsigned short proto,
		    u_char *data, int count)
{
	if ((ppp->flags & SC_REJ_COMP_TCP) == 0) {
		int new_count = slhc_uncompress (ppp->slcomp, data, count);
		if (new_count >= 0) {
			return rcv_proto_ip (ppp, PPP_IP, data, new_count);
		}
		if (ppp->flags & SC_DEBUG)
			printk (KERN_NOTICE
				"ppp: error in VJ decompression\n");
	}
	return 0;
}

/*
 * Process the receipt of an VJ Un-compressed frame
 */

static int
rcv_proto_vjc_uncomp (struct ppp *ppp, unsigned short proto,
		      u_char *data, int count)
{
	if ((ppp->flags & SC_REJ_COMP_TCP) == 0) {
		if (slhc_remember (ppp->slcomp, data, count) > 0) {
			return rcv_proto_ip (ppp, PPP_IP, data, count);
		}
		if (ppp->flags & SC_DEBUG)
			printk (KERN_NOTICE
				"ppp: error in VJ memorizing\n");
	}
	return 0;
}

/*
 * Receive all unclassified protocols.
 */

static int
rcv_proto_unknown (struct ppp *ppp, unsigned short proto,
		   u_char *data, int len)
{
	int totlen;
	register int current_idx;

#define PUTC(c)						 \
{							 \
    buf_base (ppp->ubuf) [current_idx++] = (u_char) (c); \
    current_idx &= ppp->ubuf->size;			 \
    if (current_idx == ppp->ubuf->tail)			 \
	    goto failure;				 \
}

/*
 * The total length includes the protocol data.
 * Lock the user information buffer.
 */
	if (set_bit (0, &ppp->ubuf->locked)) {
		if (ppp->flags & SC_DEBUG)
			printk (KERN_DEBUG
				"ppp_us_queue: can't get lock\n");
	} else {
		current_idx = ppp->ubuf->head;
/*
 * Insert the buffer length (not counted), the protocol, and the data
 */
		totlen = len + 2;
		PUTC (totlen >> 8);
		PUTC (totlen);

		PUTC (proto >> 8);
		PUTC (proto);

		totlen -= 2;
		while (totlen-- > 0) {
			PUTC (*data++);
		}
#undef PUTC
/*
 * The frame is complete. Update the head pointer and wakeup the pppd
 * process.
 */
		ppp->ubuf->head = current_idx;

		clear_bit (0, &ppp->ubuf->locked);
		wake_up_interruptible (&ppp->read_wait);
		if (ppp->tty->fasync != NULL)
			kill_fasync (ppp->tty->fasync, SIGIO);

		if (ppp->flags & SC_DEBUG)
			printk (KERN_INFO
				"ppp: successfully queued %d bytes\n",
				len + 2);

		ppp->ddinfo.nip_rjiffies = jiffies;
		return 1;
/*
 * The buffer is full. Unlock the header
 */
failure:
		clear_bit (0, &ppp->ubuf->locked);
		if (ppp->flags & SC_DEBUG)
			printk (KERN_INFO
				"ppp_us_queue: ran out of buffer space.\n");
	}
/*
 * Discard the frame. There are no takers for this protocol.
 */
	if (ppp->flags & SC_DEBUG)
		printk (KERN_WARNING
			"ppp: dropping packet on the floor.\n");
	slhc_toss (ppp->slcomp);
	return 0;
}

/*
 * Handle a CCP packet.
 *
 * The CCP packet is passed along to the pppd process just like any
 * other PPP frame. The difference is that some processing needs to be
 * immediate or the compressors will become confused on the peer.
 */

#ifdef PPP_COMPRESS
static void ppp_proto_ccp (struct ppp *ppp, u_char *dp, int len, int rcvd)
{
	int slen = CCP_LENGTH(dp);

	if (slen <= len) {
		switch (CCP_CODE(dp)) {
		case CCP_CONFREQ:
		case CCP_TERMREQ:
		case CCP_TERMACK:
/*
 * CCP must be going down - disable compression
 */
			if (ppp->flags & SC_CCP_UP) {
				ppp->flags &= ~(SC_CCP_UP   |
						SC_COMP_RUN |
						SC_DECOMP_RUN);
			}
			break;

		case CCP_CONFACK:
			if (ppp->flags & SC_CCP_OPEN == 0)
				break;
			if (ppp->flags & SC_CCP_UP)
				break;
			if (slen < CCP_HDRLEN + CCP_OPT_MINLEN)
				break;
			if (slen < CCP_OPT_LENGTH (dp + CCP_HDRLEN) +
			    	   CCP_HDRLEN)
				break;
/*
 * we're agreeing to send compressed packets.
 */
			if (!rcvd) {
				if (ppp->sc_xc_state == NULL)
					break;

				if ((*ppp->sc_xcomp->comp_init)
				    (ppp->sc_xc_state,
				     dp   + CCP_HDRLEN,
				     slen - CCP_HDRLEN,
				     ppp2dev (ppp)->base_addr,
				     ppp->flags & SC_DEBUG))
					ppp->flags |= SC_COMP_RUN;
				break;
			}
/*
 * peer is agreeing to send compressed packets.
 */
			if (ppp->sc_rc_state == NULL)
				break;

			if ((*ppp->sc_rcomp->decomp_init)
			    (ppp->sc_rc_state,
			     dp   + CCP_HDRLEN,
			     slen - CCP_HDRLEN,
			     ppp2dev (ppp)->base_addr,
			     ppp->mru,
			     ppp->flags & SC_DEBUG)) {
				ppp->flags |= SC_DECOMP_RUN;
				ppp->flags &= ~(SC_DC_ERROR | SC_DC_FERROR);
			}
			break;
/*
 * The protocol sequence is complete at this end
 */
		case CCP_RESETACK:
			if (ppp->flags & SC_CCP_UP == 0)
				break;

			if (!rcvd) {
				if (ppp->sc_xc_state &&
				    (ppp->flags & SC_COMP_RUN))
					(*ppp->sc_xcomp->comp_reset)
						(ppp->sc_xc_state);
				break;
			}

			if (ppp->sc_rc_state && (ppp->flags & SC_DECOMP_RUN)) {
				(*ppp->sc_rcomp->decomp_reset)
					(ppp->sc_rc_state);
				ppp->flags &= ~SC_DC_ERROR;
			}
			break;
		}
	}
}

static int
rcv_proto_ccp (struct ppp *ppp, unsigned short proto, u_char *dp, int len)
{
	ppp_proto_ccp (ppp, dp, len, 1);
	return rcv_proto_unknown (ppp, proto, dp, len);
}
#endif /* PPP_COMPRESS */

/*
 * Handle a LQR packet.
 *
 * The LQR packet is passed along to the pppd process just like any
 * other PPP frame. The difference is that some processing needs to be
 * performed to append the current data to the end of the frame.
 */

static int
rcv_proto_lqr (struct ppp *ppp, unsigned short proto, u_char * data, int len)
{
	register u_char *p;

	if (len > 8) {
		if (len < 48)
			memset (&data [len], '\0', 48 - len);
/*
 * Fill in the fields from the driver data
 */
		p = &data [48];
		p = store_long (p, ++ppp->stats.ppp_ilqrs);
		p = store_long (p, ppp->stats.ppp_ipackets);
		p = store_long (p, ppp->stats.ppp_discards);
		p = store_long (p, ppp->stats.ppp_ierrors);
		p = store_long (p, ppp->stats.ppp_ioctects + len);

		len = 68;
	}
/*
 * Pass the frame to the pppd daemon.
 */
	return rcv_proto_unknown (ppp, proto, data, len);
}

/* on entry, a received frame is in ppp->rbuf.bufr
   check it and dispose as appropriate */

static void ppp_doframe_lower (struct ppp *ppp, u_char *data, int len)
{
	u_short		proto;
	int		count = len;
	ppp_proto_type  *proto_ptr;
/*
 * Ignore empty frames
 */
	if (count <= 0)
		return;
/*
 * Count the frame and print it
 */
	++ppp->stats.ppp_ipackets;
	if (ppp->flags & SC_LOG_INPKT)
		ppp_print_buffer ("receive frame", data, count);
/*
 * Ignore the leading ADDRESS and CONTROL fields in the frame.
 */
	if ((data[0] == PPP_ALLSTATIONS) && (data[1] == PPP_UI)) {
		data  += 2;
		count -= 2;
	}
/*
 * Obtain the protocol from the frame
 */
	proto = (u_short) *data++;
	if (proto & 1)
		count--;
	else {
		proto = (proto << 8) | (u_short) *data++;
		count -= 2;
	}
/*
 * Find the procedure to handle this protocol. The last one is marked
 * as a protocol 0 which is the 'catch-all' to feed it to the pppd daemon.
 */
	proto_ptr = proto_list;
	while (proto_ptr->proto != 0 && proto_ptr->proto != proto)
		++proto_ptr;
/*
 * Update the appropriate statistic counter.
 */
	if ((*proto_ptr->func) (ppp, proto, data, count))
		ppp->stats.ppp_ioctects += len;
	else
		++ppp->stats.ppp_discards;
}

/* on entry, a received frame is in ppp->rbuf.bufr
   check it and dispose as appropriate */

static int
ppp_doframe (struct ppp *ppp)
{
	u_char	*data = buf_base (ppp->rbuf);
	int	count = ppp->rbuf->count;
#ifdef PPP_COMPRESS
	int	proto;
	int	new_count;
	u_char *new_data;
#endif
/*
 * If there is a pending error from the receiver then log it and discard
 * the damaged frame.
 */
	if (ppp->toss) {
		if (ppp->flags & SC_DEBUG)
			printk (KERN_WARNING
				"ppp_toss: tossing frame, reason = %d\n",
				ppp->toss);
		ppp->stats.ppp_ierrors++;
		return 0;
	}
/*
 * An empty frame is ignored. This occurs if the FLAG sequence precedes and
 * follows each frame.
 */
	if (count == 0)
		return 1;
/*
 * Generate an error if the frame is too small.
 */
	if (count < PPP_HARD_HDR_LEN) {
		if (ppp->flags & SC_DEBUG)
			printk (KERN_WARNING
				"ppp: got runt ppp frame, %d chars\n", count);
		slhc_toss (ppp->slcomp);
		ppp->stats.ppp_ierrors++;
		return 1;
	}
/*
 * Verify the CRC of the frame and discard the CRC characters from the
 * end of the buffer.
 */
	if (ppp->rbuf->fcs != PPP_GOODFCS) {
		if (ppp->flags & SC_DEBUG)
			printk (KERN_WARNING
				"ppp: frame with bad fcs, excess = %x\n",
				ppp->rbuf->fcs ^ PPP_GOODFCS);
		ppp->stats.ppp_ierrors++;
		return 0;
	}
	count -= 2;		/* ignore the fcs characters */

#ifdef PPP_COMPRESS
	proto  = PPP_PROTOCOL (data);
/*
 * Process the active decompressor.
 */
	if ((ppp->sc_rc_state != (void *) 0) &&
	    ((ppp->flags & SC_DECOMP_RUN) == 0)) {
/*
 * If the frame is compressed then decompress it.
 */
		if (((ppp->flags & (SC_DC_FERROR | SC_DC_ERROR)) == 0) &&
		    (proto == PPP_COMP)) {
			new_data = kmalloc (ppp->mru + 4, GFP_ATOMIC);
			if (new_data == NULL) {
				if (ppp->flags & SC_DEBUG)
					printk (KERN_ERR
						"ppp_doframe: no memory\n");
				slhc_toss (ppp->slcomp);
				(*ppp->sc_rcomp->incomp) (ppp->sc_rc_state,
							  data,
							  count);
				return 1;
			}
/*
 * Decompress the frame
 */
			new_count = bsd_decompress (ppp->sc_rc_state,
						    data,
						    count,
						    new_data,
						    ppp->mru + 4);

			switch (new_count) {
			default:
				ppp_doframe_lower (ppp, new_data, new_count);
				kfree (new_data);
				return 1;

			case DECOMP_OK:
				break;

			case DECOMP_ERROR:
				ppp->flags |= SC_DC_ERROR;
				break;

			case DECOMP_FATALERROR:
				ppp->flags |= SC_DC_FERROR;
				break;
			}
/*
 * Log the error condition and discard the frame.
 */
			if (ppp->flags & SC_DEBUG)
				printk (KERN_ERR
					"ppp_proto_comp: "
					"decompress err %d\n", new_count);
			kfree (new_data);
			slhc_toss (ppp->slcomp);
			return 1;
		}
/*
 * The frame is not special. Pass it through the decompressor without
 * actually decompressing the data
 */
		(*ppp->sc_rcomp->incomp) (ppp->sc_rc_state,
					  data,
					  count);
	}
#endif
/*
 * Process the uncompressed frame.
 */
	ppp_doframe_lower (ppp, data, count);
	return 1;
}

/*************************************************************
 * LINE DISCIPLINE SUPPORT
 *    The following functions form support user programs
 *    which read and write data on a TTY with the PPP line
 *    discipline.  Reading is done from a circular queue,
 *    filled by the lower TTY levels.
 *************************************************************/

/* read a PPP frame from the us_rbuff circular buffer,
   waiting if necessary
*/

static int
ppp_tty_read (struct tty_struct *tty, struct file *file, u_char * buf,
	      unsigned int nr)
{
	struct ppp *ppp = tty2ppp (tty);
	u_char c;
	int len, indx;

#define GETC(c)						\
{							\
    c = buf_base (ppp->ubuf) [ppp->ubuf->tail++];	\
    ppp->ubuf->tail &= ppp->ubuf->size;			\
}

/*
 * Validate the pointer to the PPP structure
 */
	if (!ppp || ppp->magic != PPP_MAGIC) {
		if (ppp->flags & SC_DEBUG)
			printk (KERN_ERR
				"ppp_tty_read: cannot find ppp channel\n");
		return -EIO;
	}
	CHECK_PPP (-ENXIO);

	if (ppp->flags & SC_DEBUG)
		printk (KERN_DEBUG
			"ppp_tty_read: called %x num %u\n",
			(unsigned int) buf,
			nr);
/*
 * Acquire the read lock.
 */
	for (;;) {
		if (set_bit (0, &ppp->ubuf->locked) != 0) {
			if (ppp->flags & SC_DEBUG)
				printk (KERN_DEBUG
				     "ppp_tty_read: sleeping(ubuf)\n");

			current->timeout = 0;
			current->state = TASK_INTERRUPTIBLE;
			schedule ();

			if (current->signal & ~current->blocked)
				return -EINTR;
			continue;
		}
/*
 * Fetch the length of the buffer from the first two bytes.
 */
		if (ppp->ubuf->head == ppp->ubuf->tail)
			len = 0;
		else {
			GETC (c);
			len = c << 8;
			GETC (c);
			len += c;
		}
/*
 * If there is no length then wait for the data to arrive.
 */
		if (len == 0) {
			/* no data */
			clear_bit (0, &ppp->ubuf->locked);
			if (file->f_flags & O_NONBLOCK) {
				if (ppp->flags & SC_DEBUG)
					printk (KERN_DEBUG
						"ppp_tty_read: no data "
						"(EWOULDBLOCK)\n");
				return -EWOULDBLOCK;
			}
			current->timeout = 0;

			if (ppp->flags & SC_DEBUG)
				printk (KERN_DEBUG
					"ppp_tty_read: sleeping(read_wait)\n");

			interruptible_sleep_on (&ppp->read_wait);
			if (current->signal & ~current->blocked)
				return -EINTR;
			continue;
		}
/*
 * Reset the time of the last read operation.
 */
		ppp->ddinfo.nip_rjiffies = jiffies;
		if (ppp->flags & SC_DEBUG)
			printk (KERN_DEBUG "ppp_tty_read: len = %d\n", len);
/*
 * Ensure that the frame will fit within the caller's buffer. If not, then
 * discard the frame from the input buffer and return an error to the caller.
 */
		if (len + 2 > nr) {
			/* Can't copy it, update us_rbuff_head */

			if (ppp->flags & SC_DEBUG)
				printk (KERN_DEBUG
				"ppp: read of %u bytes too small for %d "
				"frame\n", nr, len + 2);
			ppp->ubuf->tail += len;
			ppp->ubuf->tail &= ppp->ubuf->size;
			clear_bit (0, &ppp->ubuf->locked);
			ppp->stats.ppp_ierrors++;
			return -EOVERFLOW;
		}
/*
 * Fake the insertion of the ADDRESS and CONTROL information because these
 * were not saved in the buffer.
 */
		put_fs_byte (PPP_ALLSTATIONS, buf++);
		put_fs_byte (PPP_UI,          buf++);

		indx = len;
/*
 * Copy the received data from the buffer to the caller's area.
 */
		while (indx-- > 0) {
			GETC (c);
			put_fs_byte (c, buf++);
		}
/*
 * Release the lock and return the character count in the buffer area.
 */
		clear_bit (0, &ppp->ubuf->locked);
		len += 2; /* Account for ADDRESS and CONTROL bytes */
		if (ppp->flags & SC_DEBUG)
			printk (KERN_DEBUG
				"ppp_tty_read: passing %d bytes up\n", len);
		return len;
	}
#undef GETC
}

/* stuff a character into the transmit buffer, using PPP's way of escaping
   special characters.
   also, update fcs to take account of new character */

extern inline void
ppp_stuff_char (struct ppp *ppp, register struct ppp_buffer *buf,
		register u_char chr)
{
/*
 * The buffer should not be full.
 */
	if (ppp->flags & SC_DEBUG) {
		if ((buf->count < 0) || (buf->count > 3000))
			printk (KERN_DEBUG "ppp_stuff_char: %x %d\n",
				(unsigned int) buf->count,
				(unsigned int) buf->count);
	}
/*
 * Update the FCS and if the character needs to be escaped, do it.
 */
	buf->fcs = PPP_FCS (buf->fcs, chr);
	if (in_xmap (ppp, chr)) {
		chr ^= PPP_TRANS;
		ins_char (buf, PPP_ESCAPE);
	}
/*
 * Add the character to the buffer.
 */
	ins_char (buf, chr);
}

/*
 * Procedure to encode the data with the proper escapement and send the
 * data to the remote system.
 */

static void
ppp_dev_xmit_lower (struct ppp *ppp, struct ppp_buffer *buf,
		    u_char *data, int count, int non_ip)
{
	unsigned short int write_fcs;
/*
 * Insert the leading FLAG character
 */
	buf->count = 0;

#ifdef OPTIMIZE_FLAG_TIME
	if (non_ip)
		ins_char (buf, PPP_FLAG);
	else {
		if (jiffies - ppp->last_xmit > OPTIMIZE_FLAG_TIME)
			ins_char (buf, PPP_FLAG);
	}
	ppp->last_xmit = jiffies;
#else
	ins_char (buf, PPP_FLAG);
#endif

	buf->fcs = PPP_INITFCS;
/*
 * Insert the data
 */
	while (count-- > 0)
		ppp_stuff_char (ppp, buf, *data++);
/*
 * Add the trailing CRC and the final flag character
 */
	write_fcs = buf->fcs ^ 0xFFFF;
	ppp_stuff_char (ppp, buf, write_fcs);
	ppp_stuff_char (ppp, buf, write_fcs >> 8);

	if (ppp->flags & SC_DEBUG)
		printk (KERN_DEBUG "ppp_dev_xmit_lower: fcs is %hx\n",
			write_fcs);
/*
 * Add the trailing flag character
 */
	ins_char (buf, PPP_FLAG);
/*
 * Print the buffer
 */
	if (ppp->flags & SC_LOG_FLUSH)
		ppp_print_buffer ("ppp flush", buf_base (buf),
				  buf->count);
	else {
		if (ppp->flags & SC_DEBUG)
			printk (KERN_DEBUG
				"ppp_dev_xmit: writing %d chars\n",
				buf->count);
	}
/*
 * Send the block to the tty driver.
 */
	ppp->stats.ppp_obytes += buf->count;
	ppp_kick_tty (ppp, buf);
}

/*
 * Send an frame to the remote with the proper bsd compression.
 *
 * Return 0 if frame was queued for transmission.
 *        1 if frame must be re-queued for later driver support.
 */

int
ppp_dev_xmit_frame (struct ppp *ppp, struct ppp_buffer *buf,
		    u_char *data, int count)
{
	int     address, control;
	int	proto;
	u_char *new_data;
	int     new_count;
/*
 * Print the buffer
 */
	if (ppp->flags & SC_LOG_OUTPKT)
		ppp_print_buffer ("write frame", data, count);
/*
 * Determine if the frame may be compressed. Attempt to compress the
 * frame if possible.
 */
	address = PPP_ADDRESS  (data);
	control = PPP_CONTROL  (data);
	proto   = PPP_PROTOCOL (data);

#ifdef PPP_COMPRESS  
	if ((ppp->flags & SC_COMP_RUN != 0)	&&
	    (ppp->sc_xc_state != (void *) 0)	&&
	    (address == PPP_ALLSTATIONS)	&&
	    (control == PPP_UI)			&&
	    (proto != PPP_LCP)			&&
	    (proto != PPP_CCP)) {
		new_data = kmalloc (count, GFP_ATOMIC);
		if (new_data == NULL) {
			if (ppp->flags & SC_DEBUG)
				printk (KERN_ERR
					"ppp_dev_xmit_frame: no memory\n");
			return 1;
		}

		new_count = bsd_compress (ppp->sc_xc_state,
					  data,
					  new_data,
					  count,
					  count);

		if (new_count > 0) {
			++ppp->stats.ppp_opackets;
			ppp->stats.ppp_ooctects += count;

			ppp_dev_xmit_lower (ppp, buf, new_data,
					    new_count, 0);
			kfree (new_data);
			return 0;
		}
/*
 * The frame could not be compressed.
 */
		kfree (new_data);
	}
#endif
/*
 * The frame may not be compressed. Update the statistics before the
 * count field is destroyed. The frame will be transmitted.
 */
	++ppp->stats.ppp_opackets;
	ppp->stats.ppp_ooctects += count;
/*
 * Do not compress the protocol id if not possible
 */
	if (!(ppp->flags & SC_COMP_PROT) || (proto & 0xFF00)) {
		--data;
		++count;
	}

	data  += 3;
	count -= 3;
/*
 * Do not compress the address/control if not possible.
 */
	if (address != PPP_ALLSTATIONS ||
	    control != PPP_UI ||
	    !(ppp->flags & SC_COMP_AC)) {
		*--data = control;
		*--data = address;
		count  += 2;
	}
/*
 * Go to the escape encoding
 */
	ppp_dev_xmit_lower (ppp, buf, data, count, !!(proto & 0xFF00));
	return 0;
}

/*
 * Revise the tty frame for specific protocols.
 */

static int
send_revise_frame (register struct ppp *ppp, u_char *data, int len)
{
	u_char *p;

	switch (PPP_PROTOCOL (data)) {
/*
 * Update the LQR frame with the current MIB information. This saves having
 * the daemon read old MIB data from the driver.
 */
	case PPP_LQR:
		len = 48;			/* total size of this frame */
		p   = (u_char *) &data [40];	/* Point to last two items. */
		p   = store_long (p, ppp->stats.ppp_opackets + 1);
		p   = store_long (p, ppp->stats.ppp_ooctects + len);
		break;
/*
 * Outbound compression frames
 */
#ifdef PPP_COMPRESS
	case PPP_COMP:
		ppp_proto_ccp (ppp, data, len, 0);
		break;
#endif

/*
 * All other frame types
 */
	default:
		break;
	}

	return len;
}

/*
 * write a frame with NR chars from BUF to TTY
 * we have to put the FCS field on ourselves
 */

static int
ppp_tty_write (struct tty_struct *tty, struct file *file, u_char * data,
	       unsigned int count)
{
	struct ppp *ppp = tty2ppp (tty);
	u_char *new_data;
/*
 * Verify the pointer to the PPP data and that the tty is still in PPP mode.
 */
	if (!ppp || ppp->magic != PPP_MAGIC) {
		if (ppp->flags & SC_DEBUG)
			printk (KERN_ERR
				"ppp_tty_write: cannot find ppp unit\n");
		return -EIO;
	}

	CHECK_PPP (-ENXIO);
/*
 * Ensure that the caller does not wish to send too much.
 */
	if (count > PPP_MTU) {
		if (ppp->flags & SC_DEBUG)
			printk (KERN_WARNING
				"ppp_tty_write: truncating user packet "
				"from %u to mtu %d\n", count, PPP_MTU);
		count = PPP_MTU;
	}
/*
 * lock this PPP unit so we will be the only writer;
 * sleep if necessary
 */
	while (lock_buffer (ppp->tbuf) != 0) {
		current->timeout = 0;
		if (ppp->flags & SC_DEBUG)
			printk (KERN_DEBUG "ppp_tty_write: sleeping\n");
		interruptible_sleep_on (&ppp->write_wait);
		if (current->signal & ~current->blocked)
			return -EINTR;
	}
/*
 * Allocate a buffer for the data and fetch it from the user space.
 */
	new_data = kmalloc (count, GFP_ATOMIC);
	if (new_data == NULL) {
		if (ppp->flags & SC_DEBUG)
			printk (KERN_ERR
				"ppp_tty_write: no memory\n");
		ppp->tbuf->locked = 0;
		return 0;
	}

	memcpy_fromfs (new_data, data, count);
/*
 * Change the LQR frame
 */
	count = send_revise_frame (ppp, new_data, count);
/*
 * Send the data
 */
	ppp_dev_xmit_frame (ppp, ppp->tbuf, new_data, count);
	kfree (new_data);
	return (int) count;
}

/*
 * Process the BSD compression IOCTL event for the tty device.
 */

#ifdef	PPP_COMPRESS
static int
ppp_set_compression (struct ppp *ppp, struct ppp_option_data *odp)
{
	int error;
	int nb;
	u_char ccp_option[CCP_MAX_OPTION_LENGTH];
	struct compressor **cp;
/*
 * Validate the range of the ioctl
 */
	error = verify_area (VERIFY_READ, odp,
		     (unsigned long) (&((struct ppp_option_data *) 0)->length)
		     + sizeof (odp->length));

	if (error == 0) {
		nb = (int) get_fs_long (odp->length);
		if ((unsigned long) nb-1 >= (unsigned long) CCP_MAX_OPTION_LENGTH)
			nb = CCP_MAX_OPTION_LENGTH;

		error = verify_area (VERIFY_READ, odp, nb);
	}

	if (error != 0)
		return error;

	memcpy_fromfs (ccp_option, odp, nb);
	if (ccp_option[1] < 2)	/* preliminary check on the length byte */
		return (-EINVAL);

	for (cp = ppp_compressors; *cp != NULL; ++cp)
		if ((*cp)->compress_proto == ccp_option[0]) {
		/*
		 * Found a handler for the protocol - try to allocate
		 * a compressor or decompressor.
		 */
			error = 0;
			if (odp->transmit) {
				if (ppp->sc_xc_state != NULL)
					(*ppp->sc_xcomp->comp_free)(ppp->sc_xc_state);

				ppp->sc_xcomp = *cp;
				ppp->sc_xc_state = (*cp)->comp_alloc(ccp_option, nb);

				if (ppp->sc_xc_state == NULL) {
					if (ppp->flags & SC_DEBUG)
						printk("ppp%ld: comp_alloc failed\n",
						       ppp2dev (ppp)->base_addr);
					error = -ENOBUFS;
				}
				ppp->flags &= ~SC_COMP_RUN;
			} else {
				if (ppp->sc_rc_state != NULL)
					(*ppp->sc_rcomp->decomp_free)(ppp->sc_rc_state);
				ppp->sc_rcomp = *cp;
				ppp->sc_rc_state = (*cp)->decomp_alloc(ccp_option, nb);
				if (ppp->sc_rc_state == NULL) {
					if (ppp->flags & SC_DEBUG)
						printk("ppp%ld: decomp_alloc failed\n",
						       ppp2dev (ppp)->base_addr);
					error = ENOBUFS;
				}
				ppp->flags &= ~SC_DECOMP_RUN;
			}
			return (error);
		}

	if (ppp->flags & SC_DEBUG)
		printk (KERN_DEBUG "ppp%ld: no compressor for [%x %x %x], %x\n",
			ppp2dev (ppp)->base_addr, ccp_option[0], ccp_option[1],
			ccp_option[2], nb);
	return (-EINVAL);	/* no handler found */
}
#endif /* PPP_COMPRESS */

/*
 * Process the IOCTL event for the tty device.
 */

static int
ppp_tty_ioctl (struct tty_struct *tty, struct file *file, unsigned int param2,
	       unsigned long param3)
{
	struct ppp *ppp = tty2ppp (tty);
	register int temp_i = 0;
	int error;
/*
 * Verify the status of the PPP device.
 */
	if (!ppp || ppp->magic != PPP_MAGIC) {
		if (ppp->flags & SC_DEBUG)
			printk (KERN_ERR
			"ppp_tty_ioctl: can't find PPP block from tty!\n");
		return -EBADF;
	}
	CHECK_PPP (-ENXIO);
/*
 * The user must have an euid of root to do these requests.
 */
	if (!suser ())
		return -EPERM;
/*
 * Set the MRU value
 */
	switch (param2) {
	case PPPIOCSMRU:
		error = verify_area (VERIFY_READ, (void *) param3,
				     sizeof (temp_i));
		if (error == 0) {
			temp_i = (int) get_fs_long (param3);
			if (ppp->flags & SC_DEBUG)
				printk (KERN_INFO
				 "ppp_tty_ioctl: set mru to %x\n", temp_i);

			if (ppp->mru != temp_i)
				ppp_changedmtu (ppp, ppp2dev (ppp)->mtu, temp_i);
		}
		break;
/*
 * Fetch the flags
 */
	case PPPIOCGFLAGS:
		error = verify_area (VERIFY_WRITE, (void *) param3,
				     sizeof (temp_i));
		if (error == 0) {
			temp_i = (ppp->flags & SC_MASK);
#ifndef CHECK_CHARACTERS /* Don't generate errors if we don't check chars. */
			temp_i |= SC_RCV_B7_1 | SC_RCV_B7_0 |
				  SC_RCV_ODDP | SC_RCV_EVNP;
#endif
			put_fs_long ((long) temp_i, param3);
			if (ppp->flags & SC_DEBUG)
				printk (KERN_DEBUG
				"ppp_tty_ioctl: get flags: addr %lx flags "
				"%x\n", param3, temp_i);
		}
		break;
/*
 * Set the flags for the various options
 */
	case PPPIOCSFLAGS:
		error = verify_area (VERIFY_READ, (void *) param3,
				     sizeof (temp_i));
		if (error == 0) {
			temp_i  = (int) get_fs_long (param3) & SC_MASK;
			temp_i |= (ppp->flags & ~SC_MASK);
#ifdef PPP_COMPRESS
			if ((ppp->flags & SC_CCP_OPEN) &&
			    (temp_i & SC_CCP_OPEN) == 0)
				ppp_ccp_closed (ppp);
#else
			temp_i &= ~SC_CCP_OPEN;
#endif
			if ((ppp->flags | temp_i) & SC_DEBUG)
				printk (KERN_INFO
			       "ppp_tty_ioctl: set flags to %x\n", temp_i);
			ppp->flags = temp_i;
		}
		break;
/*
 * Set the compression mode
 */
#ifdef PPP_COMPRESS
	case PPPIOCSCOMPRESS:
		error = ppp_set_compression (ppp,
					    (struct ppp_option_data *) param3);
		break;
#endif
/*
 * Retrieve the transmit async map
 */
	case PPPIOCGASYNCMAP:
		error = verify_area (VERIFY_WRITE, (void *) param3,
				     sizeof (temp_i));
		if (error == 0) {
			put_fs_long (ppp->xmit_async_map[0], param3);
			if (ppp->flags & SC_DEBUG)
				printk (KERN_INFO
					"ppp_tty_ioctl: get asyncmap: addr "
					"%lx asyncmap %lx\n",
					param3, ppp->xmit_async_map[0]);
		}
		break;
/*
 * Set the transmit async map
 */
	case PPPIOCSASYNCMAP:
		error = verify_area (VERIFY_READ, (void *) param3,
				     sizeof (temp_i));
		if (error == 0) {
			ppp->xmit_async_map[0] = get_fs_long (param3);
			if (ppp->flags & SC_DEBUG)
				printk (KERN_INFO
				     "ppp_tty_ioctl: set xmit asyncmap %lx\n",
				     ppp->xmit_async_map[0]);
		}
		break;
/*
 * Set the receive async map
 */
	case PPPIOCSRASYNCMAP:
		error = verify_area (VERIFY_READ, (void *) param3,
				     sizeof (temp_i));
		if (error == 0) {
			ppp->recv_async_map = get_fs_long (param3);
			if (ppp->flags & SC_DEBUG)
				printk (KERN_INFO
				     "ppp_tty_ioctl: set rcv asyncmap %lx\n",
				     ppp->recv_async_map);
		}
		break;
/*
 * Obtain the unit number for this device.
 */
	case PPPIOCGUNIT:
		error = verify_area (VERIFY_WRITE, (void *) param3,
				     sizeof (temp_i));
		if (error == 0) {
			put_fs_long (ppp2dev (ppp)->base_addr, param3);
			if (ppp->flags & SC_DEBUG)
				printk (KERN_INFO
					"ppp_tty_ioctl: get unit: %ld",
					ppp2dev (ppp)->base_addr);
		}
		break;
/*
 * Set the debug level
 */
	case PPPIOCSDEBUG:
		error = verify_area (VERIFY_READ, (void *) param3,
				     sizeof (temp_i));
		if (error == 0) {
			temp_i  = (int) (get_fs_long (param3) & 0x1F) << 16;
			temp_i |= (ppp->flags & ~0x1F0000);

			if ((ppp->flags | temp_i) & SC_DEBUG)
				printk (KERN_INFO
			       "ppp_tty_ioctl: set flags to %x\n", temp_i);
			ppp->flags = temp_i;
		}
		break;
/*
 * Get the debug level
 */
	case PPPIOCGDEBUG:
		error = verify_area (VERIFY_WRITE, (void *) param3,
				     sizeof (temp_i));
		if (error == 0) {
			temp_i = (ppp->flags >> 16) & 0x1F;
			put_fs_long ((long) temp_i, param3);

			if (ppp->flags & SC_DEBUG)
				printk (KERN_INFO
					"ppp_tty_ioctl: get debug level %d\n",
					temp_i);
      		}
		break;
/*
 * Get the times since the last send/receive frame operation
 */
	case PPPIOCGTIME:
		error = verify_area (VERIFY_WRITE, (void *) param3,
				     sizeof (struct ppp_ddinfo));
		if (error == 0) {
			struct ppp_ddinfo cur_ddinfo;
			unsigned long cur_jiffies = jiffies;

			/* change absolute times to relative times. */
			cur_ddinfo.ip_sjiffies = cur_jiffies - ppp->ddinfo.ip_sjiffies;
			cur_ddinfo.ip_rjiffies = cur_jiffies - ppp->ddinfo.ip_rjiffies;
			cur_ddinfo.nip_sjiffies = cur_jiffies - ppp->ddinfo.nip_sjiffies;
			cur_ddinfo.nip_rjiffies = cur_jiffies - ppp->ddinfo.nip_rjiffies;

			memcpy_tofs ((void *) param3, &cur_ddinfo,
				     sizeof (struct ppp_ddinfo));
			if (ppp->flags & SC_DEBUG)
				printk (KERN_INFO
				"ppp_tty_ioctl: read demand dial info\n");
		}
		break;
/*
 * Retrieve the extended async map
 */
	case PPPIOCGXASYNCMAP:
		error = verify_area (VERIFY_WRITE,
				     (void *) param3,
				     sizeof (ppp->xmit_async_map));
		if (error == 0) {
			memcpy_tofs ((void *) param3,
				     ppp->xmit_async_map,
				     sizeof (ppp->xmit_async_map));

			if (ppp->flags & SC_DEBUG)
				printk (KERN_INFO
				"ppp_tty_ioctl: get xasyncmap: addr %lx\n",
				param3);
		}
		break;
/*
 * Set the async extended map
 */
	case PPPIOCSXASYNCMAP:
		error = verify_area (VERIFY_READ, (void *) param3,
				     sizeof (ppp->xmit_async_map));
		if (error == 0) {
			unsigned long temp_tbl[8];

			memcpy_fromfs (temp_tbl, (void *) param3,
				       sizeof (ppp->xmit_async_map));
			temp_tbl[1]  =  0x00000000;
			temp_tbl[2] &= ~0x40000000;
			temp_tbl[3] |=  0x60000000;

			if ((temp_tbl[2] & temp_tbl[3]) != 0 ||
			    (temp_tbl[4] & temp_tbl[5]) != 0 ||
			    (temp_tbl[6] & temp_tbl[7]) != 0)
				error = -EINVAL;
			else {
				memcpy (ppp->xmit_async_map, temp_tbl,
					sizeof (ppp->xmit_async_map));

				if (ppp->flags & SC_DEBUG)
					printk (KERN_INFO
					"ppp_tty_ioctl: set xasyncmap\n");
			}
		}
		break;
/*
 * Set the maximum VJ header compression slot number.
 */
	case PPPIOCSMAXCID:
		error = verify_area (VERIFY_READ, (void *) param3,
				     sizeof (temp_i));
		if (error == 0) {
			temp_i = (int) get_fs_long (param3) + 1;
			if (ppp->flags & SC_DEBUG)
				printk (KERN_INFO
				     "ppp_tty_ioctl: set maxcid to %d\n",
				     temp_i);
			if (ppp->slcomp != NULL)
				slhc_free (ppp->slcomp);
			ppp->slcomp = slhc_init (16, temp_i);

			if (ppp->slcomp == NULL) {
				if (ppp->flags & SC_DEBUG)
					printk (KERN_ERR
					"ppp: no space for compression buffers!\n");
				ppp_release (ppp);
				error = -ENOMEM;
			}
		}
		break;
/*
 * Allow users to read, but not set, the serial port parameters
 */
	case TCGETS:
	case TCGETA:
		error = n_tty_ioctl (tty, file, param2, param3);
		break;
/*
 *  All other ioctl() events will come here.
 */
	default:
		if (ppp->flags & SC_DEBUG)
			printk (KERN_ERR
				"ppp_tty_ioctl: invalid ioctl: %x, addr %lx\n",
				param2,
				param3);

		error = -ENOIOCTLCMD;
		break;
	}
	return error;
}

/*
 * TTY callback.
 *
 * Process the select() statement for the PPP device.
 */

static int
ppp_tty_select (struct tty_struct *tty, struct inode *inode,
		struct file *filp, int sel_type, select_table * wait)
{
	struct ppp *ppp = tty2ppp (tty);
	int result = 1;
/*
 * Verify the status of the PPP device.
 */
	if (!ppp || ppp->magic != PPP_MAGIC) {
		if (ppp->flags & SC_DEBUG)
			printk (KERN_ERR
		       "ppp_tty_select: can't find PPP block from tty!\n");
		return -EBADF;
	}
	CHECK_PPP (0);
/*
 * Branch on the type of select mode. A read request must lock the user
 * buffer area.
 */
	switch (sel_type) {
	case SEL_IN:
		if (set_bit (0, &ppp->ubuf->locked) == 0) {
			/* Test for the presence of data in the queue */
			if (ppp->ubuf->head != ppp->ubuf->tail) {
				clear_bit (0, &ppp->ubuf->locked);
				break;
			}
			clear_bit (0, &ppp->ubuf->locked);
		}		/* fall through */
		/*
 * Exceptions or read errors.
 */
	case SEL_EX:
		/* Is this a pty link and the remote disconnected? */
		if (tty->flags & (1 << TTY_SLAVE_CLOSED))
			break;

		/* Is this a local link and the modem disconnected? */
		if (tty_hung_up_p (filp))
			break;

		select_wait (&ppp->read_wait, wait);
		result = 0;
		break;
/*
 * Write mode. A write is allowed if there is no current transmission.
 */
	case SEL_OUT:
		if (ppp->tbuf->locked != 0) {
			select_wait (&ppp->write_wait, wait);
			result = 0;
		}
		break;
	}
	return result;
}

/*************************************************************
 * NETWORK OUTPUT
 *    This routine accepts requests from the network layer
 *    and attempts to deliver the packets.
 *    It also includes various routines we are compelled to
 *    have to make the network layer work (arp, etc...).
 *************************************************************/

/*
 * Callback from the network layer when the device goes up.
 */

static int
ppp_dev_open (struct device *dev)
{
	struct ppp *ppp = dev2ppp (dev);

	/* reset POINTOPOINT every time, since dev_close zaps it! */
	dev->flags |= IFF_POINTOPOINT;

	if (ppp2tty (ppp) == NULL) {
		if (ppp->flags & SC_DEBUG)
			printk (KERN_ERR
			"ppp: %s not connected to a TTY! can't go open!\n",
			dev->name);
		return -ENXIO;
	}

	if (ppp->flags & SC_DEBUG)
		printk (KERN_INFO
			"ppp: channel %s going up for IP packets!\n",
			dev->name);

	CHECK_PPP (-ENXIO);
	return 0;
}

/*
 * Callback from the network layer when the ppp device goes down.
 */

static int
ppp_dev_close (struct device *dev)
{
	struct ppp *ppp = dev2ppp (dev);

	if (ppp2tty (ppp) == NULL) {
		if (ppp->flags & SC_DEBUG)
			printk (KERN_ERR
			"ppp: %s not connected to a TTY! can't go down!\n",
			dev->name);
		return -ENXIO;
	}
/*
 * We don't do anything about the device going down. It is not important
 * for us.
 */
	if (ppp->flags & SC_DEBUG)
		printk (KERN_INFO
			"ppp: channel %s going down for IP packets!\n",
			dev->name);
	CHECK_PPP (-ENXIO);
	return 0;
}

/*
 * IOCTL operation to read the version of the driver.
 */

static int
ppp_dev_ioctl_version (struct ppp *ppp, struct ifreq *ifr)
{
        int error;
	int len;
	char *result;
/*
 * Must have write access to the buffer.
 */
	result = (char *) ifr->ifr_ifru.ifru_data;
	len    = strlen (szVersion) + 1;
	error  = verify_area (VERIFY_WRITE, result, len);
/*
 * Move the version data
 */
	if (error == 0)
		memcpy_tofs (result, szVersion, len);

	return error;
}

/*
 * IOCTL to read the statistics for the pppstats program.
 */

static int
ppp_dev_ioctl_stats (struct ppp *ppp, struct ifreq *ifr)
{
	struct ppp_stats *result, temp;
	int    error;
/*
 * Must have write access to the buffer.
 */
	result = (struct ppp_stats *) ifr->ifr_ifru.ifru_data;
	error = verify_area (VERIFY_WRITE,
			     result,
			     sizeof (temp));
/*
 * Supply the information for the caller. First move the version data
 * then move the ppp stats; and finally the vj stats.
 */
	if (error == 0) {
		memset (&temp, 0, sizeof(temp));
		memcpy (&temp.p, &ppp->stats, sizeof (struct pppstat));
/*
 * Header Compression statistics
 */
		if (ppp->slcomp != NULL) {
			temp.vj.vjs_packets    = ppp->slcomp->sls_o_nontcp +
						 ppp->slcomp->sls_o_tcp;
			temp.vj.vjs_compressed = ppp->slcomp->sls_o_compressed;
			temp.vj.vjs_searches   = ppp->slcomp->sls_o_searches;
			temp.vj.vjs_misses     = ppp->slcomp->sls_o_misses;
			temp.vj.vjs_errorin    = ppp->slcomp->sls_i_error;
			temp.vj.vjs_tossed     = ppp->slcomp->sls_i_tossed;
			temp.vj.vjs_uncompressedin = ppp->slcomp->sls_i_uncompressed;
			temp.vj.vjs_compressedin   = ppp->slcomp->sls_i_compressed;
		}
/*
 * Frame data compression statistics
 */
#ifdef PPP_COMPRESS
		if (ppp->sc_xc_state != NULL)
			(*ppp->sc_xcomp->comp_stat) (ppp->sc_xc_state,
						     &temp.c);

		if (ppp->sc_rc_state != NULL)
			(*ppp->sc_rcomp->decomp_stat) (ppp->sc_rc_state,
						       &temp.d);
#endif /* PPP_COMPRESS */

/*
 * Move the data to the caller's buffer
 */
		memcpy_tofs (result, &temp, sizeof (temp));
	}
	return error;
}

/*
 * Callback from the network layer to process the sockioctl functions.
 */

static int
ppp_dev_ioctl (struct device *dev, struct ifreq *ifr, int cmd)
{
	struct ppp *ppp = dev2ppp (dev);
	int error;
/*
 * Process the requests
 */
	switch (cmd) {
	case SIOCGPPPSTATS:
		error = ppp_dev_ioctl_stats (ppp, ifr);
		break;

	case SIOCGPPPVER:
		error = ppp_dev_ioctl_version (ppp, ifr);
		break;

	default:
		error = -EINVAL;
		break;
	}
	return error;
}

/*
 * Send an IP frame to the remote with vj header compression.
 *
 * Return 0 if frame was queued for transmission.
 *        1 if frame must be re-queued for later driver support.
 */

int
ppp_dev_xmit_ip1 (struct device *dev, struct ppp *ppp, u_char *data)
{
	int      proto = PPP_IP;
	int	 len;
	struct ppp_hdr    *hdr;
	struct tty_struct *tty = ppp2tty (ppp);
/*
 * Obtain the length from the IP header.
 */
	len = ((struct iphdr *)data) -> tot_len;
	len = ntohs (len);
/*
 * Validate the tty interface
 */
	if (tty == NULL) {
		if (ppp->flags & SC_DEBUG)
			printk (KERN_ERR
				"ppp_dev_xmit: %s not connected to a TTY!\n",
				dev->name);
		return 0;
	}
/*
 * Ensure that the PPP device is still up
 */
	if (!(dev->flags & IFF_UP)) {
		if (ppp->flags & SC_DEBUG)
			printk (KERN_WARNING
				"ppp_dev_xmit: packet sent on interface %s,"
				" which is down for IP\n",
				dev->name);
		return 0;
	}
/*
 * Detect a change in the transfer size
 */
	if (ppp->mtu != ppp2dev (ppp)->mtu) {
		ppp_changedmtu (ppp,
				ppp2dev (ppp)->mtu,
				ppp->mru);
	}
/*
 * Acquire the lock on the transmission buffer. If the buffer was busy then
 * mark the device as busy and return "failure to send, try back later" error.
 */
	if (lock_buffer (ppp->wbuf) != 0) {
		dev->tbusy = 1;
		return 1;
	}
/*
 * Print the frame being sent
 */
	if (ppp->flags & SC_LOG_OUTPKT)
		ppp_print_buffer ("ppp outpkt", data, len);
/*
 * At this point, the buffer will be transmitted. There is no other exit.
 *
 * Try to compress the header.
 */
	if (ppp->flags & SC_COMP_TCP) {
		len = slhc_compress (ppp->slcomp, data, len,
				     buf_base (ppp->cbuf) + PPP_HARD_HDR_LEN,
				     &data,
				     !(ppp->flags & SC_NO_TCP_CCID));

		if (data[0] & SL_TYPE_COMPRESSED_TCP) {
			proto    = PPP_VJC_COMP;
			data[0] ^= SL_TYPE_COMPRESSED_TCP;
		} else {
			if (data[0] >= SL_TYPE_UNCOMPRESSED_TCP)
				proto = PPP_VJC_UNCOMP;
			data[0] = (data[0] & 0x0f) | 0x40;
		}
	}
/*
 * Send the frame
 */
	len  += PPP_HARD_HDR_LEN;
	hdr   = &((struct ppp_hdr *) data)[-1];

	hdr->address     = PPP_ALLSTATIONS;
	hdr->control     = PPP_UI;
	hdr->protocol[0] = 0;
	hdr->protocol[1] = proto;

	return ppp_dev_xmit_frame (ppp, ppp->wbuf, (u_char *) hdr, len);
}

/*
 * This is just an interum solution until the 1.3 kernel's networking is
 * available. The 1.2 kernel has problems with device headers before the
 * buffers.
 *
 * This routine should be deleted, and the ppp_dev_xmit_ip1 routine called
 * by this name.
 */

int
ppp_dev_xmit_ip (struct device *dev, struct ppp *ppp, u_char *data)
{
	struct ppp_hdr    *hdr;
	int     len;
	int     answer;

	len = ((struct iphdr *)data) -> tot_len;
	len = ntohs (len);

	hdr = (struct ppp_hdr *) kmalloc (len + sizeof (struct ppp_hdr),
					  GFP_ATOMIC);

	if (hdr == NULL)
		answer = 1;
	else {
		memcpy (&hdr[1], data, len);
		answer = ppp_dev_xmit_ip1 (dev, ppp, (u_char *) &hdr[1]);
		kfree (hdr);
	}

	return answer;
}

/*
 * Send an IPX (or any other non-IP) frame to the remote.
 *
 * Return 0 if frame was queued for transmission.
 *        1 if frame must be re-queued for later driver support.
 */

int
ppp_dev_xmit_ipx1 (struct device *dev, struct ppp *ppp,
		  u_char *data, int len, int proto)
{
	struct tty_struct *tty = ppp2tty (ppp);
	struct ppp_hdr    *hdr;
/*
 * Validate the tty interface
 */
	if (tty == NULL) {
		if (ppp->flags & SC_DEBUG)
			printk (KERN_ERR
				"ppp_dev_xmit: %s not connected to a TTY!\n",
				dev->name);
		return 0;
	}
/*
 * Ensure that the PPP device is still up
 */
	if (!(dev->flags & IFF_UP)) {
		if (ppp->flags & SC_DEBUG)
			printk (KERN_WARNING
				"ppp_dev_xmit: packet sent on interface %s,"
				" which is down\n",
				dev->name);
		return 0;
	}
/*
 * Detect a change in the transfer size
 */
	if (ppp->mtu != ppp2dev (ppp)->mtu) {
		ppp_changedmtu (ppp,
				ppp2dev (ppp)->mtu,
				ppp->mru);
	}
/*
 * Acquire the lock on the transmission buffer. If the buffer was busy then
 * mark the device as busy and return "failure to send, try back later" error.
 */
	if (lock_buffer (ppp->wbuf) != 0) {
		dev->tbusy = 1;
		return 1;
	}
/*
 * Print the frame being sent
 */
	if (ppp->flags & SC_LOG_OUTPKT)
		ppp_print_buffer ("ppp outpkt", data, len);
/*
 * Send the frame
 */
	len  += PPP_HARD_HDR_LEN;
	hdr   = &((struct ppp_hdr *) data)[-1];

	hdr->address     = PPP_ALLSTATIONS;
	hdr->control     = PPP_UI;
	hdr->protocol[0] = proto >> 8;
	hdr->protocol[1] = proto;

	return ppp_dev_xmit_frame (ppp, ppp->wbuf, (u_char *) hdr, len);
}

/*
 * This is just an interum solution until the 1.3 kernel's networking is
 * available. The 1.2 kernel has problems with device headers before the
 * buffers.
 *
 * This routine should be deleted, and the ppp_dev_xmit_ipx1 routine called
 * by this name.
 */

int
ppp_dev_xmit_ipx (struct device *dev, struct ppp *ppp,
		  u_char *data, int len, int proto)
{
	struct ppp_hdr    *hdr;
	int     answer;

	hdr = (struct ppp_hdr *) kmalloc (len + sizeof (struct ppp_hdr),
					  GFP_ATOMIC);
	if (hdr == NULL)
		answer = 1;
	else {
		memcpy (&hdr[1], data, len);
		answer = (dev, ppp, (u_char *) &hdr[1], len, proto);
		kfree (hdr);
	}

	return answer;
}

/*
 * Send a frame to the remote.
 */

int
ppp_dev_xmit (sk_buff *skb, struct device *dev)
{
	int answer;
	u_char *data;
	struct ppp        *ppp = dev2ppp (dev);
	struct tty_struct *tty = ppp2tty (ppp);
/*
 * just a little sanity check.
 */
	if (skb == NULL) {
		if (ppp->flags & SC_DEBUG)
			printk (KERN_WARNING "ppp_dev_xmit: null packet!\n");
		return 0;
	}
/*
 * Avoid timing problem should tty hangup while data is queued to be sent
 */
	if (!ppp->inuse) {
		dev_kfree_skb (skb, FREE_WRITE);
		dev_close (dev);
		return 0;
	}
/*
 * Validate the tty linkage
 */
	if (ppp->flags & SC_DEBUG)
		printk (KERN_DEBUG "ppp_dev_xmit [%s]: skb %X\n",
			dev->name, (int) skb);
/*
 * Validate the tty interface
 */
	if (tty == NULL) {
		if (ppp->flags & SC_DEBUG)
			printk (KERN_ERR
				"ppp_dev_xmit: %s not connected to a TTY!\n",
				dev->name);
		dev_kfree_skb (skb, FREE_WRITE);
		return 0;
	}
/*
 * Fetch the pointer to the data
 */
	data  = skb_data (skb);
/*
 * Look at the protocol in the skb to determine the difference between
 * an IP frame and an IPX frame.
 */

#ifdef NEW_SKBUFF
	switch (skb->protocol) {
	case htons (ETH_P_IPX):
		answer = ppp_dev_xmit_ipx (dev, ppp, data, skb->len, PPP_IPX);
		break;

	case htons (ETH_P_IP):
		answer = ppp_dev_xmit_ip (dev, ppp, data);
		break;

	default: /* All others have no support at this time. */
		dev_kfree_skb (skb, FREE_WRITE);
		return 0;
	}
#else
	answer = ppp_dev_xmit_ip (dev, ppp, data);
#endif

/*
 * This is the end of the transmission. Release the buffer if it was sent.
 */
	if (answer == 0)
		dev_kfree_skb (skb, FREE_WRITE);
	return answer;
}

/*
 * Generate the statistic information for the /proc/net/dev listing.
 */

static struct enet_statistics *
ppp_dev_stats (struct device *dev)
{
	struct ppp *ppp = dev2ppp (dev);
	static struct enet_statistics ppp_stats;

	ppp_stats.rx_packets          = ppp->stats.ppp_ipackets;
	ppp_stats.rx_errors           = ppp->stats.ppp_ierrors;
	ppp_stats.rx_dropped          = ppp->stats.ppp_ierrors;
	ppp_stats.rx_fifo_errors      = 0;
	ppp_stats.rx_length_errors    = 0;
	ppp_stats.rx_over_errors      = 0;
	ppp_stats.rx_crc_errors       = 0;
	ppp_stats.rx_frame_errors     = 0;
	ppp_stats.tx_packets          = ppp->stats.ppp_opackets;
	ppp_stats.tx_errors           = ppp->stats.ppp_oerrors;
	ppp_stats.tx_dropped          = 0;
	ppp_stats.tx_fifo_errors      = 0;
	ppp_stats.collisions          = 0;
	ppp_stats.tx_carrier_errors   = 0;
	ppp_stats.tx_aborted_errors   = 0;
	ppp_stats.tx_window_errors    = 0;
	ppp_stats.tx_heartbeat_errors = 0;

	if (ppp->flags & SC_DEBUG)
		printk (KERN_INFO "ppp_dev_stats called");
	return &ppp_stats;
}

#ifdef NEW_SKBUFF
/*
 *	The PPP protocol is currently pure IP (no IPX yet). This defines
 *      the protocol layer which is blank since the driver does all the
 *      cooking.
 */

static int ppp_dev_input (struct protocol *self, struct protocol *lower,
			  sk_buff *skb, void *saddr, void *daddr)
{
	return protocol_pass_demultiplex(self, NULL, skb, NULL, NULL);
}

static int ppp_dev_output (struct protocol *self, sk_buff *skb, int type,
			   int subid, void *saddr, void *daddr, void *opt)
{
	if(skb->dev==NULL)
	{
		printk("ppp_dev_output: No device.\n");
		kfree_skb(skb, FREE_WRITE);
		return -1;
	}
	dev_queue_xmit(skb, skb->dev, skb->priority);
	return 0;
}

static int ppp_dev_getkey(int protocol, int subid, unsigned char *key)
{
	switch (protocol)
	{
	case htons (ETH_P_IP):
	case htons (ETH_P_IPX):
		return 0;

	default:
		break;
	}

	return -EAFNOSUPPORT;
}

#else

/*
 * Called to enquire about the type of the frame in the buffer. Return
 * ETH_P_IP for an IP frame, ETH_P_IPX for an IPX frame.
 */

static unsigned short
ppp_dev_type (sk_buff *skb, struct device *dev)
{
	return (htons (ETH_P_IP));
}

static int
ppp_dev_header (u_char * buff, struct device *dev, unsigned short type,
		void *daddr, void *saddr, unsigned len, sk_buff *skb)
{
	return (0);
}

static int
ppp_dev_rebuild (void *buff, struct device *dev, unsigned long raddr,
		 sk_buff *skb)
{
	return (0);
}
#endif

/*************************************************************
 * UTILITIES
 *    Miscellany called by various functions above.
 *************************************************************/

/* allocate or create a PPP channel */
static struct ppp *
ppp_alloc (void)
{
#if 1
	int		if_num;
	int		status;
	ppp_ctrl_t	*ctl;
	struct device	*dev;
	struct ppp	*ppp;

	/* try to find an free device */
	ctl      = ppp_list;
	if_num   = 0;
  
	while (ctl) {
		ppp = ctl2ppp (ctl);
		if (!set_bit(0, &ppp->inuse))
			return (ppp);
		ctl = ctl->next;
		if (++if_num == INT_MAX)
			return (NULL);
	}
/*
 * There are no available items. Allocate a device from the system pool
 */
	ctl = (ppp_ctrl_t *) kmalloc (sizeof(ppp_ctrl_t), GFP_KERNEL);
	if (ctl) {
		(void) memset(ctl, 0, sizeof(ppp_ctrl_t));
		ppp = ctl2ppp (ctl);
		dev = ctl2dev (ctl);

		/* initialize channel control data */
		set_bit(0, &ppp->inuse);

		ppp->line      = if_num;
		ppp->tty       = NULL;
		ppp->dev       = dev;
    
		dev->next      = NULL;
		dev->init      = ppp_init_dev;
		dev->name      = ctl->name;
		dev->base_addr = (unsigned long) if_num;
		dev->priv      = (void *) ppp;

		sprintf (dev->name, "ppp%d", if_num);
    
		/* link in the new channel */
		ctl->next      = ppp_list;
		ppp_list       = ctl;

/* register device so that we can be ifconfig'd */
/* ppp_init_dev() will be called as a side-effect */

		status = register_netdev (dev);
		if (status == 0) {
			printk ("registered device %s\n", dev->name);
			return (ppp);
		}

		printk (KERN_ERR
		       "ppp_alloc - register_netdev(%s) = %d failure.\n",
			dev->name, status);
		/* This one will forever be busy as it is not initialized */
	}
	return (NULL);
#else
  int i;
  for (i = 0; i < PPP_NRUNIT; i++)
    if (!set_bit(0, &ppp_ctrl[i].inuse)) return &ppp_ctrl[i];

  return NULL;
#endif
}

/*
 * Utility procedures to print a buffer in hex/ascii
 */

static void
ppp_print_hex (register u_char * out, u_char * in, int count)
{
	register u_char next_ch;
	static char hex[] = "0123456789ABCDEF";

	while (count-- > 0) {
		next_ch = *in++;
		*out++ = hex[(next_ch >> 4) & 0x0F];
		*out++ = hex[next_ch & 0x0F];
		++out;
	}
}

static void
ppp_print_char (register u_char * out, u_char * in, int count)
{
	register u_char next_ch;

	while (count-- > 0) {
		next_ch = *in++;

		if (next_ch < 0x20 || next_ch > 0x7e)
			*out++ = '.';
		else {
			*out++ = next_ch;
			if (next_ch == '%')   /* printk/syslogd has a bug !! */
				*out++ = '%';
		}
	}
	*out = '\0';
}

static void
ppp_print_buffer (const u_char * name, u_char * buf, int count)
{
	u_char line[44];

	if (name != (u_char *) NULL)
		printk (KERN_DEBUG "ppp: %s, count = %d\n", name, count);

	while (count > 8) {
		memset (line, 32, 44);
		ppp_print_hex (line, buf, 8);
		ppp_print_char (&line[8 * 3], buf, 8);
		printk (KERN_DEBUG "%s\n", line);
		count -= 8;
		buf += 8;
	}

	if (count > 0) {
		memset (line, 32, 44);
		ppp_print_hex (line, buf, count);
		ppp_print_char (&line[8 * 3], buf, count);
		printk (KERN_DEBUG "%s\n", line);
	}
}

/*************************************************************
 * Module support routines
 *************************************************************/

#ifdef MODULE
char kernel_version[] = UTS_RELEASE;

int
init_module(void)
{
	int status;

	/* register our line disciplines */
	status = ppp_first_time();
	if (status != 0) {
		printk (KERN_INFO
		       "PPP: ppp_init() failure %d\n", status);
	}
	return (status);
}

void
cleanup_module(void)
{
	int status;
	ppp_ctrl_t *ctl, *next_ctl;
	struct device *dev;
	struct ppp *ppp;
	int busy_flag = MOD_IN_USE;
/*
 * Ensure that the devices are not in operation.
 */
	if (!busy_flag) {
		ctl = ppp_list;
		while (ctl) {
			ppp = ctl2ppp (ctl);
			if (ppp->inuse && ppp->tty != NULL) {
				busy_flag = 1;
				break;
			}

			dev = ctl2dev (ctl);
			if (dev->start || dev->flags & IFF_UP) {
				busy_flag = 1;
				break;
			}
			ctl = ctl->next;
		}
	}

	if (busy_flag) {
		printk (KERN_INFO
			"PPP: device busy, remove delayed\n");
		return;
	}
/*
 * Release the tty registration of the line dicipline so that no new entries
 * may be created.
 */
	status = tty_register_ldisc (N_PPP, NULL);
	if (status != 0)
		printk (KERN_INFO
			"PPP: Unable to unregister ppp line discipline "
			"(err = %d)\n", status);
	else
		printk (KERN_INFO
			"PPP: ppp line discipline successfully unregistered\n");
/*
 * De-register the devices so that there is no problem with them
 */	
	next = ppp_list;
	while (next) {
		ctl = next;
		ppp = ctl2ppp (ctl);
		dev = ctl2dev (ctl);

		ppp_release (ppp);
		unregister_netdev (dev);
/*
 * Release the storage occupied by the control structures
 */
		next = ctl->next;
		kfree (ctl);
	}
}
#endif
