/*
   PPP for Linux

   $Id: ppp.c,v 1.3 1994/12/08 02:03:55 paulus Exp $
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
			
   NEW_SKBUFF	      - Use NET3.020 sk_buff's
*/

/* #define NEW_SKBUFF */
#define OPTIMIZE_FLAG_TIME  ((HZ * 3)/2)	/* */

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
#define skb_data(skb)	((skb)->data)
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

#ifndef PPP_IPX
#define PPP_IPX 0x2b  /* IPX protocol over PPP */
#endif

/*
 * Local functions
 */

static void ppp_init_ctrl_blk (register struct ppp *);
static void ppp_kick_tty (struct ppp *, struct ppp_buffer *bfr);
static int ppp_doframe (struct ppp *);
static int ppp_do_ip (struct ppp *, unsigned short, u_char *, int);
static int ppp_us_queue (struct ppp *, unsigned short, u_char *, int);
static struct ppp *ppp_alloc (void);
static void ppp_print_buffer (const u_char *, u_char *, int, int);
extern inline void ppp_stuff_char (struct ppp *ppp,
				   register struct ppp_buffer *buf,
				   register u_char chr);
extern inline int lock_buffer (register struct ppp_buffer *buf);

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
#define ASSERT(p) if (!p) PRINTK ((KERN_CRIT "assertion failed: " # p))
#define PRINTKN(n,p) {if (ppp_debug >= n) PRINTK (p)}
#define CHECK_PPP(a)  if (!ppp->inuse) { PRINTK ((ppp_warning, __LINE__)) return a;}
#define CHECK_PPP_VOID()  if (!ppp->inuse) { PRINTK ((ppp_warning, __LINE__)) return;}

#define in_xmap(ppp,c)	(ppp->xmit_async_map[(c) >> 5] & (1 << ((c) & 0x1f)))
#define in_rmap(ppp,c)	((((unsigned int) (u_char) (c)) < 0x20) && \
			ppp->recv_async_map & (1 << (c)))

#define bset(p,b)	((p)[(b) >> 5] |= (1 << ((b) & 0x1f)))

/* Buffer types */
#define BUFFER_TYPE_DEV_RD    0  /* ppp? read buffer      */
#define BUFFER_TYPE_TTY_WR    1  /* tty? write buffer     */
#define BUFFER_TYPE_DEV_WR    2  /* ppp? write buffer     */
#define BUFFER_TYPE_TTY_RD    3  /* tty? read buffer      */
#define BUFFER_TYPE_VJ        4  /* vj compression buffer */

/* Define this string only once for all macro envocations */
static char ppp_warning[] = KERN_WARNING "PPP: ALERT! not INUSE! %d\n";

static int first_time           = 1;
static char szVersion[]         = PPP_VERSION;
static int ppp_debug            = 5;
static int ppp_debug_netpackets = 0;
static struct tty_ldisc ppp_ldisc;
static struct ppp       ppp_ctrl   [PPP_NRUNIT];
 
#ifdef NEW_SKBUFF
struct protocol proto_ppp;
#endif

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

/*************************************************************
 * INITIALIZATION
 *************************************************************/

/* called at boot time for each ppp device */

int
ppp_init (struct device *dev)
{
	struct ppp *ppp;
	int i;

	ppp = &ppp_ctrl[dev->base_addr];

	if (first_time) {
		first_time = 0;

		printk (KERN_INFO "PPP: version %s (%d channels)"
#ifdef NEW_SKBUFF
			" NEW_SKBUFF"
#endif
			"\n", szVersion, PPP_NRUNIT);

		printk (KERN_INFO
			"TCP compression code copyright 1989 Regents of the "
			"University of California\n");

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

		i = tty_register_ldisc (N_PPP, &ppp_ldisc);
		if (i == 0) {
			printk (KERN_INFO "PPP line discipline registered.\n");
		} else {
			printk (KERN_ERR "error registering line discipline: %d\n", i);
		}

#ifdef NEW_SKBUFF  
		memset (&proto_ppp, 0, sizeof (proto_ppp));

		proto_ppp.name          = "PPP";
		proto_ppp.output        = ppp_dev_output;
		proto_ppp.input         = ppp_dev_input;
		proto_ppp.bh_input      = ppp_dev_input;
		proto_ppp.control_event = default_protocol_control;
		proto_ppp.get_binding   = ppp_dev_getkey;

		protocol_register(&proto_ppp);
#endif

	}
	/* initialize PPP control block */
	ppp_init_ctrl_blk (ppp);
	ppp->inuse = 0;
	ppp->line  = dev->base_addr;
	ppp->tty   = NULL;
	ppp->dev   = dev;

	/* clear statistics */
	memset (&ppp->p, '\0', sizeof (struct ppp_stats));

#ifdef NEW_SKBUFF  
	dev->default_protocol = &proto_ppp;	/* Our protocol layer is PPP */
#else
	dev->hard_header      = ppp_dev_header;
	dev->type_trans       = ppp_dev_type;
	dev->rebuild_header   = ppp_dev_rebuild;
	dev->hard_header_len  = 0;
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

	for (i = 0; i < DEV_NUMBUFFS; i++) {
		skb_queue_head_init (&dev->buffs[i]);
	}

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
	memset (&ppp->p, '\0', sizeof (struct ppp_stats));

	/* Reset the demand dial information */
	ppp->ddinfo.ip_sjiffies  =
	ppp->ddinfo.ip_rjiffies  =
	ppp->ddinfo.nip_sjiffies =
	ppp->ddinfo.nip_rjiffies = jiffies;
}

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
	if (ptr != NULL) {
		kfree (ptr);
	}
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
	if (state == 0) {
		buf->locked = 2;
	}
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
	dev = ppp->dev;
	mru = new_mru;
	mtu = (new_mtu * 2) + 20;

	/* RFC 1331, section 7.2 says the minimum value is 1500 bytes */
	if (mru < PPP_MRU) {
		mru = PPP_MRU;
	}
	mru += 10;

	PRINTKN (2, (KERN_INFO "ppp: channel %s mtu = %d, mru = %d\n",
		     dev->name, new_mtu, new_mru));

	new_wbuf = ppp_alloc_buf (mtu + 4, BUFFER_TYPE_DEV_WR);
	new_tbuf = ppp_alloc_buf ((PPP_MTU * 2) + 24, BUFFER_TYPE_TTY_WR);
	new_rbuf = ppp_alloc_buf (mru + 84, BUFFER_TYPE_DEV_RD);
	new_cbuf = ppp_alloc_buf (mru + 4, BUFFER_TYPE_VJ);
/*
 *  If the buffers failed to allocate then complain and release the partial
 *  allocations.
 */
	if (new_wbuf == NULL || new_tbuf == NULL ||
	    new_rbuf == NULL || new_cbuf == NULL) {
		PRINTKN (2,(KERN_ERR "ppp: failed to allocate new buffers\n"));
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
	ppp->toss = 0xE0;	/* To ignore characters until new FLAG */
	ppp->escape = 0;	/* No pending escape character */

	dev->mtu   =
	ppp->mtu   = new_mtu;
	ppp->mru   = new_mru;

	ppp->s1buf = NULL;
	ppp->s2buf = NULL;
	ppp->xbuf  = NULL;

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
 * Called to release all of the information in the current PPP structure.
 *
 * It is called when the ppp device goes down or if it is unable to go
 * up.
 */

static void
ppp_release (struct ppp *ppp)
{
	if (ppp->tty != NULL && ppp->tty->disc_data == ppp) {
		ppp->tty->disc_data = NULL;	/* Break the tty->ppp link */
	}
	if (ppp->dev) {
		ppp->dev->flags &= ~IFF_UP;	/* down the device */
		ppp->dev->flags |= IFF_POINTOPOINT;
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
	ppp->tty = NULL;
}

/*
 * Device callback.
 *
 * Called when the PPP device goes down in response to an ifconfig request.
 */

static void
ppp_tty_close (struct tty_struct *tty)
{
	struct ppp *ppp = (struct ppp *) tty->disc_data;

	if (ppp == NULL || ppp->magic != PPP_MAGIC) {
		PRINTKN (1,
		     (KERN_WARNING "ppp: trying to close unopened tty!\n"));
	} else {
		CHECK_PPP_VOID ();
		PRINTKN (2,
		  (KERN_INFO "ppp: channel %s closing.\n", ppp->dev->name));
		ppp_release (ppp);
	}
}

/*
 * TTY callback.
 *
 * Called when the tty dicipline is switched to PPP.
 */

static int
ppp_tty_open (struct tty_struct *tty)
{
	struct ppp *ppp = (struct ppp *) tty->disc_data;
/*
 * There should not be an existing table for this slot.
 */
	if (ppp) {
		PRINTKN (1, (KERN_ERR
		      "ppp_tty_open: gack! tty already associated to %s!\n",
			     ppp->magic == PPP_MAGIC ? ppp->dev->name
			     : "unknown"));
		return -EEXIST;
	}
/*
 * Allocate the structure from the system
 */
	ppp = ppp_alloc ();
	if (ppp == NULL) {
		PRINTKN (1, (KERN_ERR
			  "ppp_tty_open: couldn't allocate ppp channel\n"));
		return -ENFILE;
	}
/*
 * Initialize the control block
 */
	ppp_init_ctrl_blk (ppp);
	ppp->tty       = tty;
	tty->disc_data = ppp;
/*
 * Flush any pending characters in the driver and dicipline.
 */
	if (tty->ldisc.flush_buffer) {
		tty->ldisc.flush_buffer (tty);
	}

	if (tty->driver.flush_buffer) {
		tty->driver.flush_buffer (tty);
	}
/*
 * Allocate space for the default VJ header compression slots (16)
 */
	ppp->slcomp = slhc_init (16, 16);
	if (ppp->slcomp == NULL) {
		PRINTKN (1, (KERN_ERR
		      "ppp_tty_open: no space for compression buffers!\n"));
		ppp_release (ppp);
		return -ENOMEM;
	}
/*
 * Allocate space for the MTU and MRU buffers
 */
	if (ppp_changedmtu (ppp, ppp->dev->mtu, ppp->mru) == 0) {
		ppp_release (ppp);
		return -ENOMEM;
	}
/*
 * Allocate space for a user level buffer
 */
	ppp->ubuf = ppp_alloc_buf (RBUFSIZE, BUFFER_TYPE_TTY_RD);
	if (ppp->ubuf == NULL) {
		PRINTKN (1, (KERN_ERR
		       "ppp_tty_open: no space for user receive buffer\n"));
		ppp_release (ppp);
		return -ENOMEM;
	}

	PRINTKN (2, (KERN_INFO "ppp: channel %s open\n", ppp->dev->name));
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
	        ppp->p.ppp_oerrors++;
		actual = count;
	} else {
		ppp->bytes_sent += actual;
	}
/*
 * If the buffer has been transmitted then clear the indicators.
 */
	xbuf->tail += actual;
	if (actual == count) {
		xbuf = NULL;
		ppp->flags &= ~SC_XMIT_BUSY;
/*
 * Complete the transmisson on the current buffer.
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
			if (ppp->dev->flags & IFF_UP) {
			        ppp->dev->tbusy = 0;
				mark_bh (NET_BH);
				dev_tint (ppp->dev);
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
	struct ppp *ppp = (struct ppp *) tty->disc_data;

	if (!ppp || ppp->magic != PPP_MAGIC) {
		PRINTKN (1, (KERN_ERR "PPP: write_wakeup called but couldn't "
			     "find PPP struct.\n"));
		return;
	}
/*
 * Ensure that there is a transmission pending. Clear the re-entry flag if
 * there is no pending buffer. Otherwise, send the buffer.
 */
	xbuf = ppp->xbuf;
	if (xbuf == NULL) {
		tty->flags &= ~(1 << TTY_DO_WRITE_WAKEUP);
	} else {
		ppp_tty_wakeup_code (ppp, tty, xbuf);
	}
}

/*
 * This function is called to transmit a buffer to the rmeote. The buffer
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
		if (xbuf->type == BUFFER_TYPE_TTY_WR) {
			ppp->s1buf = xbuf;
		} else {
			ppp->s2buf = xbuf;
		}
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
	ppp_tty_wakeup_code (ppp, ppp->tty, xbuf);
}

/*************************************************************
 * TTY INPUT
 *    The following functions handle input that arrives from
 *    the TTY.	It recognizes PPP frames and either hands them
 *    to the network layer or queues them for delivery to a
 *    user process reading this TTY.
 *************************************************************/

#ifdef CHECK_CHARACTERS
static unsigned paritytab[8] =
{
	0x96696996, 0x69969669, 0x69969669, 0x96696996,
	0x69969669, 0x96696996, 0x96696996, 0x69969669
};
#endif

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
	register struct ppp *ppp = (struct ppp *) tty->disc_data;
	register struct ppp_buffer *buf = ppp->rbuf;
	u_char chr;
/*
 * Verify the table pointer and ensure that the line is still in PPP dicipline.
 */
	if (!ppp || ppp->magic != PPP_MAGIC) {
		PRINTKN (1, ("PPP: handler called but couldn't find "
			     "PPP struct.\n"));
		return;
	}
	CHECK_PPP_VOID ();
/*
 * Print the buffer if desired
 */
	if (ppp_debug >= 5) {
		ppp_print_buffer ("receive buffer", data, count, KERNEL_DS);
	}
/*
 * Collect the character and error condition for the character. Set the toss
 * flag for the first character error.
 */
	while (count-- > 0) {
		ppp->bytes_rcvd++;
		chr = *data++;
		if (flags) {
			if (*flags && ppp->toss == 0) {
				ppp->toss = *flags;
			}
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
		if (chr & 0x80) {
			ppp->flags |= SC_RCV_B7_1;
		} else {
			ppp->flags |= SC_RCV_B7_0;
		}

		if (paritytab[chr >> 5] & (1 << (chr & 0x1F))) {
			ppp->flags |= SC_RCV_ODDP;
		} else {
			ppp->flags |= SC_RCV_EVNP;
		}
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
			ppp->p.ppp_ibytes = ppp->bytes_rcvd;
			if (ppp->escape) {
				ppp->toss |= 0x80;
			}
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
 * recieve mask then ignore the character.
 */
		default:
			if (in_rmap (ppp, chr)) {
				break;
			}
/*
 * Adjust the character and if the frame is to be discarded then simply
 * ignore the character until the ending FLAG is received.
 */
			chr ^= ppp->escape;
			ppp->escape = 0;

			if (ppp->toss != 0) {
				break;
			}
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
			ppp->p.ppp_ierrors++;
			ppp->toss |= 0xC0;
			break;
		}
	}
}

/* on entry, a received frame is in ppp->rbuf.bufr
   check it and dispose as appropriate */

static int
ppp_doframe (struct ppp *ppp)
{
	u_short proto;
	u_char *data = buf_base (ppp->rbuf);
	int count    = ppp->rbuf->count;
/*
 * If there is a pending error from the receiver then log it and discard
 * the damaged frame.
 */
	if (ppp->toss) {
		PRINTKN (1, (KERN_WARNING
			     "ppp_toss: tossing frame, reason = %d\n",
			     ppp->toss));
		ppp->p.ppp_ierrors++;
		return 0;
	}
/*
 * An empty frame is ignored. This occurs if the FLAG sequence precedes and
 * follows each frame.
 */
	if (count == 0) {
		return 1;
	}
/*
 * Print the received data.
 */
	if (ppp_debug >= 3) {
		ppp_print_buffer ("receive frame", data, count, KERNEL_DS);
	}
/*
 * Generate an error if the frame is too small.
 */
	if (count < 4) {
		PRINTKN (1, (KERN_WARNING
			     "ppp: got runt ppp frame, %d chars\n", count));
		ppp->p.ppp_ierrors++;
		return 1;
	}
/*
 * Verify the CRC of the frame and discard the CRC characters from the
 * end of the buffer.
 */
	if (ppp->rbuf->fcs != PPP_GOODFCS) {
		PRINTKN (1, (KERN_WARNING
			     "ppp: frame with bad fcs, excess = %x\n",
			     ppp->rbuf->fcs ^ PPP_GOODFCS));
		ppp->p.ppp_ierrors++;
		return 0;
	}
	count -= 2;		/* ignore the fcs characters */
/*
 * Ignore the leading ADDRESS and CONTROL fields in the frame.
 */
	if ((data[0] == PPP_ALLSTATIONS) && (data[1] == PPP_UI)) {
		data  += 2;
		count -= 2;
	}

	proto = (u_short) * data++;	/* PROTO compressed */
	if (proto & 1) {
		count--;
	} else {
		proto = (proto << 8) | (u_short) * data++;
		count -= 2;
	}

	/* Send the frame to the network if the ppp device is up */
	if (ppp->dev->flags & IFF_UP) {
		if (ppp_do_ip (ppp, proto, data, count)) {
			ppp->ddinfo.ip_rjiffies = jiffies;
			return 1;
		}
	}

	/* If we got here, it has to go to a user process doing a read,
	   so queue it. */
	if (ppp_us_queue (ppp, proto, data, count)) {
		ppp->ddinfo.nip_rjiffies = jiffies;
		return 1;
	}

	/* couldn't cope. */
	PRINTKN (1, (KERN_WARNING
	     "ppp: dropping packet on the floor: nobody could take it.\n"));
	ppp->p.ppp_ierrors++;
	return 1;
}

/* Examine packet at C, attempt to pass up to net layer.
   PROTO is the protocol field from the PPP frame.
   Return 1 if could handle it, 0 otherwise.  */

static int
ppp_do_ip (struct ppp *ppp, unsigned short proto, u_char * data, int count)
{
	sk_buff *skb;
/*
 * Log the IP information
 */
	PRINTKN (4, (KERN_DEBUG "ppp_do_ip: proto %x len %d first byte %x\n",
		     (int) proto, count, data[0]));

	if (ppp_debug_netpackets) {
		PRINTK ((KERN_DEBUG "%s <-- proto %x len %d\n", ppp->dev->name,
			 (int) proto, count));
	}
/*
 * If this is uncompressed IP data then receive the data
 */
	switch (proto) {
	case PPP_IP:
		break;
/*
 * For now, reject the IPX frames. Return 1 to indicate that it has been
 * processed so that it is simply discarded.
 */
	case PPP_IPX:
		return 1;
/*
 * Process compressed IP frame. If the remote told us to reject frames then
 * do so now. Otherwise ensure that there is space in the buffer.
 */
	case PPP_VJC_COMP:
		if (ppp->flags & SC_REJ_COMP_TCP) {
			return 1;
		}
/*
 * Uncompress the header. We now can _guarantee_ that there is room.
 */
		count = slhc_uncompress (ppp->slcomp, data, count);
		if (count <= 0) {
			ppp->p.ppp_ierrors++;
			PRINTKN (1, (KERN_NOTICE
				     "ppp: error in VJ decompression\n"));
			return 1;
		}
		proto = PPP_IP;
		break;
/*
 * Process uncompressed IP frame
 */
	case PPP_VJC_UNCOMP:
		if ((ppp->flags & SC_REJ_COMP_TCP) == 0) {
			if (slhc_remember (ppp->slcomp,
					   data, count) <= 0) {
				ppp->p.ppp_ierrors++;
				PRINTKN (1, (KERN_NOTICE
					  "ppp: error in VJ memorizing\n"));
				return 1;
			}
		}
		proto = PPP_IP;
		break;
/*
 * The frame is not a valid IP frame. Ignore it.
 */
	default:
		return 0;
	}
/*
 * If debugging net packets then print the information. Process the IP
 * frames first.
 */
	if (ppp_debug_netpackets && proto == PPP_IP) {
		struct iphdr *iph = (struct iphdr *) data;
		PRINTK ((KERN_INFO
			"%s <--	  src %lx dst %lx len %d\n",
			ppp->dev->name,
			iph->saddr,
			iph->daddr,
			count));
	}
/*
 * Generate a skb buffer for the new frame.
 */
	skb = alloc_skb (count, GFP_ATOMIC);
	if (skb == NULL) {
		PRINTK ((KERN_ERR
			 "ppp_do_ip: packet dropped on %s (no memory)!\n",
			 ppp->dev->name));
	}
/*
 * Move the received data from the input buffer to the skb buffer.
 */
	else {

		skb->len = count;	/* Store the length */
		skb->dev = ppp->dev;	/* We are the device */
		memcpy ((u_char *) skb_data(skb), data, count);	/* move data */
/*
 * Tag the frame and kick it to the proper receive routine
 */
		skb->free = 1;
		netif_rx (skb);	/* Receive the buffer */
	}
	return 1;
}

/* stuff packet at BUF, length LEN, into the us_rbuff buffer
   prepend PROTO information */

static int
ppp_us_queue (struct ppp *ppp, unsigned short proto, u_char * data, int len)
{
	int totlen;
	register int current_idx;
/*
 * The total length includes the protocol data.
 * Lock the user information buffer.
 */
	if (set_bit (0, &ppp->ubuf->locked)) {
		PRINTKN (1, (KERN_NOTICE "ppp_us_queue: can't get lock\n"));
		return 0;
	}
	current_idx = ppp->ubuf->head;

#define PUTC(c)						\
{							\
    buf_base (ppp->ubuf) [current_idx++] = (u_char) (c);\
    current_idx &= ppp->ubuf->size;			\
    if (current_idx == ppp->ubuf->tail)	{		\
	    goto failure;				\
    }							\
}

/*
 * Insert the buffer length (not counted), the protocol, and the data
 */
	totlen = len + 2;
	PUTC (totlen >> 8);
	PUTC (totlen);

	PUTC (proto >> 8);
	PUTC (proto);

	while (len-- > 0) {
		PUTC (*data++);
	}
#undef PUTC
/*
 * The frame is complete. Update the head pointer and wakeup the pppd
 * process.
 */
	ppp->ubuf->head = current_idx;

	clear_bit (0, &ppp->ubuf->locked);	 /* Unlock the buffer header */
	wake_up_interruptible (&ppp->read_wait); /* select() processing */
	if (ppp->tty->fasync != NULL) {
		kill_fasync (ppp->tty->fasync, SIGIO);	/* SIGIO processing */
	}

	PRINTKN (3, (KERN_INFO "ppp: successfully queued %d bytes\n", totlen));
	return 1;
/*
 * The buffer is full. Unlock the header and return the failure condition.
 */
      failure:
	clear_bit (0, &ppp->ubuf->locked);
	PRINTKN (1, (KERN_NOTICE "ppp_us_queue: ran out of buffer space.\n"));
	return 0;
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
	struct ppp *ppp = (struct ppp *) tty->disc_data;
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
		PRINTKN (1, (KERN_ERR
			     "ppp_tty_read: cannnot find ppp channel\n"));
		return -EIO;
	}
	CHECK_PPP (-ENXIO);

	PRINTKN (4, (KERN_DEBUG "ppp_tty_read: called %x num %u\n",
		     (unsigned int) buf,
		     nr));
/*
 * Acquire the read lock.
 */
	for (;;) {
		if (set_bit (0, &ppp->ubuf->locked) != 0) {
			PRINTKN (3, (KERN_DEBUG
				     "ppp_tty_read: sleeping(ubuf)\n"));

			current->timeout = 0;
			current->state = TASK_INTERRUPTIBLE;
			schedule ();

			if (current->signal & ~current->blocked) {
				return -EINTR;
			}
			continue;
		}
/*
 * Fetch the length of the buffer from the first two bytes.
 */
		if (ppp->ubuf->head == ppp->ubuf->tail) {
			len = 0;
		} else {
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
				PRINTKN (4, (KERN_DEBUG
				  "ppp_tty_read: no data (EWOULDBLOCK)\n"));
				return -EWOULDBLOCK;
			}
			current->timeout = 0;
			PRINTKN (3, (KERN_DEBUG
				     "ppp_tty_read: sleeping(read_wait)\n"));
			interruptible_sleep_on (&ppp->read_wait);
			if (current->signal & ~current->blocked) {
				return -EINTR;
			}
			continue;
		}
/*
 * Reset the time of the last read operation.
 */
		ppp->ddinfo.nip_rjiffies = jiffies;
		PRINTKN (4, (KERN_DEBUG "ppp_tty_read: len = %d\n", len));
/*
 * Ensure that the frame will fit within the caller's buffer. If not, then
 * discard the frame from the input buffer and return an error to the caller.
 */
		if (len + 2 > nr) {
			/* Can't copy it, update us_rbuff_head */
			PRINTKN (1, (KERN_DEBUG
			   "ppp: read of %u bytes too small for %d frame\n",
				     nr, len + 2));
			ppp->ubuf->tail += len;
			ppp->ubuf->tail &= ppp->ubuf->size;
			clear_bit (0, &ppp->ubuf->locked);
			ppp->p.ppp_ierrors++;
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
		PRINTKN (3,
		(KERN_DEBUG "ppp_tty_read: passing %d bytes up\n", len));
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
	if ((buf->count < 0) || (buf->count > 3000)) {
		PRINTK ((KERN_DEBUG "ppp_stuff_char: %x %d\n",
			 (unsigned int) buf->count,
			 (unsigned int) buf->count))
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
 * write a frame with NR chars from BUF to TTY
 * we have to put the FCS field on ourselves
 */

static int
ppp_tty_write (struct tty_struct *tty, struct file *file, u_char * buf,
	       unsigned int count)
{
	struct ppp *ppp = (struct ppp *) tty->disc_data;
	int indx;
	unsigned short write_fcs;
/*
 * Verify the pointer to the PPP data and that the tty is still in PPP mode.
 */
	if (!ppp || ppp->magic != PPP_MAGIC) {
		PRINTKN (1,(KERN_ERR "ppp_tty_write: cannot find ppp unit\n"));
		return -EIO;
	}
	CHECK_PPP (-ENXIO);
/*
 * Detech a change in the transfer size
 */
	if (ppp->mtu != ppp->dev->mtu) {    /* Someone has been ifconfigging */
		ppp_changedmtu (ppp,
				ppp->dev->mtu,
				ppp->mru);
	}
/*
 * Ensure that the caller does not wish to send too much.
 */
	if (count > PPP_MTU) {
		PRINTKN (1, (KERN_WARNING
		"ppp_tty_write: truncating user packet from %u to mtu %d\n",
			     count, PPP_MTU));
		count = PPP_MTU;
	}
/*
 * Print the buffer
 */
	if (ppp_debug >= 3) {
		ppp_print_buffer ("write frame", buf, count, USER_DS);
	}
/*
 * lock this PPP unit so we will be the only writer;
 * sleep if necessary
 */
	while (lock_buffer (ppp->tbuf) != 0) {
		current->timeout = 0;
		PRINTKN (3, (KERN_DEBUG "ppp_tty_write: sleeping\n"));
		interruptible_sleep_on (&ppp->write_wait);
		if (current->signal & ~current->blocked) {
			return -EINTR;
		}
	}
/*
 * OK, locked.	Add the leading FLAG character to the buffer.
 */
	PRINTKN (4, (KERN_DEBUG "ppp_tty_write: acquired write lock\n"));
	ppp->tbuf->count = 0;

#ifdef OPTIMIZE_FLAG_TIME
	if (jiffies - ppp->last_xmit > OPTIMIZE_FLAG_TIME) {
		ins_char (ppp->tbuf, PPP_FLAG);
	}
	ppp->last_xmit = jiffies;
#else
	ins_char (ppp->tbuf, PPP_FLAG);
#endif
/*
 * Add the data for the frame to the buffer.
 */
	ppp->tbuf->fcs = PPP_INITFCS;
	indx = count;
	while (indx-- > 0) {
		register char chr = get_fs_byte (buf++);
		ppp_stuff_char (ppp, ppp->tbuf, chr);
	}
/*
 * Add the trailing CRC and the final flag character
 */
	write_fcs = ppp->tbuf->fcs ^ 0xFFFF;
	ppp_stuff_char (ppp, ppp->tbuf, write_fcs);
	ppp_stuff_char (ppp, ppp->tbuf, write_fcs >> 8);

	PRINTKN (4, (KERN_DEBUG "ppp_tty_write: fcs is %hx\n", write_fcs));
/*
 * Add the trailing FLAG character
 */
	ins_char (ppp->tbuf, PPP_FLAG);
/*
 * Update the time and print the data to the debug log.
 */
	ppp->ddinfo.nip_sjiffies = jiffies;

	if (ppp_debug >= 6) {
		ppp_print_buffer ("xmit buffer",
				  buf_base (ppp->tbuf),
				  ppp->tbuf->count,
				  KERNEL_DS);
	} else {
		PRINTKN (4, (KERN_DEBUG
		    "ppp_tty_write: writing %d chars\n", ppp->tbuf->count));
	}
/*
 * Start the transmitter and the request is complete.
 */
	ppp->p.ppp_obytes += ppp->tbuf->count;
	++ppp->p.ppp_opackets;

	ppp_kick_tty (ppp, ppp->tbuf);
	return ((int) count);
}

/*
 * Process the IOCTL event for the tty device.
 */

static int
ppp_tty_ioctl (struct tty_struct *tty, struct file *file, unsigned int param2,
	       unsigned long param3)
{
	struct ppp *ppp = (struct ppp *) tty->disc_data;
	register int temp_i = 0;
	int error;
/*
 * Verify the status of the PPP device.
 */
	if (!ppp || ppp->magic != PPP_MAGIC) {
		PRINTK ((KERN_ERR
			 "ppp_tty_ioctl: can't find PPP block from tty!\n"));
		return -EBADF;
	}
	CHECK_PPP (-ENXIO);
/*
 * The user must have an euid of root to do these requests.
 */
	if (!suser ()) {
		return -EPERM;
	}
/*
 * Set the MRU value
 */
	switch (param2) {
	case PPPIOCSMRU:
		error = verify_area (VERIFY_READ, (void *) param3,
				     sizeof (temp_i));
		if (error == 0) {
			PRINTKN (3, (KERN_INFO
				 "ppp_tty_ioctl: set mru to %x\n", temp_i));
			temp_i = (int) get_fs_long (param3);
			if (ppp->mru != temp_i) {
				ppp_changedmtu (ppp, ppp->dev->mtu, temp_i);
			}
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
			PRINTKN (3, (KERN_DEBUG
			    "ppp_tty_ioctl: get flags: addr %lx flags %x\n",
				     param3, temp_i));
		}
		break;
/*
 * Set the flags for the various options
 */
	case PPPIOCSFLAGS:
		error = verify_area (VERIFY_READ, (void *) param3,
				     sizeof (temp_i));
		if (error == 0) {
			temp_i = (int) get_fs_long (param3);
			ppp->flags ^= ((ppp->flags ^ temp_i) & SC_MASK);
			PRINTKN (3, (KERN_INFO
			       "ppp_tty_ioctl: set flags to %x\n", temp_i));
		}
		break;
/*
 * Retrieve the transmit async map
 */
	case PPPIOCGASYNCMAP:
		error = verify_area (VERIFY_WRITE, (void *) param3,
				     sizeof (temp_i));
		if (error == 0) {
			put_fs_long (ppp->xmit_async_map[0], param3);
			PRINTKN (3, (KERN_INFO
			"ppp_tty_ioctl: get asyncmap: addr %lx asyncmap %lx\n",
				     param3, ppp->xmit_async_map[0]));
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
			PRINTKN (3, (KERN_INFO
				     "ppp_tty_ioctl: set xmit asyncmap %lx\n",
				     ppp->xmit_async_map[0]));
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
			PRINTKN (3, (KERN_INFO
				     "ppp_tty_ioctl: set rcv asyncmap %lx\n",
				     ppp->recv_async_map));
		}
		break;
/*
 * Obtain the unit number for this device.
 */
	case PPPIOCGUNIT:
		error = verify_area (VERIFY_WRITE, (void *) param3,
				     sizeof (temp_i));
		if (error == 0) {
			put_fs_long (ppp->dev->base_addr, param3);
			PRINTKN (3,
				 (KERN_INFO "ppp_tty_ioctl: get unit: %d",
				  ppp->dev->base_addr));
		}
		break;
/*
 * Set the debug level
 */
	case PPPIOCSDEBUG:
		error = verify_area (VERIFY_READ, (void *) param3,
				     sizeof (temp_i));
		if (error == 0) {
			ppp_debug = (int) get_fs_long (param3);
			ppp_debug_netpackets = (ppp_debug & 0xff00) >> 8;
			ppp_debug &= 0xff;
			PRINTKN (1, (KERN_INFO
			"ppp_tty_ioctl: set debug level %d, netpacket %d\n",
				     ppp_debug, ppp_debug_netpackets));
		}
		break;
/*
 * Get the debug level
 */
	case PPPIOCGDEBUG:
		error = verify_area (VERIFY_WRITE, (void *) param3,
				     sizeof (temp_i));
		if (error == 0) {
			put_fs_long ((long) (ppp_debug |
					    (ppp_debug_netpackets << 8)),
				     param3);

			PRINTKN (3, (KERN_INFO
				     "ppp_tty_ioctl: get debug level %d\n",
				  ppp_debug | (ppp_debug_netpackets << 8)));
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
			PRINTKN (3, (KERN_INFO
				 "ppp_tty_ioctl: read demand dial info\n"));
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
			PRINTKN (3, (KERN_INFO
				 "ppp_tty_ioctl: get xasyncmap: addr %lx\n",
				     param3));
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
			temp_tbl[1]  = 0x00000000;
			temp_tbl[2] &= ~0x40000000;
			temp_tbl[3] |= 0x60000000;

			if ((temp_tbl[2] & temp_tbl[3]) != 0 ||
			    (temp_tbl[4] & temp_tbl[5]) != 0 ||
			    (temp_tbl[6] & temp_tbl[7]) != 0) {
				error = -EINVAL;
			} else {
				memcpy (ppp->xmit_async_map, temp_tbl,
					sizeof (ppp->xmit_async_map));
				PRINTKN (3, (KERN_INFO
					 "ppp_tty_ioctl: set xasyncmap\n"));
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
			PRINTKN (3, (KERN_INFO
				     "ppp_tty_ioctl: set maxcid to %d\n",
				     temp_i));
			if (ppp->slcomp != NULL) {
				slhc_free (ppp->slcomp);
			}
			ppp->slcomp = slhc_init (temp_i, temp_i);

			if (ppp->slcomp == NULL) {
				PRINTKN (1, (KERN_ERR
				"ppp: no space for compression buffers!\n"));
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
		PRINTKN (1, (KERN_ERR
			     "ppp_tty_ioctl: invalid ioctl: %x, addr %lx\n",
			     param2,
			     param3));

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
	struct ppp *ppp = (struct ppp *) tty->disc_data;
	int result = 1;
/*
 * Verify the status of the PPP device.
 */
	if (!ppp || ppp->magic != PPP_MAGIC) {
		PRINTK ((KERN_ERR
		       "ppp_tty_select: can't find PPP block from tty!\n"));
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
		if (tty->flags & (1 << TTY_SLAVE_CLOSED)) {
			break;
		}
		/* Is this a local link and the modem disconnected? */
		if (tty_hung_up_p (filp)) {
			break;
		}
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
	struct ppp *ppp = &ppp_ctrl[dev->base_addr];

	/* reset POINTOPOINT every time, since dev_close zaps it! */
	dev->flags |= IFF_POINTOPOINT;

	if (ppp->tty == NULL) {
		PRINTKN (1,
		(KERN_ERR "ppp: %s not connected to a TTY! can't go open!\n",
		 dev->name));
		return -ENXIO;
	}

	PRINTKN (2, (KERN_INFO "ppp: channel %s going up for IP packets!\n",
		     dev->name));

	CHECK_PPP (-ENXIO);
	return 0;
}

/*
 * Callback from the network layer when the ppp device goes down.
 */

static int
ppp_dev_close (struct device *dev)
{
	struct ppp *ppp = &ppp_ctrl[dev->base_addr];

	if (ppp->tty == NULL) {
		PRINTKN (1,
		(KERN_ERR "ppp: %s not connected to a TTY! can't go down!\n",
		 dev->name));
		return -ENXIO;
	}
/*
 * We don't do anything about the device going down. It is not important
 * for us.
 */
	PRINTKN (2, (KERN_INFO "ppp: channel %s going down for IP packets!\n",
		     dev->name));
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
		memcpy (&temp.p, &ppp->p, sizeof (struct pppstat));
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
	struct ppp *ppp = &ppp_ctrl[dev->base_addr];
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
 * Send a frame to the remote.
 */

int
ppp_dev_xmit (sk_buff *skb, struct device *dev)
{
	struct tty_struct *tty;
	struct ppp *ppp;
	u_char *data;
	unsigned short proto;
	int len;
	unsigned short write_fcs;
/*
 * just a little sanity check.
 */
	if (skb == NULL) {
		PRINTKN (3, (KERN_WARNING "ppp_dev_xmit: null packet!\n"));
		return 0;
	}
/*
 * Fetch the poitners to the data
 */
	ppp   = &ppp_ctrl[dev->base_addr];
	tty   = ppp->tty;
	data  = (u_char *) (&skb[1]);
	len   = skb->len;
	proto = PPP_IP;

	PRINTKN (4, (KERN_DEBUG "ppp_dev_xmit [%s]: skb %lX busy %d\n",
		     dev->name,
		     (unsigned long int) skb, ppp->wbuf->locked));

	CHECK_PPP (0);
/*
 * Validate the tty interface
 */
	do {
		if (tty == NULL) {
			PRINTKN (1,
			(KERN_ERR "ppp_dev_xmit: %s not connected to a TTY!\n",
				  dev->name));
			break;
		}
/*
 * Ensure that the PPP device is still up
 */
		if (!(dev->flags & IFF_UP)) {
			PRINTKN (1, (KERN_WARNING
				"ppp_dev_xmit: packet sent on interface %s,"
				" which is down for IP\n",
				dev->name));
			break;
		}
/*
 * Detect a change in the transfer size
 */
		if (ppp->mtu != ppp->dev->mtu) {
			ppp_changedmtu (ppp,
					ppp->dev->mtu,
					ppp->mru);
		}
/*
 * Fetch the length from the IP header.
 */
		if (len < sizeof (struct iphdr)) {
			PRINTKN (0, (KERN_ERR
			    "ppp_dev_xmit: given runt packet, ignoring\n"));
			break;
		}
		len = ntohs (((struct iphdr *) skb_data(skb))->tot_len);
/*
 * Acquire the lock on the transmission buffer. If the buffer was busy then
 * mark the device as busy and return "failure to send, try back later" error.
 */
		if (lock_buffer (ppp->wbuf) != 0) {
			dev->tbusy = 1;
			return 1;
		}
/*
 * At this point, the buffer will be transmitted. There is no other exit.
 *
 * Try to compress the header.
 */
		if (ppp->flags & SC_COMP_TCP) {
			/* last 0 argument says don't compress connection ID */
			len = slhc_compress (ppp->slcomp, data, len,
					     buf_base (ppp->cbuf),
					     &data, 0);

			if (data[0] & SL_TYPE_COMPRESSED_TCP) {
				proto = PPP_VJC_COMP;
			} else {
				if (data[0] >= SL_TYPE_UNCOMPRESSED_TCP) {
					proto   = PPP_VJC_UNCOMP;
					data[0] = (data[0] & 0x0f) | 0x40;
				}
			}
		}

		if (ppp_debug_netpackets) {
			struct iphdr *iph = (struct iphdr *) skb_data(skb);
			PRINTK ((KERN_DEBUG "%s ==> proto %x len %d src %x "
				 "dst %x proto %d\n",
			dev->name, (int) proto, (int) len, (int) iph->saddr,
				 (int) iph->daddr, (int) iph->protocol))
		}
/*
 * Insert the leading FLAG character
 */
		ppp->wbuf->count = 0;

#ifdef OPTIMIZE_FLAG_TIME
		if (jiffies - ppp->last_xmit > OPTIMIZE_FLAG_TIME) {
			ins_char (ppp->wbuf, PPP_FLAG);
		}
		ppp->last_xmit = jiffies;
#else
		ins_char (ppp->wbuf, PPP_FLAG);
#endif

		ppp->wbuf->fcs = PPP_INITFCS;
/*
 * Insert the address and control data
 */
		if (!(ppp->flags & SC_COMP_AC)) {
			ppp_stuff_char (ppp, ppp->wbuf, PPP_ALLSTATIONS);
			ppp_stuff_char (ppp, ppp->wbuf, PPP_UI);
		}
/*
 * Insert the protocol.
 */
		if (!(ppp->flags & SC_COMP_PROT) || (proto & 0xff00)) {
			ppp_stuff_char (ppp, ppp->wbuf, proto >> 8);
		}
		ppp_stuff_char (ppp, ppp->wbuf, proto);
/*
 * Insert the data
 */
		while (len-- > 0) {
			ppp_stuff_char (ppp, ppp->wbuf, *data++);
		}
/*
 * Add the trailing CRC and the final flag character
 */
		write_fcs = ppp->wbuf->fcs ^ 0xFFFF;
		ppp_stuff_char (ppp, ppp->wbuf, write_fcs);
		ppp_stuff_char (ppp, ppp->wbuf, write_fcs >> 8);

		PRINTKN (4,
		      (KERN_DEBUG "ppp_dev_xmit: fcs is %hx\n", write_fcs));
/*
 * Add the trailing flag character
 */
		ins_char (ppp->wbuf, PPP_FLAG);
/*
 * Update the times for the transmission.
 */
		ppp->ddinfo.ip_sjiffies = jiffies;
/*
 * Print the buffer
 */
		if (ppp_debug >= 6) {
			ppp_print_buffer ("xmit buffer", buf_base (ppp->wbuf),
					  ppp->wbuf->count, KERNEL_DS);
		} else {
			PRINTKN (4, (KERN_DEBUG
				     "ppp_dev_xmit: writing %d chars\n",
				     ppp->wbuf->count));
		}
/*
 * Send the block to the tty driver.
 */
		ppp->p.ppp_obytes += ppp->wbuf->count;
		++ppp->p.ppp_opackets;
		ppp_kick_tty (ppp, ppp->wbuf);
	}
	while (0);
/*
 * This is the end of the transmission. Release the buffer.
 */
	dev_kfree_skb (skb, FREE_WRITE);
	return 0;
}

static struct enet_statistics *
ppp_dev_stats (struct device *dev)
{
	struct ppp *ppp = &ppp_ctrl[dev->base_addr];
	static struct enet_statistics ppp_stats;

	ppp_stats.rx_packets          = ppp->p.ppp_ipackets;
	ppp_stats.rx_errors           = ppp->p.ppp_ierrors;
	ppp_stats.rx_dropped          = ppp->p.ppp_ierrors;
	ppp_stats.rx_fifo_errors      = 0;
	ppp_stats.rx_length_errors    = 0;
	ppp_stats.rx_over_errors      = 0;
	ppp_stats.rx_crc_errors       = 0;
	ppp_stats.rx_frame_errors     = 0;
	ppp_stats.tx_packets          = ppp->p.ppp_opackets;
	ppp_stats.tx_errors           = ppp->p.ppp_oerrors;
	ppp_stats.tx_dropped          = 0;
	ppp_stats.tx_fifo_errors      = 0;
	ppp_stats.collisions          = 0;
	ppp_stats.tx_carrier_errors   = 0;
	ppp_stats.tx_aborted_errors   = 0;
	ppp_stats.tx_window_errors    = 0;
	ppp_stats.tx_heartbeat_errors = 0;

	PRINTKN (3, (KERN_INFO "ppp_dev_stats called"));
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
	case ETH_P_IP:
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

/* allocate a PPP channel */
static struct ppp *
ppp_alloc (void)
{
	int i;
	for (i = 0; i < PPP_NRUNIT; i++) {
		if (!set_bit (0, &ppp_ctrl[i].inuse)) {
			return &ppp_ctrl[i];
		}
	}
	return NULL;
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
		next_ch = (u_char) get_fs_byte (in);
		*out++ = hex[(next_ch >> 4) & 0x0F];
		*out++ = hex[next_ch & 0x0F];
		++out;
		++in;
	}
}

static void
ppp_print_char (register u_char * out, u_char * in, int count)
{
	register u_char next_ch;

	while (count-- > 0) {
		next_ch = (u_char) get_fs_byte (in);

		if (next_ch < 0x20 || next_ch > 0x7e) {
			*out++ = '.';
		} else {
			*out++ = next_ch;
			if (next_ch == '%') { /* printk/syslogd has a bug !! */
				*out++ = '%';
			}
		}
		++in;
	}
	*out = '\0';
}

static void
ppp_print_buffer (const u_char * name, u_char * buf, int count, int seg)
{
	u_char line[44];
	int old_fs = get_fs ();

	set_fs (seg);

	if (name != (u_char *) NULL) {
		PRINTK ((KERN_DEBUG "ppp: %s, count = %d\n", name, count));
	}
	while (count > 8) {
		memset (line, ' ', sizeof (line));
		ppp_print_hex (line, buf, 8);
		ppp_print_char (&line[8 * 3], buf, 8);
		PRINTK ((KERN_DEBUG "%s\n", line));
		count -= 8;
		buf += 8;
	}

	if (count > 0) {
		memset (line, ' ', sizeof (line));
		ppp_print_hex (line, buf, count);
		ppp_print_char (&line[8 * 3], buf, count);
		PRINTK ((KERN_DEBUG "%s\n", line));
	}
	set_fs (old_fs);
}
