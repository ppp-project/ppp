/*  PPP for Linux
 *
 *  Michael Callahan <callahan@maths.ox.ac.uk>
 *  Al Longyear <longyear@netcom.com>
 *  Paul Mackerras <Paul.Mackerras@cs.anu.edu.au>
 *
 *  Dynamic PPP devices by Jim Freeman <jfree@caldera.com>.
 *  ppp_tty_receive ``noisy-raise-bug'' fixed by Ove Ewerlid <ewerlid@syscon.uu.se>
 *
 *  ==FILEVERSION 971205==
 *
 *  NOTE TO MAINTAINERS:
 *     If you modify this file at all, please set the number above to the
 *     date of the modification as YYMMDD (year month day).
 *     ppp.c is shipped with a PPP distribution as well as with the kernel;
 *     if everyone increases the FILEVERSION number above, then scripts
 *     can do the right thing when deciding whether to install a new ppp.c
 *     file.  Don't change the format of that line otherwise, so the
 *     installation script can recognize it.
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
			This is 1.5 seconds. If zero then the leading
			flag is always sent.

   CHECK_CHARACTERS   - Enable the checking on all received characters for
			8 data bits, no parity. This adds a small amount of
			processing for each received character.
*/

#define OPTIMIZE_FLAG_TIME	((HZ * 3)/2)

#define CHECK_CHARACTERS	1
#define PPP_COMPRESS		1

/* $Id: ppp.c,v 1.15 1998/02/04 01:38:11 paulus Exp $ */

#include <linux/version.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/sched.h>
#include <linux/types.h>
#include <linux/fcntl.h>
#include <linux/interrupt.h>
#include <linux/ptrace.h>

#undef VERSION
/* a nice define to generate linux version numbers */
#define VERSION(major,minor,patch) (((((major)<<8)+(minor))<<8)+(patch))

#if LINUX_VERSION_CODE < VERSION(2,1,14)
#include <linux/ioport.h>
#endif

#if LINUX_VERSION_CODE >= VERSION(2,1,23)
#include <linux/poll.h>
#endif

#include <linux/in.h>
#include <linux/malloc.h>
#include <linux/tty.h>
#include <linux/errno.h>
#include <linux/sched.h>	/* to get the struct task_struct */
#include <linux/string.h>	/* used in new tty drivers */
#include <linux/signal.h>	/* used in new tty drivers */
#include <asm/system.h>
#include <asm/bitops.h>
#include <linux/if.h>
#include <linux/if_ether.h>
#include <linux/netdevice.h>
#include <linux/skbuff.h>

#if LINUX_VERSION_CODE >= VERSION(2,1,68)
#include <linux/rtnetlink.h>
#endif

#include <linux/inet.h>
#include <linux/ioctl.h>

typedef struct sk_buff	     sk_buff;
#define skb_data(skb)	     ((__u8 *) (skb)->data)

#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/if_arp.h>
#include <net/slhc_vj.h>

#define fcstab	ppp_crc16_table		/* Name of the table in the kernel */
#include <linux/ppp_defs.h>

#include <linux/socket.h>
#include <linux/if_ppp.h>
#include <linux/if_pppvar.h>
#include <linux/ppp-comp.h>

#ifdef CONFIG_KERNELD
#include <linux/kerneld.h>
#endif

#ifndef PPP_IPX
#define PPP_IPX 0x2b  /* IPX protocol over PPP */
#endif

#ifndef PPP_LQR
#define PPP_LQR 0xc025	/* Link Quality Reporting Protocol */
#endif

#if LINUX_VERSION_CODE >= VERSION(2,1,4)
#include <asm/segment.h>
#define GET_USER(error,value,addr) error = get_user(value,addr)
#define COPY_FROM_USER(error,dest,src,size) error = copy_from_user(dest,src,size) ? -EFAULT : 0
#define PUT_USER(error,value,addr) error = put_user(value,addr)
#define COPY_TO_USER(error,dest,src,size) error = copy_to_user(dest,src,size) ? -EFAULT : 0

#if LINUX_VERSION_CODE >= VERSION(2,1,5)
#include <asm/uaccess.h>
#endif

#else  /* 2.0.x and 2.1.x before 2.1.4 */

#define GET_USER(error,value,addr)					  \
do {									  \
	error = verify_area (VERIFY_READ, (void *) addr, sizeof (value)); \
	if (error == 0)							  \
		value = get_user(addr);					  \
} while (0)

#define COPY_FROM_USER(error,dest,src,size)				  \
do {									  \
	error = verify_area (VERIFY_READ, (void *) src, size);		  \
	if (error == 0)							  \
		memcpy_fromfs (dest, src, size);			  \
} while (0)

#define PUT_USER(error,value,addr)					   \
do {									   \
	error = verify_area (VERIFY_WRITE, (void *) addr, sizeof (value)); \
	if (error == 0)							   \
		put_user (value, addr);					   \
} while (0)

#define COPY_TO_USER(error,dest,src,size)				  \
do {									  \
	error = verify_area (VERIFY_WRITE, (void *) dest, size);		  \
	if (error == 0)							  \
		memcpy_tofs (dest, src, size);				  \
} while (0)

#endif

#if LINUX_VERSION_CODE < VERSION(2,1,37)
#define test_and_set_bit(nr, addr)	set_bit(nr, addr)
#endif

#if LINUX_VERSION_CODE < VERSION(2,1,57)
#define signal_pending(p)	((p)->signal & ~(p)->blocked)
#endif

#if LINUX_VERSION_CODE < VERSION(2,1,25)
#define net_device_stats	enet_statistics
#endif

#if LINUX_VERSION_CODE < VERSION(2,1,60)
typedef int		rw_ret_t;
typedef unsigned int	rw_count_t;
#else
typedef ssize_t		rw_ret_t;
typedef size_t		rw_count_t;
#endif

static int ppp_register_compressor (struct compressor *cp);
static void ppp_unregister_compressor (struct compressor *cp);

/*
 * Local functions
 */

static struct compressor *find_compressor (int type);
static void ppp_init_ctrl_blk (register struct ppp *);
static void ppp_kick_tty (struct ppp *, struct ppp_buffer *bfr);
static struct ppp *ppp_alloc (void);
static struct ppp *ppp_find (int pid_value);
static void ppp_print_buffer (const __u8 *, const __u8 *, int);
extern inline void ppp_stuff_char (struct ppp *ppp,
				   register struct ppp_buffer *buf,
				   register __u8 chr);
extern inline int lock_buffer (register struct ppp_buffer *buf);
static int ppp_dev_xmit_ip (struct ppp *ppp, struct ppp_buffer *buf,
			    __u8 *data, int len, enum NPmode npmode);

static int rcv_proto_ip		(struct ppp *, __u16, __u8 *, int);
static int rcv_proto_ipx	(struct ppp *, __u16, __u8 *, int);
static int rcv_proto_vjc_comp	(struct ppp *, __u16, __u8 *, int);
static int rcv_proto_vjc_uncomp (struct ppp *, __u16, __u8 *, int);
static int rcv_proto_unknown	(struct ppp *, __u16, __u8 *, int);
static int rcv_proto_lqr	(struct ppp *, __u16, __u8 *, int);
static void ppp_doframe_lower	(struct ppp *, __u8 *, int);
static int ppp_doframe		(struct ppp *);

static void ppp_proto_ccp (struct ppp *ppp, __u8 *dp, int len, int rcvd);
static int  rcv_proto_ccp (struct ppp *, __u16, __u8 *, int);

#define ins_char(pbuf,c) (buf_base(pbuf) [(pbuf)->count++] = (__u8)(c))

#ifndef OPTIMIZE_FLAG_TIME
#define OPTIMIZE_FLAG_TIME	0
#endif

/*
 * Parameters which may be changed via insmod.
 */

static int  flag_time = OPTIMIZE_FLAG_TIME;

#if LINUX_VERSION_CODE >= VERSION(2,1,19) 
MODULE_PARM(flag_time, "i");
#endif

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
static struct net_device_stats *ppp_dev_stats (struct device *);

#if LINUX_VERSION_CODE < VERSION(2,1,15)
static int ppp_dev_header (sk_buff *, struct device *, __u16,
			   void *, void *, unsigned int);
static int ppp_dev_rebuild (void *eth, struct device *dev,
			    unsigned long raddr, struct sk_buff *skb);
#endif

/*
 * TTY callbacks
 */

static rw_ret_t ppp_tty_read(struct tty_struct *, struct file *, __u8 *,
			     rw_count_t);
static rw_ret_t ppp_tty_write(struct tty_struct *, struct file *, const __u8 *,
			      rw_count_t);
static int ppp_tty_ioctl (struct tty_struct *, struct file *, unsigned int,
			  unsigned long);
#if LINUX_VERSION_CODE < VERSION(2,1,23)
static int ppp_tty_select (struct tty_struct *tty, struct inode *inode,
		      struct file *filp, int sel_type, select_table * wait);
#else
static unsigned int ppp_tty_poll (struct tty_struct *tty, struct file *filp, poll_table * wait);
#endif
static int ppp_tty_open (struct tty_struct *);
static void ppp_tty_close (struct tty_struct *);
static int ppp_tty_room (struct tty_struct *tty);
static void ppp_tty_receive (struct tty_struct *tty, const __u8 * cp,
			     char *fp, int count);
static void ppp_tty_wakeup (struct tty_struct *tty);

#define CHECK_PPP_MAGIC(ppp)	do { \
	if (ppp->magic != PPP_MAGIC) { \
		printk(KERN_WARNING "bad magic for ppp %p at %s:%d\n", \
		       ppp, __FILE__, __LINE__); \
	} \
} while (0)
#define CHECK_PPP(a)	do { \
	CHECK_PPP_MAGIC(ppp); \
	if (!ppp->inuse) { \
		printk (ppp_warning, __LINE__); \
		return a; \
	} \
} while (0)
#define CHECK_PPP_VOID() do { \
	CHECK_PPP_MAGIC(ppp); \
	if (!ppp->inuse) { \
		printk (ppp_warning, __LINE__); \
	} \
} while (0)

#define in_xmap(ppp,c)	(ppp->xmit_async_map[(c) >> 5] & (1 << ((c) & 0x1f)))
#define in_rmap(ppp,c)	((((unsigned int) (__u8) (c)) < 0x20) && \
			ppp->recv_async_map & (1 << (c)))

#define bset(p,b)	((p)[(b) >> 5] |= (1 << ((b) & 0x1f)))

#define tty2ppp(tty)	((struct ppp *) ((tty)->disc_data))
#define dev2ppp(dev)	((struct ppp *) ((dev)->priv))
#define ppp2tty(ppp)	((ppp)->tty)
#define ppp2dev(ppp)	(&(ppp)->dev)

static struct ppp *ppp_list = NULL;
static struct ppp *ppp_last = NULL;

/* Buffer types */
#define BUFFER_TYPE_DEV_RD	0  /* ppp read buffer	    */
#define BUFFER_TYPE_TTY_WR	1  /* tty write buffer	    */
#define BUFFER_TYPE_DEV_WR	2  /* ppp write buffer	    */
#define BUFFER_TYPE_TTY_RD	3  /* tty read buffer	    */
#define BUFFER_TYPE_VJ		4  /* vj compression buffer */

/* Define this string only once for all macro invocations */
static char ppp_warning[] = KERN_WARNING "PPP: ALERT! not INUSE! %d\n";

static char szVersion[]		= PPP_VERSION;

/*
 * Information for the protocol decoder
 */

typedef int (*pfn_proto)  (struct ppp *, __u16, __u8 *, int);

typedef struct ppp_proto_struct {
	int		proto;
	pfn_proto	func;
} ppp_proto_type;

static
ppp_proto_type proto_list[] = {
	{ PPP_IP,	  rcv_proto_ip	       },
	{ PPP_IPX,	  rcv_proto_ipx	       },
	{ PPP_VJC_COMP,	  rcv_proto_vjc_comp   },
	{ PPP_VJC_UNCOMP, rcv_proto_vjc_uncomp },
	{ PPP_LQR,	  rcv_proto_lqr	       },
	{ PPP_CCP,	  rcv_proto_ccp	       },
	{ 0,		  rcv_proto_unknown    }  /* !!! MUST BE LAST !!! */
};

__u16 ppp_crc16_table[256] =
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
static __u32 paritytab[8] =
{
	0x96696996, 0x69969669, 0x69969669, 0x96696996,
	0x69969669, 0x96696996, 0x96696996, 0x69969669
};
#endif

/* local function to store a value into the LQR frame */
extern inline __u8 * store_long (register __u8 *p, register int value) {
	*p++ = (__u8) (value >> 24);
	*p++ = (__u8) (value >> 16);
	*p++ = (__u8) (value >>	 8);
	*p++ = (__u8) value;
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

	printk (KERN_INFO
		"PPP: version %s (demand dialling)"
		"\n", szVersion);

#ifndef MODULE /* slhc module logic has its own copyright announcement */
	printk (KERN_INFO
		"TCP compression code copyright 1989 Regents of the "
		"University of California\n");
#endif

/*
 * Register the tty discipline
 */
	(void) memset (&ppp_ldisc, 0, sizeof (ppp_ldisc));
	ppp_ldisc.magic		= TTY_LDISC_MAGIC;
#if LINUX_VERSION_CODE >= VERSION(2,1,28)
	ppp_ldisc.name          = "ppp";
#endif
	ppp_ldisc.open		= ppp_tty_open;
	ppp_ldisc.close		= ppp_tty_close;
	ppp_ldisc.read		= ppp_tty_read;
	ppp_ldisc.write		= ppp_tty_write;
	ppp_ldisc.ioctl		= ppp_tty_ioctl;
#if LINUX_VERSION_CODE < VERSION(2,1,23)
	ppp_ldisc.select	= ppp_tty_select;
#else
	ppp_ldisc.poll		= ppp_tty_poll;
#endif
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
#if LINUX_VERSION_CODE < VERSION(2,1,15)
	dev->hard_header      = ppp_dev_header;
	dev->rebuild_header   = ppp_dev_rebuild;
#endif

	dev->hard_header_len  = PPP_HDRLEN;

	/* device INFO */
	dev->mtu	      = PPP_MTU;
	dev->hard_start_xmit  = ppp_dev_xmit;
	dev->open	      = ppp_dev_open;
	dev->stop	      = ppp_dev_close;
	dev->get_stats	      = ppp_dev_stats;
	dev->do_ioctl	      = ppp_dev_ioctl;
	dev->addr_len	      = 0;
	dev->tx_queue_len     = 10;
	dev->type	      = ARPHRD_PPP;

#if LINUX_VERSION_CODE < VERSION(2,1,20)
	{
		int    indx;

		for (indx = 0; indx < DEV_NUMBUFFS; indx++)
			skb_queue_head_init (&dev->buffs[indx]);
	}
#else
	dev_init_buffers(dev);
#endif

	/* New-style flags */
	dev->flags	= IFF_POINTOPOINT | IFF_NOARP | IFF_MULTICAST;
#if LINUX_VERSION_CODE < VERSION(2,1,67)
	dev->family	= AF_INET;
	dev->pa_addr	= 0;
	dev->pa_brdaddr = 0;
	dev->pa_mask	= 0;
	dev->pa_alen	= 4; /* sizeof (__u32) */
#endif

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

	ppp->rbuf	= NULL;
	ppp->wbuf	= NULL;
	ppp->ubuf	= NULL;
	ppp->cbuf	= NULL;
	ppp->slcomp	= NULL;
	ppp->read_wait	= NULL;
	ppp->write_wait = NULL;
	ppp->last_xmit	= jiffies - flag_time;
	ppp->last_recv  = jiffies;

	/* clear statistics */
	memset(&ppp->stats, 0, sizeof (struct pppstat));
	memset(&ppp->estats, 0, sizeof(ppp->estats));

	/* PPP compression data */
	ppp->sc_xc_state =
	ppp->sc_rc_state = NULL;
}

#if LINUX_VERSION_CODE < VERSION(2,1,18)
static struct symbol_table ppp_syms = {
#include <linux/symtab_begin.h>
	X(ppp_register_compressor),
	X(ppp_unregister_compressor),
	X(ppp_crc16_table),
#include <linux/symtab_end.h>
};
#else
EXPORT_SYMBOL(ppp_register_compressor);
EXPORT_SYMBOL(ppp_unregister_compressor);
EXPORT_SYMBOL(ppp_crc16_table);
#endif

/* called at boot/load time for each ppp device defined in the kernel */

#ifndef MODULE
int
ppp_init (struct device *dev)
{
	static int first_time = 1;
	int    answer = 0;

	if (first_time) {
		first_time = 0;
		answer	   = ppp_first_time();
#if LINUX_VERSION_CODE < VERSION(2,1,18)
		if (answer == 0)
			(void) register_symtab (&ppp_syms);
#endif
	}
	if (answer == 0)
		answer = -ENODEV;
	return answer;
}
#endif

#define BUFFER_MAGIC	0x1d10
#define CHECK_BUF_MAGIC(buf)	do { \
	if (buf->magic != BUFFER_MAGIC) { \
		printk(KERN_WARNING "bad magic for ppp buffer %p at %s:%d\n", \
		       buf, __FILE__, __LINE__); \
	} \
} while (0)

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
		buf->magic  = BUFFER_MAGIC;
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
		CHECK_BUF_MAGIC(ptr);
		kfree (ptr);
	}
}

/*
 * Lock the indicated transmit buffer
 */

extern inline int
lock_buffer (register struct ppp_buffer *buf)
{
	unsigned long state;
	unsigned long flags;
/*
 * Save the current state and if free then set it to the "busy" state
 */
	CHECK_BUF_MAGIC(buf);
	save_flags (flags);
	cli ();
	state = buf->locked;
	if (state == 0)
		buf->locked = 2;

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
	unsigned long flags;

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
	CHECK_PPP(0);
	dev = ppp2dev (ppp);
	if (ppp->flags & SC_DEBUG)
		printk(KERN_DEBUG "%s: changedmtu %d %d\n", ppp->name,
		       new_mtu, new_mru);
	mru = new_mru;
	/* allow for possible escaping of every character */
	mtu = (new_mtu * 2) + 20;

	/* RFC 1331, section 7.2 says the minimum value is 1500 bytes */
	if (mru < PPP_MRU)
		mru = PPP_MRU;

	mru += 10;

	new_wbuf = ppp_alloc_buf (mtu+PPP_HDRLEN,	BUFFER_TYPE_DEV_WR);
	new_tbuf = ppp_alloc_buf ((PPP_MTU * 2) + 24,	BUFFER_TYPE_TTY_WR);
	new_rbuf = ppp_alloc_buf (mru + 84,		BUFFER_TYPE_DEV_RD);
	new_cbuf = ppp_alloc_buf (mru+PPP_HDRLEN,	BUFFER_TYPE_VJ);
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
	save_flags(flags);
	cli ();
	old_wbuf = ppp->wbuf;
	old_rbuf = ppp->rbuf;
	old_cbuf = ppp->cbuf;
	old_tbuf = ppp->tbuf;

	ppp->wbuf = new_wbuf;
	ppp->rbuf = new_rbuf;
	ppp->cbuf = new_cbuf;
	ppp->tbuf = new_tbuf;

	if (old_wbuf)
		new_wbuf->locked = old_wbuf->locked;

	ppp->rbuf->size -= 80;	/* reserve space for vj header expansion */

	dev->mem_start	= (unsigned long) buf_base (new_wbuf);
	dev->mem_end	= (unsigned long) (dev->mem_start + mtu);
	dev->rmem_start = (unsigned long) buf_base (new_rbuf);
	dev->rmem_end	= (unsigned long) (dev->rmem_start + mru);
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

	ppp->tty->flags &= ~(1 << TTY_DO_WRITE_WAKEUP);
	ppp->flags	&= ~SC_XMIT_BUSY;

	restore_flags(flags);
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

static void
ppp_ccp_closed (struct ppp *ppp)
{
	unsigned long flags;

	save_flags(flags);
	cli();
	ppp->flags &= ~(SC_CCP_OPEN | SC_CCP_UP | SC_COMP_RUN | SC_DECOMP_RUN);
	restore_flags(flags);
	if (ppp->flags & SC_DEBUG)
		printk(KERN_DEBUG "%s: ccp closed\n", ppp->name);
	if (ppp->sc_xc_state) {
		(*ppp->sc_xcomp->comp_free) (ppp->sc_xc_state);
		ppp->sc_xc_state = NULL;
	}

	if (ppp->sc_rc_state) {
		(*ppp->sc_rcomp->decomp_free) (ppp->sc_rc_state);
		ppp->sc_rc_state = NULL;
	}
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
	struct tty_struct *tty;
	struct device *dev;

	CHECK_PPP_MAGIC(ppp);
	tty = ppp2tty (ppp);
	dev = ppp2dev (ppp);

	if (ppp->flags & SC_DEBUG)
		printk(KERN_DEBUG "%s released\n", ppp->name);

	ppp_ccp_closed (ppp);

	/* Ensure that the pppd process is not hanging on select()/poll() */
	wake_up_interruptible (&ppp->read_wait);
	wake_up_interruptible (&ppp->write_wait);

	if (tty != NULL && tty->disc_data == ppp)
		tty->disc_data = NULL;	/* Break the tty->ppp link */

#if LINUX_VERSION_CODE >= VERSION(2,1,68)
	rtnl_lock();
#endif
	/* Strong layering violation. */
	if (dev && dev->flags & IFF_UP) {
		dev_close (dev); /* close the device properly */
	}
#if LINUX_VERSION_CODE >= VERSION(2,1,68)
	rtnl_unlock();
#endif

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
	ppp->backup_tty = NULL;
}

/*
 * TTY callback.
 *
 * Called when the line discipline is changed to something
 * else, the tty is closed, or the tty detects a hangup.
 */

static void
ppp_tty_close (struct tty_struct *tty)
{
	struct ppp *ppp = tty2ppp (tty);

	if (ppp != NULL) {
		if (ppp->magic != PPP_MAGIC) {
			if (ppp->flags & SC_DEBUG)
				printk (KERN_WARNING
				       "ppp: trying to close unopened tty!\n");
			return;
		}
		CHECK_PPP_VOID();
		tty->disc_data = NULL;
		if (tty == ppp->backup_tty)
			ppp->backup_tty = 0;
		if (tty != ppp->tty)
			return;
		if (ppp->backup_tty) {
			ppp->tty = ppp->backup_tty;
		} else {
			ppp->sc_xfer = 0;
			if (ppp->flags & SC_DEBUG)
				printk (KERN_INFO "ppp: channel %s closing.\n",
					ppp2dev(ppp)->name);
			ppp_release (ppp);
			MOD_DEC_USE_COUNT;
		}
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
	int indx;
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
	ppp = ppp_find(current->pid);
	if (ppp != NULL) {
		/*
		 * If we are taking over a ppp unit which is currently
		 * connected to a loopback pty, there's not much to do.
		 */
		CHECK_PPP(-EINVAL);
		tty->disc_data = ppp;
		ppp->tty       = tty;

	} else {
		ppp = ppp_alloc();
		if (ppp == NULL) {
			if (ppp->flags & SC_DEBUG)
				printk (KERN_ERR "ppp_alloc failed\n");
			return -ENFILE;
		}
/*
 * Initialize the control block
 */
		ppp_init_ctrl_blk (ppp);
		tty->disc_data = ppp;
		ppp->tty       = tty;
/*
 * Allocate space for the default VJ header compression slots
 */
		ppp->slcomp = slhc_init (16, 16);
		if (ppp->slcomp == NULL) {
			if (ppp->flags & SC_DEBUG)
				printk (KERN_ERR "ppp_tty_open: "
					"no space for compression buffers!\n");
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
				printk (KERN_ERR "ppp_tty_open: "
					"no space for user receive buffer\n");
			ppp_release (ppp);
			return -ENOMEM;
		}

		if (ppp->flags & SC_DEBUG)
			printk (KERN_INFO "ppp: channel %s open\n",
				ppp2dev(ppp)->name);

		for (indx = 0; indx < NUM_NP; ++indx)
			ppp->sc_npmode[indx] = NPMODE_PASS;

		MOD_INC_USE_COUNT;
	}
/*
 * Flush any pending characters in the driver and discipline.
 */
	if (tty->ldisc.flush_buffer)
		tty->ldisc.flush_buffer (tty);

	if (tty->driver.flush_buffer)
		tty->driver.flush_buffer (tty);
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
	unsigned long flags;

	CHECK_PPP_VOID();
	CHECK_BUF_MAGIC(xbuf);
/*
 * Prevent re-entrancy by ensuring that this routine is called only once.
 */
	save_flags(flags);
	cli ();
	if (ppp->flags & SC_XMIT_BUSY) {
		restore_flags(flags);
		return;
	}
	ppp->flags |= SC_XMIT_BUSY;
	restore_flags(flags);
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
			tty->flags  &= ~(1 << TTY_DO_WRITE_WAKEUP);
			xbuf->locked = 0;
			ppp->xbuf    = NULL;
/*
 * If the completed buffer came from the device write, then complete the
 * transmission block.
 */
			ppp2dev (ppp)->tbusy = 0;
			mark_bh (NET_BH);
/*
 * Wake up the transmission queue for all completion events.
 */
			wake_up_interruptible (&ppp->write_wait);
/*
 * Look at the priorities. Choose a daemon write over the device driver.
 */
			save_flags(flags);
			cli();
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
				restore_flags(flags);
				return;
			}
			restore_flags(flags);
		}
	}
/*
 * Clear the re-entry flag
 */
	save_flags(flags);	/* &=~ may not be atomic */
	cli ();
	ppp->flags &= ~SC_XMIT_BUSY;
	restore_flags(flags);
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

	if (!ppp)
		return;
	CHECK_PPP_VOID();

	if (tty != ppp->tty) {
		tty->flags &= ~(1 << TTY_DO_WRITE_WAKEUP);
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
	unsigned long flags;

	CHECK_PPP_VOID();
	CHECK_BUF_MAGIC(xbuf);
/*
 * Hold interrupts.
 */
	save_flags (flags);
	cli ();
/*
 * Control the flags which are best performed with the interrupts masked.
 */
	xbuf->locked	 = 1;
	xbuf->tail	 = 0;
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
	ppp->flags	&= ~SC_XMIT_BUSY;
	ppp->tty->flags |= (1 << TTY_DO_WRITE_WAKEUP);
	ppp->xbuf	 = xbuf;
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
ppp_tty_receive (struct tty_struct *tty, const __u8 * data,
		 char *flags, int count)
{
	register struct ppp *ppp = tty2ppp (tty);
	register struct ppp_buffer *buf = NULL;
	__u8 chr;

	if (ppp != 0)
		CHECK_PPP_VOID();
	/*
	 * This can happen if stuff comes in on the backup tty.
	 */
	if (ppp == 0 || tty != ppp->tty)
		return;
/*
 * Fetch the pointer to the buffer. Be careful about race conditions.
 */
	buf = ppp->rbuf;
	if (buf == NULL)
		return;
/*
 * Verify the table pointer and ensure that the line is
 * still in PPP discipline.
 */
	if (ppp->magic != PPP_MAGIC) {
		if (ppp->flags & SC_DEBUG)
			printk (KERN_DEBUG
				"PPP: tty_receive called but couldn't find "
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
			if (*flags && ppp->toss == 0) {
				ppp->toss = *flags;
				switch (ppp->toss) {
				case TTY_OVERRUN:
					++ppp->estats.rx_fifo_errors;
					break;
				case TTY_FRAME:
				case TTY_BREAK:
					++ppp->estats.rx_frame_errors;
					break;
				}
			}
			++flags;
		}

/*
 * Set the flags for d7 being 0/1 and parity being even/odd so that
 * the normal processing would have all flags set at the end of the
 * session.  A missing flag bit indicates an error condition.
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
 * Branch on the character.
 */
		switch (chr) {
/*
 * FLAG. This is the end of the block. If the block terminated by ESC FLAG,
 * then the block is to be ignored. In addition, characters before the very
 * first FLAG are also tossed by this procedure.
 */
		case PPP_FLAG:	/* PPP_FLAG: end of frame */
			ppp->stats.ppp_ibytes += ppp->rbuf->count;
			if (ppp->escape)
				ppp->toss |= 0x80;
/*
 * Process frames which are not to be ignored. If the processing failed,
 * then clean up the VJ tables.
 */
			if (ppp_doframe (ppp) == 0) {
				++ppp->stats.ppp_ierrors;
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
			/* If we're tossing, look no further. */
			if (ppp->toss != 0)
				break;

			/* If this is a control char to be ignored, do so */
			if (in_rmap (ppp, chr))
				break;

			/*
			 * Modify the next character if preceded by escape.
			 * The escape character (0x7d) could be an escaped
			 * 0x5d, if it follows an escape :-)
			 */
			if (ppp->escape) {
				chr ^= PPP_TRANS;
				ppp->escape = 0;
			} else if (chr == PPP_ESCAPE) {
				ppp->escape = PPP_TRANS;
				break;
			}

			/*
			 * Decompress A/C and protocol compression here.
			 */
			if (buf->count == 0 && chr != PPP_ALLSTATIONS) {
				buf_base(buf)[0] = PPP_ALLSTATIONS;
				buf_base(buf)[1] = PPP_UI;
				buf->count = 2;
			}
			if (buf->count == 2 && (chr & 1) != 0) {
				buf_base(buf)[2] = 0;
				buf->count = 3;
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
			++ppp->estats.rx_length_errors;
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
	__u8	*data = buf_base (ppp->rbuf);
	int	count = ppp->rbuf->count;
	int	proto;
	int	new_count;
	__u8 *new_data;

	CHECK_PPP(0);
	CHECK_BUF_MAGIC(ppp->rbuf);

/*
 * If there is a pending error from the receiver then log it and discard
 * the damaged frame.
 */
	if (ppp->toss) {
		if ((ppp->flags & SC_DEBUG) && count > 0)
			printk (KERN_DEBUG
				"ppp_toss: tossing frame, reason = %x\n",
				ppp->toss);
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
	if (count < PPP_HDRLEN + 2) {
		if (ppp->flags & SC_DEBUG)
			printk (KERN_DEBUG
				"ppp: got runt ppp frame, %d chars\n", count);
		++ppp->estats.rx_length_errors;
		return 0;
	}
/*
 * Verify the CRC of the frame and discard the CRC characters from the
 * end of the buffer.
 */
	if (ppp->rbuf->fcs != PPP_GOODFCS) {
		if (ppp->flags & SC_DEBUG) {
			printk (KERN_DEBUG
				"ppp: frame with bad fcs, length = %d\n",
				count);
			ppp_print_buffer("bad frame", data, count);
		}
		++ppp->estats.rx_crc_errors;
		return 0;
	}
	count -= 2;		/* ignore the fcs characters */
/*
 * Obtain the protocol from the frame
 */
	proto = PPP_PROTOCOL(data);
/*
 * Process the active decompressor.
 */
	if ((ppp->sc_rc_state != (void *) 0) &&
	    (ppp->flags & SC_DECOMP_RUN)     &&
	    ((ppp->flags & (SC_DC_FERROR | SC_DC_ERROR)) == 0)) {
		if (proto == PPP_COMP) {
/*
 * If the frame is compressed then decompress it.
 */
			new_data = kmalloc (ppp->mru + PPP_HDRLEN, GFP_ATOMIC);
			if (new_data == NULL) {
				if (ppp->flags & SC_DEBUG)
					printk (KERN_ERR
						"ppp_doframe: no memory\n");
				new_count = DECOMP_ERROR;
			} else {
				new_count = (*ppp->sc_rcomp->decompress)
					(ppp->sc_rc_state, data, count,
					 new_data, ppp->mru + PPP_HDRLEN);
			}
			switch (new_count) {
			default:
				ppp_doframe_lower (ppp, new_data, new_count);
				kfree (new_data);
				return 1;

			case DECOMP_ERROR:
				ppp->flags |= SC_DC_ERROR;
				break;

			case DECOMP_FATALERROR:
				ppp->flags |= SC_DC_FERROR;
				if (ppp->flags & SC_DEBUG)
					printk(KERN_ERR "ppp: fatal decomp error\n");
				break;
			}
/*
 * Log the error condition and discard the frame.
 */
			if (new_data != 0)
				kfree (new_data);
			slhc_toss (ppp->slcomp);
			++ppp->stats.ppp_ierrors;
		} else {
/*
 * The frame is not special. Pass it through the compressor without
 * actually compressing the data
 */
			(*ppp->sc_rcomp->incomp) (ppp->sc_rc_state,
						  data, count);
		}
	}
/*
 * Process the uncompressed frame.
 */
	ppp_doframe_lower (ppp, data, count);
	return 1;
}

static void ppp_doframe_lower (struct ppp *ppp, __u8 *data, int count)
{
	__u16		proto = PPP_PROTOCOL (data);
	ppp_proto_type	*proto_ptr;

	CHECK_PPP_VOID();
/*
 * Ignore empty frames
 */
	if (count <= PPP_HDRLEN)
		return;
/*
 * Count the frame and print it
 */
	++ppp->stats.ppp_ipackets;
	if (ppp->flags & SC_LOG_INPKT)
		ppp_print_buffer ("receive frame", data, count);
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
	if ((*proto_ptr->func) (ppp, proto,
				&data[PPP_HDRLEN],
				count - PPP_HDRLEN))
		ppp->stats.ppp_ioctects += count;
	else
		++ppp->stats.ppp_discards;
}

/*
 * Put the input frame into the networking system for the indicated protocol
 */

static int
ppp_rcv_rx (struct ppp *ppp, __u16 proto, __u8 * data, int count)
{
	sk_buff *skb = dev_alloc_skb (count);
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
	skb->dev      = ppp2dev (ppp);	/* We are the device */
	skb->protocol = proto;
	skb->mac.raw  = skb_data(skb);
	memcpy (skb_put(skb,count), data, count);	/* move data */
/*
 * Tag the frame and kick it to the proper receive routine
 */
#if LINUX_VERSION_CODE < VERSION(2,1,15)
	skb->free = 1;
#endif

	ppp->last_recv = jiffies;
	netif_rx (skb);
	return 1;
}

/*
 * Process the receipt of an IP frame
 */

static int
rcv_proto_ip (struct ppp *ppp, __u16 proto, __u8 * data, int count)
{
	CHECK_PPP(0);
	if ((ppp2dev (ppp)->flags & IFF_UP) && (count > 0))
		if (ppp->sc_npmode[NP_IP] == NPMODE_PASS)
			return ppp_rcv_rx (ppp, htons (ETH_P_IP), data, count);
	return 0;
}

/*
 * Process the receipt of an IPX frame
 */

static int
rcv_proto_ipx (struct ppp *ppp, __u16 proto, __u8 * data, int count)
{
	CHECK_PPP(0);
	if (((ppp2dev (ppp)->flags & IFF_UP) != 0) && (count > 0))
		return ppp_rcv_rx (ppp, htons (ETH_P_IPX), data, count);
	return 0;
}

/*
 * Process the receipt of an VJ Compressed frame
 */

static int
rcv_proto_vjc_comp (struct ppp *ppp, __u16 proto,
		    __u8 *data, int count)
{
	CHECK_PPP(0);
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
rcv_proto_vjc_uncomp (struct ppp *ppp, __u16 proto,
		      __u8 *data, int count)
{
	CHECK_PPP(0);
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
rcv_proto_unknown (struct ppp *ppp, __u16 proto,
		   __u8 *data, int len)
{
	int totlen;
	register int current_idx;

#define PUTC(c)						 \
{							 \
    buf_base (ppp->ubuf) [current_idx++] = (__u8) (c); \
    current_idx &= ppp->ubuf->size;			 \
    if (current_idx == ppp->ubuf->tail)			 \
	    goto failure;				 \
}

	CHECK_PPP(0);
/*
 * The total length includes the protocol data.
 * Lock the user information buffer.
 */
	if (test_and_set_bit (0, &ppp->ubuf->locked)) {
		if (ppp->flags & SC_DEBUG)
			printk (KERN_DEBUG
				"ppp: rcv_proto_unknown: can't get lock\n");
	} else {
		CHECK_BUF_MAGIC(ppp->ubuf);
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

		return 1;
/*
 * The buffer is full. Unlock the header
 */
failure:
		clear_bit (0, &ppp->ubuf->locked);
		if (ppp->flags & SC_DEBUG)
			printk (KERN_DEBUG
				"ppp: rcv_proto_unknown: buffer overflow\n");
	}
/*
 * Discard the frame. There are no takers for this protocol.
 */
	if (ppp->flags & SC_DEBUG)
		printk (KERN_DEBUG
			"ppp: rcv_proto_unknown: dropping packet\n");
	return 0;
}

/*
 * Handle a CCP packet.
 *
 * The CCP packet is passed along to the pppd process just like any
 * other PPP frame. The difference is that some processing needs to be
 * immediate or the compressors will become confused on the peer.
 */

static void ppp_proto_ccp (struct ppp *ppp, __u8 *dp, int len, int rcvd)
{
	int slen    = CCP_LENGTH(dp);
	__u8 *opt = dp	 + CCP_HDRLEN;
	int opt_len = slen - CCP_HDRLEN;
	unsigned long flags;

	if (slen > len)
		return;

	save_flags(flags);
	switch (CCP_CODE(dp)) {
	case CCP_CONFREQ:
	case CCP_TERMREQ:
	case CCP_TERMACK:
/*
 * CCP must be going down - disable compression
 */
		if (ppp->flags & SC_CCP_UP) {
			cli();
			ppp->flags &= ~(SC_CCP_UP   |
					SC_COMP_RUN |
					SC_DECOMP_RUN);
		}
		break;

	case CCP_CONFACK:
		if ((ppp->flags & SC_CCP_OPEN) == 0)
			break;
		if (ppp->flags & SC_CCP_UP)
			break;
		if (slen < (CCP_HDRLEN + CCP_OPT_MINLEN))
			break;
		if (slen < (CCP_OPT_LENGTH (opt) + CCP_HDRLEN))
			break;
/*
 * we're agreeing to send compressed packets.
 */
		if (!rcvd) {
			if (ppp->sc_xc_state == NULL)
				break;

			if ((*ppp->sc_xcomp->comp_init)
			    (ppp->sc_xc_state,
			     opt,
			     opt_len,
			     ppp2dev (ppp)->base_addr,
			     0,
			     ppp->flags & SC_DEBUG)) {
				if (ppp->flags & SC_DEBUG)
					printk(KERN_DEBUG "%s: comp running\n",
					       ppp->name);
				cli();
				ppp->flags |= SC_COMP_RUN;
			}
			break;
		}
/*
 * peer is agreeing to send compressed packets.
 */
		if (ppp->sc_rc_state == NULL)
			break;

		if ((*ppp->sc_rcomp->decomp_init)
		    (ppp->sc_rc_state,
		     opt,
		     opt_len,
		     ppp2dev (ppp)->base_addr,
		     0,
		     ppp->mru,
		     ppp->flags & SC_DEBUG)) {
			if (ppp->flags & SC_DEBUG)
				printk(KERN_DEBUG "%s: decomp running\n",
				       ppp->name);
			cli();
			ppp->flags |= SC_DECOMP_RUN;
			ppp->flags &= ~(SC_DC_ERROR | SC_DC_FERROR);
		}
		break;
/*
 * CCP Reset-ack resets compressors and decompressors as it passes through.
 */
	case CCP_RESETACK:
		if ((ppp->flags & SC_CCP_UP) == 0)
			break;

		if (!rcvd) {
			if (ppp->sc_xc_state && (ppp->flags & SC_COMP_RUN)) {
				(*ppp->sc_xcomp->comp_reset)(ppp->sc_xc_state);
				if (ppp->flags & SC_DEBUG)
					printk(KERN_DEBUG "%s: comp reset\n",
					       ppp->name);
			}
		} else {
			if (ppp->sc_rc_state && (ppp->flags & SC_DECOMP_RUN)) {
			      (*ppp->sc_rcomp->decomp_reset)(ppp->sc_rc_state);
			      if (ppp->flags & SC_DEBUG)
					printk(KERN_DEBUG "%s: decomp reset\n",
					       ppp->name);
			      cli();
			      ppp->flags &= ~SC_DC_ERROR;
			}
		}
		break;
	}
	restore_flags(flags);
}

static int
rcv_proto_ccp (struct ppp *ppp, __u16 proto, __u8 *dp, int len)
{
	CHECK_PPP(0);
	ppp_proto_ccp (ppp, dp, len, 1);
	return rcv_proto_unknown (ppp, proto, dp, len);
}

/*
 * Handle a LQR packet.
 */

static int
rcv_proto_lqr (struct ppp *ppp, __u16 proto, __u8 * data, int len)
{
	return rcv_proto_unknown (ppp, proto, data, len);
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

static rw_ret_t
ppp_tty_read (struct tty_struct *tty, struct file *file, __u8 * buf,
	      rw_count_t nr)
{
	struct ppp *ppp = tty2ppp (tty);
	__u8 c;
	rw_ret_t len, ret;
	int error;

#define GETC(c)						\
{							\
	c = buf_base (ppp->ubuf) [ppp->ubuf->tail++];	\
	ppp->ubuf->tail &= ppp->ubuf->size;		\
}

/*
 * Validate the pointers
 */
	if (!ppp)
		return -EIO;

	/* if (ppp->magic != PPP_MAGIC)
		return -EIO; */

	CHECK_PPP (-ENXIO);

/*
 * Before we attempt to write the frame to the user, ensure that the
 * user has access to the pages for the total buffer length.
 */
	error = verify_area (VERIFY_WRITE, buf, nr);
	if (error != 0)
		return (error);

/*
 * Acquire the read lock.
 */
	for (;;) {
		ppp = tty2ppp (tty);
		if (!ppp || ppp->magic != PPP_MAGIC || !ppp->inuse
		    || tty != ppp->tty)
			return 0;

		if (test_and_set_bit (0, &ppp->ubuf->locked) != 0) {
#if 0
			if (ppp->flags & SC_DEBUG)
				printk (KERN_DEBUG
				     "ppp_tty_read: sleeping(ubuf)\n");
#endif
			current->timeout = 0;
			current->state	 = TASK_INTERRUPTIBLE;
			schedule ();

			if (signal_pending(current))
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
			if (len)
				break;
		}

/*
 * If there is no length then wait for the data to arrive.
 */
		/* no data */
		clear_bit (0, &ppp->ubuf->locked);
		if (file->f_flags & O_NONBLOCK)
			return -EAGAIN;
		current->timeout = 0;
#if 0
		if (ppp->flags & SC_DEBUG)
			printk (KERN_DEBUG
				"ppp_tty_read: sleeping(read_wait)\n");
#endif
		interruptible_sleep_on (&ppp->read_wait);
		if (signal_pending(current))
			return -EINTR;
	}

/*
 * Ensure that the frame will fit within the caller's buffer. If not, then
 * discard the frame from the input buffer.
 */
	if (len + 2 > nr) {
		/* Can't copy it, update us_rbuff_head */

		if (ppp->flags & SC_DEBUG)
			printk (KERN_DEBUG
				"ppp: read of %lu bytes too small for %ld "
				"frame\n", (unsigned long) nr, (long) len + 2);
		ppp->stats.ppp_ierrors++;
		error = -EOVERFLOW;
		goto out;
	}

/*
 * Fake the insertion of the ADDRESS and CONTROL information because these
 * were not saved in the buffer.
 */
	PUT_USER (error, (u_char) PPP_ALLSTATIONS, buf);
	if (error)
		goto out;
	++buf;
	PUT_USER (error, (u_char) PPP_UI, buf);
	if (error)
		goto out;
	++buf;

/*
 * Copy the received data from the buffer to the caller's area.
 */
	ret = len + 2; 	/* Account for ADDRESS and CONTROL bytes */
	while (len-- > 0) {
		GETC (c);
		PUT_USER (error, c, buf);
		if (error)
			goto out;
		++buf;
	}

	clear_bit (0, &ppp->ubuf->locked);
	return ret;

out:
	ppp->ubuf->tail += len;
	ppp->ubuf->tail &= ppp->ubuf->size;
	clear_bit (0, &ppp->ubuf->locked);
	return error;
#undef GETC
}

/* stuff a character into the transmit buffer, using PPP's way of escaping
   special characters.
   also, update fcs to take account of new character */

extern inline void
ppp_stuff_char (struct ppp *ppp, register struct ppp_buffer *buf,
		register __u8 chr)
{
/*
 * The buffer should not be full.
 */
	if (ppp->flags & SC_DEBUG) {
		if ((buf->count < 0) || (buf->count > 3000))
			printk (KERN_DEBUG "ppp_stuff_char: %d %x\n",
				(unsigned int) buf->count,
				(unsigned int) chr);
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
 * Procedure to encode the data with the proper escaping and send the
 * data to the remote system.
 */

static void
ppp_dev_xmit_lower (struct ppp *ppp, struct ppp_buffer *buf,
		    __u8 *data, int count, int non_ip)
{
	__u16   write_fcs;
	int	address, control;
	int	proto;

	CHECK_PPP_VOID();
	CHECK_BUF_MAGIC(buf);
	++ppp->stats.ppp_opackets;
	ppp->stats.ppp_ooctects += count;

/*
 * Insert the leading FLAG character
 */
	buf->count = 0;

	if (non_ip || flag_time == 0)
		ins_char (buf, PPP_FLAG);
	else {
		if (jiffies - ppp->last_xmit >= flag_time)
			ins_char (buf, PPP_FLAG);
	}
	ppp->last_xmit = jiffies;
	buf->fcs       = PPP_INITFCS;
/*
 * Emit the address/control information if needed
 */
	address = PPP_ADDRESS  (data);
	control = PPP_CONTROL  (data);
	proto	= PPP_PROTOCOL (data);

	if (address != PPP_ALLSTATIONS ||
	    control != PPP_UI ||
	    (ppp->flags & SC_COMP_AC) == 0) {
		ppp_stuff_char (ppp, buf, address);
		ppp_stuff_char (ppp, buf, control);
	}
/*
 * Emit the protocol (compressed if possible)
 */
	if ((ppp->flags & SC_COMP_PROT) == 0 || (proto & 0xFF00))
		ppp_stuff_char (ppp, buf, proto >> 8);

	ppp_stuff_char (ppp, buf, proto);
/*
 * Insert the data
 */
	data  += 4;
	count -= 4;

	while (count-- > 0)
		ppp_stuff_char (ppp, buf, *data++);
/*
 * Add the trailing CRC and the final flag character
 */
	write_fcs = buf->fcs ^ 0xFFFF;
	ppp_stuff_char (ppp, buf, write_fcs);
	ppp_stuff_char (ppp, buf, write_fcs >> 8);
/*
 * Add the trailing flag character
 */
	ins_char (buf, PPP_FLAG);
/*
 * Send the block to the tty driver.
 */
	ppp->stats.ppp_obytes += buf->count;
	ppp_kick_tty (ppp, buf);
}

/*
 * Compress and send an frame to the peer.
 *
 * Return 0 if frame was queued for transmission.
 *	  1 if frame must be re-queued for later driver support.
 */

static int
ppp_dev_xmit_frame (struct ppp *ppp, struct ppp_buffer *buf,
		    __u8 *data, int count)
{
	int	proto;
	int	address, control;
	__u8 *new_data;
	int	new_count;

	CHECK_PPP(0);
	CHECK_BUF_MAGIC(buf);
/*
 * Print the buffer
 */
	if (ppp->flags & SC_LOG_OUTPKT)
		ppp_print_buffer ("write frame", data, count);
/*
 * Determine if the frame may be compressed. Attempt to compress the
 * frame if possible.
 */
	proto	= PPP_PROTOCOL (data);
	address = PPP_ADDRESS  (data);
	control = PPP_CONTROL  (data);

	if (((ppp->flags & SC_COMP_RUN) != 0)	&&
	    (ppp->sc_xc_state != (void *) 0)	&&
	    (address == PPP_ALLSTATIONS)	&&
	    (control == PPP_UI)			&&
	    (proto != PPP_LCP)			&&
	    (proto != PPP_CCP)) {
		new_data = kmalloc (ppp->mtu, GFP_ATOMIC);
		if (new_data == NULL) {
			if (ppp->flags & SC_DEBUG)
				printk (KERN_ERR
					"ppp_dev_xmit_frame: no memory\n");
			return 1;
		}

		new_count = (*ppp->sc_xcomp->compress)
		    (ppp->sc_xc_state, data, new_data, count, ppp->mtu);

		if (new_count > 0 && (ppp->flags & SC_CCP_UP)) {
			ppp_dev_xmit_lower (ppp, buf, new_data, new_count, 0);
			kfree (new_data);
			return 0;
		}
/*
 * The frame could not be compressed, or it could not be sent in
 * compressed form because CCP is not yet up.
 */
		kfree (new_data);
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
send_revise_frame (register struct ppp *ppp, __u8 *data, int len)
{
	__u8 *p;

	switch (PPP_PROTOCOL (data)) {
/*
 * Update the LQR frame with the current MIB information. This saves having
 * the daemon read old MIB data from the driver.
 */
	case PPP_LQR:
		len = 48;			/* total size of this frame */
		p   = (__u8 *) &data [40];	/* Point to last two items. */
		p   = store_long (p, ppp->stats.ppp_opackets + 1);
		p   = store_long (p, ppp->stats.ppp_ooctects + len);
		break;
/*
 * Outbound compression frames
 */
	case PPP_CCP:
		ppp_proto_ccp (ppp,
			       data + PPP_HDRLEN,
			       len  - PPP_HDRLEN,
			       0);
		break;

	default:
		break;
	}

	return len;
}

/*
 * write a frame with NR chars from BUF to TTY
 * we have to put the FCS field on ourselves
 */

static rw_ret_t
ppp_tty_write (struct tty_struct *tty, struct file *file, const __u8 * data,
	       rw_count_t count)
{
	struct ppp *ppp = tty2ppp (tty);
	__u8 *new_data;
	int error;

/*
 * Verify the pointers.
 */
	if (!ppp)
		return -EIO;

	if (ppp->magic != PPP_MAGIC)
		return -EIO;

	CHECK_PPP (-ENXIO);
/*
 * Ensure that the caller does not wish to send too much.
 */
	if (count > PPP_MTU + PPP_HDRLEN) {
		if (ppp->flags & SC_DEBUG)
			printk (KERN_WARNING
				"ppp_tty_write: truncating user packet "
				"from %lu to mtu %d\n", (unsigned long) count,
				PPP_MTU + PPP_HDRLEN);
		count = PPP_MTU + PPP_HDRLEN;
	}
/*
 * Allocate a buffer for the data and fetch it from the user space.
 */
	new_data = kmalloc (count, GFP_KERNEL);
	if (new_data == NULL) {
		if (ppp->flags & SC_DEBUG)
			printk (KERN_ERR
				"ppp_tty_write: no memory\n");
		return 0;
	}
/*
 * Retrieve the user's buffer
 */
	COPY_FROM_USER (error, new_data, data, count);
	if (error) {
		kfree (new_data);
		return error;
	}
/*
 * lock this PPP unit so we will be the only writer;
 * sleep if necessary
 */
	while (lock_buffer (ppp->tbuf) != 0) {
		current->timeout = 0;
#if 0
		if (ppp->flags & SC_DEBUG)
			printk (KERN_DEBUG "ppp_tty_write: sleeping\n");
#endif
		interruptible_sleep_on (&ppp->write_wait);

		ppp = tty2ppp (tty);
		if (!ppp || ppp->magic != PPP_MAGIC || !ppp->inuse
		    || tty != ppp->tty) {
			kfree (new_data);
			return 0;
		}

		if (signal_pending(current)) {
			kfree (new_data);
			return -EINTR;
		}
	}
/*
 * Change the LQR frame
 */
	count = send_revise_frame (ppp, new_data, count);
/*
 * Send the data
 */
	if (PPP_PROTOCOL(new_data) == PPP_IP) {
		/*
		 * IP frames can be sent by pppd when we're doing
		 * demand-dialling.  We send them via ppp_dev_xmit_ip
		 * to make sure that VJ compression happens properly.
		 */
		ppp_dev_xmit_ip(ppp, ppp->tbuf, new_data + PPP_HDRLEN,
				count - PPP_HDRLEN, NPMODE_PASS);

	} else {
		ppp_dev_xmit_frame (ppp, ppp->tbuf, new_data, count);
	}

	kfree (new_data);
	return (rw_ret_t) count;
}

/*
 * Process the BSD compression IOCTL event for the tty device.
 */

static int
ppp_set_compression (struct ppp *ppp, struct ppp_option_data *odp)
{
	struct compressor *cp;
	struct ppp_option_data data;
	int error;
	int nb;
	__u8 *ptr;
	__u8 ccp_option[CCP_MAX_OPTION_LENGTH];
	unsigned long flags;

/*
 * Fetch the compression parameters
 */
	COPY_FROM_USER (error, &data, odp, sizeof (data));

	if (error != 0)
		return error;

	nb  = data.length;
	ptr = data.ptr;
	if ((__u32) nb >= (__u32)CCP_MAX_OPTION_LENGTH)
		nb = CCP_MAX_OPTION_LENGTH;

	COPY_FROM_USER (error, ccp_option, ptr, nb);

	if (error != 0)
		return error;

	if (ccp_option[1] < 2)	/* preliminary check on the length byte */
		return (-EINVAL);

	save_flags(flags);
	cli();
	ppp->flags &= ~(SC_COMP_RUN | SC_DECOMP_RUN);
	restore_flags(flags);

	cp = find_compressor (ccp_option[0]);
#ifdef CONFIG_KERNELD
	if (cp == NULL) {
		char modname[32];
		sprintf(modname, "ppp-compress-%d", ccp_option[0]);
		request_module(modname);
		cp = find_compressor(ccp_option[0]);
	}
#endif /* CONFIG_KERNELD */

	if (cp != (struct compressor *) 0) {
		/*
		 * Found a handler for the protocol - try to allocate
		 * a compressor or decompressor.
		 */
		error = 0;
		if (data.transmit) {
			if (ppp->sc_xc_state != NULL)
				(*ppp->sc_xcomp->comp_free)(ppp->sc_xc_state);

			ppp->sc_xcomp	 = cp;
			ppp->sc_xc_state = cp->comp_alloc(ccp_option, nb);

			if (ppp->sc_xc_state == NULL) {
				if (ppp->flags & SC_DEBUG)
					printk(KERN_DEBUG "%s: comp_alloc failed\n",
					       ppp->name);
				error = -ENOBUFS;
			} else {
				if (ppp->flags & SC_DEBUG)
					printk(KERN_DEBUG "%s: comp_alloc -> %p\n",
					       ppp->name, ppp->sc_xc_state);
			}
		} else {
			if (ppp->sc_rc_state != NULL)
				(*ppp->sc_rcomp->decomp_free)(ppp->sc_rc_state);
			ppp->sc_rcomp	 = cp;
			ppp->sc_rc_state = cp->decomp_alloc(ccp_option, nb);
			if (ppp->sc_rc_state == NULL) {
				if (ppp->flags & SC_DEBUG)
					printk(KERN_DEBUG "%s: decomp_alloc failed\n",
					       ppp->name);
				error = -ENOBUFS;
			} else {
				if (ppp->flags & SC_DEBUG)
					printk(KERN_DEBUG "%s: decomp_alloc -> %p\n",
					       ppp->name, ppp->sc_rc_state);
			}
		}
		return (error);
	}

	if (ppp->flags & SC_DEBUG)
		printk(KERN_DEBUG "%s: no compressor for [%x %x %x], %x\n",
		       ppp->name, ccp_option[0], ccp_option[1],
		       ccp_option[2], nb);
	return (-EINVAL);	/* no handler found */
}

/*
 * Process the IOCTL event for the tty device.
 */

static int
ppp_tty_ioctl (struct tty_struct *tty, struct file * file,
               unsigned int param2, unsigned long param3)
{
	struct ppp *ppp = tty2ppp (tty);
	register int temp_i = 0;
	int error = 0;
/*
 * Verify the status of the PPP device.
 */
	if (!ppp)
		return -EBADF;

	if (ppp->magic != PPP_MAGIC)
		return -EBADF;

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
		GET_USER (error, temp_i, (int *) param3);
		if (error != 0)
			break;
		if (ppp->flags & SC_DEBUG)
			printk (KERN_INFO
				"ppp_tty_ioctl: set mru to %x\n", temp_i);

		if (ppp->mru != temp_i)
			ppp_changedmtu (ppp, ppp2dev (ppp)->mtu, temp_i);
		break;
/*
 * Fetch the flags
 */
	case PPPIOCGFLAGS:
		temp_i = (ppp->flags & SC_MASK);
#ifndef CHECK_CHARACTERS /* Don't generate errors if we don't check chars. */
		temp_i |= SC_RCV_B7_1 | SC_RCV_B7_0 |
			  SC_RCV_ODDP | SC_RCV_EVNP;
#endif
		PUT_USER (error, temp_i, (int *) param3);
		break;
/*
 * Set the flags for the various options
 */
	case PPPIOCSFLAGS:
		GET_USER (error, temp_i, (int *) param3);
		if (error != 0)
			break;
		temp_i &= SC_MASK;
		temp_i |= (ppp->flags & ~SC_MASK);

		if ((ppp->flags & SC_CCP_OPEN) &&
		    (temp_i & SC_CCP_OPEN) == 0)
			ppp_ccp_closed (ppp);

		if ((ppp->flags | temp_i) & SC_DEBUG)
			printk (KERN_INFO
				"ppp_tty_ioctl: set flags to %x\n", temp_i);
		ppp->flags = temp_i;
		break;
/*
 * Set the compression mode
 */
	case PPPIOCSCOMPRESS:
		error = ppp_set_compression (ppp,
					    (struct ppp_option_data *) param3);
		break;
/*
 * Retrieve the transmit async map
 */
	case PPPIOCGASYNCMAP:
		PUT_USER (error, ppp->xmit_async_map[0], (int *) param3);
		break;
/*
 * Set the transmit async map
 */
	case PPPIOCSASYNCMAP:
		GET_USER (error, temp_i, (int *) param3);
		if (error != 0)
			break;
		ppp->xmit_async_map[0] = temp_i;
		if (ppp->flags & SC_DEBUG)
			printk (KERN_INFO
				"ppp_tty_ioctl: set xmit asyncmap %x\n",
				ppp->xmit_async_map[0]);
		break;
/*
 * Set the receive async map
 */
	case PPPIOCSRASYNCMAP:
		GET_USER (error, temp_i, (int *) param3);
		if (error != 0)
			break;
		ppp->recv_async_map = temp_i;
		if (ppp->flags & SC_DEBUG)
			printk (KERN_INFO
				"ppp_tty_ioctl: set rcv asyncmap %x\n",
				ppp->recv_async_map);
		break;
/*
 * Obtain the unit number for this device.
 */
	case PPPIOCGUNIT:
		PUT_USER (error, ppp2dev (ppp)->base_addr, (int *) param3);
		if (error != 0)
			break;
		if (ppp->flags & SC_DEBUG)
			printk (KERN_INFO
				"ppp_tty_ioctl: get unit: %ld\n",
				ppp2dev (ppp)->base_addr);
		break;
/*
 * Set the debug level
 */
	case PPPIOCSDEBUG:
		GET_USER (error, temp_i, (int *) param3);
		if (error != 0)
			break;
		temp_i	= (temp_i & 0x1F) << 16;
		temp_i |= (ppp->flags & ~0x1F0000);

		if ((ppp->flags | temp_i) & SC_DEBUG)
			printk (KERN_INFO
				"ppp_tty_ioctl: set flags to %x\n", temp_i);
		ppp->flags = temp_i;
		break;
/*
 * Get the debug level
 */
	case PPPIOCGDEBUG:
		temp_i = (ppp->flags >> 16) & 0x1F;
		PUT_USER (error, temp_i, (int *) param3);
		break;
/*
 * Get the times since the last send/receive frame operation
 */
	case PPPIOCGIDLE:
		{
			struct ppp_idle cur_ddinfo;

			/* change absolute times to relative times. */
			cur_ddinfo.xmit_idle = (jiffies - ppp->last_xmit) / HZ;
			cur_ddinfo.recv_idle = (jiffies - ppp->last_recv) / HZ;
			COPY_TO_USER (error, (void *) param3, &cur_ddinfo,
				      sizeof (cur_ddinfo));
		}
		break;
/*
 * Retrieve the extended async map
 */
	case PPPIOCGXASYNCMAP:
		COPY_TO_USER (error, (void *) param3, ppp->xmit_async_map,
			      sizeof (ppp->xmit_async_map));
		break;
/*
 * Set the async extended map
 */
	case PPPIOCSXASYNCMAP:
		{
			__u32 temp_tbl[8];

			COPY_FROM_USER (error, temp_tbl, (void *) param3,
					sizeof (temp_tbl));
			if (error != 0)
				break;

			temp_tbl[1]  =	0x00000000;
			temp_tbl[2] &= ~0x40000000;
			temp_tbl[3] |=	0x60000000;

			if ((temp_tbl[2] & temp_tbl[3]) != 0 ||
			    (temp_tbl[4] & temp_tbl[5]) != 0 ||
			    (temp_tbl[6] & temp_tbl[7]) != 0)
				error = -EINVAL;
			else {
				memcpy (ppp->xmit_async_map,
					temp_tbl,
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
		GET_USER (error, temp_i, (int *) param3);
		if (error != 0)
			break;
		temp_i = (temp_i & 255) + 1;
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
		break;

    case PPPIOCXFERUNIT:
		ppp->backup_tty = tty;
		ppp->sc_xfer = current->pid;
		break;

    case PPPIOCGNPMODE:
    case PPPIOCSNPMODE:
		{
			struct npioctl npi;

			COPY_FROM_USER (error, &npi, (void *) param3,
					sizeof (npi));
			if (error != 0)
				break;

			switch (npi.protocol) {
			case PPP_IP:
				npi.protocol = NP_IP;
				break;
			default:
				if (ppp->flags & SC_DEBUG)
					printk(KERN_DEBUG "pppioc[gs]npmode: "
					       "invalid proto %d\n", npi.protocol);
				error = -EINVAL;
			}

			if (error != 0)
				break;

			if (param2 == PPPIOCGNPMODE) {
				npi.mode = ppp->sc_npmode[npi.protocol];

				COPY_TO_USER (error, (void *) param3, &npi,
					      sizeof (npi));
				break;
			}

			ppp->sc_npmode[npi.protocol] = npi.mode;
			if (ppp->flags & SC_DEBUG)
				printk(KERN_DEBUG "ppp: set np %d to %d\n",
				       npi.protocol, npi.mode);
			ppp2dev(ppp)->tbusy = 0;
			mark_bh(NET_BH);
		}
		break;
/*
 * Allow users to read, but not set, the serial port parameters
 */
	case TCGETS:
	case TCGETA:
		error = n_tty_ioctl (tty, file, param2, param3);
		break;

	case FIONREAD:
		{
			int count = ppp->ubuf->tail - ppp->ubuf->head;
			if (count < 0)
				count += (ppp->ubuf->size + 1);
			PUT_USER (error, count, (int *) param3);
		}
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
 * Process the select() (or poll()) statement for the PPP device.
 */

#if LINUX_VERSION_CODE < VERSION(2,1,23)
static int
ppp_tty_select (struct tty_struct *tty, struct inode *inode,
		struct file *filp, int sel_type, select_table * wait)
{
	struct ppp *ppp = tty2ppp (tty);
	int result = 1;
/*
 * Verify the status of the PPP device.
 */
	if (!ppp)
		return -EBADF;

	if (ppp->magic != PPP_MAGIC || tty != ppp->tty)
		return -EBADF;

	CHECK_PPP (0);
/*
 * Branch on the type of select mode. A read request must lock the user
 * buffer area.
 */
	switch (sel_type) {
	case SEL_IN:
		if (test_and_set_bit (0, &ppp->ubuf->locked) == 0) {
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
		if (tty->flags & (1 << TTY_OTHER_CLOSED))
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

#else	/* 2.1.23 or later */

static unsigned int
ppp_tty_poll (struct tty_struct *tty, struct file *filp, poll_table * wait)
{
	struct ppp *ppp = tty2ppp (tty);
	unsigned int mask = 0;

	if (ppp && ppp->magic == PPP_MAGIC && tty == ppp->tty) {
		CHECK_PPP (0);

		poll_wait(&ppp->read_wait, wait);
		poll_wait(&ppp->write_wait, wait);

		/* Must lock the user buffer area while checking. */
		CHECK_BUF_MAGIC(ppp->ubuf);
		if(test_and_set_bit(0, &ppp->ubuf->locked) == 0) {
			if(ppp->ubuf->head != ppp->ubuf->tail)
				mask |= POLLIN | POLLRDNORM;
			clear_bit(0, &ppp->ubuf->locked);
		}
		if(tty->flags & (1 << TTY_OTHER_CLOSED))
			mask |= POLLHUP;
		if(tty_hung_up_p(filp))
			mask |= POLLHUP;
		if(ppp->tbuf->locked == 0)
			mask |= POLLOUT | POLLWRNORM;
	}
	return mask;
}

#endif

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
	char *result  = (char *) ifr->ifr_ifru.ifru_data;
	int  len      = strlen (szVersion) + 1;
/*
 * Move the version data
 */
	COPY_TO_USER (error, result, szVersion, len);

	return error;
}

/*
 * IOCTL to read the statistics for the pppstats program.
 */

static int
ppp_dev_ioctl_stats (struct ppp *ppp, struct ifreq *ifr, struct device *dev)
{
	struct ppp_stats *result, temp;
	int    error;
/*
 * Supply the information for the caller. First move the version data
 * then move the ppp stats; and finally the vj stats.
 */
	memset (&temp, 0, sizeof(temp));
	if (dev->flags & IFF_UP) {
		memcpy (&temp.p, &ppp->stats, sizeof (struct pppstat));
		if (ppp->slcomp != NULL) {
			temp.vj.vjs_packets    = ppp->slcomp->sls_o_compressed+
						 ppp->slcomp->sls_o_uncompressed;
			temp.vj.vjs_compressed = ppp->slcomp->sls_o_compressed;
			temp.vj.vjs_searches   = ppp->slcomp->sls_o_searches;
			temp.vj.vjs_misses     = ppp->slcomp->sls_o_misses;
			temp.vj.vjs_errorin    = ppp->slcomp->sls_i_error;
			temp.vj.vjs_tossed     = ppp->slcomp->sls_i_tossed;
			temp.vj.vjs_uncompressedin = ppp->slcomp->sls_i_uncompressed;
			temp.vj.vjs_compressedin   = ppp->slcomp->sls_i_compressed;
		}
	}

	result = (struct ppp_stats *) ifr->ifr_ifru.ifru_data;

	COPY_TO_USER (error, result, &temp, sizeof (temp));

	return error;
}

/*
 * IOCTL to read the compression statistics for the pppstats program.
 */

static int
ppp_dev_ioctl_comp_stats (struct ppp *ppp, struct ifreq *ifr, struct device *dev)
{
	struct ppp_comp_stats *result, temp;
	int    error;
/*
 * Supply the information for the caller.
 */
	memset (&temp, 0, sizeof(temp));
	if (dev->flags & IFF_UP) {
		if (ppp->sc_xc_state != NULL)
			(*ppp->sc_xcomp->comp_stat) (ppp->sc_xc_state,
						     &temp.c);

		if (ppp->sc_rc_state != NULL)
			(*ppp->sc_rcomp->decomp_stat) (ppp->sc_rc_state,
						       &temp.d);
	}
/*
 * Move the data to the caller's buffer
 */
	result = (struct ppp_comp_stats *) ifr->ifr_ifru.ifru_data;

	COPY_TO_USER (error, result, &temp, sizeof (temp));

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

	CHECK_PPP_MAGIC(ppp);
/*
 * Process the requests
 */
	switch (cmd) {
	case SIOCGPPPSTATS:
		error = ppp_dev_ioctl_stats (ppp, ifr, dev);
		break;

	case SIOCGPPPCSTATS:
		error = ppp_dev_ioctl_comp_stats (ppp, ifr, dev);
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
 *	  1 if frame must be re-queued for later driver support.
 *	  -1 if frame should be dropped.
 */

static int
ppp_dev_xmit_ip (struct ppp *ppp, struct ppp_buffer *buf,
		 __u8 *data, int len, enum NPmode npmode)
{
	int	proto = PPP_IP;
	__u8	*hdr;
/*
 * Branch on the type of processing for the IP frame.
 */
	switch (npmode) {
	case NPMODE_PASS:
		break;

	case NPMODE_QUEUE:
		/*
		 * We may not send the packet now, so drop it.
		 * XXX It would be nice to be able to return it to the
		 * network system to be queued and retransmitted later.
		 */
		if (ppp->flags & SC_DEBUG)
			printk(KERN_DEBUG "%s: returning frame\n",
			       ppp->name);
		return -1;

	case NPMODE_ERROR:
	case NPMODE_DROP:
		if (ppp->flags & SC_DEBUG)
			printk (KERN_DEBUG
				"ppp_dev_xmit: npmode = %d on %s\n",
				ppp->sc_npmode[NP_IP], ppp->name);
		return -1;

	default:
		if (ppp->flags & SC_DEBUG)
			printk (KERN_WARNING
				"ppp_dev_xmit: unknown npmode %d on %s\n",
				ppp->sc_npmode[NP_IP], ppp->name);
		return -1;
	}
/*
 * At this point, the buffer will be transmitted. There is no other exit.
 *
 * Try to compress the header.
 */
	if (ppp->flags & SC_COMP_TCP) {
		len = slhc_compress (ppp->slcomp, data, len,
				     buf_base (ppp->cbuf) + PPP_HDRLEN,
				     &data,
				     (ppp->flags & SC_NO_TCP_CCID) == 0);

		if (data[0] & SL_TYPE_COMPRESSED_TCP) {
			proto	 = PPP_VJC_COMP;
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
	len  += PPP_HDRLEN;
	hdr   = data - PPP_HDRLEN;

	hdr[0] = PPP_ALLSTATIONS;
	hdr[1] = PPP_UI;
	hdr[2] = 0;
	hdr[3] = proto;

	return ppp_dev_xmit_frame (ppp, buf, hdr, len);
}

/*
 * Send a non-IP data frame (such as an IPX frame) to the remote.
 *
 * Return 0 if frame was queued for transmission.
 *	  1 if frame must be re-queued for later driver support.
 */
static int
ppp_dev_xmit_other (struct device *dev, struct ppp *ppp,
		  __u8 *data, int len, int proto)
{
	__u8	*hdr;
/*
 * Send the frame
 */
	len += PPP_HDRLEN;
	hdr = data - PPP_HDRLEN;

	hdr[0] = PPP_ALLSTATIONS;
	hdr[1] = PPP_UI;
	hdr[2] = proto >> 8;
	hdr[3] = proto;

	return ppp_dev_xmit_frame (ppp, ppp->wbuf, hdr, len);
}

/*
 * Send a frame to the remote.
 */

static int
ppp_dev_xmit (sk_buff *skb, struct device *dev)
{
	int answer, len;
	__u8		  *data;
	struct ppp	  *ppp = dev2ppp (dev);
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
		return 0;
	}
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
	len   = skb->len;
	data  = skb_data(skb);

	if (data == (__u8 *) 0) {
		if (ppp->flags & SC_DEBUG)
			printk (KERN_CRIT "ppp_dev_xmit: %s Null skb data\n",
				dev->name);
		dev_kfree_skb (skb, FREE_WRITE);
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
 * mark the device as busy.
 * We also require that ppp->tbuf be unlocked, in order to serialize
 * calls to ppp_dev_xmit_frame (which does compression) and the output
 * of frames w.r.t. tty writes from pppd.
 */
	CHECK_BUF_MAGIC(ppp->wbuf);
	if (ppp->tbuf->locked || lock_buffer (ppp->wbuf) != 0) {
		dev->tbusy = 1;
		if (ppp->flags & SC_DEBUG)
			printk(KERN_DEBUG "dev_xmit blocked, t=%lu w=%lu\n",
			       ppp->tbuf->locked, ppp->wbuf->locked);
		return 1;
	}
/*
 * Look at the protocol in the skb to determine the difference between
 * an IP frame and an IPX frame.
 */
	switch (ntohs (skb->protocol)) {
	case ETH_P_IPX:
		answer = ppp_dev_xmit_other (dev, ppp, data, len, PPP_IPX);
		break;

	case ETH_P_IP:
		answer = ppp_dev_xmit_ip (ppp, ppp->wbuf, data, len,
					  ppp->sc_npmode[NP_IP]);
		break;

	default: /* All others have no support at this time. */
		dev_kfree_skb (skb, FREE_WRITE);
		return 0;
	}
/*
 * This is the end of the transmission. Release the buffer if it was sent.
 */
	if (answer == 0) {
		/* packet queued OK */
		dev_kfree_skb (skb, FREE_WRITE);
	} else {
		ppp->wbuf->locked = 0;
		if (answer < 0) {
			/* packet should be dropped */
			dev_kfree_skb (skb, FREE_WRITE);
			answer = 0;
		} else {
			/* packet should be queued for later */
			dev->tbusy = 1;
		}
	}
	return answer;
}

/*
 * Generate the statistic information for the /proc/net/dev listing.
 */

static struct net_device_stats *
ppp_dev_stats (struct device *dev)
{
	struct ppp *ppp = dev2ppp (dev);

	ppp->estats.rx_packets = ppp->stats.ppp_ipackets;
	ppp->estats.rx_errors  = ppp->stats.ppp_ierrors;
	ppp->estats.tx_packets = ppp->stats.ppp_opackets;
	ppp->estats.tx_errors  = ppp->stats.ppp_oerrors;
#if LINUX_VERSION_CODE >= VERSION(2,1,25)
	ppp->estats.rx_bytes   = ppp->stats.ppp_ibytes;
	ppp->estats.tx_bytes   = ppp->stats.ppp_obytes;
#endif

	return &ppp->estats;
}

#if LINUX_VERSION_CODE < VERSION(2,1,15)
static int ppp_dev_header (sk_buff *skb, struct device *dev,
			   __u16 type, void *daddr,
			   void *saddr, unsigned int len)
{
	return (0);
}

static int
ppp_dev_rebuild (void *eth, struct device *dev,
		 unsigned long raddr, struct sk_buff *skb)
{
	return (0);
}
#endif

/*************************************************************
 * UTILITIES
 *    Miscellany called by various functions above.
 *************************************************************/

/* Locate the previous instance of the PPP channel */
static struct ppp *
ppp_find (int pid_value)
{
	struct ppp	*ppp;

	/* try to find the device which this pid is already using */
	for (ppp = ppp_list; ppp != 0; ppp = ppp->next) {
		if (ppp->inuse && ppp->sc_xfer == pid_value) {
			ppp->sc_xfer = 0;
			break;
		}
	}
	return ppp;
}

/* allocate or create a PPP channel */
static struct ppp *
ppp_alloc (void)
{
	int		if_num;
	int		status;
	struct device	*dev;
	struct ppp	*ppp;

	/* try to find an free device */
	if_num = 0;
	for (ppp = ppp_list; ppp != 0; ppp = ppp->next) {
		if (!test_and_set_bit(0, &ppp->inuse))
			return ppp;
		++if_num;
	}
/*
 * There are no available units, so make a new one.
 */
	ppp = (struct ppp *) kmalloc (sizeof(struct ppp), GFP_KERNEL);
	if (ppp == 0)
		return 0;
	memset(ppp, 0, sizeof(*ppp));

	/* initialize channel control data */
	set_bit(0, &ppp->inuse);

	ppp->line      = if_num;
	ppp->tty       = NULL;
	ppp->backup_tty = NULL;
	if (ppp_last == 0)
		ppp_list = ppp;
	else
		ppp_last->next = ppp;
	ppp_last = ppp;
	ppp->next = 0;

	dev = ppp2dev(ppp);
	dev->next      = NULL;
	dev->init      = ppp_init_dev;
	dev->name      = ppp->name;
	sprintf(dev->name, "ppp%d", if_num);
	dev->base_addr = (__u32) if_num;
	dev->priv      = (void *) ppp;

	/* register device so that we can be ifconfig'd */
	/* ppp_init_dev() will be called as a side-effect */
	status = register_netdev (dev);
	if (status == 0) {
		printk (KERN_INFO "registered device %s\n", dev->name);
	} else {
		printk (KERN_ERR
		       "ppp_alloc - register_netdev(%s) = %d failure.\n",
			dev->name, status);
		ppp = NULL;
		/* This one will forever be busy as it is not initialized */
	}
	return ppp;
}

/*
 * Utility procedures to print a buffer in hex/ascii
 */

static void
ppp_print_hex (register __u8 * out, const __u8 * in, int count)
{
	register __u8 next_ch;
	static char hex[] = "0123456789ABCDEF";

	while (count-- > 0) {
		next_ch = *in++;
		*out++ = hex[(next_ch >> 4) & 0x0F];
		*out++ = hex[next_ch & 0x0F];
		++out;
	}
}

static void
ppp_print_char (register __u8 * out, const __u8 * in, int count)
{
	register __u8 next_ch;

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
ppp_print_buffer (const __u8 * name, const __u8 * buf, int count)
{
	__u8 line[44];

	if (name != (__u8 *) NULL)
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
 * Compressor module interface
 *************************************************************/

struct compressor_link {
	struct compressor_link	*next;
	struct compressor	*comp;
};

static struct compressor_link *ppp_compressors = (struct compressor_link *) 0;

static struct compressor *find_compressor (int type)
{
	struct compressor_link *lnk;
	unsigned long flags;

	save_flags(flags);
	cli();

	lnk = ppp_compressors;
	while (lnk != (struct compressor_link *) 0) {
		if ((int) (__u8) lnk->comp->compress_proto == type) {
			restore_flags(flags);
			return lnk->comp;
		}
		lnk = lnk->next;
	}

	restore_flags(flags);
	return (struct compressor *) 0;
}

static int ppp_register_compressor (struct compressor *cp)
{
	struct compressor_link *new;
	unsigned long flags;

	new = (struct compressor_link *) kmalloc (sizeof (struct compressor_link), GFP_KERNEL);

	if (new == (struct compressor_link *) 0)
		return 1;

	save_flags(flags);
	cli();

	if (find_compressor (cp->compress_proto)) {
		restore_flags(flags);
		kfree (new);
		return 0;
	}

	new->next	= ppp_compressors;
	new->comp	= cp;
	ppp_compressors = new;

	restore_flags(flags);
	return 0;
}

static void ppp_unregister_compressor (struct compressor *cp)
{
	struct compressor_link *prev = (struct compressor_link *) 0;
	struct compressor_link *lnk;
	unsigned long flags;

	save_flags(flags);
	cli();

	lnk  = ppp_compressors;
	while (lnk != (struct compressor_link *) 0) {
		if (lnk->comp == cp) {
			if (prev)
				prev->next = lnk->next;
			else
				ppp_compressors = lnk->next;
			kfree (lnk);
			break;
		}
		prev = lnk;
		lnk  = lnk->next;
	}
	restore_flags(flags);
}

/*************************************************************
 * Module support routines
 *************************************************************/

#ifdef MODULE
int
init_module(void)
{
	int status;

	/* register our line disciplines */
	status = ppp_first_time();
	if (status != 0)
		printk (KERN_INFO
		       "PPP: ppp_init() failure %d\n", status);
#if LINUX_VERSION_CODE < VERSION(2,1,18)
	else
		(void) register_symtab (&ppp_syms);
#endif
	return (status);
}

void
cleanup_module(void)
{
	int status;
	struct device *dev;
	struct ppp *ppp, *next_ppp;
	int busy_flag = 0;
/*
 * Ensure that the devices are not in operation.
 */
	for (ppp = ppp_list; ppp != 0; ppp = ppp->next) {
		if (ppp->inuse && ppp->tty != NULL) {
			busy_flag = 1;
			break;
		}

		dev = ppp2dev (ppp);
		if (dev->start || dev->flags & IFF_UP) {
			busy_flag = 1;
			break;
		}
	}
/*
 * Ensure that there are no compressor modules registered
 */
	if (ppp_compressors != NULL)
		busy_flag = 1;

	if (busy_flag) {
		printk (KERN_INFO
			"PPP: device busy, remove delayed\n");
		return;
	}
/*
 * Release the tty registration of the line discipline so that no new entries
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
	for (ppp = ppp_list; ppp != 0; ppp = next_ppp) {
		next_ppp = ppp->next;
		ppp_release (ppp);
		unregister_netdev (&ppp->dev);
		kfree (ppp);
	}
}
#endif
