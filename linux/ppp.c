/*  PPP for Linux
 *
 *  Michael Callahan <callahan@maths.ox.ac.uk>
 *  Al Longyear <longyear@netcom.com>
 *  Extensively rewritten by Paul Mackerras <paulus@cs.anu.edu.au>
 *
 *  ==FILEVERSION 990910==
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

#define PPP_MAX_RCV_QLEN	32	/* max # frames we queue up for pppd */

/* $Id: ppp.c,v 1.33 1999/12/23 01:48:45 paulus Exp $ */

#include <linux/version.h>
#include <linux/config.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/sched.h>
#include <linux/types.h>
#include <linux/fcntl.h>
#include <linux/interrupt.h>
#include <linux/ptrace.h>

/* a macro to generate linux version number codes */
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
#include <linux/inet.h>
#include <linux/ioctl.h>
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

#ifdef CONFIG_KMOD
#include <linux/kmod.h>
#endif
#ifdef CONFIG_KERNELD
#include <linux/kerneld.h>
#endif

#undef PPP_VERSION
#define PPP_VERSION	"2.3.11"

#if LINUX_VERSION_CODE >= VERSION(2,1,4)

#if LINUX_VERSION_CODE >= VERSION(2,1,5)
#include <asm/uaccess.h>
#else
#include <asm/segment.h>
#endif

#define GET_USER	get_user
#define PUT_USER	put_user
#define COPY_FROM_USER	copy_from_user
#define COPY_TO_USER	copy_to_user

#else  /* 2.0.x and 2.1.x before 2.1.4 */

#define GET_USER(val, src)	\
	(verify_area(VERIFY_READ, src, sizeof(*src))? -EFAULT: \
	 ((val) = get_user(src), 0))
#define PUT_USER(val, dst)	\
	(verify_area(VERIFY_WRITE, dst, sizeof(*dst))? -EFAULT: \
	 (put_user(val, dst), 0))
#define COPY_FROM_USER(dst, src, size)	\
	(verify_area(VERIFY_READ, src, size)? -EFAULT: \
	 (memcpy_fromfs(dst, src, size), 0))
#define COPY_TO_USER(dst, src, size)	\
	(verify_area(VERIFY_WRITE, dst, size)? -EFAULT: \
	 (memcpy_tofs(dst, src, size), 0))

#endif /* < 2.1.4 */

#if LINUX_VERSION_CODE < VERSION(2,1,37)
#define test_and_set_bit(nr, addr)	set_bit(nr, addr)
#endif

#if LINUX_VERSION_CODE < VERSION(2,1,25)
#define net_device_stats	enet_statistics
#endif

#if LINUX_VERSION_CODE < VERSION(2,1,57)
#define signal_pending(tsk)	((tsk)->signal & ~(tsk)->blocked)
#endif

#if LINUX_VERSION_CODE < VERSION(2,1,60)
typedef int		rw_ret_t;
typedef unsigned int	rw_count_t;
#else
typedef ssize_t		rw_ret_t;
typedef size_t		rw_count_t;
#endif

#if LINUX_VERSION_CODE < VERSION(2,1,86)
#define KFREE_SKB(s)	dev_kfree_skb((s), FREE_WRITE)
#else
#define KFREE_SKB(s)	kfree_skb(s)
#endif

#if LINUX_VERSION_CODE < VERSION(2,1,15)
#define LIBERATE_SKB(s)	((s)->free = 1)
#else
#define LIBERATE_SKB(s)	do { } while (0)
#endif

#if LINUX_VERSION_CODE < VERSION(2,1,95)
#define SUSER()		suser()
#else
#define SUSER()		capable(CAP_NET_ADMIN)
#endif

#if LINUX_VERSION_CODE < VERSION(2,2,0)
#define wmb()		mb()
#endif

/*
 * Local functions
 */

static int ppp_register_compressor (struct compressor *cp);
static void ppp_unregister_compressor (struct compressor *cp);

static void ppp_async_init(struct ppp *ppp);
static void ppp_async_release(struct ppp *ppp);
static int ppp_tty_sync_push(struct ppp *ppp);
static int ppp_tty_push(struct ppp *ppp);
static int ppp_async_encode(struct ppp *ppp);
static int ppp_async_send(struct ppp *, struct sk_buff *);
static int ppp_sync_send(struct ppp *, struct sk_buff *);
static void ppp_tty_flush_output(struct ppp *);

static int ppp_ioctl(struct ppp *, unsigned int, unsigned long);
static int ppp_set_compression (struct ppp *ppp, struct ppp_option_data *odp);
static void ppp_proto_ccp(struct ppp *ppp, __u8 *dp, int len, int rcvd);
static void ppp_ccp_closed(struct ppp *ppp);
static int ppp_receive_frame(struct ppp *, struct sk_buff *);
static void ppp_receive_error(struct ppp *ppp);
static void ppp_output_wakeup(struct ppp *ppp);
static void ppp_send_ctrl(struct ppp *ppp, struct sk_buff *skb);
static void ppp_send_frame(struct ppp *ppp, struct sk_buff *skb);
static void ppp_send_frames(struct ppp *ppp);
static struct sk_buff *ppp_vj_compress(struct ppp *ppp, struct sk_buff *skb);

static struct ppp *ppp_find (int pid_value);
static struct ppp *ppp_alloc (void);
static void ppp_generic_init(struct ppp *ppp);
static void ppp_release(struct ppp *ppp);
static void ppp_print_buffer (const char *, const __u8 *, int);
static struct compressor *find_compressor (int type);

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

#define CHECK_PPP_MAGIC(ppp)	do { \
	if (ppp->magic != PPP_MAGIC) { \
		printk(ppp_magic_warn, ppp, __FILE__, __LINE__); \
	} \
} while (0)
#define CHECK_PPP(a)	do { \
	CHECK_PPP_MAGIC(ppp); \
	if (!ppp->inuse) { \
		printk(ppp_warning, __LINE__); \
		return a; \
	} \
} while (0)
#define CHECK_PPP_VOID() do { \
	CHECK_PPP_MAGIC(ppp); \
	if (!ppp->inuse) { \
		printk(ppp_warning, __LINE__); \
		return; \
	} \
} while (0)

#define tty2ppp(tty)	((struct ppp *) ((tty)->disc_data))
#define dev2ppp(dev)	((struct ppp *) ((dev)->priv))
#define ppp2tty(ppp)	((ppp)->tty)
#define ppp2dev(ppp)	(&(ppp)->dev)

static struct ppp *ppp_list = NULL;
static struct ppp *ppp_last = NULL;

/* Define these strings only once for all macro invocations */
static char ppp_warning[] = KERN_WARNING "PPP: ALERT! not INUSE! %d\n";
static char ppp_magic_warn[] = KERN_WARNING "bad magic for ppp %p at %s:%d\n";

static char szVersion[]		= PPP_VERSION;

#if LINUX_VERSION_CODE < VERSION(2,1,18)
static struct symbol_table ppp_syms = {
#include <linux/symtab_begin.h>
	X(ppp_register_compressor),
	X(ppp_unregister_compressor),
#include <linux/symtab_end.h>
};
#else
EXPORT_SYMBOL(ppp_register_compressor);
EXPORT_SYMBOL(ppp_unregister_compressor);
#endif

/*************************************************************
 * LINE DISCIPLINE SUPPORT
 *    The following code implements the PPP line discipline
 *    and supports using PPP on an async serial line.
 *************************************************************/

#define in_xmap(ppp,c)	(ppp->xmit_async_map[(c) >> 5] & (1 << ((c) & 0x1f)))
#define in_rmap(ppp,c)	((((unsigned int) (__u8) (c)) < 0x20) && \
			ppp->recv_async_map & (1 << (c)))

/*
 * TTY callbacks
 */

static rw_ret_t ppp_tty_read(struct tty_struct *, struct file *, __u8 *,
			     rw_count_t);
static rw_ret_t ppp_tty_write(struct tty_struct *, struct file *, const __u8 *,
			      rw_count_t);
static int ppp_tty_ioctl(struct tty_struct *, struct file *, unsigned int,
			 unsigned long);
#if LINUX_VERSION_CODE < VERSION(2,1,23)
static int ppp_tty_select(struct tty_struct *tty, struct inode *inode,
			struct file *filp, int sel_type, select_table * wait);
#else
static unsigned int ppp_tty_poll(struct tty_struct *tty, struct file *filp,
				 poll_table * wait);
#endif
static int ppp_tty_open (struct tty_struct *);
static void ppp_tty_close (struct tty_struct *);
static int ppp_tty_room (struct tty_struct *tty);
static void ppp_tty_receive (struct tty_struct *tty, const __u8 * cp,
			     char *fp, int count);
static void ppp_tty_wakeup (struct tty_struct *tty);

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
#if LINUX_VERSION_CODE >= VERSION(2,1,18)
EXPORT_SYMBOL(ppp_crc16_table);
#endif

#ifdef CHECK_CHARACTERS
static __u32 paritytab[8] =
{
	0x96696996, 0x69969669, 0x69969669, 0x96696996,
	0x69969669, 0x96696996, 0x96696996, 0x69969669
};
#endif

/*
 * This procedure is called at initialization time to register
 * the PPP line discipline.
 */
static int
ppp_first_time(void)
{
	static struct tty_ldisc	ppp_ldisc;
	int    status;

	printk(KERN_INFO
	       "PPP: version %s (demand dialling)"
	       "\n", szVersion);

#ifndef MODULE /* slhc module logic has its own copyright announcement */
	printk(KERN_INFO
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
		printk(KERN_INFO "PPP line discipline registered.\n");
	else
		printk(KERN_ERR "error registering line discipline: %d\n",
		       status);
	return status;
}


#ifndef MODULE
/*
 * Called at boot time if the PPP driver is compiled into the kernel.
 */
int
ppp_init(struct device *dev)
{
	static int first_time = 1;
	int    answer = 0;

	if (first_time) {
		first_time = 0;
		answer	   = ppp_first_time();
#if LINUX_VERSION_CODE < VERSION(2,1,18)
		if (answer == 0)
			(void) register_symtab(&ppp_syms);
#endif
	}
	if (answer == 0)
		answer = -ENODEV;
	return answer;
}
#endif

/*
 * Initialize the async-specific parts of the ppp structure.
 */
static void
ppp_async_init(struct ppp *ppp)
{
	ppp->escape = 0;
	ppp->toss   = 0xE0;
	ppp->tty_pushing = 0;

	memset (ppp->xmit_async_map, 0, sizeof (ppp->xmit_async_map));
	ppp->xmit_async_map[0] = 0xffffffff;
	ppp->xmit_async_map[3] = 0x60000000;
	ppp->recv_async_map    = 0xffffffff;

	ppp->tpkt = NULL;
	ppp->tfcs = PPP_INITFCS;
	ppp->optr = ppp->obuf;
	ppp->olim = ppp->obuf;

	ppp->rpkt = NULL;
	ppp->rfcs = PPP_INITFCS;

	ppp->tty  = NULL;
	ppp->backup_tty = NULL;

	ppp->bytes_sent = 0;
	ppp->bytes_rcvd = 0;
}

/*
 * Clean up the async-specific parts of the ppp structure.
 */
static void
ppp_async_release(struct ppp *ppp)
{
	struct sk_buff *skb;

	if ((skb = ppp->rpkt) != NULL)
		KFREE_SKB(skb);
	ppp->rpkt = NULL;
	if ((skb = ppp->tpkt) != NULL)
		KFREE_SKB(skb);
	ppp->tpkt = NULL;
}

/*
 * TTY callback.
 *
 * Called when the tty discipline is switched to PPP.
 */

static int
ppp_tty_open (struct tty_struct *tty)
{
	struct ppp *ppp;

	/*
	 * Allocate a ppp structure to use.
	 */
	tty->disc_data = NULL;
	ppp = ppp_find(current->pid);
	if (ppp != NULL) {
		/*
		 * If we are taking over a ppp unit which is currently
		 * connected to a loopback pty, there's not much to do.
		 */
		CHECK_PPP(-EINVAL);

	} else {
		ppp = ppp_alloc();
		if (ppp == NULL) {
			printk(KERN_ERR "ppp_alloc failed\n");
			return -ENFILE;
		}

		/*
		 * Initialize the control block
		 */
		ppp_generic_init(ppp);
		ppp_async_init(ppp);

		MOD_INC_USE_COUNT;
	}

	tty->disc_data = ppp;
	ppp->tty       = tty;

	/*
	 * Flush any pending characters in the driver
	 */
	if (tty->driver.flush_buffer)
		tty->driver.flush_buffer (tty);

	return ppp->line;
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
	struct ppp *ppp = tty2ppp(tty);

	if (ppp == NULL)
		return;
	tty->disc_data = NULL;
	if (ppp->magic != PPP_MAGIC) {
		printk(KERN_WARNING "ppp_tty_close: bogus\n");
		return;
	}
	if (!ppp->inuse) {
		printk(KERN_WARNING "ppp_tty_close: not inuse\n");
		ppp->tty = ppp->backup_tty = 0;
		return;
	}
	if (tty == ppp->backup_tty)
		ppp->backup_tty = 0;
	if (tty != ppp->tty)
		return;
	if (ppp->backup_tty) {
		ppp->tty = ppp->backup_tty;
		if (ppp_tty_push(ppp))
			ppp_output_wakeup(ppp);
		wake_up_interruptible(&ppp->read_wait);
	} else {
		ppp->tty = 0;
		ppp->sc_xfer = 0;
		if (ppp->flags & SC_DEBUG)
			printk(KERN_INFO "ppp: channel %s closing.\n",
			       ppp2dev(ppp)->name);

		ppp_async_release(ppp);
		ppp_release(ppp);
		MOD_DEC_USE_COUNT;
	}
}

/*
 * Read a PPP frame from the rcv_q list,
 * waiting if necessary
 */
static rw_ret_t
ppp_tty_read(struct tty_struct *tty, struct file *file, __u8 * buf,
	     rw_count_t nr)
{
	struct ppp *ppp = tty2ppp (tty);
	struct sk_buff *skb;
	rw_ret_t len, err;

	/*
	 * Validate the pointers
	 */
	if (!ppp)
		return -EIO;
	CHECK_PPP(-ENXIO);

	/*
	 * Before we attempt to write the frame to the user, ensure that the
	 * user has access to the pages for the total buffer length.
	 */
	err = verify_area(VERIFY_WRITE, buf, nr);
	if (err != 0)
		return (err);

	/*
	 * Wait for a frame to arrive if necessary.
	 * We increment the module use count so that the module
	 * can't go away while we're sleeping.
	 */
	MOD_INC_USE_COUNT;
	skb = NULL;
	for (;;) {
		ppp = tty2ppp(tty);
		err = 0;
		if (!ppp || ppp->magic != PPP_MAGIC || !ppp->inuse
		    || tty != ppp->tty)
			break;

		skb = skb_dequeue(&ppp->rcv_q);
		if (skb != 0)
			break;

		/*
		 * If no frame is available, return -EAGAIN or wait.
		 */
		err = -EAGAIN;
		if (file->f_flags & O_NONBLOCK)
			break;

		interruptible_sleep_on(&ppp->read_wait);
		err = -EINTR;
		if (signal_pending(current))
			break;
	}
	MOD_DEC_USE_COUNT;
	if (skb == 0)
		return err;

	/*
	 * Ensure that the frame will fit within the caller's buffer.
	 * If not, just discard the frame.
	 */
	len = skb->len;
	if (len > nr) {
		if (ppp->flags & SC_DEBUG)
			printk(KERN_DEBUG
			       "ppp: read of %lu bytes too small for %ld "
			       "frame\n", (unsigned long) nr, (long) len);
		ppp->stats.ppp_ierrors++;
		err = -EOVERFLOW;
		goto out;
	}

	/*
	 * Copy the received data from the buffer to the caller's area.
	 */
	err = len;
	if (COPY_TO_USER(buf, skb->data, len))
		err = -EFAULT;

out:
	KFREE_SKB(skb);
	return err;
}

/*
 * Writing to a tty in ppp line discipline sends a PPP frame.
 * Used by pppd to send control packets (LCP, etc.).
 */
static rw_ret_t
ppp_tty_write(struct tty_struct *tty, struct file *file, const __u8 * data,
	      rw_count_t count)
{
	struct ppp *ppp = tty2ppp (tty);
	__u8 *new_data;
	struct sk_buff *skb;

	/*
	 * Verify the pointers.
	 */
	if (!ppp)
		return -EIO;

	if (ppp->magic != PPP_MAGIC)
		return -EIO;

	CHECK_PPP(-ENXIO);

	/*
	 * Ensure that the caller does not wish to send too much.
	 */
	if (count > PPP_MTU + PPP_HDRLEN) {
		if (ppp->flags & SC_DEBUG)
			printk(KERN_WARNING
			       "ppp_tty_write: truncating user packet "
			       "from %lu to mtu %d\n", (unsigned long) count,
			       PPP_MTU + PPP_HDRLEN);
		count = PPP_MTU + PPP_HDRLEN;
	}

	/*
	 * Allocate a buffer for the data and fetch it from the user space.
	 */
	skb = alloc_skb(count, GFP_KERNEL);
	if (skb == NULL) {
		printk(KERN_ERR "ppp_tty_write: no memory\n");
		return 0;
	}
	LIBERATE_SKB(skb);
	new_data = skb_put(skb, count);

	/*
	 * Retrieve the user's buffer
	 */
	if (COPY_FROM_USER(new_data, data, count)) {
		KFREE_SKB(skb);
		return -EFAULT;
	}

	/*
	 * Send the frame
	 */
	ppp_send_ctrl(ppp, skb);

	return (rw_ret_t) count;
}

/*
 * Process the IOCTL call for the tty device.
 * Only the ioctls that relate to using ppp on async serial lines
 * are processed here; the rest are handled by ppp_ioctl.
 */
static int
ppp_tty_ioctl (struct tty_struct *tty, struct file * file,
               unsigned int param2, unsigned long param3)
{
	struct ppp *ppp = tty2ppp (tty);
	register int temp_i = 0;
	int error = -EFAULT;

	/*
	 * Verify the status of the PPP device.
	 */
	if (!ppp || ppp->magic != PPP_MAGIC || !ppp->inuse)
		return -ENXIO;

	/*
	 * The user must have an euid of root to do these requests.
	 */
	if (!SUSER())
		return -EPERM;

	switch (param2) {
	case PPPIOCGASYNCMAP:
		/*
		 * Retrieve the transmit async map
		 */
		if (PUT_USER(ppp->xmit_async_map[0], (int *) param3))
			break;
		error = 0;
		break;

	case PPPIOCSASYNCMAP:
		/*
		 * Set the transmit async map
		 */
		if (GET_USER(temp_i, (int *) param3))
			break;
		ppp->xmit_async_map[0] = temp_i;
		if (ppp->flags & SC_DEBUG)
			printk(KERN_INFO
			       "ppp_tty_ioctl: set xmit asyncmap %x\n",
			       ppp->xmit_async_map[0]);
		error = 0;
		break;

	case PPPIOCSRASYNCMAP:
		/*
		 * Set the receive async map
		 */
		if (GET_USER(temp_i, (int *) param3))
			break;
		ppp->recv_async_map = temp_i;
		if (ppp->flags & SC_DEBUG)
			printk(KERN_INFO
			       "ppp_tty_ioctl: set rcv asyncmap %x\n",
			       ppp->recv_async_map);
		error = 0;
		break;

	case PPPIOCGXASYNCMAP:
		/*
		 * Get the map of characters to be escaped on transmission.
		 */
		if (COPY_TO_USER((void *) param3, ppp->xmit_async_map,
				 sizeof (ppp->xmit_async_map)))
			break;
		error = 0;
		break;

	case PPPIOCSXASYNCMAP:
		/*
		 * Set the map of characters to be escaped on transmission.
		 */
		{
			__u32 temp_tbl[8];

			if (COPY_FROM_USER(temp_tbl, (void *) param3,
					   sizeof (temp_tbl)))
				break;

			temp_tbl[1]  =	0x00000000;
			temp_tbl[2] &= ~0x40000000;
			temp_tbl[3] |=	0x60000000;

			memcpy(ppp->xmit_async_map, temp_tbl,
			       sizeof (ppp->xmit_async_map));

			if (ppp->flags & SC_DEBUG)
				printk(KERN_INFO
				       "ppp_tty_ioctl: set xasyncmap\n");
			error = 0;
		}
		break;

	case PPPIOCXFERUNIT:
		/*
		 * Set up this PPP unit to be used next time this
		 * process sets a tty to PPP line discipline.
		 */
		ppp->backup_tty = tty;
		ppp->sc_xfer = current->pid;
		error = 0;
		break;

	case TCGETS:
	case TCGETA:
		/*
		 * Allow users to read, but not set, the serial port parameters
		 */
		error = n_tty_ioctl (tty, file, param2, param3);
		break;

	case TCFLSH:
		/*
		 * Flush our buffers, then call the generic code to
		 * flush the serial port's buffer.
		 */
		if (param3 == TCIFLUSH || param3 == TCIOFLUSH) {
			struct sk_buff *skb;
			while ((skb = skb_dequeue(&ppp->rcv_q)) != NULL)
				KFREE_SKB(skb);
		}
		if (param3 == TCIOFLUSH || param3 == TCOFLUSH)
			ppp_tty_flush_output(ppp);
		error = n_tty_ioctl (tty, file, param2, param3);
		break;

	case FIONREAD:
		/*
		 * Returns how many bytes are available for a read().
		 */
		{
			unsigned long flags;
			struct sk_buff *skb;
			int count = 0;

			save_flags(flags);
			cli();
			skb = skb_peek(&ppp->rcv_q);
			if (skb != 0)
				count = skb->len;
			restore_flags(flags);
			if (PUT_USER(count, (int *) param3))
				break;
			error = 0;
		}
		break;

	default:
		/*
		 *  All other ioctl() events will come here.
		 */
		error = ppp_ioctl(ppp, param2, param3);
		break;
	}
	return error;
}

/*
 * TTY callback.
 *
 * Process the select() or poll() statement for the PPP device.
 */

#if LINUX_VERSION_CODE < VERSION(2,1,23)
static int
ppp_tty_select(struct tty_struct *tty, struct inode *inode,
	       struct file *filp, int sel_type, select_table * wait)
{
	struct ppp *ppp = tty2ppp(tty);
	int result = 1;

	/*
	 * Verify the status of the PPP device.
	 */
	if (!ppp || tty != ppp->tty)
		return -EBADF;

	CHECK_PPP(-EBADF);

	switch (sel_type) {
	case SEL_IN:
		/* The fd is readable if the receive queue isn't empty. */
		if (skb_peek(&ppp->rcv_q) != NULL)
			break;
		/* fall through */
	case SEL_EX:
		/* Check for exceptions or read errors. */
		/* Is this a pty link and the remote disconnected? */
		if (tty->flags & (1 << TTY_OTHER_CLOSED))
			break;

		/* Is this a local link and the modem disconnected? */
		if (tty_hung_up_p (filp))
			break;

		select_wait(&ppp->read_wait, wait);
		result = 0;
		break;

	case SEL_OUT:
		/* The fd is always writable. */
		break;
	}
	return result;
}

#else	/* 2.1.23 or later */

static unsigned int
ppp_tty_poll(struct tty_struct *tty, struct file *filp, poll_table * wait)
{
	struct ppp *ppp = tty2ppp(tty);
	unsigned int mask = 0;

	if (ppp && ppp->magic == PPP_MAGIC && tty == ppp->tty) {
		CHECK_PPP(0);

		poll_wait(filp, &ppp->read_wait, wait);

		if (skb_peek(&ppp->rcv_q) != NULL)
			mask |= POLLIN | POLLRDNORM;
		if (tty->flags & (1 << TTY_OTHER_CLOSED)
		    || tty_hung_up_p(filp))
			mask |= POLLHUP;
		mask |= POLLOUT | POLLWRNORM;
	}
	return mask;
}
#endif	/* >= 2.1.23 */

/*
 * This function is called by the tty driver when the transmit buffer has
 * additional space. It is used by the ppp code to continue to transmit
 * the current buffer should the buffer have been partially sent.
 */
static void
ppp_tty_wakeup (struct tty_struct *tty)
{
	struct ppp *ppp = tty2ppp (tty);

	tty->flags &= ~(1 << TTY_DO_WRITE_WAKEUP);
	if (!ppp)
		return;
	CHECK_PPP_VOID();
	if (tty != ppp->tty)
		return;

	if (ppp_tty_push(ppp))
		ppp_output_wakeup(ppp);
}

/*
 * Send a packet to the peer over a synchronous tty line.
 * All encoding and FCS are handled by hardware.
 * Addr/Ctrl and Protocol field compression implemented.
 * Returns -1 iff the packet could not be accepted at present,
 * 0 if the packet was accepted but we can't accept another yet, or
 * 1 if we can accept another packet immediately.
 * If this procedure returns 0, ppp_output_wakeup will be called
 * exactly once.
 */
static int
ppp_sync_send(struct ppp *ppp, struct sk_buff *skb)
{
	unsigned char *data;
	int islcp;
	
	CHECK_PPP(0);

	if (ppp->tpkt != NULL)
		return -1;
	ppp->tpkt = skb;

	data = ppp->tpkt->data;
	
	/*
	 * LCP packets with code values between 1 (configure-reqest)
	 * and 7 (code-reject) must be sent as though no options
	 * had been negotiated.
	 */
	islcp = PPP_PROTOCOL(data) == PPP_LCP
		&& 1 <= data[PPP_HDRLEN] && data[PPP_HDRLEN] <= 7;

	/* only reset idle time for data packets */
	if (PPP_PROTOCOL(data) < 0x8000)
		ppp->last_xmit = jiffies;
	++ppp->stats.ppp_opackets;
	ppp->stats.ppp_ooctects += ppp->tpkt->len;

	if ( !(data[2]) && (ppp->flags & SC_COMP_PROT) ) {
		/* compress protocol field */
		data[2] = data[1];
		data[1] = data[0];
		skb_pull(ppp->tpkt,1);
		data = ppp->tpkt->data;
	}
	
	/*
	 * Do address/control compression
	 */
	if ((ppp->flags & SC_COMP_AC) && !islcp
	    && PPP_ADDRESS(data) == PPP_ALLSTATIONS
	    && PPP_CONTROL(data) == PPP_UI) {
		/* strip addr and control field */
		skb_pull(ppp->tpkt,2);
	}

	return ppp_tty_sync_push(ppp);
}

/*
 * Push a synchronous frame out to the tty.
 * Returns 1 if frame accepted (or discarded), 0 otherwise.
 */
static int
ppp_tty_sync_push(struct ppp *ppp)
{
	int sent;
	struct tty_struct *tty = ppp2tty(ppp);
	unsigned long flags;
		
	CHECK_PPP(0);

	if (ppp->tpkt == NULL)
		return 0;
		
	/* prevent reentrancy with tty_pushing flag */		
	save_flags(flags);
	cli();
	if (ppp->tty_pushing) {
		/* record wakeup attempt so we don't lose */
		/* a wakeup call while doing push processing */
		ppp->woke_up=1;
		restore_flags(flags);
		return 0;
	}
	ppp->tty_pushing = 1;
	restore_flags(flags);
	
	if (tty == NULL || tty->disc_data != (void *) ppp)
		goto flush;
		
	for(;;){
		ppp->woke_up=0;
		
		/* Note: Sync driver accepts complete frame or nothing */
		tty->flags |= (1 << TTY_DO_WRITE_WAKEUP);
		sent = tty->driver.write(tty, 0, ppp->tpkt->data, ppp->tpkt->len);
		if (sent < 0) {
			/* write error (possible loss of CD) */
			/* record error and discard current packet */
			ppp->stats.ppp_oerrors++;
			break;
		}
		ppp->stats.ppp_obytes += sent;
		if (sent < ppp->tpkt->len) {
			/* driver unable to accept frame just yet */
			save_flags(flags);
			cli();
			if (ppp->woke_up) {
				/* wake up called while processing */
				/* try to send the frame again */
				restore_flags(flags);
				continue;
			}
			/* wait for wakeup callback to try send again */
			ppp->tty_pushing = 0;
			restore_flags(flags);
			return 0;
		}
		break;
	}
flush:	
	/* done with current packet (sent or discarded) */
	KFREE_SKB(ppp->tpkt);
	ppp->tpkt = 0;
	ppp->tty_pushing = 0;
	return 1;
}

/*
 * Send a packet to the peer over an async tty line.
 * Returns -1 iff the packet could not be accepted at present,
 * 0 if the packet was accepted but we can't accept another yet, or
 * 1 if we can accept another packet immediately.
 * If this procedure returns 0, ppp_output_wakeup will be called
 * exactly once.
 */
static int
ppp_async_send(struct ppp *ppp, struct sk_buff *skb)
{
	CHECK_PPP(0);

	ppp_tty_push(ppp);

	if (ppp->tpkt != NULL)
		return -1;
	ppp->tpkt = skb;
	ppp->tpkt_pos = 0;

	return ppp_tty_push(ppp);
}

/*
 * Push as much data as possible out to the tty.
 * Returns 1 if we finished encoding the current frame, 0 otherwise.
 */
static int
ppp_tty_push(struct ppp *ppp)
{
	int avail, sent, done = 0;
	struct tty_struct *tty = ppp2tty(ppp);
	
	if (ppp->flags & SC_SYNC) 
		return ppp_tty_sync_push(ppp);

	CHECK_PPP(0);
	if (ppp->tty_pushing) {
		ppp->woke_up = 1;
		return 0;
	}
	if (tty == NULL || tty->disc_data != (void *) ppp)
		goto flush;
	while (ppp->optr < ppp->olim || ppp->tpkt != 0) {
		ppp->tty_pushing = 1;
		mb();
		ppp->woke_up = 0;
		avail = ppp->olim - ppp->optr;
		if (avail > 0) {
			tty->flags |= (1 << TTY_DO_WRITE_WAKEUP);
			sent = tty->driver.write(tty, 0, ppp->optr, avail);
			if (sent < 0)
				goto flush;	/* error, e.g. loss of CD */
			ppp->stats.ppp_obytes += sent;
			ppp->optr += sent;
			if (sent < avail) {
				wmb();
				ppp->tty_pushing = 0;
				mb();
				if (ppp->woke_up)
					continue;
				return done;
			}
		}
		if (ppp->tpkt != 0)
			done = ppp_async_encode(ppp);
		wmb();
		ppp->tty_pushing = 0;
	}
	return done;

flush:
	ppp->tty_pushing = 1;
	mb();
	ppp->stats.ppp_oerrors++;
	if (ppp->tpkt != 0) {
		KFREE_SKB(ppp->tpkt);
		ppp->tpkt = 0;
		done = 1;
	}
	ppp->optr = ppp->olim;
	wmb();
	ppp->tty_pushing = 0;
	return done;
}

/*
 * Procedure to encode the data for async serial transmission.
 * Does octet stuffing (escaping) and address/control
 * and protocol compression.
 * Assumes ppp->opkt != 0 on entry.
 * Returns 1 if we finished the current frame, 0 otherwise.
 */
static int
ppp_async_encode(struct ppp *ppp)
{
	int fcs, i, count, c;
	unsigned char *buf, *buflim;
	unsigned char *data;
	int islcp;

	CHECK_PPP(0);

	buf = ppp->obuf;
	ppp->olim = buf;
	ppp->optr = buf;
	i = ppp->tpkt_pos;
	data = ppp->tpkt->data;
	count = ppp->tpkt->len;
	fcs = ppp->tfcs;

	/*
	 * LCP packets with code values between 1 (configure-reqest)
	 * and 7 (code-reject) must be sent as though no options
	 * had been negotiated.
	 */
	islcp = PPP_PROTOCOL(data) == PPP_LCP
		&& 1 <= data[PPP_HDRLEN] && data[PPP_HDRLEN] <= 7;

	if (i == 0) {
		/*
		 * Start of a new packet - insert the leading FLAG
		 * character if necessary.
		 */
		if (islcp || flag_time == 0
		    || jiffies - ppp->last_xmit >= flag_time)
			*buf++ = PPP_FLAG;
		/* only reset idle time for data packets */
		if (PPP_PROTOCOL(data) < 0x8000)
			ppp->last_xmit = jiffies;
		fcs = PPP_INITFCS;
		++ppp->stats.ppp_opackets;
		ppp->stats.ppp_ooctects += count;

		/*
		 * Do address/control compression
		 */
		if ((ppp->flags & SC_COMP_AC) != 0 && !islcp
		    && PPP_ADDRESS(data) == PPP_ALLSTATIONS
		    && PPP_CONTROL(data) == PPP_UI)
			i += 2;
	}

	/*
	 * Once we put in the last byte, we need to put in the FCS
	 * and closing flag, so make sure there is at least 7 bytes
	 * of free space in the output buffer.
	 */
	buflim = buf + OBUFSIZE - 6;
	while (i < count && buf < buflim) {
		c = data[i++];
		if (i == 3 && c == 0 && (ppp->flags & SC_COMP_PROT))
			continue;	/* compress protocol field */
		fcs = PPP_FCS(fcs, c);
		if (in_xmap(ppp, c) || (islcp && c < 0x20)) {
			*buf++ = PPP_ESCAPE;
			c ^= 0x20;
		}
		*buf++ = c;
	}

	if (i == count) {
		/*
		 * We have finished the packet.  Add the FCS and flag.
		 */
		fcs = ~fcs;
		c = fcs & 0xff;
		if (in_xmap(ppp, c) || (islcp && c < 0x20)) {
			*buf++ = PPP_ESCAPE;
			c ^= 0x20;
		}
		*buf++ = c;
		c = (fcs >> 8) & 0xff;
		if (in_xmap(ppp, c) || (islcp && c < 0x20)) {
			*buf++ = PPP_ESCAPE;
			c ^= 0x20;
		}
		*buf++ = c;
		*buf++ = PPP_FLAG;
		ppp->olim = buf;

		KFREE_SKB(ppp->tpkt);
		ppp->tpkt = 0;
		return 1;
	}

	/*
	 * Remember where we are up to in this packet.
	 */
	ppp->olim = buf;
	ppp->tpkt_pos = i;
	ppp->tfcs = fcs;
	return 0;
}

/*
 * Flush output from our internal buffers.
 * Called for the TCFLSH ioctl.
 */
static void
ppp_tty_flush_output(struct ppp *ppp)
{
	struct sk_buff *skb;
	int done = 0;

	while ((skb = skb_dequeue(&ppp->xmt_q)) != NULL)
		KFREE_SKB(skb);
	ppp->tty_pushing = 1;
	mb();
	ppp->optr = ppp->olim;
	if (ppp->tpkt != NULL) {
		KFREE_SKB(ppp->tpkt);
		ppp->tpkt = 0;
		done = 1;
	}
	wmb();
	ppp->tty_pushing = 0;
	if (done)
		ppp_output_wakeup(ppp);
}

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
	struct sk_buff *skb;
	int chr, flg;
	unsigned char *p;

	if (ppp != 0)
		CHECK_PPP_VOID();
	/*
	 * This can happen if stuff comes in on the backup tty.
	 */
	if (ppp == 0 || tty != ppp->tty)
		return;
	/*
	 * Verify the table pointer and ensure that the line is
	 * still in PPP discipline.
	 */
	if (ppp->magic != PPP_MAGIC) {
		if (ppp->flags & SC_DEBUG)
			printk(KERN_DEBUG
			       "PPP: tty_receive called but couldn't find "
			       "PPP struct.\n");
		return;
	}
	/*
	 * Print the buffer if desired
	 */
	if (ppp->flags & SC_LOG_RAWIN)
		ppp_print_buffer ("receive buffer", data, count);

	ppp->stats.ppp_ibytes += count;
	skb = ppp->rpkt;
	
	if ( ppp->flags & SC_SYNC ) {
		/* synchronous mode */
		
		if (ppp->toss==0xE0) {
			/* this is the 1st frame, reset vj comp */
			ppp_receive_error(ppp);
			ppp->toss = 0;
		}
		
		/*
		 * Allocate an skbuff for frame.
		 * The 128 is room for VJ header expansion.
		 */
		
		if (skb == NULL)
			skb = dev_alloc_skb(ppp->mru + 128 + PPP_HDRLEN);
			
		if (skb == NULL) {
			if (ppp->flags & SC_DEBUG)
				printk(KERN_DEBUG "couldn't "
				       "alloc skb for recv\n");
		} else {
			LIBERATE_SKB(skb);
			/*
			 * Decompress A/C and protocol compression here.
			 */
			p = skb_put(skb, 2);
			p[0] = PPP_ALLSTATIONS;
			p[1] = PPP_UI;
			if (*data == PPP_ALLSTATIONS) {
				data += 2;
				count -= 2;
			}
			if ((*data & 1) != 0) {
				p = skb_put(skb, 1);
				p[0] = 0;
			}

			/* copy frame to socket buffer */
			p = skb_put(skb, count);
			memcpy(p,data,count);
			
			/*
			 * Check if we've overflowed the MRU
			 */
			if (skb->len >= ppp->mru + PPP_HDRLEN + 2
			    || skb_tailroom(skb) <= 0) {
				++ppp->estats.rx_length_errors;
				if (ppp->flags & SC_DEBUG)
					printk(KERN_DEBUG "rcv frame too long: "
					       "len=%d mru=%d hroom=%d troom=%d\n",
					       skb->len, ppp->mru, skb_headroom(skb),
					       skb_tailroom(skb));
			} else {
				if (!ppp_receive_frame(ppp, skb)) {
					KFREE_SKB(skb);
					ppp_receive_error(ppp);
				}
			}
		
			/* Reset for the next frame */
			skb = NULL;
		}
		ppp->rpkt = skb;
		return;
	}
	
	while (count-- > 0) {
		/*
		 * Collect the character and error condition for the character.
		 * Set the toss flag for the first character error.
		 */
		chr = *data++;
		if (flags) {
			flg = *flags++;
			if (flg) {
				if (ppp->toss == 0)
					ppp->toss = flg;
				switch (flg) {
				case TTY_OVERRUN:
					++ppp->estats.rx_fifo_errors;
					break;
				case TTY_FRAME:
				case TTY_BREAK:
					++ppp->estats.rx_frame_errors;
					break;
				}
				continue;
			}
		}

		/*
		 * Set the flags for d7 being 0/1 and parity being
		 * even/odd so that the normal processing would have
		 * all flags set at the end of the session.  A
		 * missing flag bit indicates an error condition.
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

		if (chr == PPP_FLAG) {
			/*
			 * FLAG. This is the end of the block. If the block
			 * ends with ESC FLAG, then the block is to be ignored.
			 */
			if (ppp->escape)
				ppp->toss |= 0x80;
			/*
			 * Process the frame if it was received correctly.
			 * If there was an error, let the VJ decompressor know.
			 * There are 4 cases here:
			 * skb != NULL, toss != 0: error in frame
			 * skb != NULL, toss == 0: frame ok
			 * skb == NULL, toss != 0: very first frame,
			 *	error on 1st char, or alloc_skb failed
			 * skb == NULL, toss == 0: empty frame (~~)
			 */
			if (ppp->toss || !ppp_receive_frame(ppp, skb)) {
				if (ppp->toss && (ppp->flags & SC_DEBUG))
					printk(KERN_DEBUG
					       "ppp: tossing frame (%x)\n",
					       ppp->toss);
				if (skb != NULL)
					KFREE_SKB(skb);
				if (!(ppp->toss == 0xE0 || ppp->toss == 0x80))
					++ppp->stats.ppp_ierrors;
				ppp_receive_error(ppp);
			}
			/*
			 * Reset for the next frame.
			 */
			skb = NULL;
			ppp->rfcs = PPP_INITFCS;
			ppp->escape = 0;
			ppp->toss = 0;
			continue;
		}

		/* If we're tossing, look no further. */
		if (ppp->toss != 0)
			continue;

		/* If this is a control char to be ignored, do so */
		if (in_rmap(ppp, chr))
			continue;

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
			continue;
		}

		/*
		 * Allocate an skbuff on the first character received.
		 * The 128 is room for VJ header expansion and FCS.
		 */
		if (skb == NULL) {
			skb = dev_alloc_skb(ppp->mru + 128 + PPP_HDRLEN);
			if (skb == NULL) {
				if (ppp->flags & SC_DEBUG)
					printk(KERN_DEBUG "couldn't "
					       "alloc skb for recv\n");
				ppp->toss = 1;
				continue;
			}
			LIBERATE_SKB(skb);
		}

		/*
		 * Decompress A/C and protocol compression here.
		 */
		if (skb->len == 0 && chr != PPP_ALLSTATIONS) {
			p = skb_put(skb, 2);
			p[0] = PPP_ALLSTATIONS;
			p[1] = PPP_UI;
		}
		if (skb->len == 2 && (chr & 1) != 0) {
			p = skb_put(skb, 1);
			p[0] = 0;
		}

		/*
		 * Check if we've overflowed the MRU
		 */
		if (skb->len >= ppp->mru + PPP_HDRLEN + 2
		    || skb_tailroom(skb) <= 0) {
			++ppp->estats.rx_length_errors;
			ppp->toss = 0xC0;
			if (ppp->flags & SC_DEBUG)
				printk(KERN_DEBUG "rcv frame too long: "
				       "len=%d mru=%d hroom=%d troom=%d\n",
				       skb->len, ppp->mru, skb_headroom(skb),
				       skb_tailroom(skb));
			continue;
		}

		/*
		 * Store the character and update the FCS.
		 */
		p = skb_put(skb, 1);
		*p = chr;
		ppp->rfcs = PPP_FCS(ppp->rfcs, chr);
	}
	ppp->rpkt = skb;
}

/*************************************************************
 * PPP NETWORK INTERFACE SUPPORT
 *	The following code implements the PPP network
 *	interface device and handles those parts of
 *	the PPP processing which are independent of the
 *	type of hardware link being used, including
 *	VJ and packet compression.
 *************************************************************/

/*
 * Network device driver callback routines
 */

static int ppp_init_dev(struct device *dev);
static int ppp_dev_open(struct device *);
static int ppp_dev_ioctl(struct device *dev, struct ifreq *ifr, int cmd);
static int ppp_dev_close(struct device *);
static int ppp_dev_xmit(struct sk_buff *, struct device *);
static struct net_device_stats *ppp_dev_stats (struct device *);

#if LINUX_VERSION_CODE < VERSION(2,1,15)
static int ppp_dev_header(struct sk_buff *, struct device *, __u16,
			  void *, void *, unsigned int);
static int ppp_dev_rebuild(void *eth, struct device *dev,
			   unsigned long raddr, struct sk_buff *skb);
#endif

/*
 * Information for the protocol decoder
 */

typedef int (*pfn_proto)  (struct ppp *, struct sk_buff *);

typedef struct ppp_proto_struct {
	int		proto;
	pfn_proto	func;
} ppp_proto_type;

static int rcv_proto_ip		(struct ppp *, struct sk_buff *);
static int rcv_proto_ipv6	(struct ppp *, struct sk_buff *);
static int rcv_proto_ipx	(struct ppp *, struct sk_buff *);
static int rcv_proto_at		(struct ppp *, struct sk_buff *);
static int rcv_proto_vjc_comp	(struct ppp *, struct sk_buff *);
static int rcv_proto_vjc_uncomp (struct ppp *, struct sk_buff *);
static int rcv_proto_ccp	(struct ppp *, struct sk_buff *);
static int rcv_proto_unknown	(struct ppp *, struct sk_buff *);

static
ppp_proto_type proto_list[] = {
	{ PPP_IP,	  rcv_proto_ip	       },
	{ PPP_IPV6,	  rcv_proto_ipv6       },
	{ PPP_IPX,	  rcv_proto_ipx	       },
	{ PPP_AT,	  rcv_proto_at	       },
	{ PPP_VJC_COMP,	  rcv_proto_vjc_comp   },
	{ PPP_VJC_UNCOMP, rcv_proto_vjc_uncomp },
	{ PPP_CCP,	  rcv_proto_ccp	       },
	{ 0,		  rcv_proto_unknown    }  /* !!! MUST BE LAST !!! */
};

/*
 * Called when the PPP network interface device is actually created.
 */
static int
ppp_init_dev (struct device *dev)
{
	dev->hard_header_len  = PPP_HDRLEN;
#if LINUX_VERSION_CODE < VERSION(2,1,15)
	dev->hard_header      = ppp_dev_header;
	dev->rebuild_header   = ppp_dev_rebuild;
#endif

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

	dev->flags = IFF_POINTOPOINT | IFF_NOARP | IFF_MULTICAST;

	return 0;
}

/*
 * Callback from the network layer when the device goes up.
 */

static int
ppp_dev_open (struct device *dev)
{
	struct ppp *ppp = dev2ppp(dev);

	if (!ppp->inuse || ppp2tty(ppp) == NULL) {
		printk(KERN_ERR "ppp: %s not active\n", dev->name);
		return -ENXIO;
	}

	MOD_INC_USE_COUNT;

	return 0;
}

/*
 * Callback from the network layer when the ppp device goes down.
 */

static int
ppp_dev_close (struct device *dev)
{
	struct ppp *ppp = dev2ppp (dev);

	CHECK_PPP_MAGIC(ppp);

	MOD_DEC_USE_COUNT;

	return 0;
}

static inline void
get_vj_stats(struct vjstat *vj, struct slcompress *slc)
{
	vj->vjs_packets    = slc->sls_o_compressed + slc->sls_o_uncompressed;
	vj->vjs_compressed = slc->sls_o_compressed;
	vj->vjs_searches   = slc->sls_o_searches;
	vj->vjs_misses     = slc->sls_o_misses;
	vj->vjs_errorin    = slc->sls_i_error;
	vj->vjs_tossed     = slc->sls_i_tossed;
	vj->vjs_uncompressedin = slc->sls_i_uncompressed;
	vj->vjs_compressedin   = slc->sls_i_compressed;
}

/*
 * Callback from the network layer to process the sockioctl functions.
 */
static int
ppp_dev_ioctl (struct device *dev, struct ifreq *ifr, int cmd)
{
	struct ppp *ppp = dev2ppp(dev);
	int nb;
	union {
		struct ppp_stats stats;
		struct ppp_comp_stats cstats;
		char vers[32];
	} u;

	CHECK_PPP_MAGIC(ppp);

	memset(&u, 0, sizeof(u));
	switch (cmd) {
	case SIOCGPPPSTATS:
		u.stats.p = ppp->stats;
		if (ppp->slcomp != NULL)
			get_vj_stats(&u.stats.vj, ppp->slcomp);
		nb = sizeof(u.stats);
		break;

	case SIOCGPPPCSTATS:
		if (ppp->sc_xc_state != NULL)
			(*ppp->sc_xcomp->comp_stat)
				(ppp->sc_xc_state, &u.cstats.c);
		if (ppp->sc_rc_state != NULL)
			(*ppp->sc_rcomp->decomp_stat)
				(ppp->sc_rc_state, &u.cstats.d);
		nb = sizeof(u.cstats);
		break;

	case SIOCGPPPVER:
		strcpy(u.vers, szVersion);
		nb = strlen(u.vers) + 1;
		break;

	default:
		return -EINVAL;
	}

	if (COPY_TO_USER((void *) ifr->ifr_ifru.ifru_data, &u, nb))
		return -EFAULT;
	return 0;
}

/*
 * Process the generic PPP ioctls, i.e. those which are not specific
 * to any particular type of hardware link.
 */
static int
ppp_ioctl(struct ppp *ppp, unsigned int param2, unsigned long param3)
{
	register int temp_i = 0, oldflags;
	int error = -EFAULT;
	unsigned long flags;
	struct ppp_idle cur_ddinfo;
	struct npioctl npi;

	CHECK_PPP(-ENXIO);

	/*
	 * The user must have an euid of root to do these requests.
	 */
	if (!SUSER())
		return -EPERM;

	switch (param2) {
	case PPPIOCSMRU:
		/*
		 * Set the MRU value
		 */
		if (GET_USER(temp_i, (int *) param3))
			break;
		if (temp_i < PPP_MRU)
			temp_i = PPP_MRU;
		ppp->mru = temp_i;
		if (ppp->flags & SC_DEBUG)
			printk(KERN_INFO
			       "ppp_ioctl: set mru to %x\n", temp_i);
		error = 0;
		break;

	case PPPIOCGFLAGS:
		/*
		 * Fetch the current flags
		 */
		temp_i = ppp->flags & SC_MASK;
#ifndef CHECK_CHARACTERS /* Don't generate errors if we don't check chars. */
		temp_i |= SC_RCV_B7_1 | SC_RCV_B7_0 |
			  SC_RCV_ODDP | SC_RCV_EVNP;
#endif
		if (PUT_USER(temp_i, (int *) param3))
			break;
		error = 0;
		break;

	case PPPIOCSFLAGS:
		/*
		 * Set the flags for the various options
		 */
		if (GET_USER(temp_i, (int *) param3))
			break;

		if (ppp->flags & ~temp_i & SC_CCP_OPEN)
			ppp_ccp_closed(ppp);

		save_flags(flags);
		cli();
		oldflags = ppp->flags;
		temp_i = (temp_i & SC_MASK) | (oldflags & ~SC_MASK);
		ppp->flags = temp_i;
		restore_flags(flags);

		if ((oldflags | temp_i) & SC_DEBUG)
			printk(KERN_INFO
			       "ppp_ioctl: set flags to %x\n", temp_i);
		error = 0;
		break;

	case PPPIOCSCOMPRESS:
		/*
		 * Set the compression mode
		 */
		error = ppp_set_compression
			(ppp, (struct ppp_option_data *) param3);
		break;

	case PPPIOCGUNIT:
		/*
		 * Obtain the unit number for this device.
		 */
		if (PUT_USER(ppp->line, (int *) param3))
			break;
		if (ppp->flags & SC_DEBUG)
			printk(KERN_INFO
			       "ppp_ioctl: get unit: %d\n", ppp->line);
		error = 0;
		break;

	case PPPIOCSDEBUG:
		/*
		 * Set the debug level
		 */
		if (GET_USER(temp_i, (int *) param3))
			break;
		temp_i = (temp_i & 0x1F) << 16;

		if ((ppp->flags | temp_i) & SC_DEBUG)
			printk(KERN_INFO
			       "ppp_ioctl: set dbg flags to %x\n", temp_i);

		save_flags(flags);
		cli();
		ppp->flags = (ppp->flags & ~0x1F0000) | temp_i;
		restore_flags(flags);
		error = 0;
		break;

	case PPPIOCGDEBUG:
		/*
		 * Get the debug level
		 */
		temp_i = (ppp->flags >> 16) & 0x1F;
		if (PUT_USER(temp_i, (int *) param3))
			break;
		error = 0;
		break;

	case PPPIOCGIDLE:
		/*
		 * Get the times since the last send/receive frame operation
		 */
		/* change absolute times to relative times. */
		cur_ddinfo.xmit_idle = (jiffies - ppp->last_xmit) / HZ;
		cur_ddinfo.recv_idle = (jiffies - ppp->last_recv) / HZ;
		if (COPY_TO_USER((void *) param3, &cur_ddinfo,
				 sizeof (cur_ddinfo)))
			break;
		error = 0;
		break;

	case PPPIOCSMAXCID:
		/*
		 * Set the maximum VJ header compression slot number.
		 */
		if (GET_USER(temp_i, (int *) param3))
			break;
		error = -EINVAL;
		if (temp_i < 2 || temp_i > 255)
			break;
		++temp_i;
		if (ppp->flags & SC_DEBUG)
			printk(KERN_INFO "ppp_ioctl: set maxcid to %d\n",
			       temp_i);
		if (ppp->slcomp != NULL)
			slhc_free(ppp->slcomp);
		ppp->slcomp = slhc_init(16, temp_i);

		error = -ENOMEM;
		if (ppp->slcomp == NULL) {
			printk(KERN_ERR "ppp: no memory for VJ compression\n");
			break;
		}
		error = 0;
		break;

	case PPPIOCGNPMODE:
	case PPPIOCSNPMODE:
		if (COPY_FROM_USER(&npi, (void *) param3, sizeof(npi)))
			break;

		switch (npi.protocol) {
		case PPP_IPV6:
			npi.protocol = NP_IPV6;
			break;
		case PPP_IP:
			npi.protocol = NP_IP;
			break;
		case PPP_IPX:
			npi.protocol = NP_IPX;
			break;
		case PPP_AT:
			npi.protocol = NP_AT;
			break;
		default:
			if (ppp->flags & SC_DEBUG)
				printk(KERN_DEBUG "pppioc[gs]npmode: "
				       "invalid proto %d\n", npi.protocol);
			error = -EINVAL;
			goto out;
		}

		if (param2 == PPPIOCGNPMODE) {
			npi.mode = ppp->sc_npmode[npi.protocol];
			if (COPY_TO_USER((void *) param3, &npi, sizeof(npi)))
				break;
		} else {
			ppp->sc_npmode[npi.protocol] = npi.mode;
			if (ppp->flags & SC_DEBUG)
				printk(KERN_DEBUG "ppp: set np %d to %d\n",
				       npi.protocol, npi.mode);
			mark_bh(NET_BH);
		}
		error = 0;
		break;

	default:
		/*
		 *  All other ioctl() events will come here.
		 */
		if (ppp->flags & SC_DEBUG)
			printk(KERN_ERR
			       "ppp_ioctl: invalid ioctl: %x, addr %lx\n",
			       param2, param3);

		error = -ENOIOCTLCMD;
		break;
	}
out:
	return error;
}

/*
 * Process the set-compression ioctl.
 */
static int
ppp_set_compression (struct ppp *ppp, struct ppp_option_data *odp)
{
	struct compressor *cp;
	int error, nb;
	unsigned long flags;
	__u8 *ptr;
	__u8 ccp_option[CCP_MAX_OPTION_LENGTH];
	struct ppp_option_data data;

	/*
	 * Fetch the compression parameters
	 */
	error = -EFAULT;
	if (COPY_FROM_USER(&data, odp, sizeof (data)))
		goto out;

	nb  = data.length;
	ptr = data.ptr;
	if ((unsigned) nb >= CCP_MAX_OPTION_LENGTH)
		nb = CCP_MAX_OPTION_LENGTH;

	if (COPY_FROM_USER(ccp_option, ptr, nb))
		goto out;

	error = -EINVAL;
	if (ccp_option[1] < 2)	/* preliminary check on the length byte */
		goto out;

	save_flags(flags);
	cli();
	ppp->flags &= ~(data.transmit? SC_COMP_RUN: SC_DECOMP_RUN);
	restore_flags(flags);

	cp = find_compressor (ccp_option[0]);
#if defined(CONFIG_KMOD) || defined(CONFIG_KERNELD)
	if (cp == NULL) {
		char modname[32];
		sprintf(modname, "ppp-compress-%d", ccp_option[0]);
		request_module(modname);
		cp = find_compressor(ccp_option[0]);
	}
#endif /* CONFIG_KMOD */

	if (cp == NULL) {
		if (ppp->flags & SC_DEBUG)
			printk(KERN_DEBUG
			       "%s: no compressor for [%x %x %x], %x\n",
			       ppp->name, ccp_option[0], ccp_option[1],
			       ccp_option[2], nb);
		goto out;		/* compressor not loaded */
	}

	/*
	 * Found a handler for the protocol - try to allocate
	 * a compressor or decompressor.
	 */
	error = 0;
	if (data.transmit) {
		if (ppp->sc_xc_state != NULL)
			(*ppp->sc_xcomp->comp_free)(ppp->sc_xc_state);
		ppp->sc_xc_state = NULL;

		ppp->sc_xcomp	 = cp;
		ppp->sc_xc_state = cp->comp_alloc(ccp_option, nb);
		if (ppp->sc_xc_state == NULL) {
			if (ppp->flags & SC_DEBUG)
				printk(KERN_DEBUG "%s: comp_alloc failed\n",
				       ppp->name);
			error = -ENOBUFS;
		}
	} else {
		if (ppp->sc_rc_state != NULL)
			(*ppp->sc_rcomp->decomp_free)(ppp->sc_rc_state);
		ppp->sc_rc_state = NULL;

		ppp->sc_rcomp	 = cp;
		ppp->sc_rc_state = cp->decomp_alloc(ccp_option, nb);
		if (ppp->sc_rc_state == NULL) {
			if (ppp->flags & SC_DEBUG)
				printk(KERN_DEBUG "%s: decomp_alloc failed\n",
				       ppp->name);
			error = -ENOBUFS;
		}
	}
out:
	return error;
}

/*
 * Handle a CCP packet.
 *
 * The CCP packet is passed along to the pppd process just like any
 * other PPP frame. The difference is that some processing needs to be
 * immediate or the compressors will become confused on the peer.
 */

static void ppp_proto_ccp(struct ppp *ppp, __u8 *dp, int len, int rcvd)
{
	int slen    = CCP_LENGTH(dp);
	__u8 *opt = dp	 + CCP_HDRLEN;
	int opt_len = slen - CCP_HDRLEN;
	unsigned long flags;

	if (slen > len)
		return;

	if (ppp->flags & SC_DEBUG)
		printk(KERN_DEBUG "ppp_proto_ccp rcvd=%d code=%x flags=%x\n",
		       rcvd, CCP_CODE(dp), ppp->flags);
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
		if (!rcvd) {
			/*
			 * we're agreeing to send compressed packets.
			 */
			if (ppp->sc_xc_state == NULL)
				break;

			if ((*ppp->sc_xcomp->comp_init)
			    (ppp->sc_xc_state,
			     opt, opt_len,
			     ppp->line, 0, ppp->flags & SC_DEBUG)) {
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
		     opt, opt_len,
		     ppp->line, 0, ppp->mru, ppp->flags & SC_DEBUG)) {
			if (ppp->flags & SC_DEBUG)
				printk(KERN_DEBUG "%s: decomp running\n",
				       ppp->name);
			cli();
			ppp->flags |= SC_DECOMP_RUN;
			ppp->flags &= ~(SC_DC_ERROR | SC_DC_FERROR);
		}
		break;

	case CCP_RESETACK:
		/*
		 * CCP Reset-ack resets compressors and decompressors
		 * as it passes through.
		 */
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

/*
 * CCP is down; free (de)compressor state if necessary.
 */

static void
ppp_ccp_closed(struct ppp *ppp)
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

/*************************************************************
 * RECEIVE-SIDE ROUTINES
 *************************************************************/

/*
 * On entry, a received frame is in skb.
 * Check it and dispose as appropriate.
 */
static int
ppp_receive_frame(struct ppp *ppp, struct sk_buff *skb)
{
	__u8	*data;
	int	count;
	int	proto;
	int	new_count;
	struct sk_buff *new_skb;
	ppp_proto_type	*proto_ptr;

	/*
	 * An empty frame is ignored. This occurs if the FLAG sequence
	 * precedes and follows each frame.
	 */
	if (skb == NULL)
		return 1;
	if (skb->len == 0) {
		KFREE_SKB(skb);
		return 1;
	}
	data = skb->data;
	count = skb->len;

	/*
	 * Generate an error if the frame is too small.
	 */
	if (count < PPP_HDRLEN + 2) {
		if (ppp->flags & SC_DEBUG)
			printk(KERN_DEBUG
			       "ppp: got runt ppp frame, %d chars\n", count);
		++ppp->estats.rx_length_errors;
		return 0;
	}

	if ( !(ppp->flags & SC_SYNC) ) { 
		/*
		 * Verify the FCS of the frame and discard the FCS characters
		 * from the end of the buffer.
		 */
		if (ppp->rfcs != PPP_GOODFCS) {
			if (ppp->flags & SC_DEBUG) {
				printk(KERN_DEBUG
				       "ppp: frame with bad fcs, length = %d\n",
				       count);
				ppp_print_buffer("bad frame", data, count);
			}
			++ppp->estats.rx_crc_errors;
			return 0;
		}
		count -= 2;		/* ignore the fcs characters */
		skb_trim(skb, count);
	}
	
	/*
	 * Process the active decompressor.
	 */
	if (ppp->sc_rc_state != NULL &&
	    (ppp->flags & SC_DECOMP_RUN) &&
	    ((ppp->flags & (SC_DC_FERROR | SC_DC_ERROR)) == 0)) {
		if (PPP_PROTOCOL(data) == PPP_COMP) {
			/*
			 * If the frame is compressed then decompress it.
			 */
			new_skb = dev_alloc_skb(ppp->mru + 128 + PPP_HDRLEN);
			if (new_skb == NULL) {
				printk(KERN_ERR "ppp_recv_frame: no memory\n");
				new_count = DECOMP_ERROR;
			} else {
				LIBERATE_SKB(new_skb);
				new_count = (*ppp->sc_rcomp->decompress)
					(ppp->sc_rc_state, data, count,
					 new_skb->data, ppp->mru + PPP_HDRLEN);
			}
			if (new_count > 0) {
				/* Frame was decompressed OK */
				KFREE_SKB(skb);
				skb = new_skb;
				count = new_count;
				data = skb_put(skb, count);

			} else {
				/*
				 * On a decompression error, we pass the
				 * compressed frame up to pppd as an
				 * error indication.
				 */
				if (ppp->flags & SC_DEBUG)
					printk(KERN_INFO "%s: decomp err %d\n",
					       ppp->name, new_count);
				if (new_skb != 0)
					KFREE_SKB(new_skb);
				if (ppp->slcomp != 0)
					slhc_toss(ppp->slcomp);
				++ppp->stats.ppp_ierrors;
				if (new_count == DECOMP_FATALERROR) {
					ppp->flags |= SC_DC_FERROR;
				} else {
					ppp->flags |= SC_DC_ERROR;
				}
			}


		} else {
			/*
			 * The frame is not compressed. Pass it to the
			 * decompression code so it can update its
			 * dictionary if necessary.
			 */
			(*ppp->sc_rcomp->incomp)(ppp->sc_rc_state,
						 data, count);
		}
	}
	else if (PPP_PROTOCOL(data) == PPP_COMP && (ppp->flags & SC_DEBUG))
		printk(KERN_INFO "%s: not decomp, rc_state=%p flags=%x\n",
		       ppp->name, ppp->sc_rc_state, ppp->flags);

	/*
	 * Count the frame and print it
	 */
	++ppp->stats.ppp_ipackets;
	ppp->stats.ppp_ioctects += count;
	if (ppp->flags & SC_LOG_INPKT)
		ppp_print_buffer ("receive frame", data, count);

	/*
	 * Find the procedure to handle this protocol.
	 * The last one is marked as protocol 0 which is the 'catch-all'
	 * to feed it to the pppd daemon.
	 */
	proto = PPP_PROTOCOL(data);
	proto_ptr = proto_list;
	while (proto_ptr->proto != 0 && proto_ptr->proto != proto)
		++proto_ptr;

	/*
	 * Update the appropriate statistic counter.
	 */
	if (!(*proto_ptr->func)(ppp, skb)) {
		KFREE_SKB(skb);
		++ppp->stats.ppp_discards;
	}

	return 1;
}

/*
 * An input error has been detected, so we need to inform
 * the VJ decompressor.
 */
static void
ppp_receive_error(struct ppp *ppp)
{
	CHECK_PPP_VOID();

	if (ppp->slcomp != 0)
		slhc_toss(ppp->slcomp);
}

/*
 * Put the input frame into the networking system for the indicated protocol
 */
static int
ppp_rcv_rx(struct ppp *ppp, __u16 proto, struct sk_buff *skb)
{

	/*
	 * Fill in a few fields of the skb and give it to netif_rx().
	 */
	skb->dev      = ppp2dev(ppp);	/* We are the device */
	skb->protocol = htons(proto);
	skb_pull(skb, PPP_HDRLEN);	/* pull off ppp header */
	skb->mac.raw   = skb->data;
	ppp->last_recv = jiffies;
	netif_rx (skb);
	return 1;
}

/*
 * Process the receipt of an IP frame
 */
static int
rcv_proto_ip(struct ppp *ppp, struct sk_buff *skb)
{
	CHECK_PPP(0);
	if ((ppp2dev(ppp)->flags & IFF_UP) && (skb->len > 0)
	    && ppp->sc_npmode[NP_IP] == NPMODE_PASS)
		return ppp_rcv_rx(ppp, ETH_P_IP, skb);
	return 0;
}

/*
 * Process the receipt of an IPv6 frame
 */
static int
rcv_proto_ipv6(struct ppp *ppp, struct sk_buff *skb)
{
	CHECK_PPP(0);
	if ((ppp2dev(ppp)->flags & IFF_UP) && (skb->len > 0)
	    && ppp->sc_npmode[NP_IPV6] == NPMODE_PASS)
		return ppp_rcv_rx(ppp, ETH_P_IPV6, skb);
	return 0;
}

/*
 * Process the receipt of an IPX frame
 */
static int
rcv_proto_ipx(struct ppp *ppp, struct sk_buff *skb)
{
	CHECK_PPP(0);
	if (((ppp2dev(ppp)->flags & IFF_UP) != 0) && (skb->len > 0)
	    && ppp->sc_npmode[NP_IPX] == NPMODE_PASS)
		return ppp_rcv_rx(ppp, ETH_P_IPX, skb);
	return 0;
}

/*
 * Process the receipt of an Appletalk frame
 */
static int
rcv_proto_at(struct ppp *ppp, struct sk_buff *skb)
{
	CHECK_PPP(0);
	if ((ppp2dev(ppp)->flags & IFF_UP) && (skb->len > 0)
	    && ppp->sc_npmode[NP_AT] == NPMODE_PASS)
		return ppp_rcv_rx(ppp, ETH_P_PPPTALK, skb);
	return 0;
}

/*
 * Process the receipt of an VJ Compressed frame
 */
static int
rcv_proto_vjc_comp(struct ppp *ppp, struct sk_buff *skb)
{
	int new_count;

	CHECK_PPP(0);
	if ((ppp->flags & SC_REJ_COMP_TCP) || ppp->slcomp == NULL)
		return 0;
	new_count = slhc_uncompress(ppp->slcomp, skb->data + PPP_HDRLEN,
				    skb->len - PPP_HDRLEN);
	if (new_count <= 0) {
		if (ppp->flags & SC_DEBUG)
			printk(KERN_NOTICE
			       "ppp: error in VJ decompression\n");
		return 0;
	}
	new_count += PPP_HDRLEN;
	if (new_count > skb->len)
		skb_put(skb, new_count - skb->len);
	else
		skb_trim(skb, new_count);
	return rcv_proto_ip(ppp, skb);
}

/*
 * Process the receipt of an VJ Un-compressed frame
 */
static int
rcv_proto_vjc_uncomp(struct ppp *ppp, struct sk_buff *skb)
{
	CHECK_PPP(0);
	if ((ppp->flags & SC_REJ_COMP_TCP) || ppp->slcomp == NULL)
		return 0;
	if (slhc_remember(ppp->slcomp, skb->data + PPP_HDRLEN,
			  skb->len - PPP_HDRLEN) <= 0) {
		if (ppp->flags & SC_DEBUG)
			printk(KERN_NOTICE "ppp: error in VJ memorizing\n");
		return 0;
	}
	return rcv_proto_ip(ppp, skb);
}

static int
rcv_proto_ccp(struct ppp *ppp, struct sk_buff *skb)
{
	CHECK_PPP(0);
	ppp_proto_ccp (ppp, skb->data + PPP_HDRLEN, skb->len - PPP_HDRLEN, 1);
	return rcv_proto_unknown(ppp, skb);
}

/*
 * Receive all unclassified protocols.
 */
static int
rcv_proto_unknown(struct ppp *ppp, struct sk_buff *skb)
{
	CHECK_PPP(0);

	/*
	 * Limit queue length by dropping old frames.
	 */
	skb_queue_tail(&ppp->rcv_q, skb);
	while (ppp->rcv_q.qlen > PPP_MAX_RCV_QLEN) {
		struct sk_buff *skb = skb_dequeue(&ppp->rcv_q);
		if (skb)
			KFREE_SKB(skb);
	}

	wake_up_interruptible (&ppp->read_wait);
	if (ppp->tty->fasync != NULL)
		kill_fasync (ppp->tty->fasync, SIGIO);

	return 1;
}

/*************************************************************
 * TRANSMIT-SIDE ROUTINES
 *************************************************************/

/* local function to store a value into the LQR frame */
extern inline __u8 * store_long (register __u8 *p, register int value) {
	*p++ = (__u8) (value >> 24);
	*p++ = (__u8) (value >> 16);
	*p++ = (__u8) (value >>	 8);
	*p++ = (__u8) value;
	return p;
}

/*
 * Compress and send an frame to the peer.
 * Should be called with xmit_busy == 1, having been set by the caller.
 * That is, we use xmit_busy as a lock to prevent reentry of this
 * procedure.
 */
static void
ppp_send_frame(struct ppp *ppp, struct sk_buff *skb)
{
	int	proto;
	__u8	*data;
	int	count;
	__u8	*p;
	int	ret;

	CHECK_PPP_VOID();
	data = skb->data;
	count = skb->len;

	/* dump the buffer */
	if (ppp->flags & SC_LOG_OUTPKT)
		ppp_print_buffer ("write frame", data, count);

	/*
	 * Handle various types of protocol-specific compression
	 * and other processing, including:
	 * - VJ TCP header compression
	 * - updating LQR packets
	 * - updating CCP state on CCP packets
	 */
	proto = PPP_PROTOCOL(data);
	switch (proto) {
	case PPP_IP:
		if ((ppp->flags & SC_COMP_TCP) && ppp->slcomp != NULL)
			skb = ppp_vj_compress(ppp, skb);
		break;

	case PPP_LQR:
		/*
		 * Update the LQR frame with the current MIB information.
		 * This way the information is accurate and up-to-date.
		 */
		if (count < 48)
			break;
		p = data + 40;	/* Point to last two items. */
		p = store_long(p, ppp->stats.ppp_opackets + 1);
		p = store_long(p, ppp->stats.ppp_ooctects + count);
		++ppp->stats.ppp_olqrs;
		break;

	case PPP_CCP:
		/*
		 * Outbound compression control frames
		 */
		ppp_proto_ccp(ppp, data + PPP_HDRLEN, count - PPP_HDRLEN, 0);
		break;
	}
	data = skb->data;
	count = skb->len;

	/*
	 * Compress the whole frame if possible.
	 */
	if (((ppp->flags & SC_COMP_RUN) != 0)	&&
	    (ppp->sc_xc_state != (void *) 0)	&&
	    (proto != PPP_LCP)			&&
	    (proto != PPP_CCP)) {
		struct sk_buff *new_skb;
		int new_count;

		/* Allocate an skb for the compressed frame. */
		new_skb = alloc_skb(ppp->mtu + PPP_HDRLEN, GFP_ATOMIC);
		if (new_skb == NULL) {
			printk(KERN_ERR "ppp_send_frame: no memory\n");
			KFREE_SKB(skb);
			ppp->xmit_busy = 0;
			return;
		}
		LIBERATE_SKB(new_skb);

		/* Compress the frame. */
		new_count = (*ppp->sc_xcomp->compress)
			(ppp->sc_xc_state, data, new_skb->data,
			 count, ppp->mtu + PPP_HDRLEN);

		/* Did it compress? */
		if (new_count > 0 && (ppp->flags & SC_CCP_UP)) {
			skb_put(new_skb, new_count);
			KFREE_SKB(skb);
			skb = new_skb;
		} else {
			/*
			 * The frame could not be compressed, or it could not
			 * be sent in compressed form because CCP is down.
			 */
			KFREE_SKB(new_skb);
		}
	}

	/*
	 * Send the frame
	 */
	if ( ppp->flags & SC_SYNC ) 
		ret = ppp_sync_send(ppp, skb);
	else
		ret = ppp_async_send(ppp, skb);
	if (ret > 0) {
		/* we can release the lock */
		ppp->xmit_busy = 0;
	} else if (ret < 0) {
		/* can't happen, since the caller got the xmit_busy lock */
		printk(KERN_ERR "ppp: ppp_async_send didn't accept pkt\n");
	}
}

/*
 * Apply VJ TCP header compression to a packet.
 */
static struct sk_buff *
ppp_vj_compress(struct ppp *ppp, struct sk_buff *skb)
{
	__u8 *orig_data, *data;
	struct sk_buff *new_skb;
	int len, proto;

	new_skb = alloc_skb(skb->len, GFP_ATOMIC);
	if (new_skb == NULL) {
		printk(KERN_ERR "ppp: no memory for vj compression\n");
		return skb;
	}
	LIBERATE_SKB(new_skb);

	orig_data = data = skb->data + PPP_HDRLEN;
	len = slhc_compress(ppp->slcomp, data, skb->len - PPP_HDRLEN,
			    new_skb->data + PPP_HDRLEN, &data,
			    (ppp->flags & SC_NO_TCP_CCID) == 0);

	if (data == orig_data) {
		/* Couldn't compress the data */
		KFREE_SKB(new_skb);
		return skb;
	}

	/* The data has been changed */
	if (data[0] & SL_TYPE_COMPRESSED_TCP) {
		proto = PPP_VJC_COMP;
		data[0] ^= SL_TYPE_COMPRESSED_TCP;
	} else {
		if (data[0] >= SL_TYPE_UNCOMPRESSED_TCP)
			proto = PPP_VJC_UNCOMP;
		else
			proto = PPP_IP;
		data[0] = orig_data[0];
	}

	data = skb_put(new_skb, len + PPP_HDRLEN);
	data[0] = PPP_ALLSTATIONS;
	data[1] = PPP_UI;
	data[2] = 0;
	data[3] = proto;

	KFREE_SKB(skb);
	return new_skb;
}

static inline void
ppp_send_frames(struct ppp *ppp)
{
	struct sk_buff *skb;

	while (!test_and_set_bit(0, &ppp->xmit_busy)) {
		skb = skb_dequeue(&ppp->xmt_q);
		if (skb == NULL) {
			ppp->xmit_busy = 0;
			break;
		}
		ppp_send_frame(ppp, skb);
	}
	if (!ppp->xmit_busy && ppp->dev.tbusy) {
		ppp->dev.tbusy = 0;
		mark_bh(NET_BH);
	}
}

/*
 * Called from the hardware (tty) layer when it can accept
 * another packet.
 */
static void
ppp_output_wakeup(struct ppp *ppp)
{
	CHECK_PPP_VOID();

	if (!ppp->xmit_busy) {
		printk(KERN_ERR "ppp_output_wakeup called but xmit_busy==0\n");
		return;
	}
	ppp->xmit_busy = 0;
	ppp_send_frames(ppp);
}

/*
 * Send a control frame (from pppd).
 */
static void
ppp_send_ctrl(struct ppp *ppp, struct sk_buff *skb)
{
	CHECK_PPP_VOID();

	/*
	 * Put the packet on the queue, then send as many as we can.
	 */
	skb_queue_tail(&ppp->xmt_q, skb);
	ppp_send_frames(ppp);
}


/*************************************************************
 * NETWORK OUTPUT
 *    This routine accepts requests from the network layer
 *    and attempts to deliver the packets.
 *************************************************************/
/*
 * Send a frame to the peer.
 * Returns 1 iff the frame was not accepted.
 */
static int
ppp_dev_xmit(struct sk_buff *skb, struct device *dev)
{
	struct ppp *ppp = dev2ppp(dev);
	struct tty_struct *tty = ppp2tty(ppp);
	enum NPmode npmode;
	int proto;
	unsigned char *hdr;

	/* just a little sanity check. */
	if (skb == NULL)
		return 0;
	if (skb->data == NULL) {
		KFREE_SKB(skb);
		return 0;
	}

	/*
	 * Avoid timing problem should tty hangup while data is
	 * queued to be sent.
	 */
	if (!ppp->inuse) {
		KFREE_SKB(skb);
		return 0;
	}

	/*
	 * Validate the tty interface
	 */
	if (tty == NULL) {
		if (ppp->flags & SC_DEBUG)
			printk(KERN_ERR
			       "ppp_dev_xmit: %s not connected to a TTY!\n",
			       dev->name);
		KFREE_SKB(skb);
		return 0;
	}

	/*
	 * Work out the appropriate network-protocol mode for this packet.
	 */
	npmode = NPMODE_PASS;	/* default */
	switch (ntohs(skb->protocol)) {
	case ETH_P_IP:
		proto = PPP_IP;
		npmode = ppp->sc_npmode[NP_IP];
		break;
	case ETH_P_IPV6:
		proto = PPP_IPV6;
		npmode = ppp->sc_npmode[NP_IPV6];
		break;
	case ETH_P_IPX:
		proto = PPP_IPX;
		npmode = ppp->sc_npmode[NP_IPX];
		break;
	case ETH_P_PPPTALK:
	case ETH_P_ATALK:
		proto = PPP_AT;
		npmode = ppp->sc_npmode[NP_AT];
		break;
	default:
		if (ppp->flags & SC_DEBUG)
			printk(KERN_INFO "%s: packet for unknown proto %x\n",
			       ppp->name, ntohs(skb->protocol));
		KFREE_SKB(skb);
		return 0;
	}

	/*
	 * Drop, accept or reject the packet depending on the mode.
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
			printk(KERN_DEBUG "%s: returning frame\n", ppp->name);
		KFREE_SKB(skb);
		return 0;

	case NPMODE_ERROR:
	case NPMODE_DROP:
		if (ppp->flags & SC_DEBUG)
			printk(KERN_DEBUG
			       "ppp_dev_xmit: dropping (npmode = %d) on %s\n",
			       npmode, ppp->name);
		KFREE_SKB(skb);
		return 0;
	}

	/*
	 * The dev->tbusy field acts as a lock to allow only
	 * one packet to be processed at a time.  If we can't
	 * get the lock, try again later.
	 * We deliberately queue as little as possible inside
	 * the ppp driver in order to minimize the latency
	 * for high-priority packets.
	 */
	if (test_and_set_bit(0, &ppp->xmit_busy)) {
		dev->tbusy = 1;	/* can't take it now */
		return 1;
	}
	dev->tbusy = 0;

	/*
	 * Put the 4-byte PPP header on the packet.
	 * If there isn't room for it, we have to copy the packet.
	 */
	if (skb_headroom(skb) < PPP_HDRLEN) {
		struct sk_buff *new_skb;

		new_skb = alloc_skb(skb->len + PPP_HDRLEN, GFP_ATOMIC);
		if (new_skb == NULL) {
			printk(KERN_ERR "%s: skb hdr alloc failed\n",
			       ppp->name);
			KFREE_SKB(skb);
			ppp->xmit_busy = 0;
			ppp_send_frames(ppp);
			return 0;
		}
		LIBERATE_SKB(new_skb);
		skb_reserve(new_skb, PPP_HDRLEN);
		memcpy(skb_put(new_skb, skb->len), skb->data, skb->len);
		KFREE_SKB(skb);
		skb = new_skb;
	}

	hdr = skb_push(skb, PPP_HDRLEN);
	hdr[0] = PPP_ALLSTATIONS;
	hdr[1] = PPP_UI;
	hdr[2] = proto >> 8;
	hdr[3] = proto;

	ppp_send_frame(ppp, skb);
	if (!ppp->xmit_busy)
		ppp_send_frames(ppp);
	return 0;
}

#if LINUX_VERSION_CODE < VERSION(2,1,15)
/*
 * Null hard_header and header_rebuild routines.
 */
static int ppp_dev_header(struct sk_buff *skb, struct device *dev,
			  unsigned short type, void *daddr,
			  void *saddr, unsigned int len)
{
	return 0;
}

static int ppp_dev_rebuild(void *eth, struct device *dev,
			   unsigned long raddr, struct sk_buff *skb)
{
	return 0;
}
#endif /* < 2.1.15 */

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

/*************************************************************
 * UTILITIES
 *    Miscellany called by various functions above.
 *************************************************************/

/* Locate the previous instance of the PPP channel */
static struct ppp *
ppp_find(int pid_value)
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
ppp_alloc(void)
{
	int		if_num;
	int		status;
	struct device	*dev;
	struct ppp	*ppp;

	/* try to find an free device */
	for (ppp = ppp_list; ppp != 0; ppp = ppp->next) {
		if (!test_and_set_bit(0, &ppp->inuse)) {
			dev = ppp2dev(ppp);
			if (dev->flags & IFF_UP) {
				clear_bit(0, &ppp->inuse);
				continue;
			}
			/* Reregister device */
			unregister_netdev(dev);
			if (register_netdev(dev) == 0)
				return ppp;
			printk(KERN_DEBUG "could not reregister ppp device\n");
			/* leave inuse set in this case */
		}
	}

	/*
	 * There are no available units, so make a new one.
	 */
	ppp = (struct ppp *) kmalloc(sizeof(struct ppp), GFP_KERNEL);
	if (ppp == 0) {
		printk(KERN_ERR "ppp: struct ppp allocation failed\n");
		return 0;
	}
	memset(ppp, 0, sizeof(*ppp));

	/* initialize channel control data */
	ppp->magic = PPP_MAGIC;
	ppp->next = NULL;
	ppp->inuse = 1;
	ppp->read_wait = NULL;

	/*
	 * Make up a suitable name for this device
	 */
	dev = ppp2dev(ppp);
	dev->name = ppp->name;
#if LINUX_VERSION_CODE < VERSION(2,1,31)
	if_num = (ppp_list == 0)? 0: ppp_last->line + 1;
	sprintf(ppp->name, "ppp%d", if_num);
#else
	if_num = dev_alloc_name(dev, "ppp%d");
#endif
	if (if_num < 0) {
		printk(KERN_ERR "ppp: dev_alloc_name failed (%d)\n", if_num);
		kfree(ppp);
		return 0;
	}
	ppp->line = if_num;
	ppp->slcomp = NULL;

	dev->next = NULL;
	dev->init = ppp_init_dev;
	dev->name = ppp->name;
	dev->priv = (void *) ppp;

	/* register device so that we can be ifconfig'd */
	/* ppp_init_dev() will be called as a side-effect */
	status = register_netdev (dev);
	if (status == 0) {
		printk(KERN_INFO "registered device %s\n", dev->name);
	} else {
		printk(KERN_ERR
		       "ppp_alloc - register_netdev(%s) = %d failure.\n",
		       dev->name, status);
		kfree(ppp);
		ppp = NULL;
	}

	/* link this unit into our list */
	if (ppp_list == 0)
		ppp_list = ppp;
	else
		ppp_last->next = ppp;
	ppp_last = ppp;

	return ppp;
}

/*
 * Initialize the generic parts of the ppp structure.
 */
static void
ppp_generic_init(struct ppp *ppp)
{
	int indx;

	ppp->flags  = 0;
	ppp->mtu    = PPP_MTU;
	ppp->mru    = PPP_MRU;

	skb_queue_head_init(&ppp->xmt_q);
	skb_queue_head_init(&ppp->rcv_q);

	ppp->last_xmit	= jiffies;
	ppp->last_recv  = jiffies;
	ppp->xmit_busy  = 0;

	/* clear statistics */
	memset(&ppp->stats, 0, sizeof (struct pppstat));
	memset(&ppp->estats, 0, sizeof(struct net_device_stats));

	/* PPP compression data */
	ppp->sc_xc_state = NULL;
	ppp->sc_rc_state = NULL;

	for (indx = 0; indx < NUM_NP; ++indx)
		ppp->sc_npmode[indx] = NPMODE_PASS;
}

/*
 * Called to clean up the generic parts of the ppp structure.
 */
static void
ppp_release(struct ppp *ppp)
{
	struct sk_buff *skb;

	CHECK_PPP_MAGIC(ppp);

	if (ppp->flags & SC_DEBUG)
		printk(KERN_DEBUG "%s released\n", ppp->name);

	ppp_ccp_closed(ppp);

        /* Ensure that the pppd process is not hanging on select()/poll() */
        wake_up_interruptible(&ppp->read_wait);

	if (ppp->slcomp) {
		slhc_free(ppp->slcomp);
		ppp->slcomp = NULL;
	}

	while ((skb = skb_dequeue(&ppp->rcv_q)) != NULL)
		KFREE_SKB(skb);
	while ((skb = skb_dequeue(&ppp->xmt_q)) != NULL)
		KFREE_SKB(skb);

	ppp->inuse = 0;
	if (ppp->dev.tbusy) {
		ppp->dev.tbusy = 0;
		mark_bh(NET_BH);
	}
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
ppp_print_buffer (const char *name, const __u8 *buf, int count)
{
	__u8 line[44];

	if (name != NULL)
		printk(KERN_DEBUG "ppp: %s, count = %d\n", name, count);

	while (count > 8) {
		memset (line, 32, 44);
		ppp_print_hex (line, buf, 8);
		ppp_print_char (&line[8 * 3], buf, 8);
		printk(KERN_DEBUG "%s\n", line);
		count -= 8;
		buf += 8;
	}

	if (count > 0) {
		memset (line, 32, 44);
		ppp_print_hex (line, buf, count);
		ppp_print_char (&line[8 * 3], buf, count);
		printk(KERN_DEBUG "%s\n", line);
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

	new = (struct compressor_link *)
		kmalloc (sizeof (struct compressor_link), GFP_KERNEL);

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
		printk(KERN_INFO "PPP: ppp_init() failure %d\n", status);
#if LINUX_VERSION_CODE < VERSION(2,1,18)
	else
		(void) register_symtab (&ppp_syms);
#endif

	return status;
}

void
cleanup_module(void)
{
	int status;
	struct ppp *ppp, *next_ppp;
	int busy = 0;

	/*
	 * Ensure that the devices are not in operation.
	 */
	for (ppp = ppp_list; ppp != 0; ppp = ppp->next) {
		CHECK_PPP_MAGIC(ppp);
		if (ppp->inuse || (ppp->dev.flags & IFF_UP))
			++busy;
	}
	if (busy)
		printk(KERN_CRIT "PPP: removing despite %d units in use!\n",
		       busy);

	/*
	 * Release the tty registration of the line discipline so that
	 * ttys can no longer be put into PPP line discipline.
	 */
	status = tty_register_ldisc (N_PPP, NULL);
	if (status != 0)
		printk(KERN_ERR
		       "PPP: Unable to unregister ppp line discipline "
		       "(err = %d)\n", status);
	else
		printk(KERN_INFO
		       "PPP: ppp line discipline successfully unregistered\n");

	/*
	 * De-register the devices so that there is no problem with them
	 */
	for (ppp = ppp_list; ppp != 0; ppp = next_ppp) {
		next_ppp = ppp->next;
		unregister_netdev(&ppp->dev);
		kfree (ppp);
	}
}
#endif
