/*
   PPP for Linux

   $Id: ppp.c,v 1.2 1994/05/30 02:42:55 paulus Exp $
*/

/*
   Sources:

   slip.c

   RFC1331: The Point-to-Point Protocol (PPP) for the Transmission of
   Multi-protocol Datagrams over Point-to-Point Links

   RFC1332: IPCP

   ppp-2.0

   Flags for this module (any combination is acceptable for testing.):

   NET02D	      -	Define if using Net-2-Debugged in kernels earler
   			than v1.1.4.

   NEW_TTY_DRIVERS    -	Define if using new Ted Ts'o's alpha TTY drivers
   			from tsx-11.mit.edu. From Ted Ts'o.

   OPTIMIZE_FLAG_TIME -	Number of jiffies to force sending of leading flag
			character. This is normally set to ((HZ * 3) / 2).
			This is 1.5 seconds. If not defined then the leading
			flag is always sent.  
*/

/* #define NET02D					/* */
/* #define NEW_TTY_DRIVERS			/* */
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
#include <linux/sched.h>   /* to get the struct task_struct */
#include <linux/string.h>  /* used in new tty drivers */
#include <linux/signal.h>  /* used in new tty drivers */
#include <asm/system.h>
#include <asm/bitops.h>
#include <asm/segment.h>

#ifdef NET02D				/* v1.1.4 net code and earlier */
#include <dev.h>
#include <skbuff.h>
#define	skb_queue_head_init(buf)	*(buf) = NULL
#else					/* v1.1.5 and later */
#include <linux/netdevice.h>
#include <linux/skbuff.h>
#endif

#include <linux/ppp.h>

#include <ip.h>
#include <tcp.h>
#include <inet.h>
#include "slhc.h"

#include <linux/if_arp.h>
#ifndef ARPHRD_PPP
#define ARPHRD_PPP 0
#endif

#define PRINTK(p) printk p ;
#define ASSERT(p) if (!p) PRINTK ((KERN_CRIT "assertion failed: " # p))
#define PRINTKN(n,p) {if (ppp_debug >= n) PRINTK (p)}
#define CHECK_PPP(a)  if (!ppp->inuse) { PRINTK ((ppp_warning, __LINE__)) return a;}
#define CHECK_PPP_VOID()  if (!ppp->inuse) { PRINTK ((ppp_warning, __LINE__)) return;}

#define in_xmap(ppp,c)	(ppp->xmit_async_map[(c) >> 5] & (1 << ((c) & 0x1f)))
#define in_rmap(ppp,c)	((((unsigned int) (unsigned char) (c)) < 0x20) && \
			ppp->recv_async_map & (1 << (c)))

#define bset(p,b)	((p)[(b) >> 5] |= (1 << ((b) & 0x1f)))

int ppp_debug = 2;
int ppp_debug_netpackets = 0;

/* Define this string only once for all macro envocations */
static char ppp_warning[] = KERN_WARNING "PPP: ALERT! not INUSE! %d\n";

int ppp_init(struct device *);
static void ppp_init_ctrl_blk(struct ppp *);
static int ppp_dev_open(struct device *);
static int ppp_dev_close(struct device *);
static void ppp_kick_tty(struct ppp *);

#ifdef NEW_TTY_DRIVERS
#define ppp_find(tty) ((struct ppp *) tty->disc_data)
#else
static void ppp_output_done(void *);
static void ppp_unesc(struct ppp *ppp, unsigned char *c, int n);
static struct ppp *ppp_find(struct tty_struct *);
#endif

static void ppp_doframe(struct ppp *);
static int ppp_do_ip(struct ppp *, unsigned short, unsigned char *, int);
static int ppp_us_queue(struct ppp *, unsigned short, unsigned char *, int);
static int ppp_xmit(struct sk_buff *, struct device *);
static unsigned short ppp_type_trans(struct sk_buff *, struct device *);

#ifdef NET02D
static int ppp_header(unsigned char *buff, struct device *dev,
		      unsigned short type, unsigned long daddr,
		      unsigned long saddr, unsigned len);
static int ppp_rebuild_header(void *buff, struct device *dev);
static void ppp_add_arp(unsigned long addr, struct sk_buff *skb,
			struct device *dev);
#else
static int ppp_header(unsigned char *, struct device *, unsigned short,
		      void *, void *, unsigned, struct sk_buff *);
static int ppp_rebuild_header(void *, struct device *, unsigned long,
			      struct sk_buff *);
#endif

static struct enet_statistics *ppp_get_stats (struct device *);
static struct ppp *ppp_alloc(void);
static int ppp_lock(struct ppp *);
static void ppp_unlock(struct ppp *);
static void ppp_add_fcs(struct ppp *);
static int ppp_check_fcs(struct ppp *);
static void ppp_print_buffer(const char *,char *,int,int);

static int ppp_read(struct tty_struct *, struct file *, unsigned char *,
		    unsigned int);
static int ppp_write(struct tty_struct *, struct file *, unsigned char *,
		     unsigned int);
static int ppp_ioctl(struct tty_struct *, struct file *, unsigned int,
		     unsigned long);
static int ppp_select(struct tty_struct *tty, struct inode * inode,
		      struct file * filp, int sel_type, select_table * wait);
static int ppp_open(struct tty_struct *);
static void ppp_close(struct tty_struct *);

#ifdef NEW_TTY_DRIVERS
static void ppp_receive_buf(struct tty_struct *tty, unsigned char *cp,
			    char *fp, int count);
static void ppp_write_wakeup(struct tty_struct *tty);
#else
static void ppp_tty_input_ready(struct tty_struct *);
#endif

/* FCS table from RFC1331 */

static unsigned short fcstab[256] = {
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

struct tty_ldisc ppp_ldisc;

static struct ppp ppp_ctrl[PPP_NRUNIT];

/*************************************************************
 * INITIALIZATION
 *************************************************************/

static int first_time = 1;

/* called at boot time for each ppp device */

int
ppp_init(struct device *dev)
{
  struct ppp *ppp;
  int i;

  ppp = &ppp_ctrl[dev->base_addr];

  if (first_time) {
    first_time = 0;

    printk (KERN_INFO "PPP: version %s (%d channels)"
#ifdef NET02D
	   " NET02D"
#endif
#ifdef NEW_TTY_DRIVERS
	   " NEW_TTY_DRIVERS"
#endif
#ifdef OPTIMIZE_FLAG_TIME
	   " OPTIMIZE_FLAGS"
#endif
	   "\n", PPP_VERSION, PPP_NRUNIT);

    printk (KERN_INFO
	   "TCP compression code copyright 1989 Regents of the "
	   "University of California\n");

    (void) memset(&ppp_ldisc, 0, sizeof(ppp_ldisc));
    ppp_ldisc.open    = ppp_open;
    ppp_ldisc.close   = ppp_close;
    ppp_ldisc.read    = ppp_read;
    ppp_ldisc.write   = ppp_write;
    ppp_ldisc.ioctl   = ppp_ioctl;
    ppp_ldisc.select  = ppp_select;

#ifdef NEW_TTY_DRIVERS
    ppp_ldisc.magic       = TTY_LDISC_MAGIC;
    ppp_ldisc.receive_buf = ppp_receive_buf;
    ppp_ldisc.write_wakeup = ppp_write_wakeup;
#else
    ppp_ldisc.handler     = ppp_tty_input_ready;
#endif

    if ((i = tty_register_ldisc(N_PPP, &ppp_ldisc)) == 0)
      printk(KERN_INFO "PPP line discipline registered.\n");
    else
      printk(KERN_ERR "error registering line discipline: %d\n", i);
  }

  /* initialize PPP control block */
  ppp_init_ctrl_blk (ppp);
  ppp->inuse = 0;
  ppp->line  = dev->base_addr;
  ppp->tty   = NULL;
  ppp->dev   = dev;

  /* clear statistics */
  memset (&ppp->stats, '\0', sizeof (struct ppp_stats));

  /* device INFO */
  dev->mtu             = PPP_MTU;
  dev->hard_start_xmit = ppp_xmit;
  dev->open            = ppp_dev_open;
  dev->stop            = ppp_dev_close;
  dev->get_stats       = ppp_get_stats;
  dev->hard_header     = ppp_header;
  dev->type_trans      = ppp_type_trans;
  dev->rebuild_header  = ppp_rebuild_header;
  dev->hard_header_len = 0;
  dev->addr_len        = 0;
  dev->type            = ARPHRD_PPP;

#ifdef NET02D
  dev->add_arp         = ppp_add_arp;
  dev->queue_xmit      = dev_queue_xmit;
#endif

  for (i = 0; i < DEV_NUMBUFFS; i++)
    skb_queue_head_init(&dev->buffs[i]);  /* = NULL if NET02D */

  /* New-style flags */
  dev->flags      = IFF_POINTOPOINT;
  dev->family     = AF_INET;
  dev->pa_addr    = 0;
  dev->pa_brdaddr = 0;
  dev->pa_mask    = 0;
  dev->pa_alen    = sizeof(unsigned long);

  return 0;
}

static void
ppp_init_ctrl_blk(struct ppp *ppp)
{
  ppp->magic		= PPP_MAGIC;
  ppp->sending		= 0;
  ppp->toss		= 0xFE;
  ppp->escape		= 0;

  ppp->flags		= 0;
  ppp->mtu		= PPP_MTU;
  ppp->mru		= PPP_MRU;
  ppp->fcs		= 0;

  memset (ppp->xmit_async_map, 0, sizeof (ppp->xmit_async_map));
  ppp->xmit_async_map[0] = 0xffffffff;
  ppp->xmit_async_map[3] = 0x60000000;
  ppp->recv_async_map	 = 0x00000000;

  ppp->slcomp		= NULL;
  ppp->rbuff		= NULL;
  ppp->xbuff		= NULL;
  ppp->cbuff		= NULL;

  ppp->rhead		= NULL;
  ppp->rend		= NULL;
  ppp->rcount		= 0;
  ppp->xhead		= NULL;
  ppp->xtail		= NULL;

  ppp->us_rbuff		= NULL;
  ppp->us_rbuff_end	= NULL;
  ppp->us_rbuff_head	= NULL;
  ppp->us_rbuff_tail	= NULL;
  ppp->read_wait	= NULL;
  ppp->write_wait	= NULL;
  ppp->us_rbuff_lock	= 0;
  ppp->inp_sig		= 0;
  ppp->inp_sig_pid	= 0;

#ifdef OPTIMIZE_FLAG_TIME /* ensure flag will always be sent first time */
  ppp->last_xmit	= jiffies - OPTIMIZE_FLAG_TIME;
#else
  ppp->last_xmit	= 0;
#endif

  /* clear statistics */
  memset (&ppp->stats, '\0', sizeof (struct ppp_stats));

  /* Reset the demand dial information */
  ppp->ddinfo.ip_sjiffies  =
  ppp->ddinfo.ip_rjiffies  =
  ppp->ddinfo.nip_sjiffies =
  ppp->ddinfo.nip_rjiffies = jiffies;
}

/*
 * MTU has been changed by the IP layer. Unfortunately we are not told
 * about this, but we spot it ourselves and fix things up. We could be
 * in an upcall from the tty driver, or in an ip packet queue.
 */
   
static void
ppp_changedmtu (struct ppp *ppp, int new_mtu, int new_mru)
{
  struct device *dev;
  unsigned char *new_rbuff, *new_xbuff, *new_cbuff;
  unsigned char *old_rbuff, *old_xbuff, *old_cbuff;
  int mtu, mru;
/*
 *  Allocate the buffer from the kernel for the data
 */
  dev = ppp->dev;
  mru = new_mru;
  mtu = new_mtu;

  /* RFC 1331, section 7.2 says the minimum value is 1500 bytes */
  if (mru < PPP_MRU)
    mru = PPP_MRU;

  mtu = (mtu * 2) + 20;
  mru = (mru * 2) + 20;

  PRINTKN (2,(KERN_INFO "ppp: channel %s mtu = %d, mru = %d\n",
	      dev->name, new_mtu, new_mru));
	
  new_xbuff = (unsigned char *) kmalloc(mtu + 4, GFP_ATOMIC);
  new_rbuff = (unsigned char *) kmalloc(mru + 4, GFP_ATOMIC);
  new_cbuff = (unsigned char *) kmalloc(mru + 4, GFP_ATOMIC);
/*
 *  If the buffers failed to allocate then complain.
 */
  if (new_xbuff == NULL || new_rbuff == NULL || new_cbuff == NULL)
    {
      PRINTKN (2,(KERN_ERR "ppp: failed to allocate new buffers\n"));
/*
 *  Release new buffer pointers if the updates were not performed
 */
      if (new_rbuff != NULL)
	kfree (new_rbuff);

      if (new_xbuff != NULL)
	kfree (new_xbuff);

      if (new_cbuff != NULL)
	kfree (new_cbuff);
    }
/*
 *  Update the pointers to the new buffer structures.
 */
  else
    {
      cli();
      old_xbuff       = ppp->xbuff;
      old_rbuff       = ppp->rbuff;
      old_cbuff       = ppp->cbuff;

      ppp->xbuff      = new_xbuff;
      ppp->rbuff      = new_rbuff;
      ppp->cbuff      = new_cbuff;

      dev->mem_start  = (unsigned long) new_xbuff;
      dev->mem_end    = (unsigned long) (dev->mem_start + mtu);

      dev->rmem_start = (unsigned long) new_rbuff;
      ppp->rend       = (unsigned char *)
      dev->rmem_end   = (unsigned long) (dev->rmem_start + mru);

      ppp->rhead      = new_rbuff;
/*
 *  Update the parameters for the new buffer sizes
 */
      ppp->toss		= 0xFE;
      ppp->escape	= 0;
      ppp->sending	= 0;
      ppp->rcount	= 0;

      ppp->mru		= new_mru;

      ppp->mtu		=
      dev->mtu		= new_mtu;

      sti();
/*
 *  Release old buffer pointers
 */
      if (old_rbuff != NULL)
	kfree (old_rbuff);

      if (old_xbuff != NULL)
	kfree (old_xbuff);

      if (old_cbuff != NULL)
	kfree (old_cbuff);
    }
}

/* called when we abandon the PPP line discipline */

static void
ppp_release(struct ppp *ppp)
{
#ifdef NEW_TTY_DRIVERS
  if (ppp->tty != NULL && ppp->tty->disc_data == ppp)
    ppp->tty->disc_data = NULL; /* Break the tty->ppp link */
#endif

  if (ppp->dev) {
    ppp->dev->flags &= ~IFF_UP; /* down the device */
    ppp->dev->flags |= IFF_POINTOPOINT;
  }

  kfree (ppp->xbuff);
  kfree (ppp->cbuff);
  kfree (ppp->rbuff);
  kfree (ppp->us_rbuff);

  ppp->xbuff    =
  ppp->cbuff    =
  ppp->rbuff    =
  ppp->us_rbuff = NULL;

  if (ppp->slcomp) {
    slhc_free(ppp->slcomp);
    ppp->slcomp = NULL;
  }

  ppp->inuse = 0;
  ppp->tty   = NULL;
}

static void
ppp_close(struct tty_struct *tty)
{
  struct ppp *ppp = ppp_find(tty);

  if (ppp == NULL || ppp->magic != PPP_MAGIC) {
    PRINTKN (1,(KERN_WARNING "ppp: trying to close unopened tty!\n"));
  } else {
    CHECK_PPP_VOID();
    ppp_release (ppp);

    PRINTKN (2,(KERN_INFO "ppp: channel %s closing.\n", ppp->dev->name));
  }
}

/* called when PPP line discipline is selected on a tty */
static int
ppp_open(struct tty_struct *tty)
{
  struct ppp *ppp = ppp_find(tty);

  if (ppp) {
    PRINTKN (1,(KERN_ERR "ppp_open: gack! tty already associated to %s!\n",
		ppp->magic == PPP_MAGIC ? ppp->dev->name : "unknown"));
    return -EEXIST;
  }

  ppp = ppp_alloc();
  if (ppp == NULL) {
    PRINTKN (1,(KERN_ERR "ppp_open: couldn't allocate ppp channel\n"));
    return -ENFILE;
  }

  /* make sure the channel is actually open */
  ppp_init_ctrl_blk (ppp);

  ppp->tty = tty;

#ifdef NEW_TTY_DRIVERS
  tty->disc_data = ppp;
  if (tty->driver.flush_buffer)
    tty->driver.flush_buffer(tty);
  if (tty->ldisc.flush_buffer)
    tty->ldisc.flush_buffer(tty);
#else
  tty_read_flush (tty);
  tty_write_flush (tty);
#endif

  if ((ppp->slcomp = slhc_init(16, 16)) == NULL) {
    PRINTKN (1,(KERN_ERR "ppp: no space for compression buffers!\n"));
    ppp_release (ppp);
    return -ENOMEM;
  }

  /* Define the buffers for operation */
  ppp_changedmtu (ppp, ppp->dev->mtu, ppp->mru);
  if (ppp->rbuff == NULL) {
    ppp_release (ppp);
    return -ENOMEM;
  }

  /* Allocate a user-level receive buffer */
  ppp->us_rbuff = kmalloc (RBUFSIZE, GFP_KERNEL);
  if (ppp->us_rbuff == NULL) {
    PRINTKN (1,(KERN_ERR "ppp: no space for user receive buffer\n"));
    ppp_release (ppp);
    return -ENOMEM;
  }

  ppp->us_rbuff_head =
  ppp->us_rbuff_tail = ppp->us_rbuff;
  ppp->us_rbuff_end  = ppp->us_rbuff + RBUFSIZE;

  PRINTKN (2,(KERN_INFO "ppp: channel %s open\n", ppp->dev->name));

  return (ppp->line);
}

/* called when ppp interface goes "up".  here this just means we start
   passing IP packets */
static int
ppp_dev_open(struct device *dev)
{
  struct ppp *ppp = &ppp_ctrl[dev->base_addr];

  /* reset POINTOPOINT every time, since dev_close zaps it! */
  dev->flags |= IFF_POINTOPOINT;

  if (ppp->tty == NULL) {
    PRINTKN (1,(KERN_ERR "ppp: %s not connected to a TTY! can't go open!\n",
		dev->name));
    return -ENXIO;
  }

  PRINTKN (2,(KERN_INFO "ppp: channel %s going up for IP packets!\n",
	      dev->name));

  CHECK_PPP(-ENXIO);
  return 0;
}

static int
ppp_dev_close(struct device *dev)
{
  struct ppp *ppp = &ppp_ctrl[dev->base_addr];

  if (ppp->tty == NULL) {
    PRINTKN (1,(KERN_ERR "ppp: %s not connected to a TTY! can't go down!\n",
		dev->name));
    return -ENXIO;
  }

  PRINTKN (2,(KERN_INFO "ppp: channel %s going down for IP packets!\n",
	      dev->name));
  CHECK_PPP(-ENXIO);
  return 0;
}

/*************************************************************
 * TTY OUTPUT
 *    The following function delivers a fully-formed PPP
 *    frame in ppp->xbuff to the TTY for output.
 *************************************************************/

#ifdef NEW_TTY_DRIVERS
static inline void
#else
static void
#endif
ppp_output_done (void *ppp)
{
  /* unlock the transmitter queue */
  ppp_unlock ((struct ppp *) ppp);

  /* If the device is still up then enable the transmitter of the
     next frame. */
  if (((struct ppp *) ppp)->dev->flags & IFF_UP)
    dev_tint (((struct ppp *) ppp)->dev);

  /* enable any blocked process pending transmission */
  wake_up_interruptible (&((struct ppp *) ppp)->write_wait);
}

#ifndef NEW_TTY_DRIVERS
static void
ppp_kick_tty (struct ppp *ppp)
{
  register int count = ppp->xhead - ppp->xbuff;
  register int answer;

  ppp->stats.sbytes += count;

  answer = tty_write_data (ppp->tty,
			   ppp->xbuff,
			   count,
			   ppp_output_done,
			   (void *) ppp);

  if (answer == 0)
    ppp_output_done (ppp);   /* Should not happen */
  else
    if (answer < 0) {
      ppp->stats.serrors++;
      ppp_output_done (ppp); /* unlock the transmitter */
    }
}

#else

static void
ppp_kick_tty (struct ppp *ppp)
{
	register int count, actual;
	
	count = ppp->xhead - ppp->xbuff;
	
	actual = ppp->tty->driver.write(ppp->tty, 0, ppp->xbuff, count);
	ppp->stats.sbytes += actual;
	if (actual == count) {
		ppp_output_done(ppp);
	} else {
		ppp->xtail = ppp->xbuff + actual;
		ppp->tty->flags |= (1 << TTY_DO_WRITE_WAKEUP);
	}
}

static void ppp_write_wakeup(struct tty_struct *tty)
{
	register int count, actual;
	struct ppp *ppp = ppp_find(tty);

	if (!ppp || ppp->magic != PPP_MAGIC) {
		PRINTKN (1,
			 (KERN_ERR "PPP: write_wakeup called but couldn't "
			  "find PPP struct.\n"));
		return;
	}

	if (!ppp->xtail || (ppp->flags & SC_XMIT_BUSY))
		return;

	cli();
	if (ppp->flags & SC_XMIT_BUSY)
		return;
	ppp->flags |= SC_XMIT_BUSY;
	sti();
	
	count = ppp->xhead - ppp->xtail;
	
	actual = tty->driver.write(tty, 0, ppp->xtail, count);
	ppp->stats.sbytes += actual;
	if (actual == count) {
		ppp->xtail = 0;
		tty->flags &= ~TTY_DO_WRITE_WAKEUP;

		ppp_output_done(ppp);
	} else {
		ppp->xtail += actual;
	}
	ppp->flags &= ~SC_XMIT_BUSY;
}
#endif

/*************************************************************
 * TTY INPUT
 *    The following functions handle input that arrives from
 *    the TTY.  It recognizes PPP frames and either hands them
 *    to the network layer or queues them for delivery to a
 *    user process reading this TTY.
 *************************************************************/

/* stuff a single character into the receive buffer */

inline void
ppp_enqueue(struct ppp *ppp, unsigned char c)
{
  unsigned long flags;

  save_flags(flags);
  cli();
  if (ppp->rhead < ppp->rend) {
    *ppp->rhead = c;
    ppp->rhead++;
    ppp->rcount++;
  } else
    ppp->stats.roverrun++;
  restore_flags(flags);
}

#ifdef CHECK_CHARACTERS
static unsigned paritytab[8] = {
    0x96696996, 0x69969669, 0x69969669, 0x96696996,
    0x69969669, 0x96696996, 0x96696996, 0x69969669
};
#endif

#ifndef NEW_TTY_DRIVERS
static void
ppp_dump_inqueue(struct tty_struct *tty)
{
  int  head = tty->read_q.head,
       tail = tty->read_q.tail,
       i, count;
  char buffer[8];

  PRINTK ((KERN_DEBUG "INQUEUE: head %d tail %d imode %x:\n", head, tail, 
	   (unsigned int) tty->termios->c_iflag))

  i     = tail;
  count = 0;

  while (i != head) {
    buffer [count] = tty->read_q.buf[i];
    if (++count == 8) {
      ppp_print_buffer (NULL, buffer, 8, KERNEL_DS);
      count = 0;
    }
    i = (i + 1) & (TTY_BUF_SIZE - 1);
  }
  ppp_print_buffer (NULL, buffer, count, KERNEL_DS);
}

/* called by lower levels of TTY driver when data becomes available.
   all incoming data comes through this function. */

void ppp_tty_input_ready(struct tty_struct *tty)
{
  struct ppp *ppp = ppp_find(tty);
  int n, error;
  unsigned char buff[128];

/*  PRINTK( (KERN_DEBUG "PPP: handler called.\n") ) */
  if (!ppp || ppp->magic != PPP_MAGIC) {
    PRINTKN (1,
	     (KERN_ERR "PPP: handler called but couldn't find PPP struct.\n"));
    return;
  }

  CHECK_PPP_VOID();

  /* ZZZ */
  if (ppp_debug >= 5)
    ppp_dump_inqueue(ppp->tty);

  do {
    n = tty_read_raw_data(tty, buff, 128);
    if ( n == 0 )		/* nothing there */
      break;

    if (ppp_debug >= 5)
      ppp_print_buffer ("receive buffer", buff, n > 0 ? n : -n, KERNEL_DS);

    if ( n < 0 ) {
      /* Last character is error flag.
	 Process the previous characters, then set toss flag. */
      n = (-n) - 1;
      error = buff[n];
    } else error = 0;
    ppp->stats.rbytes += n;
    ppp_unesc(ppp,buff,n);
    if (error)
      ppp->toss = error;
  } while (1);
}

/* recover frame by undoing PPP escape mechanism;
   copies N chars of input data from C into PPP->rbuff
   calls ppp_doframe to dispose of any frames it finds
*/

static void
ppp_unesc(struct ppp *ppp, unsigned char *c, int n)
{
  int i;

  for (i = 0; i < n; i++, c++) {
    PRINTKN (6,(KERN_DEBUG "(%x)", (unsigned int) *c));

#ifdef CHECK_CHARACTERS
    if (*c & 0x80)
	sc->sc_flags |= SC_RCV_B7_1;
    else
	sc->sc_flags |= SC_RCV_B7_0;

    if (paritytab[*c >> 5] & (1 << (*c & 0x1F)))
	sc->sc_flags |= SC_RCV_ODDP;
    else
	sc->sc_flags |= SC_RCV_EVNP;
#endif

    switch (*c) {
    case PPP_ESC:		/* PPP_ESC: invert 0x20 in next character */
      ppp->escape = PPP_TRANS;
      break;

    case PPP_FLAG:		/* PPP_FLAG: end of frame */
      if (ppp->escape)		/* PPP_ESC just before PPP_FLAG is illegal */
	ppp->toss = 0xFF;

      if ((ppp->toss & 0x80) == 0)
	ppp_doframe(ppp);	/* pass frame on to next layers */

      ppp->rcount = 0;
      ppp->rhead  = ppp->rbuff;
      ppp->escape = 0;
      ppp->toss   = 0;
      break;

    default:			/* regular character */
      if (!in_rmap (ppp, *c)) {
	if (ppp->toss == 0)
	  ppp_enqueue (ppp, *c ^ ppp->escape);
	ppp->escape = 0;
      }
      break;
    }
  }
}

#else
static void ppp_receive_buf(struct tty_struct *tty, unsigned char *cp,
			    char *fp, int count)
{
  register struct ppp *ppp = ppp_find (tty);
  unsigned char c;
 
/*  PRINTK( ("PPP: handler called.\n") ); */

  if (!ppp || ppp->magic != PPP_MAGIC) {
    PRINTKN (1,("PPP: handler called but couldn't find "
		"PPP struct.\n"));
    return;
  }

  CHECK_PPP_VOID();
 
  if (ppp_debug >= 5) {
    ppp_print_buffer ("receive buffer", cp, count, KERNEL_DS);
  }
 
  while (count-- > 0) {
    c = *cp++;

    if (fp) {
      if (*fp && ppp->toss == 0)
	ppp->toss = *fp;
      fp++;
    }

#ifdef CHECK_CHARACTERS
    if (c & 0x80)
	sc->sc_flags |= SC_RCV_B7_1;
    else
	sc->sc_flags |= SC_RCV_B7_0;

    if (paritytab[c >> 5] & (1 << (c & 0x1F)))
	sc->sc_flags |= SC_RCV_ODDP;
    else
	sc->sc_flags |= SC_RCV_EVNP;
#endif

    switch (c) {
    case PPP_ESC:		/* PPP_ESC: invert 0x20 in next character */
      ppp->escape = PPP_TRANS;
      break;

    case PPP_FLAG:		/* PPP_FLAG: end of frame */
      if (ppp->escape)		/* PPP_ESC just before PPP_FLAG is "cancel"*/
	ppp->toss = 0xFF;

      if ((ppp->toss & 0x80) == 0)
	ppp_doframe(ppp);	/* pass frame on to next layers */

      ppp->rcount = 0;
      ppp->rhead  = ppp->rbuff;
      ppp->escape = 0;
      ppp->toss   = 0;
      break;

    default:			/* regular character */
      if (!in_rmap (ppp, c)) {
	if (ppp->toss == 0)
	  ppp_enqueue (ppp, c ^ ppp->escape);
	ppp->escape = 0;
      }
    }
  }
}
#endif

/* on entry, a received frame is in ppp->rbuff
   check it and dispose as appropriate */
static void
ppp_doframe(struct ppp *ppp)
{
  u_char *c = ppp->rbuff;
  u_short proto;
  int count = ppp->rcount;

  /* forget it if we've already noticed an error */
  if (ppp->toss) {
    PRINTKN (1, (KERN_WARNING "ppp_toss: tossing frame, reason = %d\n",
		 ppp->toss));
    ppp->stats.rerrors++;
    return;
  }

  /* do this before printing buffer to avoid generating copious output */
  if (count == 0)
    return;

  if (ppp_debug >= 3)
    ppp_print_buffer ("receive frame", c, count, KERNEL_DS);

  if (count < 4) {
    PRINTKN (1,(KERN_WARNING "ppp: got runt ppp frame, %d chars\n", count));
    ppp->stats.runts++;
    return;
  }

  /* check PPP error detection field */
  if (!ppp_check_fcs(ppp)) {
    PRINTKN (1,(KERN_WARNING "ppp: frame with bad fcs\n"));
    ppp->stats.rerrors++;
    return;
  }

  count -= 2;			/* ignore last two characters */

  /* now we have a good frame */
  /* figure out the protocol field */
  if ((c[0] == PPP_ADDRESS) && (c[1] == PPP_CONTROL)) {
    c = c + 2;			/* ADDR/CTRL not compressed, so skip */
    count -= 2;
  }

  proto = (u_short) *c++;		/* PROTO compressed */
  if (proto & 1) {
    count--;
  } else {
    proto = (proto << 8) | (u_short) *c++; /* PROTO uncompressed */
    count -= 2;
  }

  /* Send the frame to the network if the ppp device is up */
  if ((ppp->dev->flags & IFF_UP) && ppp_do_ip(ppp, proto, c, count)) {
    ppp->ddinfo.ip_rjiffies = jiffies;
    return;
  }

  /* If we got here, it has to go to a user process doing a read,
     so queue it.

     User process expects to get whole frame (for some reason), so
     use count+2 so as to include FCS field. */

  if (ppp_us_queue (ppp, proto, c, count+2)) {
    ppp->ddinfo.nip_rjiffies = jiffies;
    ppp->stats.rothers++;
    return;
  }

  /* couldn't cope. */
  PRINTKN (1,(KERN_WARNING
	      "ppp: dropping packet on the floor: nobody could take it.\n"));
  ppp->stats.tossed++;
}

/* Examine packet at C, attempt to pass up to net layer. 
   PROTO is the protocol field from the PPP frame.
   Return 1 if could handle it, 0 otherwise.  */

static int
ppp_do_ip (struct ppp *ppp, unsigned short proto, unsigned char *c,
	  int count)
{
  int flags, done;

  PRINTKN (4,(KERN_DEBUG "ppp_do_ip: proto %x len %d first byte %x\n",
	      (int) proto, count, c[0]));

  if (ppp_debug_netpackets) {
    PRINTK (("KERN_DEBUG %s <-- proto %x len %d\n", ppp->dev->name,
	     (int) proto, count));
  }
    
  if (proto == PROTO_IP) {
    ppp->stats.runcomp++;
    goto sendit;
  }

  if ((proto == PROTO_VJCOMP) && !(ppp->flags & SC_REJ_COMP_TCP)) {
    /* get space for uncompressing the header */
    done = 0;
    save_flags (flags);
    cli();
    if ((ppp->rhead + 80) < ppp->rend) {
      ppp->rhead += 80;
      ppp->rcount += 80;
      done = 1;
    }
    restore_flags(flags);

    if (! done)	{
      PRINTKN (1,(KERN_NOTICE
		  "ppp: no space to decompress VJ compressed TCP header.\n"));
      ppp->stats.roverrun++;
      return 1;
    }

    count = slhc_uncompress(ppp->slcomp, c, count);
    if (count <= 0) {
      ppp->stats.rerrors++;
      PRINTKN (1,(KERN_NOTICE "ppp: error in VJ decompression\n"));
      return 1;
    }
    ppp->stats.rcomp++;
    goto sendit;
  }
  
  if ((proto == PROTO_VJUNCOMP) && !(ppp->flags & SC_REJ_COMP_TCP)) {
    if (slhc_remember(ppp->slcomp, c, count) <= 0) {
      ppp->stats.rerrors++;
      PRINTKN (1,(KERN_NOTICE "ppp: error in VJ memorizing\n"));
      return 1;
    }
    ppp->stats.runcomp++;
    goto sendit;
  }

  /* not ours */
  return 0;

 sendit:
  if (ppp_debug_netpackets) {
    struct iphdr *iph = (struct iphdr *) c;
    PRINTK ((KERN_INFO "%s <--    src %lx dst %lx len %d\n", ppp->dev->name, 
	     iph->saddr, iph->daddr, count))
  }

  /* receive the frame through the network software */
  while ((dev_rint(c, count, 0, ppp->dev) & ~1) != 0)
    ;

  return 1;
}

/* stuff packet at BUF, length LEN, into the us_rbuff buffer
   prepend PROTO information */

#define PUTC(c,label) *ppp->us_rbuff_head++ = c; \
                if (ppp->us_rbuff_head == ppp->us_rbuff_end) \
                     ppp->us_rbuff_head = ppp->us_rbuff; \
                if (ppp->us_rbuff_head == ppp->us_rbuff_tail) \
                     goto label;
#define GETC(c) c = *ppp->us_rbuff_tail++; \
                if (ppp->us_rbuff_tail == ppp->us_rbuff_end) \
                     ppp->us_rbuff_tail = ppp->us_rbuff;

static int
ppp_us_queue(struct ppp *ppp, unsigned short proto, 
	     unsigned char *buf, int len)
{
  int totlen;
  unsigned char *saved_head;

  totlen = len+2;		/* including protocol */

  if (set_bit(1, &ppp->us_rbuff_lock)) {
    PRINTKN (1, (KERN_NOTICE "ppp_us_queue: can't get lock\n"));
    return 0;
  }
  saved_head = ppp->us_rbuff_head;

  PUTC((totlen & 0xff00) >> 8, failure);
  PUTC(totlen & 0x00ff, failure);
  PUTC((proto & 0xff00) >> 8, failure);
  PUTC(proto & 0x00ff, failure);

  while (len-- > 0) {
    PUTC(*buf++, failure);
  }

  PRINTKN (3, (KERN_INFO "ppp: successfully queued %d bytes\n", totlen));
  clear_bit(1, &ppp->us_rbuff_lock);
  wake_up_interruptible (&ppp->read_wait);

#ifdef NEW_TTY_DRIVERS
  kill_fasync(ppp->tty->fasync, SIGIO);
#endif

  if (ppp->inp_sig && ppp->inp_sig_pid)
    if (kill_proc (ppp->inp_sig_pid, ppp->inp_sig, 1) != 0) {
      /* process is gone */
      PRINTKN (2,(KERN_NOTICE
		  "ppp: process that requested notification is gone\n"));
      ppp->inp_sig = 0;
      ppp->inp_sig_pid = 0;
    }
  return 1;

 failure:
  ppp->us_rbuff_head = saved_head;
  clear_bit(1, &ppp->us_rbuff_lock);

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
ppp_read(struct tty_struct *tty, struct file *file, unsigned char *buf, unsigned int nr)
{
  struct ppp *ppp = ppp_find(tty);
  unsigned char c;
  int len, i;

  if (!ppp || ppp->magic != PPP_MAGIC) {
    PRINTKN (1,(KERN_ERR "ppp_read: cannnot find ppp channel\n"));
    return -EIO;
  }

  CHECK_PPP(-ENXIO);

  PRINTKN (4,(KERN_DEBUG "ppp_read: called %x num %u\n",
	      (unsigned int) buf,
	      nr));

  do {
    /* try to acquire read lock */
    if (set_bit(0, &ppp->us_rbuff_lock) == 0) {
      /* got lock */
      if (ppp->us_rbuff_head == ppp->us_rbuff_tail) {
	/* no data */
	PRINTKN (4,(KERN_DEBUG "ppp_read: no data\n"));
	clear_bit(0, &ppp->us_rbuff_lock);
        if (ppp->inp_sig) {
	  PRINTKN (4,(KERN_DEBUG "ppp_read: EWOULDBLOCK\n"));
	  return -EWOULDBLOCK;
        } else goto wait;
      }

      /* reset the time of the last read operation */
      ppp->ddinfo.nip_rjiffies = jiffies;

      GETC (c); len = c << 8; GETC (c); len += c;

      PRINTKN (4,(KERN_DEBUG "ppp_read: len = %d\n", len));

      if (len + 2 > nr) {
	/* frame too big; can't copy it, but do update us_rbuff_head */
	PRINTKN (1,(KERN_DEBUG
		    "ppp: read of %u bytes too small for %d frame\n",
		    nr, len+2));
	ppp->us_rbuff_head += len;
	if (ppp->us_rbuff_head > ppp->us_rbuff_end)
	  ppp->us_rbuff_head += - (ppp->us_rbuff_end - ppp->us_rbuff);
	clear_bit(0, &ppp->us_rbuff_lock);
	wake_up_interruptible (&ppp->read_wait);
	ppp->stats.rgiants++;
	return -EOVERFLOW;		/* ZZZ; HACK! */
      } else {
	/* have the space: copy the packet, faking the first two bytes */
	put_fs_byte (PPP_ADDRESS, buf++);
	put_fs_byte (PPP_CONTROL, buf++);
	i = len;
	while (i-- > 0) {
	  GETC (c);
	  put_fs_byte (c, buf++);
	}
      }

      clear_bit(0, &ppp->us_rbuff_lock);
      PRINTKN (3,(KERN_DEBUG "ppp_read: passing %d bytes up\n", len + 2));
      ppp->stats.rothers++;
      return len + 2;
    }

    /* need to wait */
  wait:
    current->timeout = 0;
    PRINTKN (3,(KERN_DEBUG "ppp_read: sleeping\n"));
    interruptible_sleep_on (&ppp->read_wait);
    if (current->signal & ~current->blocked)
      return -EINTR;
  } while (1);
}

/* stuff a character into the transmit buffer, using PPP's way of escaping
   special characters.
   also, update ppp->fcs to take account of new character */
static inline void
ppp_stuff_char(struct ppp *ppp, unsigned char c)
{
  int curpt = ppp->xhead - ppp->xbuff;
  if ((curpt < 0) || (curpt > 3000)) {
    PRINTK ((KERN_DEBUG "ppp_stuff_char: %x %x %d\n",
	     (unsigned int) ppp->xbuff, (unsigned int) ppp->xhead, curpt))
  }
  if (in_xmap (ppp, c)) {
    *ppp->xhead++ = PPP_ESC;
    *ppp->xhead++ = c ^ PPP_TRANS;
  } else
    *ppp->xhead++ = c;
  ppp->fcs = (ppp->fcs >> 8) ^ fcstab[(ppp->fcs ^ c) & 0xff];
}

/* write a frame with NR chars from BUF to TTY
   we have to put the FCS field on ourselves
*/

static int
ppp_write(struct tty_struct *tty, struct file *file, unsigned char *buf, unsigned int nr)
{
  struct ppp *ppp = ppp_find(tty);
  int i;

  if (!ppp || ppp->magic != PPP_MAGIC) {
    PRINTKN (1,(KERN_ERR "ppp_write: cannot find ppp unit\n"));
    return -EIO;
  }

  CHECK_PPP(-ENXIO);
  
  if (ppp->mtu != ppp->dev->mtu)	/* Someone has been ifconfigging */
    ppp_changedmtu (ppp, ppp->dev->mtu, ppp->mru);

  if (nr > ppp->mtu) {
    PRINTKN (1,(KERN_WARNING
		"ppp_write: truncating user packet from %u to mtu %d\n",
		nr, ppp->mtu));
    nr = ppp->mtu;
  }

  if (ppp_debug >= 3)
    ppp_print_buffer ("write frame", buf, nr, USER_DS);

  /* lock this PPP unit so we will be the only writer;
     sleep if necessary */
  while ((ppp->sending == 1) || !ppp_lock(ppp)) {
    current->timeout = 0;
    PRINTKN (3,(KERN_DEBUG "ppp_write: sleeping\n"));
    interruptible_sleep_on(&ppp->write_wait);
    if (current->signal & ~current->blocked)
      return -EINTR;
  }

  /* OK, locked.  Stuff the given bytes into the buffer. */

  PRINTKN(4,(KERN_DEBUG "ppp_write: acquired write lock\n"));
  ppp->xhead = ppp->xbuff;

#ifdef OPTIMIZE_FLAG_TIME
  if (jiffies - ppp->last_xmit > OPTIMIZE_FLAG_TIME)
    *ppp->xhead++ = PPP_FLAG;
  ppp->last_xmit = jiffies;
#else      
  *ppp->xhead++ = PPP_FLAG;
#endif

  ppp->fcs = PPP_FCS_INIT;
  i = nr;
  while (i-- > 0)
    ppp_stuff_char(ppp,get_fs_byte(buf++));

  ppp_add_fcs(ppp);		/* concatenate FCS at end */

  *ppp->xhead++ = PPP_FLAG;
  
  /* reset the time of the last write operation */
  ppp->ddinfo.nip_sjiffies = jiffies;

  if (ppp_debug >= 6)
    ppp_print_buffer ("xmit buffer", ppp->xbuff, ppp->xhead - ppp->xbuff, KERNEL_DS);
  else {
    PRINTKN (4,(KERN_DEBUG
		"ppp_write: writing %d chars\n", ppp->xhead - ppp->xbuff));
  }

  /* packet is ready-to-go */
  ++ppp->stats.sothers;
  ppp_kick_tty(ppp);

  return((int)nr);
}
 
static int
ppp_ioctl(struct tty_struct *tty, struct file *file, unsigned int i,
	  unsigned long l)
{
  struct ppp *ppp = ppp_find(tty);
  register int temp_i = 0;
  int error;

  if (!ppp || ppp->magic != PPP_MAGIC) {
    PRINTK ((KERN_ERR "ppp_ioctl: can't find PPP block from tty!\n"))
    return -EBADF;
  }

  CHECK_PPP(-ENXIO);

  /* This must be root user */
  if (!suser())
    return -EPERM;

  switch (i) {
  case PPPIOCSMRU:
    error = verify_area (VERIFY_READ, (void *) l, sizeof (temp_i));
    if (error == 0) {
      PRINTKN (3,(KERN_INFO "ppp_ioctl: set mru to %x\n", temp_i));
      temp_i = (int) get_fs_long (l);
      if (ppp->mru != temp_i)
	ppp_changedmtu (ppp, ppp->mtu, temp_i);
    }
    break;

  case PPPIOCGFLAGS:
    error = verify_area (VERIFY_WRITE, (void *) l, sizeof (temp_i));
    if (error == 0) {
      temp_i = (ppp->flags & SC_MASK);
#ifndef CHECK_CHARACTERS /* Don't generate errors if we don't check chars. */
      temp_i |= SC_RCV_B7_1 | SC_RCV_B7_0 | SC_RCV_ODDP | SC_RCV_EVNP;
#endif
      put_fs_long ((long) temp_i, l);
      PRINTKN (3,(KERN_DEBUG "ppp_ioctl: get flags: addr %lx flags %x\n",
		  l,
		  temp_i));
    }
    break;

  case PPPIOCSFLAGS:
    error = verify_area (VERIFY_READ, (void *) l, sizeof (temp_i));
    if (error == 0) {
      temp_i      = (int) get_fs_long (l);
      ppp->flags ^= ((ppp->flags ^ temp_i) & SC_MASK);
      PRINTKN (3,(KERN_INFO "ppp_ioctl: set flags to %x\n", temp_i));
    }
    break;

  case PPPIOCGASYNCMAP:
    error = verify_area (VERIFY_WRITE, (void *) l, sizeof (temp_i));
    if (error == 0) {
      put_fs_long (ppp->xmit_async_map[0], l);
      PRINTKN (3,(KERN_INFO "ppp_ioctl: get asyncmap: addr %lx asyncmap %lx\n",
		  l, ppp->xmit_async_map[0]));
    }
    break;

  case PPPIOCSASYNCMAP:
    error = verify_area (VERIFY_READ, (void *) l, sizeof (temp_i));
    if (error == 0) {
      memset (ppp->xmit_async_map, 0, sizeof (ppp->xmit_async_map));
      ppp->xmit_async_map[0] = get_fs_long (l);
      bset (ppp->xmit_async_map, PPP_FLAG);
      bset (ppp->xmit_async_map, PPP_ESC);
      PRINTKN (3,(KERN_INFO "ppp_ioctl: set xmit asyncmap %lx\n",
		  ppp->xmit_async_map[0]));
    }
    break;

  case PPPIOCRASYNCMAP:
    error = verify_area (VERIFY_READ, (void *) l, sizeof (temp_i));
    if (error == 0) {
      ppp->recv_async_map = get_fs_long (l);
      PRINTKN (3,(KERN_INFO "ppp_ioctl: set recv asyncmap %lx\n",
		  ppp->recv_async_map));
    }
    break;

  case PPPIOCGUNIT:
    error = verify_area (VERIFY_WRITE, (void *) l, sizeof (temp_i));
    if (error == 0) {
      put_fs_long (ppp->dev->base_addr, l);
      PRINTKN (3,(KERN_INFO "ppp_ioctl: get unit: %d", ppp->dev->base_addr));
    }
    break;

  case PPPIOCSINPSIG:
    error = verify_area (VERIFY_READ, (void *) l, sizeof (temp_i));
    if (error == 0) {
      ppp->inp_sig     = (int) get_fs_long (l);
      ppp->inp_sig_pid = current->pid;
      PRINTKN (3,(KERN_INFO "ppp_ioctl: set input signal %d\n", ppp->inp_sig));
    }
    break;

  case PPPIOCSDEBUG:
    error = verify_area (VERIFY_READ, (void *) l, sizeof (temp_i));
    if (error == 0) {
      ppp_debug = (int) get_fs_long (l);
      ppp_debug_netpackets = (ppp_debug & 0xff00) >> 8;
      ppp_debug &= 0xff;
      PRINTKN (1, (KERN_INFO "ppp_ioctl: set debug level %d, netpacket %d\n", 
		   ppp_debug, ppp_debug_netpackets));
    }
    break;

  case PPPIOCGDEBUG:
    error = verify_area (VERIFY_WRITE, (void *) l, sizeof (temp_i));
    if (error == 0) {
      put_fs_long ((long) (ppp_debug | (ppp_debug_netpackets << 8)), l);
      PRINTKN (3,(KERN_INFO "ppp_ioctl: get debug level %d\n", 
		  ppp_debug | (ppp_debug_netpackets << 8)));
    }
    break;

  case PPPIOCGSTAT:
    error = verify_area (VERIFY_WRITE, (void *) l, sizeof (struct ppp_stats));
    if (error == 0) {
      memcpy_tofs ((void *) l, &ppp->stats, sizeof (struct ppp_stats));
      PRINTKN (3,(KERN_INFO "ppp_ioctl: read statistics\n"));
    }
    break;

  case PPPIOCGTIME:
    error = verify_area (VERIFY_WRITE, (void *) l, sizeof (struct ppp_ddinfo));
    if (error == 0) {
      struct ppp_ddinfo cur_ddinfo;
      unsigned long cur_jiffies = jiffies;

      /* change absolute times to relative times. */
      cur_ddinfo.ip_sjiffies  = cur_jiffies - ppp->ddinfo.ip_sjiffies;
      cur_ddinfo.ip_rjiffies  = cur_jiffies - ppp->ddinfo.ip_rjiffies;
      cur_ddinfo.nip_sjiffies = cur_jiffies - ppp->ddinfo.nip_sjiffies;
      cur_ddinfo.nip_rjiffies = cur_jiffies - ppp->ddinfo.nip_rjiffies;
      
      memcpy_tofs ((void *) l, &cur_ddinfo, sizeof (struct ppp_ddinfo));
      PRINTKN (3,(KERN_INFO "ppp_ioctl: read demand dial info\n"));
    }
    break;

  case PPPIOCGXASYNCMAP:
    error = verify_area (VERIFY_WRITE,
			 (void *) l,
			 sizeof (ppp->xmit_async_map));
    if (error == 0) {
      memcpy_tofs ((void *) l,
		   ppp->xmit_async_map,
		   sizeof (ppp->xmit_async_map));
      PRINTKN (3,(KERN_INFO "ppp_ioctl: get xasyncmap: addr %lx\n", l));
    }
    break;

  case PPPIOCSXASYNCMAP:
    error = verify_area (VERIFY_READ, (void *) l,
			 sizeof (ppp->xmit_async_map));
    if (error == 0) {
      unsigned long temp_tbl [8];

      memcpy_fromfs (temp_tbl, (void *) l, sizeof (ppp->xmit_async_map));
      temp_tbl[1]  =  0x00000000; /* must not escape 0x20 - 0x3f */
      temp_tbl[2] &= ~0x40000000; /* must not escape 0x5e        */
      temp_tbl[3] |=  0x60000000; /* must escape 0x7d and 0x7e   */

      if ((temp_tbl[2] & temp_tbl[3]) != 0 ||
	  (temp_tbl[4] & temp_tbl[5]) != 0 ||
	  (temp_tbl[6] & temp_tbl[7]) != 0)
	error = -EINVAL;
      else {
	memcpy (ppp->xmit_async_map, temp_tbl, sizeof (ppp->xmit_async_map));
	PRINTKN (3,(KERN_INFO "ppp_ioctl: set xasyncmap\n"));
      }
    }
    break;

  case PPPIOCSMAXCID:
    error = verify_area (VERIFY_READ, (void *) l, sizeof (temp_i));
    if (error == 0) {
      temp_i = (int) get_fs_long (l) + 1;
      PRINTKN (3,(KERN_INFO "ppp_ioctl: set maxcid to %d\n", temp_i));
      if (ppp->slcomp != NULL)
	slhc_free (ppp->slcomp);

      ppp->slcomp = slhc_init (temp_i, temp_i);

      if (ppp->slcomp == NULL) {
	PRINTKN (1,(KERN_ERR "ppp: no space for compression buffers!\n"));
	ppp_release (ppp);
	error = -ENOMEM;
      }
    }
    break;

#ifdef NEW_TTY_DRIVERS
    /* Allow stty to read, but not set, the serial port */
  case TCGETS:
  case TCGETA:
    error = n_tty_ioctl(tty, file, i, l);
    break;
#endif

/*
 *  All other ioctl() events will come here.
 */

  default:
    PRINTKN (1,(KERN_ERR "ppp_ioctl: invalid ioctl: %x, addr %lx\n",
		i,
		l));
#ifdef NEW_TTY_DRIVERS
    error = -ENOIOCTLCMD;
#else
    error = -EINVAL;
#endif
    break;
  }
  return error;
}

static int
ppp_select (struct tty_struct *tty, struct inode * inode,
	    struct file * filp, int sel_type, select_table * wait)
{
  struct ppp *ppp = ppp_find (tty);
  
  if (!ppp || ppp->magic != PPP_MAGIC) {
    PRINTK ((KERN_ERR "ppp_select: can't find PPP block from tty!\n"))
    return -EBADF;
  }
  
  /* If the PPP protocol is no longer active, return false */
  CHECK_PPP (0);
  
  /* Process the request based upon the type desired */
  switch (sel_type) {
  case SEL_IN:
    if (set_bit(0, &ppp->us_rbuff_lock) == 0) {
      /* Test for the presence of data in the queue */
      if (ppp->us_rbuff_head != ppp->us_rbuff_tail) {
	clear_bit (0, &ppp->us_rbuff_lock);
	return 1;
      }
      clear_bit (0, &ppp->us_rbuff_lock);
    } /* fall through */

  case SEL_EX:
    /* Is there a pending error condition? */
    if (tty->packet && tty->link->ctrl_status)
      return 1;
    
    /* closed? */
    if (tty->flags & (1 << TTY_SLAVE_CLOSED))
      return 1;
    
    /* If the tty is disconnected, then this is an exception too */
    if (tty_hung_up_p(filp))
      return 1;

    select_wait (&ppp->read_wait, wait);
    break;
    
  case SEL_OUT:
    if (ppp_lock (ppp)) {
      if (ppp->sending == 0) {
	ppp_unlock (ppp);
	return 1;
      }
      ppp_unlock (ppp);
    }
    select_wait (&ppp->write_wait, wait);
    break;
  }
  return 0;
}

/*************************************************************
 * NETWORK OUTPUT
 *    This routine accepts requests from the network layer
 *    and attempts to deliver the packets.
 *    It also includes various routines we are compelled to
 *    have to make the network layer work (arp, etc...).
 *************************************************************/

int
ppp_xmit(struct sk_buff *skb, struct device *dev)
{
  struct tty_struct *tty;
  struct ppp *ppp;
  unsigned char *p;
  unsigned short proto;
  int len;

  /* just a little sanity check. */
  if (skb == NULL) {
    PRINTKN(3,(KERN_WARNING "ppp_xmit: null packet!\n"));
    return 0;
  }

  /* Get pointers to the various components */
  ppp   = &ppp_ctrl[dev->base_addr];
  tty   = ppp->tty;
  p     = (unsigned char *) (skb + 1);
  len   = skb->len;
  proto = PROTO_IP;

  PRINTKN(4,(KERN_DEBUG "ppp_xmit [%s]: skb %lX busy %d\n", dev->name, 
	     (unsigned long int) skb, ppp->sending));

  CHECK_PPP(0);

  if (tty == NULL) {
    PRINTKN(1,(KERN_ERR "ppp_xmit: %s not connected to a TTY!\n", dev->name));
    goto done;
  }

  if (!(dev->flags & IFF_UP)) {
    PRINTKN(1,(KERN_WARNING
	       "ppp_xmit: packet sent on interface %s, which is down for IP\n",
	       dev->name));
    goto done;
  }

  /* get length from IP header as per Alan Cox bugfix for slip.c */
  if (len < sizeof(struct iphdr)) {
    PRINTKN(0,(KERN_ERR "ppp_xmit: given runt packet, ignoring\n"));
    return 1;
  }
  len = ntohs( ((struct iphdr *)(skb->data)) -> tot_len );

  /* If doing demand dial then divert the first frame to pppd. */
  if (ppp->flags & SC_IP_DOWN) {
    if (ppp->flags & SC_IP_FLUSH == 0) {
      if (ppp_us_queue (ppp, proto, p, len))
	ppp->flags |= SC_IP_FLUSH;
    }
    goto done;
  }

  /* Attempt to acquire send lock */
  if (ppp->sending || !ppp_lock(ppp)) {
    PRINTKN(3,(KERN_WARNING "ppp_xmit: busy\n"));
    ppp->stats.sbusy++;
    return 1;
  }

  ppp->xhead = ppp->xbuff;

  /* try to compress, if VJ compression mode is on */
  if (ppp->flags & SC_COMP_TCP) {
    /* NOTE: last 0 argument says never to compress connection ID */
    len = slhc_compress(ppp->slcomp, p, len, ppp->cbuff, &p, 0);
    if (p[0] & SL_TYPE_COMPRESSED_TCP)
      proto = PROTO_VJCOMP;
    else {
      if (p[0] >= SL_TYPE_UNCOMPRESSED_TCP) {
	proto = PROTO_VJUNCOMP;
	p[0] = (p[0] & 0x0f) | 0x40; 
      }
    }
  }

  /* increment appropriate counter */
  if (proto == PROTO_VJCOMP)
    ++ppp->stats.scomp;
  else
    ++ppp->stats.suncomp;
      
  if (ppp_debug_netpackets) {
    struct iphdr *iph = (struct iphdr *) (skb + 1);
    PRINTK ((KERN_DEBUG "%s ==> proto %x len %d src %x dst %x proto %d\n",
	    dev->name, (int) proto, (int) len, (int) iph->saddr,
	    (int) iph->daddr, (int) iph->protocol))
  }

  /* start of frame:   FLAG  ALL_STATIONS  CONTROL  <protohi> <protolo> */
#ifdef OPTIMIZE_FLAG_TIME
  if (jiffies - ppp->last_xmit > OPTIMIZE_FLAG_TIME)
    *ppp->xhead++ = PPP_FLAG;
  ppp->last_xmit = jiffies;
#else      
  *ppp->xhead++ = PPP_FLAG;
#endif

  ppp->fcs = PPP_FCS_INIT;
  if (!(ppp->flags & SC_COMP_AC)) { 
    ppp_stuff_char(ppp, PPP_ADDRESS);
    ppp_stuff_char(ppp, PPP_CONTROL);
  }

  if (!(ppp->flags & SC_COMP_PROT) || (proto & 0xff00))
    ppp_stuff_char(ppp, proto>>8);
  ppp_stuff_char(ppp, proto&0xff);

  /* data part */
  while (len-- > 0)
    ppp_stuff_char(ppp, *p++);

  /* fcs and flag */
  ppp_add_fcs(ppp);
  *ppp->xhead++ = PPP_FLAG;

  /* update the time for demand dial function */
  ppp->ddinfo.ip_sjiffies = jiffies;

  /* send it! */
  if (ppp_debug >= 6)
    ppp_print_buffer ("xmit buffer", ppp->xbuff, ppp->xhead - ppp->xbuff, KERNEL_DS);
  else {
    PRINTKN (4,(KERN_DEBUG
		"ppp_write: writing %d chars\n", ppp->xhead - ppp->xbuff));
  }

  ppp_kick_tty(ppp);

 done:
  if (skb->free) 
    kfree_skb(skb, FREE_WRITE);
  return 0;
}
  
static unsigned short
ppp_type_trans (struct sk_buff *skb, struct device *dev)
{
  return(htons(ETH_P_IP));
}

#ifdef NET02D
static int
ppp_header(unsigned char *buff, struct device *dev, unsigned short type,
	   unsigned long daddr, unsigned long saddr, unsigned len)
{
  return(0);
}

static int
ppp_rebuild_header(void *buff, struct device *dev)
{
  return(0);
}

static void
ppp_add_arp(unsigned long addr, struct sk_buff *skb, struct device *dev)
{
}

#else

static int
ppp_header(unsigned char *buff, struct device *dev, unsigned short type,
	   void *daddr, void *saddr, unsigned len, struct sk_buff *skb)
{
  return(0);
}

static int
ppp_rebuild_header(void *buff, struct device *dev, unsigned long raddr,
		   struct sk_buff *skb)
{
  return(0);
}
#endif

static struct enet_statistics *
ppp_get_stats (struct device *dev)
{
  struct ppp *ppp = &ppp_ctrl[dev->base_addr];
  static struct enet_statistics ppp_stats;

  ppp_stats.rx_packets = ppp->stats.rcomp + ppp->stats.runcomp;
  ppp_stats.rx_errors = ppp->stats.rerrors;
  ppp_stats.rx_dropped = ppp->stats.tossed;
  ppp_stats.rx_fifo_errors = 0;
  ppp_stats.rx_length_errors = ppp->stats.runts;
  ppp_stats.rx_over_errors = ppp->stats.roverrun;
  ppp_stats.rx_crc_errors = 0;
  ppp_stats.rx_frame_errors = 0;
  ppp_stats.tx_packets = ppp->stats.scomp + ppp->stats.suncomp;
  ppp_stats.tx_errors = ppp->stats.serrors;
  ppp_stats.tx_dropped = 0;
  ppp_stats.tx_fifo_errors = 0;
  ppp_stats.collisions = ppp->stats.sbusy;
  ppp_stats.tx_carrier_errors = 0;
  ppp_stats.tx_aborted_errors = 0;
  ppp_stats.tx_window_errors = 0;
  ppp_stats.tx_heartbeat_errors = 0;

  PRINTKN (3, (KERN_INFO "ppp_get_stats called"));
  return &ppp_stats;
}

/*************************************************************
 * UTILITIES
 *    Miscellany called by various functions above.
 *************************************************************/

#ifndef NEW_TTY_DRIVERS
/* find a PPP channel given a TTY */
struct ppp *
ppp_find(struct tty_struct *tty)
{
  int i;
  for (i = 0; i < PPP_NRUNIT; i++)
    if (ppp_ctrl[i].inuse && (ppp_ctrl[i].tty == tty)) return &ppp_ctrl[i];

  return NULL;
}
#endif

/* allocate a PPP channel */
static struct ppp *
ppp_alloc(void)
{
  int i;
  for (i = 0; i < PPP_NRUNIT; i++)
    if (!set_bit(0, &ppp_ctrl[i].inuse)) return &ppp_ctrl[i];

  return NULL;
}

/* marks a PPP interface 'busy'.  user processes will wait, if
   they try to write, and the network code will refrain from sending
   return nonzero if succeeded in acquiring lock
*/

static int
ppp_lock(struct ppp *ppp)
{
  int flags, locked;
  save_flags(flags);
  cli();
  locked = ppp->sending;
  ppp->sending = 1;
  if (ppp->dev->flags & IFF_UP)
    ppp->dev->tbusy = 1;
  restore_flags(flags);
  return locked == 0;
}

static void
ppp_unlock(struct ppp *ppp)
{
  int flags;
  save_flags(flags);
  cli();
  ppp->sending = 0;
  if (ppp->dev->flags & IFF_UP)
    ppp->dev->tbusy = 0;
  restore_flags(flags);
}

/* FCS support functions */

static void
ppp_add_fcs(struct ppp *ppp)
{
  unsigned short fcs = ppp->fcs;

  fcs ^= 0xffff;
  ppp_stuff_char(ppp, fcs & 0x00ff);
  ppp_stuff_char(ppp, (fcs & 0xff00) >> 8);
  ASSERT (ppp->fcs == PPP_FCS_GOOD);
  PRINTKN (4,(KERN_DEBUG "ppp_add_fcs: fcs is %lx\n",
	      (long) (unsigned long) fcs));
}

static int
ppp_check_fcs(struct ppp *ppp)
{
  unsigned short fcs = PPP_FCS_INIT, msgfcs;
  unsigned char *c = ppp->rbuff;
  int i;

  for (i = 0; i < ppp->rcount - 2; i++, c++)
    fcs = (fcs >> 8) ^ fcstab[(fcs ^ *c) & 0xff];

  fcs ^= 0xffff;
  msgfcs = (c[1] << 8) + c[0];
  PRINTKN (4,(KERN_INFO "ppp_check_fcs: got %lx want %lx\n",
	      (unsigned long) msgfcs, (unsigned long) fcs));
  return fcs == msgfcs;
}

static char hex[] = "0123456789ABCDEF";

inline void ppp_print_hex (register char *out, char *in, int count);
inline void ppp_print_hex (register char *out, char *in, int count)
{
  register unsigned char next_ch;

  while (count-- > 0) {
    next_ch = (unsigned char) get_fs_byte (in);

    *out++  = hex[(next_ch >> 4) & 0x0F];
    *out++  = hex[next_ch        & 0x0F];
    ++out;
    ++in;
  }
}

inline void ppp_print_char (register char *out, char *in, int count);
inline void ppp_print_char (register char *out, char *in, int count)
{
  register unsigned char next_ch;

  while (count-- > 0) {
    next_ch = (unsigned char) get_fs_byte (in);

    if (next_ch < 0x20 || next_ch > 0x7e)
      *out++ = '.';
    else {
      *out++ = next_ch;
      if (next_ch == '%')	/* printk/syslogd has a bug !! */
	*out++ = '%';
    }
    ++in;
  }
  *out = '\0';
}

static void ppp_print_buffer(const char *name, char *buf, int count, int seg)
{
  char line [44];
  int  old_fs = get_fs();

  set_fs (seg);

  if (name != (char *) NULL)
    PRINTK ((KERN_DEBUG "ppp: %s, count = %d\n", name, count));

  while (count > 8) {
    memset         (line, ' ', sizeof (line));
    ppp_print_hex  (line, buf, 8);
    ppp_print_char (&line[8 * 3], buf, 8);
    PRINTK ((KERN_DEBUG "%s\n", line));
    count -= 8;
    buf   += 8;
  }

  if (count > 0) {
    memset         (line, ' ', sizeof (line));
    ppp_print_hex  (line, buf, count);
    ppp_print_char (&line[8 * 3], buf, count);
    PRINTK ((KERN_DEBUG "%s\n", line));
  }

  set_fs (old_fs);
}
