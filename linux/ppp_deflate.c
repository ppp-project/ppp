/*
 *  ==FILEVERSION 960926==
 *
 * ppp_deflate.c - interface the zlib procedures for Deflate compression
 * and decompression (as used by gzip) to the PPP code.
 * This version is for use with Linux kernel 1.3.X.
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
 * THE AUSTRALIAN NATIONAL UNIVERSITY HAS BEEN ADVISED OF THE POSSIBILITY
 * OF SUCH DAMAGE.
 *
 * THE AUSTRALIAN NATIONAL UNIVERSITY SPECIFICALLY DISCLAIMS ANY WARRANTIES,
 * INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY
 * AND FITNESS FOR A PARTICULAR PURPOSE.  THE SOFTWARE PROVIDED HEREUNDER IS
 * ON AN "AS IS" BASIS, AND THE AUSTRALIAN NATIONAL UNIVERSITY HAS NO
 * OBLIGATION TO PROVIDE MAINTENANCE, SUPPORT, UPDATES, ENHANCEMENTS,
 * OR MODIFICATIONS.
 *
 * From: deflate.c,v 1.1 1996/01/18 03:17:48 paulus Exp
 */

#include <linux/module.h>

#include <endian.h>
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

#include <linux/if_ether.h>
#include <linux/netdevice.h>
#include <linux/skbuff.h>
#include <linux/inet.h>
#include <linux/ioctl.h>

#include <linux/ppp_defs.h>

#ifdef NEW_SKBUFF
#include <linux/netprotocol.h>
#endif

#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <net/if_arp.h>
#include <linux/ppp-comp.h>

#include "zlib.c"

#define USEMEMPOOL	0	/* use kmalloc, not memPool routines */

/*
 * State for a Deflate (de)compressor.
 */
struct ppp_deflate_state {
    int		seqno;
    int		w_size;
    int		unit;
    int		mru;
    int		debug;
    int		in_alloc;	/* set when we're in [de]comp_alloc */
    z_stream	strm;
    struct compstat stats;
};

#define DEFLATE_OVHD	2		/* Deflate overhead/packet */

static void	*zalloc __P((void *, unsigned int items, unsigned int size));
static void	zfree __P((void *, void *ptr, unsigned int nb));
static void	*z_comp_alloc __P((unsigned char *options, int opt_len));
static void	*z_decomp_alloc __P((unsigned char *options, int opt_len));
static void	z_comp_free __P((void *state));
static void	z_decomp_free __P((void *state));
static int	z_comp_init __P((void *state, unsigned char *options,
				 int opt_len,
				 int unit, int hdrlen, int debug));
static int	z_decomp_init __P((void *state, unsigned char *options,
				   int opt_len,
				   int unit, int hdrlen, int mru, int debug));
static int	z_compress __P((void *state, unsigned char *rptr,
				unsigned char *obuf,
				int isize, int osize));
static void	z_incomp __P((void *state, unsigned char *ibuf, int icnt));
static int	z_decompress __P((void *state, unsigned char *ibuf,
				int isize, unsigned char *obuf, int osize));
static void	z_comp_reset __P((void *state));
static void	z_decomp_reset __P((void *state));
static void	z_comp_stats __P((void *state, struct compstat *stats));

#if USEMEMPOOL
/*
 * This is a small set of memory allocation routines.  I created them so
 * that all memory allocation from the kernel takes place at the
 * z_(de)comp_alloc and z_(de)comp_free routines.  This eliminates worry
 * about calling valloc() from within an interrupt.
 *
 * The free list is a single linked list sorted by memory address.
 * The zfree() function re-combines any segments it can.
 */
typedef struct memchunk {
    unsigned int m_size;
    struct memchunk *m_next;
} MemChunk;

typedef struct {
    void *memHead;
    MemChunk *freePool;
} MemPool;

static int     memPoolAlloc __P((void *arg, unsigned int size));
static void    memPoolFree __P((void *arg));

static int
memPoolAlloc(arg, size)
void *arg;
unsigned int size;
{
    MemPool **memPool = arg;
    MemChunk *freePool;

    if ((*memPool = kmalloc(sizeof(MemPool), GFP_KERNEL)) == NULL) {
	printk(KERN_DEBUG "Unable to allocate Memory Head\n");
        return 0;
    }

    if (((*memPool)->memHead = (void *)vmalloc(size)) == NULL) {
	printk(KERN_DEBUG "Unable to allocate Memory Pool\n");
	kfree(*memPool);
	return 0;
    }
    freePool = (*memPool)->freePool = (*memPool)->memHead;
    freePool->m_size = size;
    freePool->m_next = 0;

    return 1;
}

static void
memPoolFree(arg)
void *arg;
{
    MemPool **memPool = arg;

    if (*memPool) {
	vfree((*memPool)->memHead);
	kfree(*memPool);
	*memPool = NULL;
    }
}

#ifdef POOLDGB
static void    showFreeList __P((MemChunk *));

static void
showFreeList(freePool)
MemChunk *freePool;
{
    MemChunk *node;
    
    for (node = freePool; node; node = node->m_next)
        printk(KERN_DEBUG "{%x,%d}->", node, node->m_size);
    printk(KERN_DEBUG "\n");
}
#endif
#endif /* USEMEMPOOL */

/*
 * Space allocation and freeing routines for use by zlib routines.
 */
void
zfree(arg, ptr, nbytes)
    void *arg;
    void *ptr;
    unsigned int nbytes;
{
#if !USEMEMPOOL
    kfree(ptr);
#else
    MemPool *memPool = (MemPool *)arg;
    MemChunk *mprev = 0, *node;
    MemChunk *new = (void *)(((unsigned char *)ptr) - sizeof(MemChunk));

    if (!memPool->freePool) {
        new->m_next = 0;
	memPool->freePool = new;
    } else {
    	/*
	 * Find where this new chunk fits in the free list.
	 */
	for (node = memPool->freePool; node && new > node; node = node->m_next)
	    mprev = node;
	/*
	 * Re-combine with the following free chunk if possible.
	 */
	if ((((unsigned char *)new) + new->m_size) == (unsigned char *)node) {
	    new->m_size += node->m_size;
	    new->m_next = node->m_next;
	    if (mprev) {
		if ((((unsigned char *)mprev) + mprev->m_size) == (unsigned char *)new) {
	            mprev->m_size += new->m_size;
		    mprev->m_next = new->m_next;
		} else
		    mprev->m_next = new;
	    } else
		memPool->freePool = new;
	/*
	 * Re-combine with the previous free chunk if possible.
	 */
	} else if (mprev && (((unsigned char *)mprev) + mprev->m_size) ==
	  (unsigned char *)new) {
	    mprev->m_size += new->m_size;
	    if ((((unsigned char *)mprev) + mprev->m_size) == (unsigned char *)node) {
	        mprev->m_size += node->m_size;
		mprev->m_next = node->m_next;
	    } else
		mprev->m_next = node;
	/*
	 * No luck re-combining, just insert the new chunk into the list.
	 */
	} else {
	    if (mprev)
		mprev->m_next = new;
	    else
		memPool->freePool = new;
	    new->m_next = node;
	}
    }
#endif /* USEMEMPOOL */
}

void *
zalloc(arg, items, size)
    void *arg;
    unsigned int items, size;
{
#if !USEMEMPOOL
    struct ppp_deflate_state *state = arg;

    return kmalloc(items * size, state->in_alloc? GFP_KERNEL: GFP_ATOMIC);
#else
    MemPool *memPool = (MemPool *)arg;
    MemChunk *mprev = 0, *node;

    size *= items;
    size += sizeof(MemChunk);
    if (size & 0x3)
    	size = (size + 7) & ~3; 
    for (node = memPool->freePool; node; node = node->m_next) {
	if (size == node->m_size) {
	    if (mprev)
		mprev->m_next = node->m_next;
	    else
		memPool->freePool = node->m_next;
	    return (void *)(((unsigned char *)node)+sizeof(MemChunk));
	} else if (node->m_size > (size + sizeof(MemChunk) + 7)) {
	    MemChunk *new;

	    new = (void *)(((unsigned char *)node) + size);
	    new->m_size = node->m_size - size;
	    new->m_next = node->m_next;
	    if (mprev)
		mprev->m_next = new;
	    else
		memPool->freePool = new;

	    node->m_size = size;

	    return (void *)(((unsigned char *)node)+sizeof(MemChunk));
	    break;
	}
	mprev = node;
    }
    printk(KERN_DEBUG
	   "zalloc(%d)... Out of memory in Pool!\n", size - sizeof(MemChunk)); 
    return NULL;
#endif /* USEMEMPOOL */
}

static void
z_comp_free(arg)
    void *arg;
{
    struct ppp_deflate_state *state = (struct ppp_deflate_state *) arg;

    if (state) {
	    deflateEnd(&state->strm);
#if USEMEMPOOL
	    memPoolFree(&state->strm.opaque);
#endif
	    kfree(state);
	    MOD_DEC_USE_COUNT;
    }
}

/*
 * Allocate space for a compressor.
 */
static void *
z_comp_alloc(options, opt_len)
    unsigned char *options;
    int opt_len;
{
    struct ppp_deflate_state *state;
    int w_size;

    if (opt_len != CILEN_DEFLATE || options[0] != CI_DEFLATE
	|| options[1] != CILEN_DEFLATE
	|| DEFLATE_METHOD(options[2]) != DEFLATE_METHOD_VAL
	|| options[3] != DEFLATE_CHK_SEQUENCE)
	return NULL;
    w_size = DEFLATE_SIZE(options[2]);
    if (w_size < DEFLATE_MIN_SIZE || w_size > DEFLATE_MAX_SIZE)
	return NULL;

    state = (struct ppp_deflate_state *) kmalloc(sizeof(*state), GFP_KERNEL);
    if (state == NULL)
	return NULL;

    MOD_INC_USE_COUNT;
    memset (state, 0, sizeof (struct ppp_deflate_state));
    state->strm.next_in = NULL;
    state->strm.zalloc  = zalloc;
    state->strm.zfree   = zfree;
    state->w_size       = w_size;
    state->in_alloc = 1;

#if USEMEMPOOL
    if (!memPoolAlloc(&state->strm.opaque, 0x50000)) {
	z_comp_free(state);
	return NULL;
    }
#else
    state->strm.opaque = state;
#endif

    if (deflateInit2(&state->strm, Z_DEFAULT_COMPRESSION, DEFLATE_METHOD_VAL,
		     -w_size, 8, Z_DEFAULT_STRATEGY, DEFLATE_OVHD+2) != Z_OK) {
	z_comp_free(state);
	return NULL;
    }
    state->in_alloc = 0;
    return (void *) state;
}

static int
z_comp_init(arg, options, opt_len, unit, hdrlen, debug)
    void *arg;
    unsigned char *options;
    int opt_len, unit, hdrlen, debug;
{
    struct ppp_deflate_state *state = (struct ppp_deflate_state *) arg;

    if (opt_len < CILEN_DEFLATE || options[0] != CI_DEFLATE
	|| options[1] != CILEN_DEFLATE
	|| DEFLATE_METHOD(options[2]) != DEFLATE_METHOD_VAL
	|| DEFLATE_SIZE(options[2]) != state->w_size
	|| options[3] != DEFLATE_CHK_SEQUENCE)
	return 0;

    state->seqno = 0;
    state->unit  = unit;
    state->debug = debug;

    deflateReset(&state->strm);

    return 1;
}

static void
z_comp_reset(arg)
    void *arg;
{
    struct ppp_deflate_state *state = (struct ppp_deflate_state *) arg;

    state->seqno = 0;
    deflateReset(&state->strm);
}

int
z_compress(arg, rptr, obuf, isize, osize)
    void *arg;
    unsigned char *rptr;	/* uncompressed packet (in) */
    unsigned char *obuf;	/* compressed packet (out) */
    int isize, osize;
{
    struct ppp_deflate_state *state = (struct ppp_deflate_state *) arg;
    int r, proto, off, olen;
    unsigned char *wptr;

    /*
     * Check that the protocol is in the range we handle.
     */
    proto = PPP_PROTOCOL(rptr);
    if (proto > 0x3fff || proto == 0xfd || proto == 0xfb)
	return 0;

    /* Don't generate compressed packets which are larger than
       the uncompressed packet. */
    if (osize > isize)
	osize = isize;

    wptr = obuf;

    /*
     * Copy over the PPP header and store the 2-byte sequence number.
     */
    wptr[0] = PPP_ADDRESS(rptr);
    wptr[1] = PPP_CONTROL(rptr);
    wptr[2] = PPP_COMP >> 8;
    wptr[3] = PPP_COMP;
    wptr += PPP_HDRLEN;
    wptr[0] = state->seqno >> 8;
    wptr[1] = state->seqno;
    wptr += 2;
    state->strm.next_out = wptr;
    state->strm.avail_out = osize - (PPP_HDRLEN + 2);
    ++state->seqno;

    off = (proto > 0xff) ? 2 : 3;	/* skip 1st proto byte if 0 */
    rptr += off;
    state->strm.next_in = rptr;
    state->strm.avail_in = (isize - off);

    olen = 0;
    for (;;) {
	r = deflate(&state->strm, Z_PACKET_FLUSH);
	if (r != Z_OK) {
	    if (state->debug)
		printk(KERN_DEBUG "z_compress: deflate returned %d (%s)\n",
		       r, (state->strm.msg? state->strm.msg: ""));
	    break;
	}
	if (state->strm.avail_out == 0) {
	    olen += osize;
	    state->strm.next_out = NULL;
	    state->strm.avail_out = 1000000;
	} else {
	    break;		/* all done */
	}
    }
    if (olen < osize)
	olen += osize - state->strm.avail_out;

    /*
     * See if we managed to reduce the size of the packet.
     * If the compressor just gave us a single zero byte, it means
     * the packet was incompressible.
     */
    if (olen < isize && !(olen == PPP_HDRLEN + 3 && *wptr == 0)) {
	state->stats.comp_bytes += olen;
	state->stats.comp_packets++;
    } else {
	state->stats.inc_bytes += isize;
	state->stats.inc_packets++;
	olen = 0;
    }
    state->stats.unc_bytes += isize;
    state->stats.unc_packets++;

    return olen;
}

static void
z_comp_stats(arg, stats)
    void *arg;
    struct compstat *stats;
{
    struct ppp_deflate_state *state = (struct ppp_deflate_state *) arg;

    *stats = state->stats;
}

static void
z_decomp_free(arg)
    void *arg;
{
    struct ppp_deflate_state *state = (struct ppp_deflate_state *) arg;

    if (state) {
	    inflateEnd(&state->strm);
#if USEMEMPOOL
	    memPoolFree(&state->strm.opaque);
#endif
	    kfree(state);
	    MOD_DEC_USE_COUNT;
    }
}

/*
 * Allocate space for a decompressor.
 */
static void *
z_decomp_alloc(options, opt_len)
    unsigned char *options;
    int opt_len;
{
    struct ppp_deflate_state *state;
    int w_size;

    if (opt_len != CILEN_DEFLATE || options[0] != CI_DEFLATE
	|| options[1] != CILEN_DEFLATE
	|| DEFLATE_METHOD(options[2]) != DEFLATE_METHOD_VAL
	|| options[3] != DEFLATE_CHK_SEQUENCE)
	return NULL;
    w_size = DEFLATE_SIZE(options[2]);
    if (w_size < DEFLATE_MIN_SIZE || w_size > DEFLATE_MAX_SIZE)
	return NULL;

    state = (struct ppp_deflate_state *) kmalloc(sizeof(*state), GFP_KERNEL);
    if (state == NULL)
	return NULL;

    MOD_INC_USE_COUNT;
    memset (state, 0, sizeof (struct ppp_deflate_state));
    state->w_size        = w_size;
    state->strm.next_out = NULL;
    state->strm.zalloc   = zalloc;
    state->strm.zfree    = zfree;
    state->in_alloc = 1;

#if USEMEMPOOL
    if (!memPoolAlloc(&state->strm.opaque, 0x10000)) {
	z_decomp_free(state);
	return NULL;
    }
#else
    state->strm.opaque = state;
#endif

    if (inflateInit2(&state->strm, -w_size) != Z_OK) {
	z_decomp_free(state);
	return NULL;
    }
    state->in_alloc = 0;
    return (void *) state;
}

static int
z_decomp_init(arg, options, opt_len, unit, hdrlen, mru, debug)
    void *arg;
    unsigned char *options;
    int opt_len, unit, hdrlen, mru, debug;
{
    struct ppp_deflate_state *state = (struct ppp_deflate_state *) arg;

    if (opt_len < CILEN_DEFLATE || options[0] != CI_DEFLATE
	|| options[1] != CILEN_DEFLATE
	|| DEFLATE_METHOD(options[2]) != DEFLATE_METHOD_VAL
	|| DEFLATE_SIZE(options[2]) != state->w_size
	|| options[3] != DEFLATE_CHK_SEQUENCE)
	return 0;

    state->seqno = 0;
    state->unit  = unit;
    state->debug = debug;
    state->mru   = mru;

    inflateReset(&state->strm);

    return 1;
}

static void
z_decomp_reset(arg)
    void *arg;
{
    struct ppp_deflate_state *state = (struct ppp_deflate_state *) arg;

    state->seqno = 0;
    inflateReset(&state->strm);
}

/*
 * Decompress a Deflate-compressed packet.
 *
 * Because of patent problems, we return DECOMP_ERROR for errors
 * found by inspecting the input data and for system problems, but
 * DECOMP_FATALERROR for any errors which could possibly be said to
 * be being detected "after" decompression.  For DECOMP_ERROR,
 * we can issue a CCP reset-request; for DECOMP_FATALERROR, we may be
 * infringing a patent of Motorola's if we do, so we take CCP down
 * instead.
 *
 * Given that the frame has the correct sequence number and a good FCS,
 * errors such as invalid codes in the input most likely indicate a
 * bug, so we return DECOMP_FATALERROR for them in order to turn off
 * compression, even though they are detected by inspecting the input.
 */
int
z_decompress(arg, ibuf, isize, obuf, osize)
    void *arg;
    unsigned char *ibuf;
    int isize;
    unsigned char *obuf;
    int osize;
{
    struct ppp_deflate_state *state = (struct ppp_deflate_state *) arg;
    int olen, seq, r;
    int decode_proto, overflow;
    unsigned char overflow_buf[1];

    if (isize <= PPP_HDRLEN + DEFLATE_OVHD) {
	if (state->debug)
	    printk(KERN_DEBUG "z_decompress%d: short packet (len=%d)\n",
		   state->unit, isize);
	return DECOMP_ERROR;
    }

    /* Check the sequence number. */
    seq = (ibuf[PPP_HDRLEN] << 8) + ibuf[PPP_HDRLEN+1];
    if (seq != state->seqno) {
	if (state->debug)
	    printk(KERN_DEBUG "z_decompress%d: bad seq # %d, expected %d\n",
		   state->unit, seq, state->seqno);
	return DECOMP_ERROR;
    }
    ++state->seqno;

    /*
     * Fill in the first part of the PPP header.  The protocol field
     * comes from the decompressed data.
     */
    obuf[0] = PPP_ADDRESS(ibuf);
    obuf[1] = PPP_CONTROL(ibuf);
    obuf[2] = 0;

    /*
     * Set up to call inflate.  We set avail_out to 1 initially so we can
     * look at the first byte of the output and decide whether we have
     * a 1-byte or 2-byte protocol field.
     */
    state->strm.next_in = ibuf + PPP_HDRLEN + DEFLATE_OVHD;
    state->strm.avail_in = isize - (PPP_HDRLEN + DEFLATE_OVHD);
    state->strm.next_out = obuf + 3;
    state->strm.avail_out = 1;
    decode_proto = 1;
    overflow = 0;

    /*
     * Call inflate, supplying more input or output as needed.
     */
    for (;;) {
	r = inflate(&state->strm, Z_PACKET_FLUSH);
	if (r != Z_OK) {
	    if (state->debug)
		printk(KERN_DEBUG "z_decompress%d: inflate returned %d (%s)\n",
		       state->unit, r, (state->strm.msg? state->strm.msg: ""));
	    return DECOMP_FATALERROR;
	}
	if (state->strm.avail_out != 0)
	    break;		/* all done */
	if (decode_proto) {
	    state->strm.avail_out = osize - PPP_HDRLEN;
	    if ((obuf[3] & 1) == 0) {
		/* 2-byte protocol field */
		obuf[2] = obuf[3];
		--state->strm.next_out;
		++state->strm.avail_out;
	    }
	    decode_proto = 0;
	} else if (!overflow) {
	    /*
	     * We've filled up the output buffer; the only way to
	     * find out whether inflate has any more characters left
	     * is to give it another byte of output space.
	     */
	    state->strm.next_out = overflow_buf;
	    state->strm.avail_out = 1;
	    overflow = 1;
	} else {
	    if (state->debug)
		printk(KERN_DEBUG "z_decompress%d: ran out of mru\n",
		       state->unit);
	    return DECOMP_FATALERROR;
	}
    }

    if (decode_proto)
	return DECOMP_ERROR;

    olen = osize - state->strm.avail_out;
    state->stats.unc_bytes += olen;
    state->stats.unc_packets++;
    state->stats.comp_bytes += isize;
    state->stats.comp_packets++;

    return olen;
}

/*
 * Incompressible data has arrived - add it to the history.
 */
static void
z_incomp(arg, ibuf, icnt)
    void *arg;
    unsigned char *ibuf;
    int icnt;
{
    struct ppp_deflate_state *state = (struct ppp_deflate_state *) arg;
    int proto, r;

    /*
     * Check that the protocol is one we handle.
     */
    proto = PPP_PROTOCOL(ibuf);
    if (proto > 0x3fff || proto == 0xfd || proto == 0xfb)
	return;

    ++state->seqno;

    /*
     * Iterate through the message blocks, adding the characters in them
     * to the decompressor's history.  For the first block, we start
     * at the either the 1st or 2nd byte of the protocol field,
     * depending on whether the protocol value is compressible.
     */
    state->strm.next_in = ibuf + 3;
    state->strm.avail_in = icnt - 3;
    if (proto > 0xff) {
	--state->strm.next_in;
	++state->strm.avail_in;
    }

    r = inflateIncomp(&state->strm);
    if (r != Z_OK) {
	/* gak! */
	if (state->debug) {
	    printk(KERN_DEBUG "z_incomp%d: inflateIncomp returned %d (%s)\n",
		   state->unit, r, (state->strm.msg? state->strm.msg: ""));
	}
	return;
    }

    /*
     * Update stats.
     */
    state->stats.inc_bytes += icnt;
    state->stats.inc_packets++;
    state->stats.unc_bytes += icnt;
    state->stats.unc_packets++;
}

/*************************************************************
 * Module interface table
 *************************************************************/

/* These are in ppp.c */
extern int  ppp_register_compressor   (struct compressor *cp);
extern void ppp_unregister_compressor (struct compressor *cp);

/*
 * Procedures exported to if_ppp.c.
 */
struct compressor ppp_deflate = {
    CI_DEFLATE,			/* compress_proto */
    z_comp_alloc,		/* comp_alloc */
    z_comp_free,		/* comp_free */
    z_comp_init,		/* comp_init */
    z_comp_reset,		/* comp_reset */
    z_compress,			/* compress */
    z_comp_stats,		/* comp_stat */
    z_decomp_alloc,		/* decomp_alloc */
    z_decomp_free,		/* decomp_free */
    z_decomp_init,		/* decomp_init */
    z_decomp_reset,		/* decomp_reset */
    z_decompress,		/* decompress */
    z_incomp,			/* incomp */
    z_comp_stats,		/* decomp_stat */
};

#ifdef MODULE
/*************************************************************
 * Module support routines
 *************************************************************/

int
init_module(void)
{  
        int answer = ppp_register_compressor (&ppp_deflate);
        if (answer == 0)
                printk (KERN_INFO
			"PPP Deflate Compression module registered\n");
        return answer;
}
     
void
cleanup_module(void)
{
	if (MOD_IN_USE)
		printk (KERN_INFO
			"Deflate Compression module busy, remove delayed\n");
	else
	        ppp_unregister_compressor (&ppp_deflate);
}
#endif
