/* Because this code is derived from the 4.3BSD compress source:
 *
 *
 * Copyright (c) 1985, 1986 The Regents of the University of California.
 * All rights reserved.
 *
 * This code is derived from software contributed to Berkeley by
 * James A. Woods, derived from original work by Spencer Thomas
 * and Joseph Orost.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *	This product includes software developed by the University of
 *	California, Berkeley and its contributors.
 * 4. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

/*
 * This version is for use with STREAMS under SunOS 4.x.
 */

#include <sys/param.h>
#include <sys/types.h>
#include <sys/stream.h>
#include <sys/kmem_alloc.h>
#include <net/ppp_str.h>

#define PACKET	mblk_t
#include <net/ppp-comp.h>

/*
 * PPP "BSD compress" compression
 *  The differences between this compression and the classic BSD LZW
 *  source are obvious from the requirement that the classic code worked
 *  with files while this handles arbitrarily long streams that
 *  are broken into packets.  They are:
 *
 *	When the code size expands, a block of junk is not emitted by
 *	    the compressor and not expected by the decompressor.
 *
 *	New codes are not necessarily assigned every time an old
 *	    code is output by the compressor.  This is because a packet
 *	    end forces a code to be emitted, but does not imply that a
 *	    new sequence has been seen.
 *
 *	The compression ratio is checked at the first end of a packet
 *	    after the appropriate gap.	Besides simplifying and speeding
 *	    things up, this makes it more likely that the transmitter
 *	    and receiver will agree when the dictionary is cleared when
 *	    compression is not going well.
 */

/*
 * A dictionary for doing BSD compress.
 */
struct bsd_db {
    int	    totlen;			/* length of this structure */
    u_int   hsize;			/* size of the hash table */
    u_char  hshift;			/* used in hash function */
    u_char  n_bits;			/* current bits/code */
    char    debug;
    u_char  unit;
    u_short mru;
    u_int   maxmaxcode;			/* largest valid code */
    u_int   max_ent;			/* largest code in use */
    u_long  seqno;			/* # of last byte of packet */
    u_long  in_count;			/* uncompressed bytes */
    u_long  bytes_out;			/* compressed bytes */
    u_long  ratio;			/* recent compression ratio */
    u_long  checkpoint;			/* when to next check the ratio */
    int	    clear_count;		/* times dictionary cleared */
    int	    incomp_count;		/* incompressible packets */
    u_short *lens;			/* array of lengths of codes */
    struct bsd_dict {
	union {				/* hash value */
	    u_long	fcode;
	    struct {
#ifdef BSD_LITTLE_ENDIAN
		u_short prefix;		/* preceding code */
		u_char	suffix;		/* last character of new code */
		u_char	pad;
#else
		u_char	pad;
		u_char	suffix;		/* last character of new code */
		u_short prefix;		/* preceding code */
#endif
	    } hs;
	} f;
	u_short codem1;			/* output of hash table -1 */
	u_short cptr;			/* map code to hash table entry */
    } dict[1];
};

#define BSD_OVHD	3		/* BSD compress overhead/packet */
#define MIN_BSD_BITS	9
#define BSD_INIT_BITS	MIN_BSD_BITS
#define MAX_BSD_BITS	15

static void	*bsd_comp_alloc __P((u_char *options, int opt_len));
static void	*bsd_decomp_alloc __P((u_char *options, int opt_len));
static void	bsd_free __P((void *state));
static int	bsd_comp_init __P((void *state, u_char *options, int opt_len,
				   int unit, int debug));
static int	bsd_decomp_init __P((void *state, u_char *options, int opt_len,
				     int unit, int mru, int debug));
static int	bsd_compress __P((void *state, mblk_t **mret,
				  mblk_t *mp, int slen, int maxolen));
static void	bsd_incomp __P((void *state, mblk_t *dmsg));
static mblk_t	*bsd_decompress __P((void *state, mblk_t *cmp, int hdroff));
static void	bsd_reset __P((void *state));

/*
 * Procedures exported to ppp_comp.c.
 */
struct compressor ppp_bsd_compress = {
    0x21,			/* compress_proto */
    bsd_comp_alloc,		/* comp_alloc */
    bsd_free,			/* comp_free */
    bsd_comp_init,		/* comp_init */
    bsd_reset,			/* comp_reset */
    bsd_compress,		/* compress */
    bsd_decomp_alloc,		/* decomp_alloc */
    bsd_free,			/* decomp_free */
    bsd_decomp_init,		/* decomp_init */
    bsd_reset,			/* decomp_reset */
    bsd_decompress,		/* decompress */
    bsd_incomp,			/* incomp */
};

/*
 * the next two codes should not be changed lightly, as they must not
 * lie within the contiguous general code space.
 */
#define CLEAR	256			/* table clear output code */
#define FIRST	257			/* first free entry */
#define LAST	255

#define MAXCODE(b)	((1 << (b)) - 1)
#define BADCODEM1	MAXCODE(MAX_BSD_BITS);

#define BSD_HASH(prefix,suffix,hshift) ((((u_long)(suffix)) << (hshift)) \
				       ^ (u_long)(prefix))
#define BSD_KEY(prefix,suffix) ((((u_long)(suffix)) << 16) + (u_long)(prefix))

#define CHECK_GAP	10000		/* Ratio check interval */


/*
 * clear the dictionary
 */
static void
bsd_clear(db)
    struct bsd_db *db;
{
    db->clear_count++;
    db->max_ent = FIRST-1;
    db->n_bits = BSD_INIT_BITS;
    db->ratio = 0;
    db->bytes_out = 0;
    db->in_count = 0;
    db->incomp_count = 0;
    db->checkpoint = CHECK_GAP;
}

/*
 * If the dictionary is full, then see if it is time to reset it.
 *
 * Compute the compression ratio using fixed-point arithmetic
 * with 8 fractional bits.
 *
 * Since we have an infinite stream instead of a single file,
 * watch only the local compression ratio.
 *
 * Since both peers must reset the dictionary at the same time even in
 * the absence of CLEAR codes (while packets are incompressible), they
 * must compute the same ratio.
 */
static int				/* 1=output CLEAR */
bsd_check(db)
    struct bsd_db *db;
{
    u_long new_ratio;

    if (db->in_count >= db->checkpoint) {
	/* age the ratio by limiting the size of the counts */
	if (db->in_count >= 0x7fffff
	    || db->bytes_out >= 0x7fffff) {
	    db->in_count -= db->in_count/4;
	    db->bytes_out -= db->bytes_out/4;
	}

	db->checkpoint = db->in_count + CHECK_GAP;

	if (db->max_ent >= db->maxmaxcode) {
	    /* Reset the dictionary only if the ratio is worse,
	     * or if it looks as if it has been poisoned
	     * by incompressible data.
	     *
	     * This does not overflow, because
	     *	db->in_count <= 0x7fffff.
	     */
	    new_ratio = db->in_count<<8;
	    if (db->bytes_out != 0)
		new_ratio /= db->bytes_out;

	    if (new_ratio < db->ratio || new_ratio < 256) {
		bsd_clear(db);
		return 1;
	    }
	    db->ratio = new_ratio;
	}
    }
    return 0;
}

/*
 * Reset state, as on a CCP ResetReq.
 */
static void
bsd_reset(state)
    void *state;
{
    struct bsd_db *db = (struct bsd_db *) state;

    db->seqno = 0;
    bsd_clear(db);
    db->clear_count = 0;
}

/*
 * Allocate space for a (de) compressor.
 */
static void *
bsd_alloc(options, opt_len, decomp)
    u_char *options;
    int opt_len, decomp;
{
    int bits;
    u_int newlen, hsize, hshift, maxmaxcode;
    struct bsd_db *db;

    if (opt_len != 3 || options[0] != 0x21 || options[1] != 3)
	return NULL;
    bits = options[2];
    switch (bits) {
    case 9:			/* needs 82152 for both directions */
    case 10:			/* needs 84144 */
    case 11:			/* needs 88240 */
    case 12:			/* needs 96432 */
	hsize = 5003;
	hshift = 4;
	break;
    case 13:			/* needs 176784 */
	hsize = 9001;
	hshift = 5;
	break;
    case 14:			/* needs 353744 */
	hsize = 18013;
	hshift = 6;
	break;
    case 15:			/* needs 691440 */
	hsize = 35023;
	hshift = 7;
	break;
    case 16:			/* needs 1366160--far too much, */
	/* hsize = 69001; */	/* and 69001 is too big for cptr */
	/* hshift = 8; */	/* in struct bsd_db */
	/* break; */
    default:
	return NULL;
    }

    maxmaxcode = MAXCODE(bits);
    newlen = sizeof(*db) + (hsize-1) * (sizeof(db->dict[0]));
    db = (struct bsd_db *) kmem_alloc(newlen, KMEM_NOSLEEP);
    if (!db)
	return NULL;
    bzero(db, sizeof(*db) - sizeof(db->dict));

    if (!decomp) {
	db->lens = NULL;
    } else {
	db->lens = (u_short *) kmem_alloc((maxmaxcode+1) * sizeof(db->lens[0]),
					  KMEM_NOSLEEP);
	if (!db->lens) {
	    kmem_free(db, newlen);
	    return NULL;
	}
    }

    db->totlen = newlen;
    db->hsize = hsize;
    db->hshift = hshift;
    db->maxmaxcode = maxmaxcode;

    return (void *) db;
}

static void
bsd_free(state)
    void *state;
{
    struct bsd_db *db = (struct bsd_db *) state;

    if (db->lens)
	kmem_free(db->lens, (db->maxmaxcode+1) * sizeof(db->lens[0]));
    kmem_free(db, db->totlen);
}

static void *
bsd_comp_alloc(options, opt_len)
    u_char *options;
    int opt_len;
{
    return bsd_alloc(options, opt_len, 0);
}

static void *
bsd_decomp_alloc(options, opt_len)
    u_char *options;
    int opt_len;
{
    return bsd_alloc(options, opt_len, 1);
}

/*
 * Initialize the database.
 */
static int
bsd_init(db, options, opt_len, unit, mru, debug, decomp)
    struct bsd_db *db;
    u_char *options;
    int opt_len, unit, mru, debug, decomp;
{
    int i;

    if (opt_len != 3 || options[0] != 0x21 || options[1] != 3
	|| MAXCODE(options[2]) != db->maxmaxcode
	|| decomp && db->lens == NULL)
	return 0;

    if (decomp) {
	i = LAST+1;
	while (i != 0)
	    db->lens[--i] = 1;
    }
    i = db->hsize;
    while (i != 0) {
	db->dict[--i].codem1 = BADCODEM1;
	db->dict[i].cptr = 0;
    }

    db->unit = unit;
    db->mru = mru;
    db->clear_count = -1;
    if (debug)
	db->debug = 1;

    bsd_clear(db);

    return 1;
}

static int
bsd_comp_init(state, options, opt_len, unit, debug)
    void *state;
    u_char *options;
    int opt_len, unit, debug;
{
    return bsd_init((struct bsd_db *) state, options, opt_len,
		    unit, 0, debug, 0);
}

static int
bsd_decomp_init(state, options, opt_len, unit, mru, debug)
    void *state;
    u_char *options;
    int opt_len, unit, mru, debug;
{
    return bsd_init((struct bsd_db *) state, options, opt_len,
		    unit, mru, debug, 1);
}



/*
 * compress a packet
 *	Assume the protocol is known to be >= 0x21 and < 0xff.
 *	One change from the BSD compress command is that when the
 *	code size expands, we do not output a bunch of padding.
 */
static int			/* new slen */
bsd_compress(state, mret, mp, slen, maxolen)
    void *state;
    mblk_t **mret;		/* return compressed mbuf chain here */
    mblk_t *mp;			/* from here */
    int slen;			/* uncompressed length */
    int maxolen;		/* max compressed length */
{
    struct bsd_db *db = (struct bsd_db *) state;
    int hshift = db->hshift;
    u_int max_ent = db->max_ent;
    u_int n_bits = db->n_bits;
    u_int bitno = 32;
    u_long accm = 0;
    struct bsd_dict *dictp;
    u_long fcode;
    u_char c;
    long hval, disp, ent;
    mblk_t *np;
    u_char *rptr, *wptr;
    u_char *cp_end;
    int olen;
    mblk_t *m, **mnp;
    int proto;

#define PUTBYTE(v) {					\
    if (wptr) {						\
	*wptr++ = (v);					\
	if (wptr >= cp_end) {				\
	    m->b_wptr = wptr;				\
	    m = m->b_cont;				\
	    if (m) {					\
		wptr = m->b_wptr;			\
		cp_end = m->b_datap->db_lim;		\
	    } else					\
		wptr = NULL;				\
	}						\
    }							\
    ++olen;						\
}

#define OUTPUT(ent) {					\
    bitno -= n_bits;					\
    accm |= ((ent) << bitno);				\
    do {						\
	PUTBYTE(accm >> 24);				\
	accm <<= 8;					\
	bitno += 8;					\
    } while (bitno <= 24);				\
}

    /* Don't generate compressed packets which are larger than
       the uncompressed packet. */
    if (maxolen > slen)
	maxolen = slen;

    /* Allocate enough message blocks to give maxolen total space. */
    mnp = mret;
    for (olen = maxolen; olen > 0; ) {
	m = allocb((olen < 4096? olen: 4096), BPRI_MED);
	*mnp = m;
	if (m == NULL) {
	    if (*mret != NULL) {
		freemsg(*mret);
		mnp = mret;
	    }
	    break;
	}
	mnp = &m->b_cont;
	olen -= m->b_datap->db_lim - m->b_wptr;
    }
    *mnp = NULL;

    rptr = mp->b_rptr;
    if ((m = *mret) != NULL) {
	wptr = m->b_wptr;
	cp_end = m->b_datap->db_lim;
    } else
	wptr = cp_end = NULL;
    olen = 0;

    /*
     * Copy the PPP header over, changing the protocol,
     * and install the 3-byte sequence number.
     */
    slen += db->seqno - PPP_HDRLEN + 1;
    db->seqno = slen;
    if (wptr) {
	wptr[0] = rptr[0];	/* assumes the ppp header is */
	wptr[1] = rptr[1];	/* all in one mblk */
	wptr[2] = 0;		/* change the protocol */
	wptr[3] = PPP_COMP;
	wptr[4] = slen>>16;
	wptr[5] = slen>>8;
	wptr[6] = slen;
	wptr += PPP_HDRLEN + BSD_OVHD;
    }

    /* start with the protocol byte */
    ent = rptr[3];
    rptr += PPP_HDRLEN;
    slen = mp->b_wptr - rptr;
    db->in_count += slen + 1;
    np = mp->b_cont;
    for (;;) {
	if (slen <= 0) {
	    if (!np)
		break;
	    rptr = np->b_rptr;
	    slen = np->b_wptr - rptr;
	    np = np->b_cont;
	    if (!slen)
		continue;   /* handle 0-length buffers */
	    db->in_count += slen;
	}

	slen--;
	c = *rptr++;
	fcode = BSD_KEY(ent, c);
	hval = BSD_HASH(ent, c, hshift);
	dictp = &db->dict[hval];

	/* Validate and then check the entry. */
	if (dictp->codem1 >= max_ent)
	    goto nomatch;
	if (dictp->f.fcode == fcode) {
	    ent = dictp->codem1+1;
	    continue;	/* found (prefix,suffix) */
	}

	/* continue probing until a match or invalid entry */
	disp = (hval == 0) ? 1 : hval;
	do {
	    hval += disp;
	    if (hval >= db->hsize)
		hval -= db->hsize;
	    dictp = &db->dict[hval];
	    if (dictp->codem1 >= max_ent)
		goto nomatch;
	} while (dictp->f.fcode != fcode);
	ent = dictp->codem1+1;		/* finally found (prefix,suffix) */
	continue;

    nomatch:
	OUTPUT(ent);		/* output the prefix */

	/* code -> hashtable */
	if (max_ent < db->maxmaxcode) {
	    struct bsd_dict *dictp2;
	    /* expand code size if needed */
	    if (max_ent >= MAXCODE(n_bits))
		db->n_bits = ++n_bits;

	    /* Invalidate old hash table entry using
	     * this code, and then take it over.
	     */
	    dictp2 = &db->dict[max_ent+1];
	    if (db->dict[dictp2->cptr].codem1 == max_ent)
		db->dict[dictp2->cptr].codem1 = BADCODEM1;
	    dictp2->cptr = hval;
	    dictp->codem1 = max_ent;
	    dictp->f.fcode = fcode;

	    db->max_ent = ++max_ent;
	}
	ent = c;
    }

    OUTPUT(ent);			/* output the last code */
    db->bytes_out += olen;

    if (bsd_check(db))
	OUTPUT(CLEAR);			/* do not count the CLEAR */

    /* Pad dribble bits of last code with ones.
     * Do not emit a completely useless byte of ones.
     */
    if (bitno != 32)
	PUTBYTE((accm | (0xff << (bitno-8))) >> 24);

    /* Increase code size if we would have without the packet
     * boundary and as the decompressor will.
     */
    if (max_ent >= MAXCODE(n_bits) && max_ent < db->maxmaxcode)
	db->n_bits++;

    if (olen + PPP_HDRLEN + BSD_OVHD > maxolen && *mret != NULL) {
	/* throw away the compressed stuff if it is longer than uncompressed */
	freemsg(*mret);
	*mret = NULL;
    } else if (wptr != NULL) {
	m->b_wptr = wptr;
	if (m->b_cont) {
	    freemsg(m->b_cont);
	    m->b_cont = NULL;
	}
    }

    return olen + PPP_HDRLEN + BSD_OVHD;
#undef OUTPUT
#undef PUTBYTE
}


/*
 * Update the "BSD Compress" dictionary on the receiver for
 * incompressible data by pretending to compress the incoming data.
 * The protocol is assumed to be < 0x100.
 */
static void
bsd_incomp(state, dmsg)
    void *state;
    mblk_t *dmsg;
{
    struct bsd_db *db = (struct bsd_db *) state;
    u_int hshift = db->hshift;
    u_int max_ent = db->max_ent;
    u_int n_bits = db->n_bits;
    struct bsd_dict *dictp;
    u_long fcode;
    u_char c;
    long hval, disp;
    int slen;
    u_int bitno = 7;
    u_char *rptr;
    u_int ent;

    db->incomp_count++;

    db->seqno++;
    db->in_count++;		/* count the protocol as 1 byte */
    rptr = dmsg->b_rptr;
    ent = rptr[3];		/* get the protocol */
    rptr += PPP_HDRLEN;
    for (;;) {
	slen = dmsg->b_wptr - rptr;
	if (slen <= 0) {
	    dmsg = dmsg->b_cont;
	    if (!dmsg)
		break;
	    rptr = dmsg->b_rptr;
	    continue;		/* skip zero-length buffers */
	}
	db->in_count += slen;
	db->seqno += slen;

	do {
	    c = *rptr++;
	    fcode = BSD_KEY(ent, c);
	    hval = BSD_HASH(ent, c, hshift);
	    dictp = &db->dict[hval];

	    /* validate and then check the entry */
	    if (dictp->codem1 >= max_ent)
		goto nomatch;
	    if (dictp->f.fcode == fcode) {
		ent = dictp->codem1+1;
		continue;   /* found (prefix,suffix) */
	    }

	    /* continue probing until a match or invalid entry */
	    disp = (hval == 0) ? 1 : hval;
	    do {
		hval += disp;
		if (hval >= db->hsize)
		    hval -= db->hsize;
		dictp = &db->dict[hval];
		if (dictp->codem1 >= max_ent)
		    goto nomatch;
	    } while (dictp->f.fcode != fcode);
	    ent = dictp->codem1+1;
	    continue;	/* finally found (prefix,suffix) */

	nomatch:		/* output (count) the prefix */
	    bitno += n_bits;

	    /* code -> hashtable */
	    if (max_ent < db->maxmaxcode) {
		struct bsd_dict *dictp2;
		/* expand code size if needed */
		if (max_ent >= MAXCODE(n_bits))
		    db->n_bits = ++n_bits;

		/* Invalidate previous hash table entry
		 * assigned this code, and then take it over.
		 */
		dictp2 = &db->dict[max_ent+1];
		if (db->dict[dictp2->cptr].codem1 == max_ent)
		    db->dict[dictp2->cptr].codem1 = BADCODEM1;
		dictp2->cptr = hval;
		dictp->codem1 = max_ent;
		dictp->f.fcode = fcode;

		db->max_ent = ++max_ent;
		db->lens[max_ent] = db->lens[ent]+1;
	    }
	    ent = c;
	} while (--slen != 0);
    }
    bitno += n_bits;		/* output (count) the last code */
    db->bytes_out += bitno/8;
    (void)bsd_check(db);

    /* Increase code size if we would have without the packet
     * boundary and as the decompressor will.
     */
    if (max_ent >= MAXCODE(n_bits) && max_ent < db->maxmaxcode)
	db->n_bits++;
}


/*
 * Decompress "BSD Compress"
 */
static mblk_t *				/* 0=failed, so zap CCP */
bsd_decompress(state, cmsg, hdroff)
    void *state;
    mblk_t *cmsg;
    int hdroff;
{
    struct bsd_db *db = (struct bsd_db *) state;
    u_int max_ent = db->max_ent;
    u_long accm = 0;
    u_int bitno = 32;		/* 1st valid bit in accm */
    u_int n_bits = db->n_bits;
    u_int tgtbitno = 32-n_bits;	/* bitno when we have a code */
    struct bsd_dict *dictp;
    int explen, i, seq, len;
    u_int incode, oldcode, finchar;
    u_char *p, *rptr, *wptr;
    mblk_t *dmsg;
    int adrs, ctrl;
    int dlen, space, codelen;

    /*
     * Get at least the BSD Compress header in the first buffer
     */
    rptr = cmsg->b_rptr;
    if (rptr + PPP_HDRLEN + BSD_OVHD <= cmsg->b_wptr) {
	if (!pullupmsg(cmsg, PPP_HDRLEN + BSD_OVHD + 1)) {
	    if (db->debug)
		printf("bsd_decomp%d: failed to pullup\n", db->unit);
	    return 0;
	}
	rptr = cmsg->b_rptr;
    }

    /*
     * Save the address/control from the PPP header
     * and then get the sequence number.
     */
    adrs = PPP_ADDRESS(rptr);
    ctrl = PPP_CONTROL(rptr);
    rptr += PPP_HDRLEN;
    seq = (rptr[0] << 16) + (rptr[1] << 8) + rptr[2];
    rptr += 3;
    len = cmsg->b_wptr - rptr;

    /*
     * Check the sequence number and give up if the length is nonsense.
     * The check is against mru+1 because we compress one byte of protocol.
     */
    explen = (seq - db->seqno) & 0xffffff;
    db->seqno = seq;
    if (explen > db->mru + 1 || explen < 1) {
	if (db->debug)
	    printf("bsd_decomp%d: bad length 0x%x\n", db->unit, explen);
	return 0;
    }

    /* allocate enough message blocks for the decompressed message */
    dlen = explen + PPP_HDRLEN - 1 + hdroff;
    /* XXX assume decompressed packet fits in a single block */
    dmsg = allocb(dlen, BPRI_HI);
    if (!dmsg) {
	/* give up if cannot get an uncompressed buffer */
	return 0;
    }
    wptr = dmsg->b_wptr;

    /* Fill in the ppp header, but not the last byte of the protocol
       (that comes from the decompressed data). */
    wptr[0] = adrs;
    wptr[1] = ctrl;
    wptr[2] = 0;
    wptr += PPP_HDRLEN - 1;
    space = dmsg->b_datap->db_lim - wptr;

    db->bytes_out += len;
    dlen = explen;
    oldcode = CLEAR;
    for (;;) {
	if (len == 0) {
	    cmsg = cmsg->b_cont;
	    if (!cmsg) {	/* quit at end of message */
		if (dlen != 0) {
		    freemsg(dmsg);
		    if (db->debug)
			printf("bsd_decomp%d: lost %d bytes\n",
			       db->unit, explen);
		    return 0;
		}
		break;
	    }
	    rptr = cmsg->b_rptr;
	    len = cmsg->b_wptr - rptr;
	    db->bytes_out += len;
	    continue;		/* handle 0-length buffers */
	}

	/* Accumulate bytes until we have a complete code.
	 * Then get the next code, relying on the 32-bit,
	 * unsigned accm to mask the result.
	 */
	bitno -= 8;
	accm |= *rptr++ << bitno;
	--len;
	if (tgtbitno < bitno)
	    continue;
	incode = accm >> tgtbitno;
	accm <<= n_bits;
	bitno += n_bits;

	if (incode == CLEAR) {
	    /* The dictionary must only be cleared at
	     * the end of a packet.  But there could be an
	     * empty message block at the end.
	     */
	    if (len > 0 || cmsg->b_cont != 0) {
		if (cmsg->b_cont)
		    len += msgdsize(cmsg->b_cont);
		if (len > 0) {
		    freemsg(dmsg);
		    if (db->debug)
			printf("bsd_decomp%d: bad CLEAR\n", db->unit);
		    return 0;
		}
	    }
	    bsd_clear(db);
	    explen = 0;
	    break;
	}

	/* Special case for KwKwK string. */
	if (incode > max_ent) {
	    if (incode > max_ent+2 || incode > db->maxmaxcode
		|| oldcode == CLEAR) {
		freemsg(dmsg);
		if (db->debug) {
		    printf("bsd_decomp%d: bad code 0x%x oldcode=0x%x ",
			   db->unit, incode, oldcode);
		    printf("max_ent=0x%x dlen=%d seqno=%d\n",
			   max_ent, dlen, db->seqno);
		}
		return 0;
	    }
	    finchar = oldcode;
	    --dlen;
	} else
	    finchar = incode;

	codelen = db->lens[finchar];
	dlen -= codelen;
	if (dlen < 0) {
	    freemsg(dmsg);
	    if (db->debug)
		printf("bsd_decomp%d: ran out of buffer\n", db->unit);
	    return 0;
	}

	/* decode code and install in decompressed buffer */
	space -= codelen;
	if (space < 0) {
#ifdef DEBUG
	    if (cmsg->b_cont)
		len += msgdsize(cmsg->b_cont);
	    printf("bsd_decomp%d: overran output by %d with %d bytes left\n",
		   db->unit, -space, len);
#endif
	    freemsg(dmsg);
	    return 0;
	}
	p = (wptr += codelen);
	while (finchar > LAST) {
	    dictp = &db->dict[db->dict[finchar].cptr];
#ifdef DEBUG
	    --codelen;
	    if (codelen <= 0) {
		freemsg(dmsg);
		printf("bsd_decomp%d: fell off end of chain ", db->unit);
		printf("0x%x at 0x%x by 0x%x, max_ent=0x%x\n",
		       incode, finchar, db->dict[finchar].cptr, max_ent);
		return 0;
	    }
	    if (dictp->codem1 != finchar-1) {
		freemsg(dmsg);
		printf("bsd_decomp%d: bad code chain 0x%x finchar=0x%x ",
		       db->unit, incode, finchar);
		printf("oldcode=0x%x cptr=0x%x codem1=0x%x\n", oldcode,
		       db->dict[finchar].cptr, dictp->codem1);
		return 0;
	    }
#endif
	    *--p = dictp->f.hs.suffix;
	    finchar = dictp->f.hs.prefix;
	}
	*--p = finchar;

#ifdef DEBUG
	if (--codelen != 0)
	    printf("bsd_decomp%d: short by %d after code 0x%x, max_ent=0x%x\n",
		   db->unit, codelen, incode, max_ent);
#endif

	if (incode > max_ent) {		/* the KwKwK case again */
	    *wptr++ = finchar;
	    --space;
	}

	/*
	 * If not first code in a packet, and
	 * if not out of code space, then allocate a new code.
	 *
	 * Keep the hash table correct so it can be used
	 * with uncompressed packets.
	 */
	if (oldcode != CLEAR && max_ent < db->maxmaxcode) {
	    struct bsd_dict *dictp2;
	    u_long fcode;
	    long hval, disp;

	    fcode = BSD_KEY(oldcode,finchar);
	    hval = BSD_HASH(oldcode,finchar,db->hshift);
	    dictp = &db->dict[hval];

	    /* look for a free hash table entry */
	    if (dictp->codem1 < max_ent) {
		disp = (hval == 0) ? 1 : hval;
		do {
		    hval += disp;
		    if (hval >= db->hsize)
			hval -= db->hsize;
		    dictp = &db->dict[hval];
		} while (dictp->codem1 < max_ent);
	    }

	    /* Invalidate previous hash table entry
	     * assigned this code, and then take it over
	     */
	    dictp2 = &db->dict[max_ent+1];
	    if (db->dict[dictp2->cptr].codem1 == max_ent) {
		db->dict[dictp2->cptr].codem1 = BADCODEM1;
	    }
	    dictp2->cptr = hval;
	    dictp->codem1 = max_ent;
	    dictp->f.fcode = fcode;

	    db->max_ent = ++max_ent;
	    db->lens[max_ent] = db->lens[oldcode]+1;

	    /* Expand code size if needed. */
	    if (max_ent >= MAXCODE(n_bits) && max_ent < db->maxmaxcode) {
		db->n_bits = ++n_bits;
		tgtbitno = 32-n_bits;
	    }
	}
	oldcode = incode;
    }
    dmsg->b_wptr = wptr;

    /* fail on packets with bad lengths/sequence numbers */
    if (dlen != 0) {
	freemsg(dmsg);
	return 0;
    }

    /* Keep the checkpoint right so that incompressible packets
     * clear the dictionary at the right times.
     */
    db->in_count += explen;
    if (bsd_check(db) && db->debug) {
	printf("bsd_decomp%d: peer should have cleared dictionary\n",
	       db->unit);
    }

    return dmsg;
}
