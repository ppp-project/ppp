/*
 * All very trivial - the simpler the better I say. We try and keep
 * quqes of netbufs by squirreling a pointer away below the data area.
 * This is done by the ppp_nb_alloc function. As long as everyone
 * uses the ppp shrink and grow functions we should be o.k. This code
 * has now been modified to keep the mark_t stuff nhere as well since
 * we probably shafted that good and proper in the last version. oops !
 * PCF
 */

#ifndef __NBQ_H__
#define __NBQ_H__


#define KERNEL 1

#include <sys/types.h>
#include <kernserv/prototypes.h>

#include "netbuf.h"
typedef u_int mark_t;

/*
 * Netbufs and Netbuf wrappers don't help us because we
 * have no way of keeping track of information on start
 * position once nb_grow* or nb_shrink* are called.
 */

#ifdef NETBUF_PROXY

#warning ...you are compiling with NETBUF_PROXY

typedef struct _bpf_encapsulater
{
  /*
   * Depending on the direction of packet travel, these
   * values have different meanings.
   *
   * INCOMING:
   *    first  -- time first byte of packet received.
   *    second -- time last byte of packet received.
   *    third  -- Decompression start time
   *    fourth  -- Packet Handoff time
   *   (second-first) -- receive time
   *   (third-second) -- queue time waiting for decompression
   *   (fourth-third) -- decompression time
   *   (fourth - first) -- total receive time.
   *   (fourth - second) -- total system process time.
   *
   *   async_esc  -- The number of characters escaped in this packet.
   *   size1  --  The size of the inital packet before decompression.
   *              This value includes the expansion caused by AC and PC compression.
   *                If flags set:
   *                   AC implies packet got increased by 2 during receive.
   *                   PC implies packet got increased by 1 during receive.
   *              This + "async_esc" - (AC + PC expansion) describe actual bytes over link.
   *              Includes PPP header and trailer.  
   *              Doesn't count framing PPP_FLAG character.
   *
   *   size2  --  The size after BSD decompression.  PPP trailer was removed
   *              so packet should be at least 2 shorter than original.
   *   size3  --  The size after VJ decompression.
   *
   *
   * OUTGOING:  (very similar to incoming)
   *   first  -- time packet arrived to pppwrite() or pppoutput()
   *   second -- time compression started
   *   third  -- time compression ended
   *   fourth -- time first byte sent to interface
   *   fifth --  time last byte sent to interface
   *
   *   (second - first) Time waiting in system before compression
   *   (third - second) Time for compression
   *   (fourth - third) Time waiting in system out queue waiting to be
   *                      selected for sending to interface
   *   (fourth - first) Total system processing time
   *   (fifth-fourth)   Total interface send time.
   *   (fifth-first)    Total send time.
   *
   *   size1 -- The size of the intial packet as receved from the stack
   *   size2 -- The size after VJ compression
   *   size3 -- The size after BSD compression
   *
   */
  struct timeval first, second, third, fourth, fifth;
  unsigned async_esc, size1, size2, size3;

  int flags;                                 /* info about packet   */
#define NBFLAG_INCOMING     0x01             /* else outgoing       */
#define NBFLAG_AC           0x02             /* Address compressed  */
#define NBFLAG_PC           0x04             /* Protocol Compressed */
#define NBFLAG_VJC          0x08             /* VJ compressed       */
#define NBFLAG_CCP          0x10             /* BSD compressed      */
#define NBFLAG_CCPINC       0x20             /* BSD incompressible  */
#define NBFLAG_VJCINC       0x40             /* VJ incompressible   */					       

} bpf_encapsulater;

typedef struct _ppp_netbuf_t
{
  netbuf_t buffer;
  netbuf_t orig_buffer;                     /*
					     * Original outgoing datagram
					     * received.  We do compression and
					     * statistics gathering on buffer,
					     * we send buffer, but we return
					     * orig_buffer to BPF so that it doesn't
					     * have to understand all the compression.
					     */
					       

  struct _ppp_netbuf_t *next;               /* for linked list */

  unsigned int size;                        /* original size requested for netbuf.
					     * We leave it up to caller to
					     * determine extra space they need.  We
					     * may also include extra space we need 
					     * for bounds checking.
					     */

  unsigned char *wrapper,                   /* unaligned address returned for this containing
					     * structure.  Used for freeing.
					     */

  *init_offset;                             /* Init_offset is nb_map  of the netbuf_t before
					     * user can change it around.  Can check bounds
					     * against this.
					     */
  mark_t mark;

  bpf_encapsulater pktinfo;                  /* The size and compression stats that
					      *	get passed to user level tcpdump
					      */

} *ppp_netbuf_t;

/*
 * These prototypes are identical to the corrisponding functions
 * found in netbuf.h except they use the ppp_netbuf_t type.
 */
 
extern ppp_netbuf_t    cb_nb_alloc(unsigned size);
extern void            cb_nb_free(ppp_netbuf_t nb);
extern void            cb_nb_duplicate(ppp_netbuf_t from, ppp_netbuf_t to);
extern char *          cb_nb_map(ppp_netbuf_t nb);
extern char *          cb_nb_map_orig(ppp_netbuf_t nb);
extern unsigned        cb_nb_size(ppp_netbuf_t nb);
extern unsigned        cb_nb_size_orig(ppp_netbuf_t nb);
extern int             cb_nb_shrink_top(ppp_netbuf_t nb, unsigned size);
extern int             cb_nb_grow_top(ppp_netbuf_t nb, unsigned size);
extern int             cb_nb_shrink_bot(ppp_netbuf_t nb, unsigned size);
extern int             cb_nb_grow_bot(ppp_netbuf_t nb, unsigned size);
extern int             cb_nb_read(ppp_netbuf_t nb, unsigned offset, unsigned size, void *target);
extern int             cb_nb_write(ppp_netbuf_t nb, unsigned offset, unsigned size, void *source);
extern void            cb_nb_get_mark(ppp_netbuf_t nb, mark_t *ptr);
extern void            cb_nb_set_mark(ppp_netbuf_t nb, mark_t ptr);
extern void            cb_nb_get_next(ppp_netbuf_t nb, ppp_netbuf_t *ptr);
extern void            cb_nb_set_next(ppp_netbuf_t nb, ppp_netbuf_t ptr);
extern ppp_netbuf_t    cb_nb_to_NB(netbuf_t);
extern netbuf_t        cb_NB_to_nb(ppp_netbuf_t);

#define NETBUF_T ppp_netbuf_t
#define NB_ALLOC cb_nb_alloc
#define NB_FREE cb_nb_free
#define NB_DUPLICATE cb_nb_duplicate
#define NB_MAP cb_nb_map
#define NB_MAP_ORIG cb_nb_map_orig
#define NB_SIZE cb_nb_size
#define NB_SIZE_ORIG cb_nb_size_orig
#define NB_SHRINK_TOP cb_nb_shrink_top
#define NB_GROW_TOP cb_nb_grow_top
#define NB_SHRINK_BOT cb_nb_shrink_bot
#define NB_GROW_BOT cb_nb_grow_bot
#define NB_READ cb_nb_read
#define NB_WRITE cb_nb_write
#define NB_GET_MARK cb_nb_get_mark
#define NB_SET_MARK cb_nb_set_mark
#define NB_GET_NEXT cb_nb_get_next
#define NB_SET_NEXT cb_nb_set_next
#define nb_TO_NB cb_nb_to_NB
#define NB_TO_nb cb_NB_to_nb

#else  /* NETBUF_PROXY */

#define NETBUF_T netbuf_t
#define NB_ALLOC ppp_nb_alloc
#define NB_FREE nb_free
#define NB_MAP nb_map
#define NB_SIZE nb_size
#define NB_SHRINK_TOP ppp_nb_shrink_top
#define NB_GROW_TOP ppp_nb_grow_top
#define NB_SHRINK_BOT nb_shrink_bot
#define NB_GROW_BOT nb_grow_bot
#define NB_READ nb_read
#define NB_WRITE nb_write
#define NB_GET_MARK nb_get_mark
#define NB_SET_MARK nb_set_mark
#define NB_GET_NEXT nb_get_next
#define NB_SET_NEXT nb_set_next
#define nb_TO_NB(nb) (nb)
#define NB_TO_nb(NB) (NB)

#endif /* NETBUF_PROXY  */


struct qparms {
    u_char	q_low, q_high, q_max;
    char 	*q_name;
};

struct nb_queue {
    char	*name;
    int		low, high, max, len, dropped;
    NETBUF_T 	head, tail;
};

#ifndef NETBUF_PROXY
#define NB_EXTRA (sizeof(mark_t)+sizeof(netbuf_t))

static inline void
nb_set_next(netbuf_t nb, netbuf_t ptr)
{
if(nb) bcopy(&ptr,NB_MAP(nb)-sizeof(netbuf_t),sizeof(netbuf_t));
}

static inline void
nb_get_next(netbuf_t nb, netbuf_t *ptr)
{
if(nb && ptr) bcopy(NB_MAP(nb)-sizeof(netbuf_t),ptr,sizeof(netbuf_t));
}

static inline void
nb_set_mark(netbuf_t nb, mark_t ptr)
{
if(nb) bcopy(&ptr,NB_MAP(nb)-NB_EXTRA,sizeof(mark_t));
}

static inline void
nb_get_mark(netbuf_t nb, mark_t *ptr)
{
if(nb && ptr) bcopy(NB_MAP(nb)-NB_EXTRA,ptr,sizeof(mark_t));
}

static inline void
ppp_nb_shrink_top(netbuf_t nb, unsigned int size)
{
    netbuf_t ptr;
    mark_t   mark;
    NB_GET_NEXT(nb,&ptr);
    NB_GET_MARK(nb,&mark);
    nb_shrink_top(nb,size);
    NB_SET_MARK(nb,mark);
    NB_SET_NEXT(nb,ptr);
}

static inline void
ppp_nb_grow_top(netbuf_t nb, unsigned int size)
{
    netbuf_t ptr;
    mark_t   mark;
    NB_GET_NEXT(nb,&ptr);
    NB_GET_MARK(nb,&mark);
    nb_grow_top(nb,size);
    NB_SET_MARK(nb,mark);
    NB_SET_NEXT(nb,ptr);
}


static inline netbuf_t
ppp_nb_alloc(unsigned int size)
{
    netbuf_t nb;

    size+=NB_EXTRA;
    nb=nb_alloc(size);
    if(nb) {
	NB_SHRINK_TOP(nb,NB_EXTRA);
	NB_SET_NEXT(nb,NULL);
	NB_SET_MARK(nb,0);
    }
    return nb;
}
#endif /* NETBUF_PROXY  */
#endif /* __NBQ_H__ */

