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
#if !(NS_TARGET >= 40)
#include <kernserv/prototypes.h>
#endif /* NS_TARGET */

#include "netbuf.h"
typedef u_int mark_t;

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


struct qparms {
    u_char	q_low, q_high, q_max;
    char 	*q_name;
};

struct nb_queue {
    char	*name;
    int		low, high, max, len, dropped;
    NETBUF_T 	head, tail;
};

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
	nb_shrink_top(nb,NB_EXTRA);
	NB_SET_NEXT(nb,NULL);
	NB_SET_MARK(nb,0);
    }
    return nb;
}
#endif /* __NBQ_H__ */

