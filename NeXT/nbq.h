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

struct qparms {
    u_char	q_low, q_high, q_max;
    char 	*q_name;
};

struct nb_queue {
    char	*name;
    int		low, high, max, len, dropped;
    netbuf_t 	head, tail;
};

typedef u_int mark_t;
#define NB_EXTRA (sizeof(mark_t)+sizeof(netbuf_t))

static inline void
nb_set_next(netbuf_t nb, netbuf_t ptr)
{
if(nb) bcopy(&ptr,nb_map(nb)-sizeof(netbuf_t),sizeof(netbuf_t));
}

static inline void
nb_get_next(netbuf_t nb, netbuf_t *ptr)
{
if(nb && ptr) bcopy(nb_map(nb)-sizeof(netbuf_t),ptr,sizeof(netbuf_t));
}

static inline void
nb_set_mark(netbuf_t nb, mark_t ptr)
{
if(nb) bcopy(&ptr,nb_map(nb)-NB_EXTRA,sizeof(mark_t));
}

static inline void
nb_get_mark(netbuf_t nb, mark_t *ptr)
{
if(nb && ptr) bcopy(nb_map(nb)-NB_EXTRA,ptr,sizeof(mark_t));
}

static inline void
ppp_nb_shrink_top(netbuf_t nb, unsigned int size)
{
    netbuf_t ptr;
    mark_t   mark;
    nb_get_next(nb,&ptr);
    nb_get_mark(nb,&mark);
    nb_shrink_top(nb,size);
    nb_set_mark(nb,mark);
    nb_set_next(nb,ptr);
}

static inline void
ppp_nb_grow_top(netbuf_t nb, unsigned int size)
{
    netbuf_t ptr;
    mark_t   mark;
    nb_get_next(nb,&ptr);
    nb_get_mark(nb,&mark);
    nb_grow_top(nb,size);
    nb_set_mark(nb,mark);
    nb_set_next(nb,ptr);
}

static inline netbuf_t
ppp_nb_alloc(unsigned int size)
{
    netbuf_t nb;

    size+=NB_EXTRA;
    nb=nb_alloc(size);
    if(nb) {
	nb_shrink_top(nb,NB_EXTRA);
	nb_set_next(nb,NULL);
	nb_set_mark(nb,0);
    }
    return nb;
}
#endif /* __NBQ_H__ */

