/*
 * Netbufs don't come with nifty queuing functions
 * like mbufs. We therefore make our own quques by
 * squirreling away an extra pointer before the data
 * in a netbuf. As we can't guarantee that this will
 * be aligned to anything in particular I use bcopy to
 * read and write it. bcopy can use 32 bit if it really
 * feels like it...
 * PCF
 *

#if defined(m68k)
#import "spl.h"
#else
#import <kernserv/machine/spl.h>
#endif
#include <kernserv/kern_server_types.h>
#include <kernserv/kalloc.h>
#include "nbq.h"

/*
 * There is no driver kit for the Moto release.
 */
#ifndef IOLog
#define IOLog printf
#define	IOLogDbg		if (sc->sc_flags & SC_DEBUG) printf
#else
#define	IOLogDbg		if (sc->sc_flags & SC_DEBUG) IOLog
#endif

extern kern_server_t instance;

/*
 * Careful about using this function.  Some places
 * in the code drop packets based on this count
 * but they never free them.
 */

static inline int
nbq_full(struct nb_queue* nbq)
{
    int rv;
    rv = (nbq->len >= nbq->max);
    return rv;
}

static inline int
nbq_empty(struct nb_queue* nbq)
{
    int rv;
    rv = (!nbq->head);
    return rv;
}

static inline int
nbq_low(struct nb_queue* nbq)
{
    int rv;
    rv = (nbq->len <= nbq->low);
    return rv;
}

static inline int
nbq_high(struct nb_queue* nbq)
{
    int rv;
    rv = (nbq->len >= nbq->high);
    return rv;
}

static inline NETBUF_T
nbq_peek(struct nb_queue* nbq)
{
    int s;
    NETBUF_T nb;

    s = splimp();
    nb = nbq->head;
    splx(s);
    return nb;
}

static inline NETBUF_T
nbq_dequeue(struct nb_queue* nbq)
{
  int s;
  NETBUF_T nb;

  if (!nbq->head)
      return NULL;

  s = splimp();
  nb = nbq->head;
  NB_GET_NEXT(nb,&nbq->head);
  if (!nbq->head)
	nbq->tail = NULL;
  --nbq->len;
  splx(s);

  return nb;
}

/*
 * One simple note about nbq_enqueue: it will enqueue packets even if
 * it is full, so the caller is responsible for checking this first...
 *
 * We return 1 if we added, else we return 0
 * if there was a problem. We leave it up to the caller
 * to detect an error return value (0) and print
 * an appropriate message/update stats.  However, in the spirit of
 * keeping the code as close to the netbsd version as is possible,
 * WE WILL FREE a packet that can't be enqueued.  This should be the
 * responsibility of the caller but that is currently not the case.
 *
 * Actually, now I'm using the hidden pointer arrangement then theres
 * no circumstances under which this can return 0, oh well...
 * PCF
 */

static inline int
nbq_enqueue(struct nb_queue* nbq, NETBUF_T nb)
{
  int s;

  NB_SET_NEXT(nb,NULL);
  s = splimp();
  if (nbq->tail)
    NB_SET_NEXT(nbq->tail,nb);
  else
    nbq->head = nb;
  nbq->tail = nb;
  ++nbq->len;
  splx(s);
  return 1;
}

static inline void
nbq_flush(struct nb_queue *nbq)
{
    NETBUF_T nb,temp;
    int s;

    s  = splimp();
    nb = nbq->head;
    while(nb) {
	temp=nb;
	NB_GET_NEXT(nb,&nb);
	NB_FREE(temp);
    }

    nbq->head = nbq->tail = NULL;
    nbq->len = 0;
    nbq->dropped = 0;
    splx(s);
}

/*
 * Must not be called at interrupt priority
 */

static inline void
nbq_init(struct nb_queue *nbq, struct qparms *qp)
{
  nbq->name = qp->q_name;
  nbq->head = nbq->tail = NULL;
  nbq->low = qp->q_low;
  nbq->high = qp->q_high;
  nbq->max = qp->q_max;
  nbq->len = 0;
  nbq->dropped = 0;
}

static inline void
nbq_free(struct nb_queue *nbq)
{
  nbq_flush(nbq);
}

static inline void
nbq_drop(struct nb_queue *nbq)
{
    ++nbq->dropped;
}

/*
 * Not very pretty, but it makes for less "diffs"...
 */
#define mtod(m,type)	((type) NB_MAP(m))

typedef void (*pfv)(void *);

/* used by both ppp_tty.c and if_ppp.c */
static inline kern_return_t
pppsched(pfv func, struct ppp_softc *sc)
{
    extern kern_server_t instance;
    kern_return_t result;

    if ((result = kern_serv_callout(&instance, func, (void *)sc)) != KERN_SUCCESS)
      IOLog("kern_serv_callout failed: ret = %x\n", result);

    return result;
}

#undef	u

static inline thread_t
current_thread(void)
{
	extern thread_t active_threads[];

	return active_threads[0];
}

extern struct proc *proc_from_thread(thread_t);
extern struct uthread *uthread_from_thread(thread_t);

#define	curproc		(proc_from_thread(current_thread()))

