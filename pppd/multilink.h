#ifndef PPP_MULTILINK_H
#define PPP_MULTILINK_H

#include "pppdconf.h"

/*
 * values for epdisc.class
 */
#define EPD_NULL        0	/* null discriminator, no data */
#define EPD_LOCAL       1
#define EPD_IP          2
#define EPD_MAC         3
#define EPD_MAGIC       4
#define EPD_PHONENUM    5

struct epdisc;

#ifdef PPP_WITH_MULTILINK

/*
 * Check multilink-related options
 */
void mp_check_options(void);

/*
 * Join our link to an appropriate bundle
 */
int mp_join_bundle(void);

/*
 * Disconnected our link from the bundle
 */
void mp_exit_bundle(void);

/*
 * Multipoint bundle terminated
 */
void mp_bundle_terminated(void);

/*
 * Acting as a multilink master
 */
bool mp_master();

/*
 * Was multilink negotiated
 */
bool mp_on();

/*
 * Convert an endpoint discriminator to a string
 */
char *epdisc_to_str(struct epdisc *);

/*
 * Convert a string to an endpoint discriminator
 */
int str_to_epdisc(struct epdisc *, char *);

/*
 * Hook for plugin to hear when an interface joins a multilink bundle
 */
typedef void (multilink_join_hook_fn)(void);
extern multilink_join_hook_fn *multilink_join_hook;

#endif // PPP_WITH_MULTILINK
#endif // PPP_MULTILINK_H
