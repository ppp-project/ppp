/*
 * linedisc.h -- includes for use with loadable line disciplines
 */
#define	KERNEL		1
#define	KERNEL_FEATURES	1

#ifdef m68k
#import <machine/reg.h>
#endif

#import <sys/param.h>
/*
#import <sys/systm.h>
*/
#import <sys/user.h>
#import <sys/ioctl.h>
#import <sys/tty.h>
#import <sys/proc.h>
/*
#import <sys/vnode.h>
#import <sys/file.h>
*/
#import <sys/conf.h>
#import <sys/buf.h>
#import <sys/dk.h>
#import <sys/uio.h>
#import <sys/kernel.h>

/*
#import <machine/spl.h>
*/
#ifdef m68k
#include "spl.h"
#endif

#if	NeXT
/*
#import <next/cons.h>
#import <nextdev/kmreg.h>
*/
#endif	NeXT

/*
 * Line discipline "kind"
 * NORMAL_LDISC -- Normal line disciplines use tty struct clists in
 *			standard manner
 * SPECIAL_LDISC -- Special line disciplines have private buffering
 *			strategy
 */
#define	NORMAL_LDISC	0
#define	SPECIAL_LDISC	1

extern int tty_ld_install(
	int ld_number,
	int ld_kind,
	int (*ld_open)(dev_t dev, struct tty *tp),
	void (*ld_close)(struct tty *tp),
	int (*ld_read)(struct tty *tp, struct uio *uiop),
	int (*ld_write)(struct tty *tp, struct uio *uiop),
	int (*ld_ioctl)(struct tty *tp, int command, void *dataptr, int flag),
	void (*ld_rint)(int c, struct tty *tp),
	void (*ld_rend)(char *cp, u_int n, struct tty *tp),
	void (*ld_start)(struct tty *tp),
	int (*ld_modem)(struct tty *tp, int dcd_on),
	int (*ld_select)(struct tty *tp, int rw)
);
extern int tty_ld_remove(int ld_number);
extern void ttydevstart(struct tty *tp);
extern void ttydevstop(struct tty *tp);
extern void ttyselwait(struct tty *tp, int rw);
extern void ttselwakeup(struct tty *tp);

