/*
 * pppd.h - PPP daemon global declarations.
 *
 * Copyright (c) 1989 Carnegie Mellon University.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms are permitted
 * provided that the above copyright notice and this paragraph are
 * duplicated in all such forms and that any documentation,
 * advertising materials, and other materials related to such
 * distribution and use acknowledge that the software was developed
 * by Carnegie Mellon University.  The name of the
 * University may not be used to endorse or promote products derived
 * from this software without specific prior written permission.
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND WITHOUT ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, WITHOUT LIMITATION, THE IMPLIED
 * WARRANTIES OF MERCHANTIBILITY AND FITNESS FOR A PARTICULAR PURPOSE.
 *
 * $Id: pppd.h,v 1.9 1995/10/27 03:40:12 paulus Exp $
 */

/*
 * TODO:
 */

#ifndef __PPPD_H__
#define __PPPD_H__

#include <stdio.h>		/* for FILE */
#include <sys/param.h>		/* for MAXPATHLEN and BSD4_4, if defined */
#include <sys/types.h>		/* for u_int32_t, if defined */
#include <sys/time.h>		/* for struct timeval */
#include <net/ppp_defs.h>

#define NUM_PPP	1		/* One PPP interface supported (per process) */

/*
 * Limits.
 */

#define MAXWORDLEN	1024	/* max length of word in file (incl null) */
#define MAXARGS		1	/* max # args to a command */
#define MAXNAMELEN	256	/* max length of hostname or name for auth */
#define MAXSECRETLEN	256	/* max length of password or secret */

/*
 * Global variables.
 */

extern int	hungup;		/* Physical layer has disconnected */
extern int	ifunit;		/* Interface unit number */
extern char	ifname[];	/* Interface name */
extern int	fd;		/* Serial device file descriptor */
extern char	hostname[];	/* Our hostname */
extern u_char	outpacket_buf[]; /* Buffer for outgoing packets */
extern int	phase;		/* Current state of link - see values below */
extern int	baud_rate;	/* Current link speed in bits/sec */
extern char	*progname;	/* Name of this program */

/*
 * Variables set by command-line options.
 */

extern int	debug;		/* Debug flag */
extern int	kdebugflag;	/* Tell kernel to print debug messages */
extern int	default_device;	/* Using /dev/tty or equivalent */
extern char	devnam[];	/* Device name */
extern int	crtscts;	/* Use hardware flow control */
extern int	modem;		/* Use modem control lines */
extern int	inspeed;	/* Input/Output speed requested */
extern u_int32_t netmask;	/* IP netmask to set on interface */
extern int	lockflag;	/* Create lock file to lock the serial dev */
extern int	nodetach;	/* Don't detach from controlling tty */
extern char	*connector;	/* Script to establish physical link */
extern char	*disconnector;	/* Script to disestablish physical link */
extern char	user[];		/* Username for PAP */
extern char	passwd[];	/* Password for PAP */
extern int	auth_required;	/* Peer is required to authenticate */
extern int	proxyarp;	/* Set up proxy ARP entry for peer */
extern int	persist;	/* Reopen link after it goes down */
extern int	uselogin;	/* Use /etc/passwd for checking PAP */
extern int	lcp_echo_interval; /* Interval between LCP echo-requests */
extern int	lcp_echo_fails;	/* Tolerance to unanswered echo-requests */
extern char	our_name[];	/* Our name for authentication purposes */
extern char	remote_name[];	/* Peer's name for authentication */
extern int	usehostname;	/* Use hostname for our_name */
extern int	disable_defaultip; /* Don't use hostname for default IP adrs */
extern char	*ipparam;	/* Extra parameter for ip up/down scripts */
extern int	cryptpap;	/* Others' PAP passwords are encrypted */

/*
 * Values for phase.
 */
#define PHASE_DEAD		0
#define PHASE_ESTABLISH		1
#define PHASE_AUTHENTICATE	2
#define PHASE_NETWORK		3
#define PHASE_TERMINATE		4

/*
 * Prototypes.
 */

/* Procedures exported from main.c. */
void die __P((int));		/* Cleanup and exit */
void quit __P((void));		/* like die(1) */
void novm __P((char *));	/* Say we ran out of memory, and die */
void timeout __P((void (*func)(), caddr_t arg, int t));
				/* Call func(arg) after t seconds */
void untimeout __P((void (*func)(), caddr_t arg));
				/* Cancel call to func(arg) */
int run_program __P((char *prog, char **args, int must_exist));
				/* Run program prog with args in child */
void demuxprotrej __P((int, int));
				/* Demultiplex a Protocol-Reject */
void format_packet __P((u_char *, int, void (*) (void *, char *, ...),
		void *));	/* Format a packet in human-readable form */
void log_packet __P((u_char *, int, char *));
				/* Format a packet and log it with syslog */
void print_string __P((char *, int,  void (*) (void *, char *, ...),
		void *));	/* Format a string for output */

/* Procedures exported from auth.c */
void link_required __P((int));	  /* we are starting to use the link */
void link_terminated __P((int));  /* we are finished with the link */
void link_down __P((int));	  /* the LCP layer has left the Opened state */
void link_established __P((int)); /* the link is up; authenticate now */
void auth_peer_fail __P((int, int));
				/* peer failed to authenticate itself */
void auth_peer_success __P((int, int));
				/* peer successfully authenticated itself */
void auth_withpeer_fail __P((int, int));
				/* we failed to authenticate ourselves */
void auth_withpeer_success __P((int, int));
				/* we successfully authenticated ourselves */
void check_auth_options __P((void));
				/* check authentication options supplied */
int  check_passwd __P((int, char *, int, char *, int, char **, int *));
				/* Check peer-supplied username/password */
int  get_secret __P((int, char *, char *, char *, int *, int));
				/* get "secret" for chap */
int  auth_ip_addr __P((int, u_int32_t));
				/* check if IP address is authorized */
int  bad_ip_adrs __P((u_int32_t));
				/* check if IP address is unreasonable */
void check_access __P((FILE *, char *));
				/* check permissions on secrets file */

/* Procedures exported from sys-*.c */
void sys_init __P((void));	/* Do system-dependent initialization */
void sys_cleanup __P((void));	/* Restore system state before exiting */
void note_debug_level __P((void)); /* Note change in debug level */
int  ppp_available __P((void));	/* Test whether ppp kernel support exists */
void establish_ppp __P((void));	/* Turn serial port into a ppp interface */
void disestablish_ppp __P((void)); /* Restore port to normal operation */
void set_up_tty __P((int, int)); /* Set up port's speed, parameters, etc. */
void restore_tty __P((void));	/* Restore port's original parameters */
void setdtr __P((int, int));	/* Raise or lower port's DTR line */
void output __P((int, u_char *, int)); /* Output a PPP packet */
void wait_input __P((struct timeval *));
				/* Wait for input, with timeout */
int  read_packet __P((u_char *)); /* Read PPP packet */
void ppp_send_config __P((int, int, u_int32_t, int, int));
				/* Configure i/f transmit parameters */
void ppp_set_xaccm __P((int, ext_accm));
				/* Set extended transmit ACCM */
void ppp_recv_config __P((int, int, u_int32_t, int, int));
				/* Configure i/f receive parameters */
int  ccp_test __P((int, u_char *, int, int));
				/* Test support for compression scheme */
void ccp_flags_set __P((int, int, int));
				/* Set kernel CCP state */
int  ccp_fatal_error __P((int)); /* Test for fatal decomp error in kernel */
int  sifvjcomp __P((int, int, int, int));
				/* Configure VJ TCP header compression */
int  sifup __P((int));		/* Configure i/f up (for IP) */
int  sifdown __P((int));	/* Configure i/f down (for IP) */
int  sifaddr __P((int, u_int32_t, u_int32_t, u_int32_t));
				/* Configure IP addresses for i/f */
int  cifaddr __P((int, u_int32_t, u_int32_t));
				/* Reset i/f IP addresses */
int  sifdefaultroute __P((int, u_int32_t));
				/* Create default route through i/f */
int  cifdefaultroute __P((int, u_int32_t));
				/* Delete default route through i/f */
int  sifproxyarp __P((int, u_int32_t));
				/* Add proxy ARP entry for peer */
int  cifproxyarp __P((int, u_int32_t));
				/* Delete proxy ARP entry for peer */
u_int32_t GetMask __P((u_int32_t)); /* Get appropriate netmask for address */
int  lock __P((char *));	/* Create lock file for device */
void unlock __P((void));	/* Delete previously-created lock file */
int  daemon __P((int, int));	/* Detach us from terminal session */
int  logwtmp __P((char *, char *, char *));
				/* Write entry to wtmp file */

/*
 * Inline versions of get/put char/short/long.
 * Pointer is advanced; we assume that both arguments
 * are lvalues and will already be in registers.
 * cp MUST be u_char *.
 */
#define GETCHAR(c, cp) { \
	(c) = *(cp)++; \
}
#define PUTCHAR(c, cp) { \
	*(cp)++ = (u_char) (c); \
}


#define GETSHORT(s, cp) { \
	(s) = *(cp)++ << 8; \
	(s) |= *(cp)++; \
}
#define PUTSHORT(s, cp) { \
	*(cp)++ = (u_char) ((s) >> 8); \
	*(cp)++ = (u_char) (s); \
}

#define GETLONG(l, cp) { \
	(l) = *(cp)++ << 8; \
	(l) |= *(cp)++; (l) <<= 8; \
	(l) |= *(cp)++; (l) <<= 8; \
	(l) |= *(cp)++; \
}
#define PUTLONG(l, cp) { \
	*(cp)++ = (u_char) ((l) >> 24); \
	*(cp)++ = (u_char) ((l) >> 16); \
	*(cp)++ = (u_char) ((l) >> 8); \
	*(cp)++ = (u_char) (l); \
}

#define INCPTR(n, cp)	((cp) += (n))
#define DECPTR(n, cp)	((cp) -= (n))

#undef  FALSE
#define FALSE	0
#undef  TRUE
#define TRUE	1

/*
 * System dependent definitions for user-level 4.3BSD UNIX implementation.
 */

#define DEMUXPROTREJ(u, p)	demuxprotrej(u, p)

#define TIMEOUT(r, f, t)	timeout((r), (f), (t))
#define UNTIMEOUT(r, f)		untimeout((r), (f))

#define BCOPY(s, d, l)		memcpy(d, s, l)
#define BZERO(s, n)		memset(s, 0, n)
#define EXIT(u)			quit()

#define PRINTMSG(m, l)	{ m[l] = '\0'; syslog(LOG_INFO, "Remote message: %s", m); }

/*
 * MAKEHEADER - Add Header fields to a packet.
 */
#define MAKEHEADER(p, t) { \
    PUTCHAR(PPP_ALLSTATIONS, p); \
    PUTCHAR(PPP_UI, p); \
    PUTSHORT(t, p); }


#ifdef DEBUGALL
#define DEBUGMAIN	1
#define DEBUGFSM	1
#define DEBUGLCP	1
#define DEBUGIPCP	1
#define DEBUGUPAP	1
#define DEBUGCHAP	1
#endif

#ifndef LOG_PPP			/* we use LOG_LOCAL2 for syslog by default */
#if defined(DEBUGMAIN) || defined(DEBUGFSM) || defined(DEBUG) \
  || defined(DEBUGLCP) || defined(DEBUGIPCP) || defined(DEBUGUPAP) \
  || defined(DEBUGCHAP) 
#define LOG_PPP LOG_LOCAL2
#else
#define LOG_PPP LOG_DAEMON
#endif
#endif /* LOG_PPP */

#ifdef DEBUGMAIN
#define MAINDEBUG(x)	if (debug) syslog x
#else
#define MAINDEBUG(x)
#endif

#ifdef DEBUGFSM
#define FSMDEBUG(x)	if (debug) syslog x
#else
#define FSMDEBUG(x)
#endif

#ifdef DEBUGLCP
#define LCPDEBUG(x)	if (debug) syslog x
#else
#define LCPDEBUG(x)
#endif

#ifdef DEBUGIPCP
#define IPCPDEBUG(x)	if (debug) syslog x
#else
#define IPCPDEBUG(x)
#endif

#ifdef DEBUGUPAP
#define UPAPDEBUG(x)	if (debug) syslog x
#else
#define UPAPDEBUG(x)
#endif

#ifdef DEBUGCHAP
#define CHAPDEBUG(x)	if (debug) syslog x
#else
#define CHAPDEBUG(x)
#endif

#ifndef SIGTYPE
#if defined(sun) || defined(SYSV) || defined(POSIX_SOURCE)
#define SIGTYPE void
#else
#define SIGTYPE int
#endif /* defined(sun) || defined(SYSV) || defined(POSIX_SOURCE) */
#endif /* SIGTYPE */

#ifndef MIN
#define MIN(a, b)	((a) < (b)? (a): (b))
#endif
#ifndef MAX
#define MAX(a, b)	((a) > (b)? (a): (b))
#endif

#endif /* __PPP_H__ */
