/*
 * pppd.h - PPP daemon global declarations.
 *
 * Copyright (c) 1984-2000 Carnegie Mellon University. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * 3. The name "Carnegie Mellon University" must not be used to
 *    endorse or promote products derived from this software without
 *    prior written permission. For permission or any legal
 *    details, please contact
 *      Office of Technology Transfer
 *      Carnegie Mellon University
 *      5000 Forbes Avenue
 *      Pittsburgh, PA  15213-3890
 *      (412) 268-4387, fax: (412) 268-7395
 *      tech-transfer@andrew.cmu.edu
 *
 * 4. Redistributions of any form whatsoever must retain the following
 *    acknowledgment:
 *    "This product includes software developed by Computing Services
 *     at Carnegie Mellon University (http://www.cmu.edu/computing/)."
 *
 * CARNEGIE MELLON UNIVERSITY DISCLAIMS ALL WARRANTIES WITH REGARD TO
 * THIS SOFTWARE, INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
 * AND FITNESS, IN NO EVENT SHALL CARNEGIE MELLON UNIVERSITY BE LIABLE
 * FOR ANY SPECIAL, INDIRECT OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN
 * AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING
 * OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#ifndef PPP_PPPD_H
#define PPP_PPPD_H

#include "pppdconf.h"

/*
 * Limits
 */
#define NUM_PPP		1	/* One PPP interface supported (per process) */
#define MAXWORDLEN	1024	/* max length of word in file (incl null) */
#define MAXARGS		1	/* max # args to a command */
#define MAXNAMELEN	256	/* max length of hostname or name for auth */
#define MAXSECRETLEN	256	/* max length of password or secret */


/*
 * Values for phase.
 */
#define PHASE_DEAD          0
#define PHASE_INITIALIZE    1
#define PHASE_SERIALCONN    2
#define PHASE_DORMANT       3
#define PHASE_ESTABLISH     4
#define PHASE_AUTHENTICATE  5
#define PHASE_CALLBACK      6
#define PHASE_NETWORK       7
#define PHASE_RUNNING       8
#define PHASE_TERMINATE     9
#define PHASE_DISCONNECT    10
#define PHASE_HOLDOFF       11
#define PHASE_MASTER        12

typedef enum
{
    EXIT_OK                 = 0,
    EXIT_FATAL_ERROR        = 1,
    EXIT_OPTION_ERROR       = 2,
    EXIT_NOT_ROOT           = 3,
    EXIT_NO_KERNEL_SUPPORT  = 4,
    EXIT_USER_REQUEST       = 5,
    EXIT_LOCK_FAILED        = 6,
    EXIT_OPEN_FAILED        = 7,
    EXIT_CONNECT_FAILED     = 8,
    EXIT_PTYCMD_FAILED      = 9,
    EXIT_NEGOTIATION_FAILED = 10,
    EXIT_PEER_AUTH_FAILED   = 11,
    EXIT_IDLE_TIMEOUT       = 12,
    EXIT_CONNECT_TIME       = 13,
    EXIT_CALLBACK           = 14,
    EXIT_PEER_DEAD          = 15,
    EXIT_HANGUP             = 16,
    EXIT_LOOPBACK           = 17,
    EXIT_INIT_FAILED        = 18,
    EXIT_AUTH_TOPEER_FAILED = 19,
    EXIT_TRAFFIC_LIMIT      = 20,
    EXIT_CNID_AUTH_FAILED   = 21
} ppp_exit_code_t;

ppp_exit_code_t ppp_status();
void ppp_set_status(ppp_exit_code_t code);


struct option;
typedef void (*printer_func)(void *, char *, ...);

/*
 * The following struct gives the addresses of procedures to call for a particular protocol.
 */
struct protent {
    /* PPP protocol number */
    unsigned short protocol;
    /* Initialization procedure */
    void (*init)(int unit);
    /* Process a received packet */
    void (*input)(int unit, unsigned char *pkt, int len);
    /* Process a received protocol-reject */
    void (*protrej)(int unit);
    /* Lower layer has come up */
    void (*lowerup)(int unit);
    /* Lower layer has gone down */
    void (*lowerdown)(int unit);
    /* Open the protocol */
    void (*open)(int unit);
    /* Close the protocol */
    void (*close)(int unit, char *reason);
    /* Print a packet in readable form */
    int  (*printpkt)(unsigned char *pkt, int len, printer_func printer, void *arg);
    /* Process a received data packet */
    void (*datainput)(int unit, unsigned char *pkt, int len);
    /* 0 iff protocol is disabled */
    bool enabled_flag;
    /* Text name of protocol */
    char *name;
    /* Text name of corresponding data protocol */
    char *data_name;
    /* List of command-line options */
    struct option *options;
    /* Check requested options, assign defaults */
    void (*check_options)(void);
    /* Configure interface for demand-dial */
    int  (*demand_conf)(int unit);
    /* Say whether to bring up link for this pkt */
    int  (*active_pkt)(unsigned char *pkt, int len);
};

/* Table of pointers to supported protocols */
extern struct protent *protocols[];


/*
 * This struct contains pointers to a set of procedures for doing operations on a "channel".  
 * A channel provides a way to send and receive PPP packets - the canonical example is a serial 
 * port device in PPP line discipline (or equivalently with PPP STREAMS modules pushed onto it).
 */
struct channel {
	/* set of options for this channel */
	struct option *options;
	/* find and process a per-channel options file */
	void (*process_extra_options)(void);
	/* check all the options that have been given */
	void (*check_options)(void);
	/* get the channel ready to do PPP, return a file descriptor */
	int  (*connect)(void);
	/* we're finished with the channel */
	void (*disconnect)(void);
	/* put the channel into PPP `mode' */
	int  (*establish_ppp)(int);
	/* take the channel out of PPP `mode', restore loopback if demand */
	void (*disestablish_ppp)(int);
	/* set the transmit-side PPP parameters of the channel */
	void (*send_config)(int, uint32_t, int, int);
	/* set the receive-side PPP parameters of the channel */
	void (*recv_config)(int, uint32_t, int, int);
	/* cleanup on error or normal exit */
	void (*cleanup)(void);
	/* close the device, called in children after fork */
	void (*close)(void);
};

extern struct channel *the_channel;


/*
 * Functions for string formatting and debugging
 */

/* Safe sprintf++ */
int slprintf(char *, int, char *, ...);		

/* vsprintf++ */
int vslprintf(char *, int, char *, va_list);

/* safe strcpy */
size_t strlcpy(char *, const char *, size_t);

/* safe strncpy */
size_t strlcat(char *, const char *, size_t);

/* log a debug message */
void dbglog(char *, ...);

/* log an informational message */
void info(char *, ...);

/* log a notice-level message */
void notice(char *, ...);

/* log a warning message */
void warn(char *, ...);

/* log an error message */
void error(char *, ...);	

/* log an error message and die(1) */
void fatal(char *, ...);	

/* Say we ran out of memory, and die */
void novm(char *);

/* Format a packet and log it with syslog */
void log_packet(unsigned char *, int, char *, int);

/* dump packet to debug log if interesting */
void dump_packet(const char *, unsigned char *, int);

/* initialize for using pr_log */
void init_pr_log(const char *, int);

/* printer fn, output to syslog */
void pr_log(void *, char *, ...);

/* finish up after using pr_log */
void end_pr_log(void);


/* RADIUS */

extern unsigned int maxoctets;	     /* Maximum octetes per session (in bytes) */
extern int       maxoctets_dir;      /* Direction :
				      0 - in+out (default)
				      1 - in
				      2 - out
				      3 - max(in,out) */
extern int       maxoctets_timeout;  /* Timeout for check of octets limit */
#define PPP_OCTETS_DIRECTION_SUM        0
#define PPP_OCTETS_DIRECTION_IN         1
#define PPP_OCTETS_DIRECTION_OUT        2
#define PPP_OCTETS_DIRECTION_MAXOVERAL  3
/* same as previous, but little different on RADIUS side */
#define PPP_OCTETS_DIRECTION_MAXSESSION 4

/*
 * Unfortunately, the linux kernel driver uses a different structure
 * for statistics from the rest of the ports.
 * This structure serves as a common representation for the bits
 * pppd needs.
 */
struct pppd_stats {
    uint64_t		bytes_in;
    uint64_t		bytes_out;
    unsigned int	pkts_in;
    unsigned int	pkts_out;
};

extern int	link_stats_valid; /* set if link_stats is valid */
void print_link_stats(void); /* Print stats, if available */
void reset_link_stats(int); /* Reset (init) stats when link goes up */
void update_link_stats(int); /* Get stats at link termination */

extern struct pppd_stats link_stats; /* byte/packet counts etc. for link */


int get_time(struct timeval *);
void timeout(void (*func)(void *), void *arg, int s, int us);
				/* Call func(arg) after s.us seconds */
void untimeout(void (*func)(void *), void *arg);
				/* Cancel call to func(arg) */

#define TIMEOUT(r, f, t)	timeout((r), (f), (t), 0)
#define UNTIMEOUT(r, f)		untimeout((r), (f))


void sys_close(void);	/* Clean up in a child before execing */
pid_t safe_fork(int, int, int);	/* Fork & close stuff in child */

/*
 * Get the current hostname
 */
const char *ppp_get_hostname(char *name, size_t *namesiz);

/*
 * Check if current session is using multi-link
 */
bool ppp_multilink_on();

/*
 * Check if we are multi-link master
 */
bool ppp_multilink_master();

/*
 * Is pppd using pty as a device (opposed to notty or pty opt).
 */
bool ppp_using_pty();

/*
 * Device is synchronous serial device
 */
bool ppp_sync_serial();

/*
 * Check if pppd got signaled, returns 0 if not signaled, returns -1 on failure, and the signal number when signaled.
 */
bool ppp_signaled(int sig);

/*
 * Maximum connect time in seconds
 */
int ppp_get_max_connect_time();

/*
 * Set the maximum connect time in seconds
 */
void ppp_set_max_connect_time(unsigned int max);

/*
 * Get the link idle time before shutting the link down
 */
int ppp_get_max_idle_time();

/*
 * Set the link idle time before shutting the link down
 */
void ppp_set_max_idle_time(unsigned int idle);

/*
 * Get the duration the link was up (uptime)
 */
int ppp_get_link_uptime();

/*
 * Get the ipparam configured with pppd
 */
const char *ppp_ipparam(char *buf, size_t bufsz);

/*
 * check if IP address is unreasonable
 */
bool ppp_bad_ip_addr(uint32_t);


extern int	ifunit;		/* Interface unit number */
extern char	ifname[];	/* Interface name (IFNAMSIZ) */
extern char	devnam[];	/* Device name */
extern char	ppp_devnam[];	/* name of PPP tty (maybe ttypx) */
extern int	debug;		/* Debug flag */
extern char	remote_name[MAXNAMELEN]; /* Peer's name for authentication */
extern char	peer_authname[];/* Authenticated name of peer */
extern char remote_number[MAXNAMELEN]; /* Remote telephone number, if avail. */
extern int  ppp_session_number; /* Session number (eg PPPoE session) */

void script_setenv(char *, char *, int);	/* set script env var */
void script_unsetenv(char *);		/* unset script env var */

int  ppp_available(void);	/* Test whether ppp kernel support exists */
void generic_disestablish_ppp(int dev_fd); /* Restore device setting */
int  generic_establish_ppp(int dev_fd); /* Make a ppp interface */
extern bool	modem;		/* Use modem control lines */

				/* Get current time, monotonic if possible. */
void netif_set_mtu(int, int); /* Set PPP interface MTU */
int  netif_get_mtu(int);      /* Get PPP interface MTU */


#ifndef MIN
#define MIN(a, b)	((a) < (b)? (a): (b))
#endif
#ifndef MAX
#define MAX(a, b)	((a) > (b)? (a): (b))
#endif


/* 
 * Register notification callback on certain events
 */

typedef void (*notify_func)(void *, int);

struct notifier {
    struct notifier *next;
    notify_func	    func;
    void	    *arg;
};

extern struct notifier *pidchange;   /* for notifications of pid changing */
extern struct notifier *phasechange; /* for notifications of phase changes */
extern struct notifier *exitnotify;  /* for notification that we're exiting */
extern struct notifier *sigreceived; /* notification of received signal */
extern struct notifier *ip_up_notifier;     /* IPCP has come up */
extern struct notifier *ip_down_notifier;   /* IPCP has gone down */
extern struct notifier *ipv6_up_notifier;   /* IPV6CP has come up */
extern struct notifier *ipv6_down_notifier; /* IPV6CP has gone down */
extern struct notifier *auth_up_notifier; /* peer has authenticated */
extern struct notifier *link_down_notifier; /* link has gone down */
extern struct notifier *fork_notifier;	/* we are a new child process */

/* Add a callback notifier */
void add_notifier(struct notifier **, notify_func, void *);

/* Remove the callback notifier */
void remove_notifier(struct notifier **, notify_func, void *);


/*
 * Hooks to enable plugins to hook into various parts of the code
 */

/* Declared in <linux/ppp_defs.h> */
struct ppp_idle;

extern int (*new_phase_hook)(int);
extern int (*idle_time_hook)(struct ppp_idle *);
extern int (*holdoff_hook)(void);
extern int  (*allowed_address_hook)(uint32_t addr);
extern void (*ip_up_hook)(void);
extern void (*ip_down_hook)(void);
extern void (*ip_choose_hook)(uint32_t *);
extern void (*ipv6_up_hook)(void);
extern void (*ipv6_down_hook)(void);

extern void (*multilink_join_hook)(void);
extern void (*snoop_recv_hook)(unsigned char *p, int len);
extern void (*snoop_send_hook)(unsigned char *p, int len);

#endif /* PPP_PPPD_H */
