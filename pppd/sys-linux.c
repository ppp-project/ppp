/*
 * sys-linux.c - System-dependent procedures for setting up
 * PPP interfaces on Linux systems
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
 */

#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/errno.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <sys/utsname.h>

#include <stdio.h>
#include <stdlib.h>
#include <syslog.h>
#include <string.h>
#include <time.h>
#include <memory.h>
#include <utmp.h>
#include <mntent.h>
#include <signal.h>
#include <fcntl.h>
#include <ctype.h>
#include <termios.h>

/* This is in netdevice.h. However, this compile will fail miserably if
   you attempt to include netdevice.h because it has so many references
   to __memcpy functions which it should not attempt to do. So, since I
   really don't use it, but it must be defined, define it now. */

#ifndef MAX_ADDR_LEN
#define MAX_ADDR_LEN 7
#endif

#include <linux/if.h>
#include <linux/ppp_defs.h>
#include <linux/if_arp.h>
#include <linux/if_ppp.h>
#include <linux/route.h>
#include <linux/if_ether.h>
#include <netinet/in.h>

#include "pppd.h"
#include "fsm.h"
#include "ipcp.h"

#ifndef RTF_DEFAULT  /* Normally in <linux/route.h> from <net/route.h> */
#define RTF_DEFAULT  0
#endif

#ifdef IPX_CHANGE
#include "ipxcp.h"
#endif

#ifdef LOCKLIB
#include <sys/locks.h>
#endif

#define ok_error(num) ((num)==EIO)

static int tty_disc = N_TTY;	/* The TTY discipline */
static int ppp_disc = N_PPP;	/* The PPP discpline */
static int initfdflags = -1;	/* Initial file descriptor flags for fd */
static int ppp_fd = -1;		/* fd which is set to PPP discipline */
static int sock_fd = -1;	/* socket for doing interface ioctls */
static int slave_fd = -1;
static int master_fd = -1;

static int has_proxy_arp       = 0;
static int driver_version      = 0;
static int driver_modification = 0;
static int driver_patch        = 0;
static int driver_is_old       = 0;
static int restore_term        = 0;	/* 1 => we've munged the terminal */
static struct termios inittermios;	/* Initial TTY termios */

static char loop_name[20];
static unsigned char inbuf[512]; /* buffer for chars read from loopback */

static int	if_is_up;	/* Interface has been marked up */
static u_int32_t default_route_gateway;	/* Gateway for default route added */
static u_int32_t proxy_arp_addr;	/* Addr for proxy arp entry added */

static char *lock_file;

static struct utsname utsname;	/* for the kernel version */

#define MAX_IFS		100

#define FLAGS_GOOD (IFF_UP          | IFF_BROADCAST)
#define FLAGS_MASK (IFF_UP          | IFF_BROADCAST | \
		    IFF_POINTOPOINT | IFF_LOOPBACK  | IFF_NOARP)

/* Prototypes for procedures local to this file. */
static int get_flags (void);
static void set_flags (int flags);
static int translate_speed (int bps);
static int baud_rate_of (int speed);
static char *path_to_route (void);
static void close_route_table (void);
static int open_route_table (void);
static int read_route_table (struct rtentry *rt);
static int defaultroute_exists (struct rtentry *rt);
static int get_ether_addr (u_int32_t ipaddr, struct sockaddr *hwaddr,
			   char *name);
static void decode_version (char *buf, int *version, int *mod, int *patch);

extern u_char	inpacket_buf[];	/* borrowed from main.c */

/*
 * SET_SA_FAMILY - set the sa_family field of a struct sockaddr,
 * if it exists.
 */

#define SET_SA_FAMILY(addr, family)			\
    memset ((char *) &(addr), '\0', sizeof(addr));	\
    addr.sa_family = (family);

/*
 * Determine if the PPP connection should still be present.
 */

extern int hungup;
#define still_ppp() (hungup == 0)

#ifndef LOCK_PREFIX
#define LOCK_PREFIX	"/var/lock/LCK.."
#endif

/********************************************************************
 *
 * Functions to read and set the flags value in the device driver
 */

static void set_ppp_fd (int new_fd)
  {    
    SYSDEBUG ((LOG_DEBUG, "setting ppp_fd to %d\n", ppp_fd));
    ppp_fd = new_fd;
  }

/********************************************************************
 *
 * Functions to read and set the flags value in the device driver
 */

static int get_flags (void)
  {    
    int flags;

    if (ioctl(ppp_fd, PPPIOCGFLAGS, (caddr_t) &flags) < 0)
      {
	if ( ok_error (errno) )
	  {
	    flags = 0;
	  }
	else
	  {
	    syslog(LOG_ERR, "ioctl(PPPIOCGFLAGS): %m");
	    quit();
	  }
      }

    SYSDEBUG ((LOG_DEBUG, "get flags = %x\n", flags));
    return flags;
  }

/********************************************************************/

static void set_flags (int flags)
  {    
    SYSDEBUG ((LOG_DEBUG, "set flags = %x\n", flags));

    if (ioctl(ppp_fd, PPPIOCSFLAGS, (caddr_t) &flags) < 0)
      {
	if (! ok_error (errno) )
	  {
	    syslog(LOG_ERR, "ioctl(PPPIOCSFLAGS, %x): %m(%d)", flags, errno);
	    quit();
	  }
      }
  }

/********************************************************************
 *
 * sys_init - System-dependent initialization.
 */

void sys_init(void)
  {
    openlog("pppd", LOG_PID | LOG_NDELAY, LOG_PPP);
    setlogmask(LOG_UPTO(LOG_INFO));
    if (debug)
      {
	setlogmask(LOG_UPTO(LOG_DEBUG));
      }
    
    /* Get an internet socket for doing socket ioctls. */
    sock_fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock_fd < 0)
      {
	if ( ! ok_error ( errno ))
	  {
	    syslog(LOG_ERR, "Couldn't create IP socket: %m(%d)", errno);
	    die(1);
	  }
      }

    uname(&utsname);
  }

/********************************************************************
 *
 * sys_cleanup - restore any system state we modified before exiting:
 * mark the interface down, delete default route and/or proxy arp entry.
 * This should call die() because it's called from die().
 */

void sys_cleanup(void)
  {
    struct ifreq ifr;
/*
 * Take down the device
 */
    if (if_is_up)
      {
	sifdown(0);
      }
/*
 * Delete any routes through the device.
 */
    if (default_route_gateway != 0)
      {
	cifdefaultroute(0, 0, default_route_gateway);
      }

    if (has_proxy_arp)
      {
	cifproxyarp(0, proxy_arp_addr);
      }
  }

/********************************************************************
 *
 * sys_close - Clean up in a child process before execing.
 */
void
sys_close(void)
  {
    close(sock_fd);
    sock_fd = -1;
    closelog();
  }

/********************************************************************
 *
 * note_debug_level - note a change in the debug level.
 */

void note_debug_level (void)
  {
    if (debug)
      {
	SYSDEBUG ((LOG_INFO, "Debug turned ON, Level %d", debug));
	setlogmask(LOG_UPTO(LOG_DEBUG));
      }
    else
      {
	setlogmask(LOG_UPTO(LOG_WARNING));
      }
  }

/********************************************************************
 *
 * set_kdebugflag - Define the debugging level for the kernel
 */

int set_kdebugflag (int requested_level)
  {
    if (ioctl(ppp_fd, PPPIOCSDEBUG, &requested_level) < 0)
      {
	if ( ! ok_error (errno) )
	  {
	    syslog (LOG_ERR, "ioctl(PPPIOCSDEBUG): %m");
	  }
	return (0);
      }
    SYSDEBUG ((LOG_INFO, "set kernel debugging level to %d",
		requested_level));
    return (1);
  }

/********************************************************************
 *
 * establish_ppp - Turn the serial port into a ppp interface.
 */

void establish_ppp (int tty_fd)
  {
    int x;
/*
 * The current PPP device will be the tty file.
 */
    set_ppp_fd (tty_fd);
/*
 * Ensure that the tty device is in exclusive mode.
 */
    if (ioctl(tty_fd, TIOCEXCL, 0) < 0)
      {
	if ( ! ok_error ( errno ))
	  {
	    syslog (LOG_WARNING, "ioctl(TIOCEXCL): %m");
	  }
      }
/*
 * Demand mode - prime the old ppp device to relinquish the unit.
 */
    if (demand && ioctl(slave_fd, PPPIOCXFERUNIT, 0) < 0)
      {
	syslog(LOG_ERR, "ioctl(transfer ppp unit): %m(%d)", errno);
	die(1);
      }
/*
 * Set the current tty to the PPP discpline
 */
    if (ioctl(ppp_fd, TIOCSETD, &ppp_disc) < 0)
      {
	if ( ! ok_error (errno) )
	  {
	    syslog(LOG_ERR, "ioctl(TIOCSETD): %m(%d)", errno);
	    die(1);
	  }
      }
/*
 * Find out which interface we were given.
 */
    if (ioctl(ppp_fd, PPPIOCGUNIT, &x) < 0)
      {	
	if ( ! ok_error (errno))
	  {
	    syslog(LOG_ERR, "ioctl(PPPIOCGUNIT): %m(%d)", errno);
	    die(1);
	  }
      }
/*
 * Check that we got the same unit again.
 */
    if (demand)
      {
	if (x != ifunit)
	  {
	    syslog(LOG_ERR, "transfer_ppp failed: wanted unit %d, got %d",
		   ifunit, x);
	    die(1);
	  }
      }

    ifunit = x;
/*
 * Enable debug in the driver if requested.
 */
    if (!demand)
      set_kdebugflag (kdebugflag);

    set_flags (get_flags() & ~(SC_RCV_B7_0 | SC_RCV_B7_1 |
			       SC_RCV_EVNP | SC_RCV_ODDP));

    SYSDEBUG ((LOG_NOTICE, "Using version %d.%d.%d of PPP driver",
	    driver_version, driver_modification, driver_patch));
/*
 * Fetch the initial file flags and reset blocking mode on the file.
 */
    initfdflags = fcntl(ppp_fd, F_GETFL);

    if (initfdflags == -1 ||
	fcntl(ppp_fd, F_SETFL, initfdflags | O_NONBLOCK) == -1)
      {
	if ( ! ok_error (errno))
	  {
	    syslog(LOG_WARNING,
		   "Couldn't set device to non-blocking mode: %m");
	  }
      }
  }

/********************************************************************
 *
 * disestablish_ppp - Restore the serial port to normal operation.
 * This shouldn't call die() because it's called from die().
 */

void disestablish_ppp(int tty_fd)
  {
    int x;
    char *s;

/*
 * Attempt to restore the previous tty settings
 */
    if (!hungup)
      {
/*
 * Restore the previous line discipline
 */
	if (ioctl(tty_fd, TIOCSETD, &tty_disc) < 0)
	  {
	    if ( ! ok_error (errno))
	      {
		syslog(LOG_ERR, "ioctl(TIOCSETD, N_TTY): %m");
	      }
	  }
	
	if (ioctl(tty_fd, TIOCNXCL, 0) < 0)
	  {
	    if ( ! ok_error (errno))
	      {
		syslog (LOG_WARNING, "ioctl(TIOCNXCL): %m(%d)", errno);
	      }
	  }

	/* Reset non-blocking mode on fd. */
	if (initfdflags != -1 && fcntl(tty_fd, F_SETFL, initfdflags) < 0)
	  {
	    if ( ! ok_error (errno))
	      {
		syslog (LOG_WARNING,
			"Couldn't restore device fd flags: %m");
	      }
	  }
      }
    initfdflags = -1;
  }

/********************************************************************
 *
 * clean_check - Fetch the flags for the device and generate
 * appropriate error messages.
 */
void clean_check(void)
  {
    int x;
    char *s;

    if (still_ppp())
      {
	if (ioctl(ppp_fd, PPPIOCGFLAGS, (caddr_t) &x) == 0)
	  {
	    s = NULL;
	    switch (~x & (SC_RCV_B7_0|SC_RCV_B7_1|SC_RCV_EVNP|SC_RCV_ODDP))
	      {
	      case SC_RCV_B7_0:
	      case SC_RCV_B7_0 | SC_RCV_EVNP:
	      case SC_RCV_B7_0 | SC_RCV_ODDP:
	      case SC_RCV_B7_0 | SC_RCV_ODDP | SC_RCV_EVNP:
		s = "all had bit 7 set to 1";
		break;
		
	      case SC_RCV_B7_1:
	      case SC_RCV_B7_1 | SC_RCV_EVNP:
	      case SC_RCV_B7_1 | SC_RCV_ODDP:
	      case SC_RCV_B7_1 | SC_RCV_ODDP | SC_RCV_EVNP:
		s = "all had bit 7 set to 0";
		break;
		
	      case SC_RCV_EVNP:
		s = "all had odd parity";
		break;
		
	      case SC_RCV_ODDP:
		s = "all had even parity";
		break;
	      }
	    
	    if (s != NULL)
	      {
		syslog(LOG_WARNING, "Receive serial link is not"
		       " 8-bit clean:");
		syslog(LOG_WARNING, "Problem: %s", s);
	      }
	  }
      }
  }
	

/*
 * List of valid speeds.
 */

struct speed {
    int speed_int, speed_val;
} speeds[] = {
#ifdef B50
    { 50, B50 },
#endif
#ifdef B75
    { 75, B75 },
#endif
#ifdef B110
    { 110, B110 },
#endif
#ifdef B134
    { 134, B134 },
#endif
#ifdef B150
    { 150, B150 },
#endif
#ifdef B200
    { 200, B200 },
#endif
#ifdef B300
    { 300, B300 },
#endif
#ifdef B600
    { 600, B600 },
#endif
#ifdef B1200
    { 1200, B1200 },
#endif
#ifdef B1800
    { 1800, B1800 },
#endif
#ifdef B2000
    { 2000, B2000 },
#endif
#ifdef B2400
    { 2400, B2400 },
#endif
#ifdef B3600
    { 3600, B3600 },
#endif
#ifdef B4800
    { 4800, B4800 },
#endif
#ifdef B7200
    { 7200, B7200 },
#endif
#ifdef B9600
    { 9600, B9600 },
#endif
#ifdef B19200
    { 19200, B19200 },
#endif
#ifdef B38400
    { 38400, B38400 },
#endif
#ifdef B57600
    { 57600, B57600 },
#endif
#ifdef B115200
    { 115200, B115200 },
#endif
#ifdef EXTA
    { 19200, EXTA },
#endif
#ifdef EXTB
    { 38400, EXTB },
#endif
    { 0, 0 }
};

/********************************************************************
 *
 * Translate from bits/second to a speed_t.
 */

static int translate_speed (int bps)
  {
    struct speed *speedp;

    if (bps != 0)
      {
	for (speedp = speeds; speedp->speed_int; speedp++)
	  {
	    if (bps == speedp->speed_int)
	      {
		return speedp->speed_val;
	      }
	  }
	syslog(LOG_WARNING, "speed %d not supported", bps);
      }
    return 0;
  }

/********************************************************************
 *
 * Translate from a speed_t to bits/second.
 */

static int baud_rate_of (int speed)
  {
    struct speed *speedp;
    
    if (speed != 0)
      {
	for (speedp = speeds; speedp->speed_int; speedp++)
	  {
	    if (speed == speedp->speed_val)
	      {
		return speedp->speed_int;
	      }
	  }
      }
    return 0;
  }

/********************************************************************
 *
 * set_up_tty: Set up the serial port on `fd' for 8 bits, no parity,
 * at the requested speed, etc.  If `local' is true, set CLOCAL
 * regardless of whether the modem option was specified.
 */

void set_up_tty (int tty_fd, int local)
  {
    int speed, x;
    struct termios tios;
    
    if (tcgetattr(tty_fd, &tios) < 0)
      {
	syslog(LOG_ERR, "tcgetattr: %m(%d)", errno);
	die(1);
      }
    
    if (!restore_term)
      {
	inittermios = tios;
      }
    
    tios.c_cflag     &= ~(CSIZE | CSTOPB | PARENB | CLOCAL);
    tios.c_cflag     |= CS8 | CREAD | HUPCL;

    tios.c_iflag      = IGNBRK | IGNPAR;
    tios.c_oflag      = 0;
    tios.c_lflag      = 0;
    tios.c_cc[VMIN]   = 1;
    tios.c_cc[VTIME]  = 0;
    
    if (local || !modem)
      {
	tios.c_cflag ^= (CLOCAL | HUPCL);
      }

    switch (crtscts)
      {
    case 1:
	tios.c_cflag |= CRTSCTS;
	break;

    case -2:
	tios.c_iflag     |= IXON | IXOFF;
	tios.c_cc[VSTOP]  = 0x13;	/* DC3 = XOFF = ^S */
	tios.c_cc[VSTART] = 0x11;	/* DC1 = XON  = ^Q */
	break;

    case -1:
	tios.c_cflag &= ~CRTSCTS;
	break;

    default:
	break;
      }
    
    speed = translate_speed(inspeed);
    if (speed)
      {
	cfsetospeed (&tios, speed);
	cfsetispeed (&tios, speed);
      }
/*
 * We can't proceed if the serial port speed is B0,
 * since that implies that the serial port is disabled.
 */
    else
      {
	speed = cfgetospeed(&tios);
	if (speed == B0)
	  {
	    syslog(LOG_ERR, "Baud rate for %s is 0; need explicit baud rate",
		   devnam);
	    die (1);
	  }
      }

    if (tcsetattr(tty_fd, TCSAFLUSH, &tios) < 0)
      {
	syslog(LOG_ERR, "tcsetattr: %m");
	die(1);
      }
    
    baud_rate    = baud_rate_of(speed);
    restore_term = TRUE;
  }

/********************************************************************
 *
 * setdtr - control the DTR line on the serial port.
 * This is called from die(), so it shouldn't call die().
 */

void setdtr (int tty_fd, int on)
  {
    int modembits = TIOCM_DTR;

    ioctl(tty_fd, (on ? TIOCMBIS : TIOCMBIC), &modembits);
  }

/********************************************************************
 *
 * restore_tty - restore the terminal to the saved settings.
 */

void restore_tty (int tty_fd)
  {
    if (restore_term)
      {
	restore_term = 0;
/*
 * Turn off echoing, because otherwise we can get into
 * a loop with the tty and the modem echoing to each other.
 * We presume we are the sole user of this tty device, so
 * when we close it, it will revert to its defaults anyway.
 */
	if (!default_device)
	  {
	    inittermios.c_lflag &= ~(ECHO | ECHONL);
	  }
	
	if (tcsetattr(tty_fd, TCSAFLUSH, &inittermios) < 0)
	  {
	    if (! ok_error (errno))
	      {
		syslog(LOG_WARNING, "tcsetattr: %m");
	      }
	  }
      }
  }

/********************************************************************
 *
 * output - Output PPP packet.
 */

void output (int unit, unsigned char *p, int len)
  {
    if (debug)
      {
        log_packet(p, len, "sent ", LOG_DEBUG);
      }
    
    if (write(ppp_fd, p, len) < 0)
      {
	if (errno == EWOULDBLOCK || errno == ENOBUFS
	    || errno == ENXIO || errno == EIO)
	  {
	    syslog(LOG_WARNING, "write: warning: %m(%d)", errno);
	  } 
	else
	  {
	    syslog(LOG_ERR, "write: %m(%d)", errno);
	    die(1);
	  }
      }
  }

/********************************************************************
 *
 * wait_input - wait until there is data available on ppp_fd,
 * for the length of time specified by *timo (indefinite
 * if timo is NULL).
 */

void wait_input (struct timeval *timo)
  {
    fd_set ready;
    int n;
    
    FD_ZERO(&ready);
    FD_SET(ppp_fd, &ready);

    n = select(ppp_fd + 1, &ready, NULL, &ready, timo);
    if (n < 0 && errno != EINTR)
      {
	syslog(LOG_ERR, "select: %m(%d)", errno);
	die(1);
      }
  }

/********************************************************************
 *
 * wait_loop_output - wait until there is data available on the
 * loopback, for the length of time specified by *timo (indefinite
 * if timo is NULL).
 */
void wait_loop_output(timo)
    struct timeval *timo;
  {
    fd_set ready;
    int n;

    FD_ZERO(&ready);
    FD_SET(master_fd, &ready);
    n = select(master_fd + 1, &ready, NULL, &ready, timo);
    if (n < 0 && errno != EINTR)
      {
	syslog(LOG_ERR, "select: %m(%d)", errno);
	die(1);
      }
  }

/********************************************************************
 *
 * wait_time - wait for a given length of time or until a
 * signal is received.
 */

void wait_time(timo)
    struct timeval *timo;
{
    int n;

    n = select(0, NULL, NULL, NULL, timo);
    if (n < 0 && errno != EINTR) {
        syslog(LOG_ERR, "select: %m(%d)", errno);
        die(1);
    }
}

/********************************************************************
 *
 * read_packet - get a PPP packet from the serial device.
 */

int read_packet (unsigned char *buf)
  {
    int len;
  
    len = read(ppp_fd, buf, PPP_MTU + PPP_HDRLEN);
    if (len < 0)
      {
	if (errno == EWOULDBLOCK)
	  {
	    return -1;
	  }
	syslog(LOG_ERR, "read: %m(%d)", errno);
	die(1);
      }
    return len;
  }

/********************************************************************
 *
 * get_loop_output - get outgoing packets from the ppp device,
 * and detect when we want to bring the real link up.
 * Return value is 1 if we need to bring up the link, 0 otherwise.
 */
int
get_loop_output(void)
  {
    int rv = 0;
    int n  = read(master_fd, inbuf, sizeof(inbuf));

    while (n > 0)
      {
	if (loop_chars(inbuf, n))
	  {
	    rv = 1;
	  }
	n = read(master_fd, inbuf, sizeof(inbuf));
      }

    if (n == 0)
      {
	syslog(LOG_ERR, "eof on loopback");
	die(1);
      }

    if (errno != EWOULDBLOCK)
      {
	syslog(LOG_ERR, "read from loopback: %m(%d)", errno);
	die(1);
      }
    
    return rv;
  }

/********************************************************************
 *
 * ppp_send_config - configure the transmit characteristics of
 * the ppp interface.
 */

void ppp_send_config (int unit,int mtu,u_int32_t asyncmap,int pcomp,int accomp)
  {
    u_int x;
    struct ifreq ifr;
  
    SYSDEBUG ((LOG_DEBUG, "send_config: mtu = %d\n", mtu));
/*
 * Ensure that the link is still up.
 */
    if (still_ppp())
      {
/*
 * Set the MTU and other parameters for the ppp device
 */
	memset (&ifr, '\0', sizeof (ifr));
	strncpy(ifr.ifr_name, ifname, sizeof (ifr.ifr_name));
	ifr.ifr_mtu = mtu;
	
	if (ioctl(sock_fd, SIOCSIFMTU, (caddr_t) &ifr) < 0)
	  {
	    syslog(LOG_ERR, "ioctl(SIOCSIFMTU): %m(%d)", errno);
	    quit();
	  }
	
	SYSDEBUG ((LOG_DEBUG, "send_config: asyncmap = %lx\n", asyncmap));
	if (ioctl(ppp_fd, PPPIOCSASYNCMAP, (caddr_t) &asyncmap) < 0)
	  {
	    syslog(LOG_ERR, "ioctl(PPPIOCSASYNCMAP): %m(%d)", errno);
	    quit();
	  }
    
	x = get_flags();
	x = pcomp  ? x | SC_COMP_PROT : x & ~SC_COMP_PROT;
	x = accomp ? x | SC_COMP_AC   : x & ~SC_COMP_AC;
	set_flags(x);
      }
  }

/********************************************************************
 *
 * ppp_set_xaccm - set the extended transmit ACCM for the interface.
 */

void ppp_set_xaccm (int unit, ext_accm accm)
  {
    SYSDEBUG ((LOG_DEBUG, "set_xaccm: %08lx %08lx %08lx %08lx\n",
		accm[0], accm[1], accm[2], accm[3]));

    if (ioctl(ppp_fd, PPPIOCSXASYNCMAP, accm) < 0 && errno != ENOTTY)
      {
	if ( ! ok_error (errno))
	  {
	    syslog(LOG_WARNING, "ioctl(set extended ACCM): %m(%d)", errno);
	  }
      }
  }

/********************************************************************
 *
 * ppp_recv_config - configure the receive-side characteristics of
 * the ppp interface.
 */

void ppp_recv_config (int unit,int mru,u_int32_t asyncmap,int pcomp,int accomp)
  {
    u_int x;

    SYSDEBUG ((LOG_DEBUG, "recv_config: mru = %d\n", mru));
/*
 * If we were called because the link has gone down then there is nothing
 * which may be done. Just return without incident.
 */
    if (!still_ppp())
      {
	return;
      }
/*
 * Set the receiver parameters
 */
    if (ioctl(ppp_fd, PPPIOCSMRU, (caddr_t) &mru) < 0)
      {
	if ( ! ok_error (errno))
	  {
	    syslog(LOG_ERR, "ioctl(PPPIOCSMRU): %m(%d)", errno);
	  }
      }

    SYSDEBUG ((LOG_DEBUG, "recv_config: asyncmap = %lx\n", asyncmap));
    if (ioctl(ppp_fd, PPPIOCSRASYNCMAP, (caddr_t) &asyncmap) < 0)
      {
        syslog(LOG_ERR, "ioctl(PPPIOCSRASYNCMAP): %m(%d)", errno);
	quit();
      }

    x = get_flags();
    x = !accomp? x | SC_REJ_COMP_AC: x &~ SC_REJ_COMP_AC;
    set_flags (x);
  }

/********************************************************************
 *
 * ccp_test - ask kernel whether a given compression method
 * is acceptable for use.
 */

int ccp_test (int unit, u_char *opt_ptr, int opt_len, int for_transmit)
  {
    struct ppp_option_data data;

    memset (&data, '\0', sizeof (data));
    data.ptr      = opt_ptr;
    data.length   = opt_len;
    data.transmit = for_transmit;

    if (ioctl(ppp_fd, PPPIOCSCOMPRESS, (caddr_t) &data) >= 0)
      {
	return 1;
      }

    return (errno == ENOBUFS)? 0: -1;
  }

/********************************************************************
 *
 * ccp_flags_set - inform kernel about the current state of CCP.
 */

void ccp_flags_set (int unit, int isopen, int isup)
  {
    if (still_ppp())
      {
	int x = get_flags();
	x = isopen? x | SC_CCP_OPEN : x &~ SC_CCP_OPEN;
	x = isup?   x | SC_CCP_UP   : x &~ SC_CCP_UP;
	set_flags (x);
      }
  }

/********************************************************************
 *
 * get_idle_time - return how long the link has been idle.
 */
int
get_idle_time(u, ip)
    int u;
    struct ppp_idle *ip;
{
    return ioctl(ppp_fd, PPPIOCGIDLE, ip) >= 0;
} 

/********************************************************************
 *
 * ccp_fatal_error - returns 1 if decompression was disabled as a
 * result of an error detected after decompression of a packet,
 * 0 otherwise.  This is necessary because of patent nonsense.
 */

int ccp_fatal_error (int unit)
  {
    int x = get_flags();

    return x & SC_DC_FERROR;
  }

/*
 * path_to_route - determine the path to the proc file system data
 */

FILE *route_fd = (FILE *) 0;
static char route_buffer [512];

static char *path_to_route (void);
static int open_route_table (void);
static void close_route_table (void);
static int read_route_table (struct rtentry *rt);

/********************************************************************
 *
 * path_to_procfs - find the path to the proc file system mount point
 */

static int path_to_procfs (void)
  {
    struct mntent *mntent;
    FILE *fp;

    fp = fopen (MOUNTED, "r");
    if (fp != 0)
      {
	mntent = getmntent (fp);
        while (mntent != (struct mntent *) 0)
	  {
	    if (strcmp (mntent->mnt_type, MNTTYPE_IGNORE) != 0)
	      {
		if (strcmp (mntent->mnt_type, "proc") == 0)
		  {
		    strncpy (route_buffer, mntent->mnt_dir,
			     sizeof (route_buffer)-10);
		    route_buffer [sizeof (route_buffer)-10] = '\0';
		    fclose (fp);
		    return 1;
		  }
	      }
	    mntent = getmntent (fp);
	  }
	fclose (fp);
      }
    return 0;
  }

/********************************************************************
 *
 * path_to_route - find the path to the route tables in the proc file system
 */

static char *path_to_route (void)
  {
    if (! path_to_procfs())
      {
	syslog (LOG_ERR, "proc file system not mounted");
	return 0;
      }
    strcat (route_buffer, "/net/route");
    return (route_buffer);
  }

/********************************************************************
 *
 * close_route_table - close the interface to the route table
 */

static void close_route_table (void)
  {
    if (route_fd != (FILE *) 0)
      {
        fclose (route_fd);
        route_fd = (FILE *) 0;
      }
  }

/********************************************************************
 *
 * open_route_table - open the interface to the route table
 */

static int open_route_table (void)
  {
    char *path;

    close_route_table();

    path = path_to_route();
    if (path == NULL)
      {
        return 0;
      }

    route_fd = fopen (path, "r");
    if (route_fd == (FILE *) 0)
      {
        syslog (LOG_ERR, "can not open %s: %m(%d)", path, errno);
        return 0;
      }
    return 1;
  }

/********************************************************************
 *
 * read_route_table - read the next entry from the route table
 */

static int read_route_table (struct rtentry *rt)
  {
    static char delims[] = " \t\n";
    char *dev_ptr, *ptr, *dst_ptr, *gw_ptr, *flag_ptr;
	
    memset (rt, '\0', sizeof (struct rtentry));

    for (;;)
      {
	if (fgets (route_buffer, sizeof (route_buffer), route_fd) ==
	    (char *) 0)
	  {
	    return 0;
	  }

	dev_ptr  = strtok (route_buffer, delims); /* interface name */
	dst_ptr  = strtok (NULL,         delims); /* destination address */
	gw_ptr   = strtok (NULL,         delims); /* gateway */
	flag_ptr = strtok (NULL,         delims); /* flags */
    
	if (flag_ptr == (char *) 0) /* assume that we failed, somewhere. */
	  {
	    return 0;
	  }
	
	/* Discard that stupid header line which should never
	 * have been there in the first place !! */
	if (isxdigit (*dst_ptr) && isxdigit (*gw_ptr) && isxdigit (*flag_ptr))
	  {
	    break;
	  }
      }

    ((struct sockaddr_in *) &rt->rt_dst)->sin_addr.s_addr =
      strtoul (dst_ptr, NULL, 16);

    ((struct sockaddr_in *) &rt->rt_gateway)->sin_addr.s_addr =
      strtoul (gw_ptr, NULL, 16);

    rt->rt_flags = (short) strtoul (flag_ptr, NULL, 16);
    rt->rt_dev   = dev_ptr;

    return 1;
  }

/********************************************************************
 *
 * defaultroute_exists - determine if there is a default route
 */

static int defaultroute_exists (struct rtentry *rt)
  {
    int    result = 0;

    if (!open_route_table())
      {
        return 0;
      }

    while (read_route_table(rt) != 0)
      {
        if ((rt->rt_flags & RTF_UP) == 0)
	  {
	    continue;
	  }

        if (((struct sockaddr_in *) (&rt->rt_dst))->sin_addr.s_addr == 0L)
	  {
	    result = 1;
	    break;
	  }
      }

    close_route_table();
    return result;
  }

/********************************************************************
 *
 * sifdefaultroute - assign a default route through the address given.
 */

int sifdefaultroute (int unit, u_int32_t ouraddr, u_int32_t gateway)
  {
    struct rtentry rt;

    if (defaultroute_exists(&rt))
      {
	struct in_addr old_gateway =
	  ((struct sockaddr_in *) (&rt.rt_gateway))-> sin_addr;

	if (old_gateway.s_addr != gateway)
	  {
	    syslog (LOG_ERR,
		    "not replacing existing default route to %s [%s]",
		    rt.rt_dev,
		    inet_ntoa (old_gateway));
	  }
	return 0;
      }

    memset (&rt, '\0', sizeof (rt));
    SET_SA_FAMILY (rt.rt_dst,     AF_INET);
    SET_SA_FAMILY (rt.rt_gateway, AF_INET);

    if (strcmp(utsname.release, "2.1.0") > 0) {
      SET_SA_FAMILY (rt.rt_genmask, AF_INET);
      ((struct sockaddr_in *) &rt.rt_genmask)->sin_addr.s_addr = 0L;
    }

    ((struct sockaddr_in *) &rt.rt_gateway)->sin_addr.s_addr = gateway;
    
    rt.rt_flags = RTF_UP | RTF_GATEWAY | RTF_DEFAULT;
    if (ioctl(sock_fd, SIOCADDRT, &rt) < 0)
      {
	if ( ! ok_error ( errno ))
	  {
	    syslog (LOG_ERR, "default route ioctl(SIOCADDRT): %m(%d)", errno);
	  }
	return 0;
      }

    default_route_gateway = gateway;
    return 1;
  }

/********************************************************************
 *
 * cifdefaultroute - delete a default route through the address given.
 */

int cifdefaultroute (int unit, u_int32_t ouraddr, u_int32_t gateway)
  {
    struct rtentry rt;

    default_route_gateway = 0;

    memset (&rt, '\0', sizeof (rt));
    SET_SA_FAMILY (rt.rt_dst,     AF_INET);
    SET_SA_FAMILY (rt.rt_gateway, AF_INET);

    if (strcmp(utsname.release, "2.1.0") > 0) {
      SET_SA_FAMILY (rt.rt_genmask, AF_INET);
      ((struct sockaddr_in *) &rt.rt_genmask)->sin_addr.s_addr = 0L;
    }

    ((struct sockaddr_in *) &rt.rt_gateway)->sin_addr.s_addr = gateway;
    
    rt.rt_flags = RTF_UP | RTF_GATEWAY | RTF_DEFAULT;
    if (ioctl(sock_fd, SIOCDELRT, &rt) < 0 && errno != ESRCH)
      {
	if (still_ppp())
	  {
	    if ( ! ok_error ( errno ))
	      {
		syslog (LOG_ERR,
			"default route ioctl(SIOCDELRT): %m(%d)", errno);
	      }
	    return 0;
	  }
      }

    return 1;
  }

/********************************************************************
 *
 * sifproxyarp - Make a proxy ARP entry for the peer.
 */

int sifproxyarp (int unit, u_int32_t his_adr)
  {
    struct arpreq arpreq;

    if (has_proxy_arp == 0)
      {
	memset (&arpreq, '\0', sizeof(arpreq));
    
	SET_SA_FAMILY(arpreq.arp_pa, AF_INET);
	((struct sockaddr_in *) &arpreq.arp_pa)->sin_addr.s_addr = his_adr;
	arpreq.arp_flags = ATF_PERM | ATF_PUBL;
/*
 * Get the hardware address of an interface on the same subnet
 * as our local address.
 */
	if (!get_ether_addr(his_adr, &arpreq.arp_ha, arpreq.arp_dev))
	  {
	    syslog(LOG_ERR, "Cannot determine ethernet address for proxy ARP");
	    return 0;
	  }
	
	if (ioctl(sock_fd, SIOCSARP, (caddr_t)&arpreq) < 0)
	  {
	    if ( ! ok_error ( errno ))
	      {
		syslog(LOG_ERR, "ioctl(SIOCSARP): %m(%d)", errno);
	      }
	    return 0;
	  }
      }

    proxy_arp_addr = his_adr;
    has_proxy_arp = 1;
    return 1;
  }

/********************************************************************
 *
 * cifproxyarp - Delete the proxy ARP entry for the peer.
 */

int cifproxyarp (int unit, u_int32_t his_adr)
  {
    struct arpreq arpreq;

    if (has_proxy_arp == 1)
      {
	memset (&arpreq, '\0', sizeof(arpreq));
	SET_SA_FAMILY(arpreq.arp_pa, AF_INET);
	((struct sockaddr_in *) &arpreq.arp_pa)->sin_addr.s_addr = his_adr;
	arpreq.arp_flags = ATF_PERM | ATF_PUBL;

	if (ioctl(sock_fd, SIOCDARP, (caddr_t)&arpreq) < 0)
	  {
	    if ( ! ok_error ( errno ))
	      {
		syslog(LOG_WARNING, "ioctl(SIOCDARP): %m(%d)", errno);
	      }
	    return 0;
	  }
      }
    has_proxy_arp = 0;
    return 1;
  }
     
/********************************************************************
 *
 * get_ether_addr - get the hardware address of an interface on the
 * the same subnet as ipaddr.
 */

static int get_ether_addr (u_int32_t ipaddr,
			   struct sockaddr *hwaddr,
			   char *name)
  {
    struct ifreq *ifr, *ifend, *ifp;
    int i;
    u_int32_t ina, mask;
    struct ifreq ifreq;
    struct ifconf ifc;
    struct ifreq ifs[MAX_IFS];
    
    ifc.ifc_len = sizeof(ifs);
    ifc.ifc_req = ifs;
    if (ioctl(sock_fd, SIOCGIFCONF, &ifc) < 0)
      {
	if ( ! ok_error ( errno ))
	  {
	    syslog(LOG_ERR, "ioctl(SIOCGIFCONF): %m(%d)", errno);
	  }
	return 0;
      }

    SYSDEBUG ((LOG_DEBUG, "proxy arp: scanning %d interfaces for IP %s",
		ifc.ifc_len / sizeof(struct ifreq), ip_ntoa(ipaddr)));
/*
 * Scan through looking for an interface with an Internet
 * address on the same subnet as `ipaddr'.
 */
    ifend = ifs + (ifc.ifc_len / sizeof(struct ifreq));
    for (ifr = ifc.ifc_req; ifr < ifend; ifr++)
      {
	if (ifr->ifr_addr.sa_family == AF_INET)
	  {
	    ina = ((struct sockaddr_in *) &ifr->ifr_addr)->sin_addr.s_addr;
	    strncpy(ifreq.ifr_name, ifr->ifr_name, sizeof(ifreq.ifr_name));
            SYSDEBUG ((LOG_DEBUG, "proxy arp: examining interface %s",
			ifreq.ifr_name));
/*
 * Check that the interface is up, and not point-to-point
 * nor loopback.
 */
	    if (ioctl(sock_fd, SIOCGIFFLAGS, &ifreq) < 0)
	      {
		continue;
	      }

	    if (((ifreq.ifr_flags ^ FLAGS_GOOD) & FLAGS_MASK) != 0)
	      {
		continue;
	      }
/*
 * Get its netmask and check that it's on the right subnet.
 */
	    if (ioctl(sock_fd, SIOCGIFNETMASK, &ifreq) < 0)
	      {
	        continue;
	      }

	    mask = ((struct sockaddr_in *) &ifreq.ifr_addr)->sin_addr.s_addr;
	    SYSDEBUG ((LOG_DEBUG, "proxy arp: interface addr %s mask %lx",
			ip_ntoa(ina), ntohl(mask)));

	    if (((ipaddr ^ ina) & mask) != 0)
	      {
	        continue;
	      }
	    break;
	  }
      }
    
    if (ifr >= ifend)
      {
        return 0;
      }

    memcpy (name, ifreq.ifr_name, sizeof(ifreq.ifr_name));
    syslog(LOG_INFO, "found interface %s for proxy arp", name);
/*
 * Now get the hardware address.
 */
    memset (&ifreq.ifr_hwaddr, 0, sizeof (struct sockaddr));
    if (ioctl (sock_fd, SIOCGIFHWADDR, &ifreq) < 0)
      {
        syslog(LOG_ERR, "SIOCGIFHWADDR(%s): %m(%d)", ifreq.ifr_name, errno);
        return 0;
      }

    memcpy (hwaddr,
	    &ifreq.ifr_hwaddr,
	    sizeof (struct sockaddr));

    SYSDEBUG ((LOG_DEBUG,
	   "proxy arp: found hwaddr %02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x",
		(int) ((unsigned char *) &hwaddr->sa_data)[0],
		(int) ((unsigned char *) &hwaddr->sa_data)[1],
		(int) ((unsigned char *) &hwaddr->sa_data)[2],
		(int) ((unsigned char *) &hwaddr->sa_data)[3],
		(int) ((unsigned char *) &hwaddr->sa_data)[4],
		(int) ((unsigned char *) &hwaddr->sa_data)[5],
		(int) ((unsigned char *) &hwaddr->sa_data)[6],
		(int) ((unsigned char *) &hwaddr->sa_data)[7]));
    return 1;
  }

/********************************************************************
 *
 * Return user specified netmask, modified by any mask we might determine
 * for address `addr' (in network byte order).
 * Here we scan through the system's list of interfaces, looking for
 * any non-point-to-point interfaces which might appear to be on the same
 * network as `addr'.  If we find any, we OR in their netmask to the
 * user-specified netmask.
 */

u_int32_t GetMask (u_int32_t addr)
  {
    u_int32_t mask, nmask, ina;
    struct ifreq *ifr, *ifend, ifreq;
    struct ifconf ifc;
    struct ifreq ifs[MAX_IFS];

    addr = ntohl(addr);
    
    if (IN_CLASSA(addr))	/* determine network mask for address class */
      {
	nmask = IN_CLASSA_NET;
      }
    else
      {
	if (IN_CLASSB(addr))
	  {
	    nmask = IN_CLASSB_NET;
	  }
	else
	  {
	    nmask = IN_CLASSC_NET;
	  }
      }
    
    /* class D nets are disallowed by bad_ip_adrs */
    mask = netmask | htonl(nmask);
/*
 * Scan through the system's network interfaces.
 */
    ifc.ifc_len = sizeof(ifs);
    ifc.ifc_req = ifs;
    if (ioctl(sock_fd, SIOCGIFCONF, &ifc) < 0)
      {
	if ( ! ok_error ( errno ))
	  {
	    syslog(LOG_WARNING, "ioctl(SIOCGIFCONF): %m(%d)", errno);
	  }
	return mask;
      }
    
    ifend = (struct ifreq *) (ifc.ifc_buf + ifc.ifc_len);
    for (ifr = ifc.ifc_req; ifr < ifend; ifr++)
      {
/*
 * Check the interface's internet address.
 */
	if (ifr->ifr_addr.sa_family != AF_INET)
	  {
	    continue;
	  }
	ina = ((struct sockaddr_in *) &ifr->ifr_addr)->sin_addr.s_addr;
	if (((ntohl(ina) ^ addr) & nmask) != 0)
	  {
	    continue;
	  }
/*
 * Check that the interface is up, and not point-to-point nor loopback.
 */
	strncpy(ifreq.ifr_name, ifr->ifr_name, sizeof(ifreq.ifr_name));
	if (ioctl(sock_fd, SIOCGIFFLAGS, &ifreq) < 0)
	  {
	    continue;
	  }
	
	if (((ifreq.ifr_flags ^ FLAGS_GOOD) & FLAGS_MASK) != 0)
	  {
	    continue;
	  }
/*
 * Get its netmask and OR it into our mask.
 */
	if (ioctl(sock_fd, SIOCGIFNETMASK, &ifreq) < 0)
	  {
	    continue;
	  }
	mask |= ((struct sockaddr_in *)&ifreq.ifr_addr)->sin_addr.s_addr;
	break;
      }
    return mask;
  }

/********************************************************************
 *
 * Internal routine to decode the version.modification.patch level
 */

static void decode_version (char *buf, int *version,
			    int *modification, int *patch)
  {
    *version      = (int) strtoul (buf, &buf, 10);
    *modification = 0;
    *patch        = 0;
    
    if (*buf == '.')
      {
	++buf;
	*modification = (int) strtoul (buf, &buf, 10);
	if (*buf == '.')
	  {
	    ++buf;
	    *patch = (int) strtoul (buf, &buf, 10);
	  }
      }
    
    if (*buf != '\0')
      {
	*version      =
	*modification =
	*patch        = 0;
      }
  }

/********************************************************************
 *
 * Procedure to determine if the PPP line dicipline is registered.
 */

int
ppp_registered(void)
  {
    int local_fd;
    int init_disc = -1;
    int initfdflags;

    local_fd = open(devnam, O_NONBLOCK | O_RDWR, 0);
    if (local_fd < 0)
      {
	syslog(LOG_ERR, "Failed to open %s: %m(%d)", devnam, errno);
	return 0;
      }

    initfdflags = fcntl(local_fd, F_GETFL);
    if (initfdflags == -1)
      {
	syslog(LOG_ERR, "Couldn't get device fd flags: %m(%d)", errno);
	close (local_fd);
	return 0;
      }

    initfdflags &= ~O_NONBLOCK;
    fcntl(local_fd, F_SETFL, initfdflags);
/*
 * Read the initial line dicipline and try to put the device into the
 * PPP dicipline.
 */
    if (ioctl(local_fd, TIOCGETD, &init_disc) < 0)
      {
	syslog(LOG_ERR, "ioctl(TIOCGETD): %m(%d)", errno);
	close (local_fd);
	return 0;
      }
    
    if (ioctl(local_fd, TIOCSETD, &ppp_disc) < 0)
      {
	syslog(LOG_ERR, "ioctl(TIOCSETD): %m(%d)", errno);
	close (local_fd);
	return 0;
      }
    
    if (ioctl(local_fd, TIOCSETD, &init_disc) < 0)
      {
	syslog(LOG_ERR, "ioctl(TIOCSETD): %m(%d)", errno);
	close (local_fd);
	return 0;
      }
    
    close (local_fd);
    return 1;
  }

/********************************************************************
 *
 * ppp_available - check whether the system has any ppp interfaces
 * (in fact we check whether we can do an ioctl on ppp0).
 */

int ppp_available(void)
  {
    int s, ok;
    struct ifreq ifr;
    int    size;
    int    my_version, my_modification, my_patch;
    extern char *no_ppp_msg;
/*
 * Open a socket for doing the ioctl operations.
 */    
    s = socket(AF_INET, SOCK_DGRAM, 0);
    if (s < 0)
      {
	return 0;
      }
    
    strncpy (ifr.ifr_name, "ppp0", sizeof (ifr.ifr_name));
    ok = ioctl(s, SIOCGIFFLAGS, (caddr_t) &ifr) >= 0;
/*
 * If the device did not exist then attempt to create one by putting the
 * current tty into the PPP discipline. If this works then obtain the
 * flags for the device again.
 */
    if (!ok)
      {
	if (ppp_registered())
	  {
	    strncpy (ifr.ifr_name, "ppp0", sizeof (ifr.ifr_name));
	    ok = ioctl(s, SIOCGIFFLAGS, (caddr_t) &ifr) >= 0;
	  }
      }
/*
 * Ensure that the hardware address is for PPP and not something else
 */
    if (ok)
      {
        ok = ioctl (s, SIOCGIFHWADDR, (caddr_t) &ifr) >= 0;
      }

    if (ok && ((ifr.ifr_hwaddr.sa_family & ~0xFF) != ARPHRD_PPP))
      {
        ok = 0;
      }

    if (!ok)
      {
	no_ppp_msg = 
	  "This system lacks kernel support for PPP.  This could be because\n"
	  "the PPP kernel module is not loaded, or because the kernel is\n"
	  "not configured for PPP.  See the README.linux file in the\n"
	  "ppp-2.3.2 distribution.\n";
      }
/*
 *  This is the PPP device. Validate the version of the driver at this
 *  point to ensure that this program will work with the driver.
 */
    else
      {
	char   abBuffer [1024];

	ifr.ifr_data = abBuffer;
	size = ioctl (s, SIOCGPPPVER, (caddr_t) &ifr);
	ok   = size >= 0;

	if (ok)
	  {
	    decode_version (abBuffer,
			    &driver_version,
			    &driver_modification,
			    &driver_patch);
	  }
    
	if (!ok)
	  {
	    driver_version      =
	    driver_modification =
	    driver_patch        = 0;
	  }
/*
 * Validate the version of the driver against the version that we used.
 */
	decode_version (PPP_VERSION,
			&my_version,
			&my_modification,
			&my_patch);

	/* The version numbers must match */
	if (driver_version != my_version)
	  {
	    ok = 0;
	  }
      
	/* The modification levels must be legal */
	if (driver_modification < my_modification)
	  {
	    if (driver_modification >= 2) {
	      /* we can cope with 2.2.0 and above */
	      driver_is_old = 1;
	    } else {
	      ok = 0;
	    }
	  }

	close (s);
	if (!ok)
	  {
	    sprintf (route_buffer,
		     "Sorry - PPP driver version %d.%d.%d is out of date\n",
		     driver_version, driver_modification, driver_patch);

	    no_ppp_msg = route_buffer;
	  }
      }
    return ok;
  }

/********************************************************************
 *
 * Update the wtmp file with the appropriate user name and tty device.
 */

void logwtmp (const char *line, const char *name, const char *host)
  {
    int    wtmp;
    struct utmp ut, *utp;
    pid_t  mypid = getpid();
/*
 * Update the signon database for users.
 * Christoph Lameter: Copied from poeigl-1.36 Jan 3, 1996
 */
    utmpname(_PATH_UTMP);
    setutent();
    while ((utp = getutent()) && (utp->ut_pid != mypid))
        /* nothing */;

    /* Is this call really necessary? There is another one after the 'put' */
    endutent();
    
    if (utp)
      {
	memcpy(&ut, utp, sizeof(ut));
      }
    else
      {
	/* some gettys/telnetds don't initialize utmp... */
	memset(&ut, 0, sizeof(ut));
      }

    if (ut.ut_id[0] == 0)
      {
	strncpy(ut.ut_id, line + 3, sizeof(ut.ut_id));
      }
	
    strncpy(ut.ut_user, name, sizeof(ut.ut_user));
    strncpy(ut.ut_line, line, sizeof(ut.ut_line));

    time(&ut.ut_time);

    ut.ut_type = USER_PROCESS;
    ut.ut_pid  = mypid;

    /* Insert the host name if one is supplied */
    if (*host)
      {
	strncpy (ut.ut_host, host, sizeof(ut.ut_host));
      }

    /* Insert the IP address of the remote system if IP is enabled */
    if (ipcp_protent.enabled_flag && ipcp_hisoptions[0].neg_addr)
      {
	memcpy  (&ut.ut_addr, (char *) &ipcp_hisoptions[0].hisaddr,
		 sizeof(ut.ut_addr));
      }
	
    /* CL: Makes sure that the logout works */
    if (*host == 0 && *name==0)
      {
	ut.ut_host[0]=0;
      }

    pututline(&ut);
    endutent();
/*
 * Update the wtmp file.
 */
    wtmp = open(_PATH_WTMP, O_APPEND|O_WRONLY);
    if (wtmp >= 0)
      {
	flock(wtmp, LOCK_EX);

    	/* we really should check for error on the write for a full disk! */
	write (wtmp, (char *)&ut, sizeof(ut));
	close (wtmp);

	flock(wtmp, LOCK_UN);
      }
  }

/********************************************************************
 * Code for locking/unlocking the serial device.
 * This code is derived from chat.c.
 */

/*
 * lock - create a lock file for the named device
 */

int lock (char *dev)
  {
#ifdef LOCKLIB
    int result;
    lock_file = malloc(strlen(dev) + 1);
    if (lock_file == NULL)
      {
	novm("lock file name");
      }
    strcpy (lock_file, dev);
    result = mklock (dev, (void *) 0);

    if (result > 0)
      {
        syslog (LOG_NOTICE, "Device %s is locked by pid %d", dev, result);
	free (lock_file);
	lock_file = NULL;
	result = -1;
      }
    else
      {
        if (result < 0)
	  {
	    syslog (LOG_ERR, "Can't create lock file %s", lock_file);
	    free (lock_file);
	    lock_file = NULL;
	    result = -1;
	  }
      }
    return (result);
#else
    char hdb_lock_buffer[12];
    int fd, n;
    int pid = getpid();
    char *p;

    p = strrchr(dev, '/');
    if (p != NULL)
      {
	dev = ++p;
      }

    lock_file = malloc(strlen(LOCK_PREFIX) + strlen(dev) + 1);
    if (lock_file == NULL)
      {
	novm("lock file name");
      }

    strcpy (lock_file, LOCK_PREFIX);
    strcat (lock_file, dev);
/*
 * Attempt to create the lock file at this point.
 */
    while (1)
      {
	fd = open(lock_file, O_EXCL | O_CREAT | O_RDWR, 0644);
	if (fd >= 0)
	  {
	    pid = getpid();
#ifndef PID_BINARY
	    sprintf (hdb_lock_buffer, "%010d\n", pid);
	    write (fd, hdb_lock_buffer, 11);
#else
	    write(fd, &pid, sizeof (pid));
#endif
	    close(fd);
	    return 0;
	  }
/*
 * If the file exists then check to see if the pid is stale
 */
	if (errno == EEXIST)
	  {
	    fd = open(lock_file, O_RDONLY, 0);
	    if (fd < 0)
	      {
		if (errno == ENOENT) /* This is just a timing problem. */
		  {
		    continue;
		  }
		break;
	      }

	    /* Read the lock file to find out who has the device locked */
	    n = read (fd, hdb_lock_buffer, 11);
	    close (fd);
	    if (n < 0)
	      {
		syslog(LOG_ERR, "Can't read pid from lock file %s", lock_file);
		break;
	      }

	    /* See the process still exists. */
	    if (n > 0)
	      {
#ifndef PID_BINARY
		hdb_lock_buffer[n] = '\0';
		sscanf (hdb_lock_buffer, " %d", &pid);
#else
		pid = ((int *) hdb_lock_buffer)[0];
#endif
		if (pid == 0 || pid == getpid()
		    || (kill(pid, 0) == -1 && errno == ESRCH))
		  {
		    n = 0;
		  }
	      }

	    /* If the process does not exist then try to remove the lock */
	    if (n == 0 && unlink (lock_file) == 0)
	      {
		syslog (LOG_NOTICE, "Removed stale lock on %s (pid %d)",
			dev, pid);
		continue;
	      }

	    syslog (LOG_NOTICE, "Device %s is locked by pid %d", dev, pid);
	    break;
	  }

	syslog(LOG_ERR, "Can't create lock file %s: %m(%d)", lock_file, errno);
	break;
      }

    free(lock_file);
    lock_file = NULL;
    return -1;
#endif
}


/********************************************************************
 *
 * unlock - remove our lockfile
 */

void unlock(void)
  {
    if (lock_file)
      {
#ifdef LOCKLIB
	(void) rmlock (lock_file, (void *) 0);
#else
	unlink(lock_file);
#endif
	free(lock_file);
	lock_file = NULL;
      }
  }

/********************************************************************
 *
 * sifvjcomp - config tcp header compression
 */

int sifvjcomp (int u, int vjcomp, int cidcomp, int maxcid)
  {
    u_int x = get_flags();

    if (vjcomp)
      {
        if (ioctl (ppp_fd, PPPIOCSMAXCID, (caddr_t) &maxcid) < 0)
	  {
	    if (! ok_error (errno))
	      {
		syslog (LOG_ERR, "ioctl(PPPIOCSFLAGS): %m(%d)", errno);
	      }
	    vjcomp = 0;
	  }
      }

    x = vjcomp  ? x | SC_COMP_TCP     : x &~ SC_COMP_TCP;
    x = cidcomp ? x & ~SC_NO_TCP_CCID : x | SC_NO_TCP_CCID;
    set_flags (x);

    return 1;
  }

/********************************************************************
 *
 * sifup - Config the interface up and enable IP packets to pass.
 */

int sifup (int u)
  {
    struct ifreq ifr;

    memset (&ifr, '\0', sizeof (ifr));
    strncpy(ifr.ifr_name, ifname, sizeof (ifr.ifr_name));
    if (ioctl(sock_fd, SIOCGIFFLAGS, (caddr_t) &ifr) < 0)
      {
	if (! ok_error (errno))
	  {
	    syslog(LOG_ERR, "ioctl (SIOCGIFFLAGS): %m(%d)", errno);
	  }
	return 0;
      }

    ifr.ifr_flags |= (IFF_UP | IFF_POINTOPOINT);
    if (ioctl(sock_fd, SIOCSIFFLAGS, (caddr_t) &ifr) < 0)
      {
	if (! ok_error (errno))
	  {
	    syslog(LOG_ERR, "ioctl(SIOCSIFFLAGS): %m(%d)", errno);
	  }
	return 0;
      }
    if_is_up = 1;
    return 1;
  }

/********************************************************************
 *
 * sifdown - Config the interface down and disable IP.
 */

int sifdown (int u)
  {
    struct ifreq ifr;

    if_is_up = 0;

    memset (&ifr, '\0', sizeof (ifr));
    strncpy(ifr.ifr_name, ifname, sizeof (ifr.ifr_name));
    if (ioctl(sock_fd, SIOCGIFFLAGS, (caddr_t) &ifr) < 0)
      {
	if (! ok_error (errno))
	  {
	    syslog(LOG_ERR, "ioctl (SIOCGIFFLAGS): %m(%d)", errno);
	  }
	return 0;
      }

    ifr.ifr_flags &= ~IFF_UP;
    ifr.ifr_flags |= IFF_POINTOPOINT;
    if (ioctl(sock_fd, SIOCSIFFLAGS, (caddr_t) &ifr) < 0)
      {
	if (! ok_error (errno))
	  {
	    syslog(LOG_ERR, "ioctl(SIOCSIFFLAGS): %m(%d)", errno);
	  }
	return 0;
      }
    return 1;
  }

/********************************************************************
 *
 * sifaddr - Config the interface IP addresses and netmask.
 */

int sifaddr (int unit, u_int32_t our_adr, u_int32_t his_adr,
	     u_int32_t net_mask)
  {
    struct ifreq   ifr; 
    struct rtentry rt;
    
    memset (&ifr, '\0', sizeof (ifr));
    memset (&rt,  '\0', sizeof (rt));
    
    SET_SA_FAMILY (ifr.ifr_addr,    AF_INET); 
    SET_SA_FAMILY (ifr.ifr_dstaddr, AF_INET); 
    SET_SA_FAMILY (ifr.ifr_netmask, AF_INET); 

    strncpy (ifr.ifr_name, ifname, sizeof (ifr.ifr_name));
/*
 *  Set our IP address
 */
    ((struct sockaddr_in *) &ifr.ifr_addr)->sin_addr.s_addr = our_adr;
    if (ioctl(sock_fd, SIOCSIFADDR, (caddr_t) &ifr) < 0)
      {
	if (errno != EEXIST)
	  {
	    if (! ok_error (errno))
	      {
		syslog (LOG_ERR, "ioctl(SIOCAIFADDR): %m(%d)", errno);
	      }
	  }
        else
	  {
	    syslog (LOG_WARNING, "ioctl(SIOCAIFADDR): Address already exists");
	  }
        return (0);
      } 
/*
 *  Set the gateway address
 */
    ((struct sockaddr_in *) &ifr.ifr_dstaddr)->sin_addr.s_addr = his_adr;
    if (ioctl(sock_fd, SIOCSIFDSTADDR, (caddr_t) &ifr) < 0)
      {
	if (! ok_error (errno))
	  {
	    syslog (LOG_ERR, "ioctl(SIOCSIFDSTADDR): %m(%d)", errno); 
	  }
	return (0);
      } 
/*
 *  Set the netmask.
 *  For recent kernels, force the netmask to 255.255.255.255.
 */
    if (strcmp(utsname.release, "2.1.16") >= 0)
      net_mask = ~0L;
    if (net_mask != 0)
      {
	((struct sockaddr_in *) &ifr.ifr_netmask)->sin_addr.s_addr = net_mask;
	if (ioctl(sock_fd, SIOCSIFNETMASK, (caddr_t) &ifr) < 0)
	  {
	    if (! ok_error (errno))
	      {
		syslog (LOG_ERR, "ioctl(SIOCSIFNETMASK): %m(%d)", errno); 
	      }
	    return (0);
	  } 
      }
/*
 *  Add the device route
 */
    if (strcmp(utsname.release, "2.1.16") < 0) {
      SET_SA_FAMILY (rt.rt_dst,     AF_INET);
      SET_SA_FAMILY (rt.rt_gateway, AF_INET);
      rt.rt_dev = ifname;

      ((struct sockaddr_in *) &rt.rt_gateway)->sin_addr.s_addr = 0L;
      ((struct sockaddr_in *) &rt.rt_dst)->sin_addr.s_addr     = his_adr;
      rt.rt_flags = RTF_UP | RTF_HOST;

      if (strcmp(utsname.release, "2.1.0") > 0) {
	SET_SA_FAMILY (rt.rt_genmask, AF_INET);
	((struct sockaddr_in *) &rt.rt_genmask)->sin_addr.s_addr = -1L;
      }

      if (ioctl(sock_fd, SIOCADDRT, &rt) < 0)
	{
	  if (! ok_error (errno))
	    {
	      syslog (LOG_ERR, "ioctl(SIOCADDRT) device route: %m(%d)", errno);
	    }
	  return (0);
	}
    }
    return 1;
  }

/********************************************************************
 *
 * cifaddr - Clear the interface IP addresses, and delete routes
 * through the interface if possible.
 */

int cifaddr (int unit, u_int32_t our_adr, u_int32_t his_adr)
  {
    struct rtentry rt;

    if (strcmp(utsname.release, "2.1.16") < 0) {
/*
 *  Delete the route through the device
 */
      memset (&rt, '\0', sizeof (rt));

      SET_SA_FAMILY (rt.rt_dst,     AF_INET);
      SET_SA_FAMILY (rt.rt_gateway, AF_INET);
      rt.rt_dev = ifname;

      ((struct sockaddr_in *) &rt.rt_gateway)->sin_addr.s_addr = 0;
      ((struct sockaddr_in *) &rt.rt_dst)->sin_addr.s_addr     = his_adr;
      rt.rt_flags = RTF_UP | RTF_HOST;

      if (strcmp(utsname.release, "2.1.0") > 0) {
	SET_SA_FAMILY (rt.rt_genmask, AF_INET);
	((struct sockaddr_in *) &rt.rt_genmask)->sin_addr.s_addr = -1L;
      }

      if (ioctl(sock_fd, SIOCDELRT, &rt) < 0 && errno != ESRCH)
	{
	  if (still_ppp() && ! ok_error (errno))
	    {
	      syslog (LOG_ERR, "ioctl(SIOCDELRT) device route: %m(%d)", errno);
	    }
	  return (0);
	}
    }
    return 1;
  }

/********************************************************************
 *
 * open_loopback - open the device we use for getting packets
 * in demand mode.  Under Linux, we use our existing fd
 * to the ppp driver.
 */
void
open_ppp_loopback(void)
  {
    int flags, i;
    struct termios tios;

    master_fd = -1;
    for (i = 0; i < 64; ++i) {
      sprintf(loop_name, "/dev/pty%c%x", 'p' + i / 16, i % 16);
      master_fd = open(loop_name, O_RDWR, 0);
      if (master_fd >= 0)
	break;
    }
    if (master_fd < 0) {
      syslog(LOG_ERR, "No free pty for loopback");
      die(1);
    }
    SYSDEBUG((LOG_DEBUG, "using %s for loopback", loop_name));
    loop_name[5] = 't';
    slave_fd = open(loop_name, O_RDWR, 0);
    if (slave_fd < 0) {
      syslog(LOG_ERR, "Couldn't open %s for loopback: %m", loop_name);
      die(1);
    }

    set_ppp_fd(slave_fd);

    if (tcgetattr(ppp_fd, &tios) == 0)
      {
	tios.c_cflag &= ~(CSIZE | CSTOPB | PARENB);
	tios.c_cflag |= CS8 | CREAD;
	tios.c_iflag  = IGNPAR | CLOCAL;
	tios.c_oflag  = 0;
	tios.c_lflag  = 0;
	if (tcsetattr(ppp_fd, TCSAFLUSH, &tios) < 0)
	  {
	    syslog(LOG_WARNING, "couldn't set attributes on loopback: %m(%d)", errno);
	  }
      }

    flags = fcntl(master_fd, F_GETFL);
    if (flags == -1 ||
	fcntl(master_fd, F_SETFL, flags | O_NONBLOCK) == -1)
      {
	syslog(LOG_WARNING, "couldn't set master loopback to nonblock: %m(%d)", errno);
      }

    flags = fcntl(ppp_fd, F_GETFL);
    if (flags == -1 ||
	fcntl(ppp_fd, F_SETFL, flags | O_NONBLOCK) == -1)
      {
	syslog(LOG_WARNING, "couldn't set slave loopback to nonblock: %m(%d)", errno);
      }

    if (ioctl(ppp_fd, TIOCSETD, &ppp_disc) < 0)
      {
	syslog(LOG_ERR, "ioctl(TIOCSETD): %m(%d)", errno);
	die(1);
      }
/*
 * Find out which interface we were given.
 */
    if (ioctl(ppp_fd, PPPIOCGUNIT, &ifunit) < 0)
      {	
	syslog(LOG_ERR, "ioctl(PPPIOCGUNIT): %m(%d)", errno);
	die(1);
      }
/*
 * Enable debug in the driver if requested.
 */
    set_kdebugflag (kdebugflag);
  }

/********************************************************************
 *
 * restore_loop - reattach the ppp unit to the loopback.
 *
 * The kernel ppp driver automatically reattaches the ppp unit to
 * the loopback if the serial port is set to a line discipline other
 * than ppp, or if it detects a modem hangup.  The former will happen
 * in disestablish_ppp if the latter hasn't already happened, so we
 * shouldn't need to do anything.
 *
 * Just to be sure, set the real serial port to the normal discipline.
 */

void
restore_loop(void)
  {
    if (ppp_fd != slave_fd)
      {
	(void) ioctl(ppp_fd, TIOCSETD, &tty_disc);
	set_ppp_fd(slave_fd);
      }
  }

/********************************************************************
 *
 * sifnpmode - Set the mode for handling packets for a given NP.
 */

int
sifnpmode(u, proto, mode)
    int u;
    int proto;
    enum NPmode mode;
{
    struct npioctl npi;

    npi.protocol = proto;
    npi.mode     = mode;
    if (ioctl(ppp_fd, PPPIOCSNPMODE, (caddr_t) &npi) < 0)
      {
	if (! ok_error (errno))
	  {
	    syslog(LOG_ERR, "ioctl(PPPIOCSNPMODE, %d, %d): %m(%d)",
		   proto, mode, errno);
	    syslog(LOG_ERR, "ppp_fd=%d slave_fd=%d\n", ppp_fd, slave_fd);
	  }
	return 0;
      }
    return 1;
  }


#include <linux/ipx.h>

/********************************************************************
 *
 * sipxfaddr - Config the interface IPX networknumber
 */

int sipxfaddr (int unit, unsigned long int network, unsigned char * node )
  {
    int    result = 1;

#ifdef IPX_CHANGE
    int    skfd; 
    struct sockaddr_ipx  ipx_addr;
    struct ifreq         ifr;
    struct sockaddr_ipx *sipx = (struct sockaddr_ipx *) &ifr.ifr_addr;

    skfd = socket (AF_IPX, SOCK_DGRAM, 0);
    if (skfd < 0)
      { 
	if (! ok_error (errno))
	  {
	    syslog (LOG_DEBUG, "socket(AF_IPX): %m(%d)", errno);
	  }
	result = 0;
      }
    else
      {
	memset (&ifr, '\0', sizeof (ifr));
	strcpy (ifr.ifr_name, ifname);

	memcpy (sipx->sipx_node, node, IPX_NODE_LEN);
	sipx->sipx_family  = AF_IPX;
	sipx->sipx_port    = 0;
	sipx->sipx_network = htonl (network);
	sipx->sipx_type    = IPX_FRAME_ETHERII;
	sipx->sipx_action  = IPX_CRTITF;
/*
 *  Set the IPX device
 */
	if (ioctl(skfd, SIOCSIFADDR, (caddr_t) &ifr) < 0)
	  {
	    result = 0;
	    if (errno != EEXIST)
	      {
		if (! ok_error (errno))
		  {
		    syslog (LOG_DEBUG,
			    "ioctl(SIOCAIFADDR, CRTITF): %m(%d)", errno);
		  }
	      }
	    else
	      {
		syslog (LOG_WARNING,
			"ioctl(SIOCAIFADDR, CRTITF): Address already exists");
	      }
	  }
	close (skfd);
      }
#endif
    return result;
  }

/********************************************************************
 *
 * cipxfaddr - Clear the information for the IPX network. The IPX routes
 *	       are removed and the device is no longer able to pass IPX
 *	       frames.
 */

int cipxfaddr (int unit)
  {
    int    result = 1;

#ifdef IPX_CHANGE
    int    skfd; 
    struct sockaddr_ipx  ipx_addr;
    struct ifreq         ifr;
    struct sockaddr_ipx *sipx = (struct sockaddr_ipx *) &ifr.ifr_addr;

    skfd = socket (AF_IPX, SOCK_DGRAM, 0);
    if (skfd < 0)
      { 
	if (! ok_error (errno))
	  {
	    syslog (LOG_DEBUG, "socket(AF_IPX): %m(%d)", errno);
	  }
	result = 0;
      }
    else
      {
	memset (&ifr, '\0', sizeof (ifr));
	strcpy (ifr.ifr_name, ifname);

	sipx->sipx_type    = IPX_FRAME_ETHERII;
	sipx->sipx_action  = IPX_DLTITF;
	sipx->sipx_family  = AF_IPX;
/*
 *  Set the IPX device
 */
	if (ioctl(skfd, SIOCSIFADDR, (caddr_t) &ifr) < 0)
	  {
	    if (! ok_error (errno))
	      {
		syslog (LOG_INFO,
			"ioctl(SIOCAIFADDR, IPX_DLTITF): %m(%d)", errno);
	      }
	    result = 0;
	  }
	close (skfd);
      }
#endif
    return result;
  }

/*
 * daemon - Detach us from controlling terminal session.
 */
int
daemon(nochdir, noclose)
    int nochdir, noclose;
{
    int pid;

    if ((pid = fork()) < 0)
	return -1;
    if (pid != 0)
	exit(0);		/* parent dies */
    setsid();
    if (!nochdir)
	chdir("/");
    if (!noclose) {
	fclose(stdin);		/* don't need stdin, stdout, stderr */
	fclose(stdout);
	fclose(stderr);
    }
    return 0;
}

/********************************************************************
 *
 * sys_check_options - check the options that the user specified
 */

void
sys_check_options(void)
  {
#ifdef IPX_CHANGE
    struct stat stat_buf;
/*
 * Disable the IPX protocol if the support is not present in the kernel.
 * If we disable it then ensure that IP support is enabled.
 */
    while (ipxcp_protent.enabled_flag)
      {
        if (path_to_procfs())
	  {
	    strcat (route_buffer, "/net/ipx_interface");
	    if (lstat (route_buffer, &stat_buf) >= 0)
	      {
		break;
	      }
	  }
	syslog (LOG_ERR, "IPX support is not present in the kernel\n");
	ipxcp_protent.enabled_flag = 0;
	ipcp_protent.enabled_flag  = 1;
	break;
      }
#endif
    if (demand && driver_is_old) {
      option_error("demand dialling is not supported by kernel driver version "
		   "%d.%d.%d", driver_version, driver_modification,
		   driver_patch);
      demand = 0;
    }
  }
