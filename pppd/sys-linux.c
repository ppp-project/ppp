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

/*
 * TODO:
 */

#include <stdio.h>
#include <syslog.h>
#include <string.h>
#include <time.h>
#include <memory.h>
#include <utmp.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/errno.h>
#include <mntent.h>

#include <net/if.h>
#include <net/ppp_defs.h>
#include <net/if_arp.h>
#include <linux/ppp.h>
#include <linux/route.h>
#include <linux/if_ether.h>
#include <netinet/in.h>
#include <signal.h>

#include "pppd.h"
#include "fsm.h"
#include "ipcp.h"

static int initdisc = -1;	/* Initial TTY discipline */
static int prev_kdebugflag = 0;

static int restore_term;		/* 1 => we've munged the terminal */
static struct termios inittermios;	/* Initial TTY termios */

static int driver_version = 0;
static int driver_modification = 0;
static int driver_patch = 0;

#define MAX_IFS		32

/*
 * SET_SA_FAMILY - set the sa_family field of a struct sockaddr,
 * if it exists.
 */

#define SET_SA_FAMILY(addr, family)			\
    memset ((char *) &(addr), '\0', sizeof(addr));	\
    addr.sa_family = (family);

/*
 * sys_init - System-dependent initialization.
 */
void
sys_init()
{
    openlog("pppd", LOG_PID | LOG_NDELAY, LOG_PPP);
    setlogmask(LOG_UPTO(LOG_INFO));
    if (debug)
	setlogmask(LOG_UPTO(LOG_DEBUG));
}

/*
 * note_debug_level - note a change in the debug level.
 */
void
note_debug_level()
{
    if (debug) {
	syslog(LOG_INFO, "Debug turned ON, Level %d", debug);
	setlogmask(LOG_UPTO(LOG_DEBUG));
    } else {
	setlogmask(LOG_UPTO(LOG_WARNING));
    }
}

/*
 * set_kdebugflag - Define the debugging level for the kernel
 */

int set_kdebugflag (int requested_level)
{
    if (ioctl(fd, PPPIOCGDEBUG, &prev_kdebugflag) < 0) {
	syslog(LOG_ERR, "ioctl(PPPIOCGDEBUG): %m");
	return (0);
    }

    if (prev_kdebugflag != requested_level) {
	if (ioctl(fd, PPPIOCSDEBUG, &requested_level) < 0) {
	    syslog (LOG_ERR, "ioctl(PPPIOCSDEBUG): %m");
	    return (0);
	}
        syslog(LOG_INFO, "set kernel debugging level to %d", requested_level);
    }
    return (1);
}

/*
 * establish_ppp - Turn the serial port into a ppp interface.
 */

void establish_ppp (void)
{
    int pppdisc = NUM_PPP;
    int sig	= SIGIO;

    if (ioctl(fd, TIOCEXCL, 0) < 0) {
	syslog (LOG_WARNING, "ioctl(TIOCEXCL): %m");
    }

    if (ioctl(fd, TIOCGETD, &initdisc) < 0) {
	syslog(LOG_ERR, "ioctl(TIOCGETD): %m");
	die (1);
    }
    
    if (ioctl(fd, TIOCSETD, &pppdisc) < 0) {
	syslog(LOG_ERR, "ioctl(TIOCSETD): %m");
	die (1);
    }
    if (ioctl(fd, PPPIOCGUNIT, &ifunit) < 0) {
	syslog(LOG_ERR, "ioctl(PPPIOCGUNIT): %m");
	die (1);
    }

    set_kdebugflag (kdebugflag);

    syslog (LOG_NOTICE, "Using version %d.%d.%d of PPP driver",
	    driver_version, driver_modification, driver_patch);
}

/*
 * disestablish_ppp - Restore the serial port to normal operation.
 * This shouldn't call die() because it's called from die().
 */

void disestablish_ppp(void)
{
    int x;
    char *s;

    if (initdisc >= 0) {
        set_kdebugflag (prev_kdebugflag);
	/*
	 * Check whether the link seems not to be 8-bit clean.
	 */
	if (ioctl(fd, PPPIOCGFLAGS, (caddr_t) &x) == 0) {
	    s = NULL;
	    switch (~x & (SC_RCV_B7_0|SC_RCV_B7_1|SC_RCV_EVNP|SC_RCV_ODDP)) {
	    case SC_RCV_B7_0:
		s = "bit 7 set to 1";
		break;
	    case SC_RCV_B7_1:
		s = "bit 7 set to 0";
		break;
	    case SC_RCV_EVNP:
		s = "odd parity";
		break;
	    case SC_RCV_ODDP:
		s = "even parity";
		break;
	    }
	    if (s != NULL) {
		syslog(LOG_WARNING, "Serial link is not 8-bit clean:");
		syslog(LOG_WARNING, "All received characters had %s", s);
	    }
	}

	if (ioctl(fd, TIOCSETD, &initdisc) < 0)
	    syslog(LOG_ERR, "ioctl(TIOCSETD): %m");

	if (ioctl(fd, TIOCNXCL, 0) < 0)
	    syslog (LOG_WARNING, "ioctl(TIOCNXCL): %m");

	initdisc = -1;
    }
}

#if B9600 == 9600
/*
 * XXX assume speed_t values numerically equal bits per second
 * (so we can ask for any speed).
 */
#define translate_speed(bps)	(bps)
#define baud_rate_of(speed)	(speed)

#else
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
#ifdef EXTA
    { 19200, EXTA },
#endif
#ifdef EXTB
    { 38400, EXTB },
#endif
#ifdef B57600
    { 57600, B57600 },
#endif
#ifdef B115200
    { 115200, B115200 },
#endif
    { 0, 0 }
};

/*
 * Translate from bits/second to a speed_t.
 */
int
translate_speed(bps)
    int bps;
{
    struct speed *speedp;

    if (bps == 0)
	return 0;
    for (speedp = speeds; speedp->speed_int; speedp++)
	if (bps == speedp->speed_int)
	    return speedp->speed_val;
    syslog(LOG_WARNING, "speed %d not supported", bps);
    return 0;
}

/*
 * Translate from a speed_t to bits/second.
 */
int
baud_rate_of(speed)
    int speed;
{
    struct speed *speedp;

    if (speed == 0)
	return 0;
    for (speedp = speeds; speedp->speed_int; speedp++)
	if (speed == speedp->speed_val)
	    return speedp->speed_int;
    return 0;
}
#endif

/*
 * set_up_tty: Set up the serial port on `fd' for 8 bits, no parity,
 * at the requested speed, etc.  If `local' is true, set CLOCAL
 * regardless of whether the modem option was specified.
 */
set_up_tty(fd, local)
    int fd, local;
{
    int speed, x;
    struct termios tios;

    if (tcgetattr(fd, &tios) < 0) {
	syslog(LOG_ERR, "tcgetattr: %m");
	die(1);
    }

    if (!restore_term)
	inittermios = tios;

#ifdef CRTSCTS
    tios.c_cflag &= ~(CSIZE | CSTOPB | PARENB | CLOCAL | CRTSCTS);
    if (crtscts == 1)
	tios.c_cflag |= CRTSCTS;
#else
    tios.c_cflag &= ~(CSIZE | CSTOPB | PARENB | CLOCAL);
#endif	/* CRTSCTS */

    tios.c_cflag |= CS8 | CREAD | HUPCL;
    if (local || !modem)
	tios.c_cflag |= CLOCAL;
    tios.c_iflag = IGNBRK | IGNPAR;
    tios.c_oflag = 0;
    tios.c_lflag = 0;
    tios.c_cc[VMIN] = 1;
    tios.c_cc[VTIME] = 0;

    if (crtscts == 2) {
	tios.c_iflag |= IXOFF;
	tios.c_cc[VSTOP] = 0x13;	/* DC3 = XOFF = ^S */
	tios.c_cc[VSTART] = 0x11;	/* DC1 = XON  = ^Q */
    }

    speed = translate_speed(inspeed);
    if (speed) {
	cfsetospeed(&tios, speed);
	cfsetispeed(&tios, speed);
    } else {
	speed = cfgetospeed(&tios);
	/*
	 * We can't proceed if the serial port speed is B0,
	 * since that implies that the serial port is disabled.
	 */
	if (speed == B0) {
	    syslog(LOG_ERR, "Baud rate for %s is 0; need explicit baud rate",
		   devnam);
	    die(1);
	}
    }

    if (tcsetattr(fd, TCSAFLUSH, &tios) < 0) {
	syslog(LOG_ERR, "tcsetattr: %m");
	die(1);
    }

    baud_rate = baud_rate_of(speed);
    restore_term = TRUE;
}

/*
 * setdtr - control the DTR line on the serial port.
 * This is called from die(), so it shouldn't call die().
 */
setdtr(fd, on)
int fd, on;
{
    int modembits = TIOCM_DTR;

    ioctl(fd, (on? TIOCMBIS: TIOCMBIC), &modembits);
}

/*
 * restore_tty - restore the terminal to the saved settings.
 */
void
restore_tty()
{
    if (restore_term) {
	if (tcsetattr(fd, TCSAFLUSH, &inittermios) < 0)
	    if (errno != ENXIO)
		syslog(LOG_WARNING, "tcsetattr: %m");
	restore_term = 0;
    }
}

/*
 * output - Output PPP packet.
 */

void output (int unit, unsigned char *p, int len)
{
    if (unit != 0)
	MAINDEBUG((LOG_WARNING, "output: unit != 0!"));

    if (debug)
        log_packet(p, len, "sent ");
    
    if (write(fd, p, len) < 0) {
        syslog(LOG_ERR, "write: %m");
	die(1);
    }
}

/*
 * wait_input - wait until there is data available on fd,
 * for the length of time specified by *timo (indefinite
 * if timo is NULL).
 */
wait_input(timo)
    struct timeval *timo;
{
    fd_set ready;
    int n;

    FD_ZERO(&ready);
    FD_SET(fd, &ready);
    n = select(fd+1, &ready, NULL, &ready, timo);
    if (n < 0 && errno != EINTR) {
	syslog(LOG_ERR, "select: %m");
	die(1);
    }
}


/*
 * read_packet - get a PPP packet from the serial device.
 */

int read_packet (unsigned char *buf)
{
    int len;
  
    len = read(fd, buf, PPP_MTU + PPP_HDRLEN);
    if (len < 0) {
	if (errno == EWOULDBLOCK) {
#if 0
	    MAINDEBUG((LOG_DEBUG, "read(fd): EWOULDBLOCK"));
#endif
	    return -1;
	}
	syslog(LOG_ERR, "read(fd): %m");
	die(1);
    }
    return len;
}

/*
 * ppp_send_config - configure the transmit characteristics of
 * the ppp interface.
 */
void ppp_send_config (int unit,int mtu,u_int32_t asyncmap,int pcomp,int accomp)
{
    u_int x;
    struct ifreq ifr;
  
    MAINDEBUG ((LOG_DEBUG, "send_config: mtu = %d\n", mtu));
    strncpy(ifr.ifr_name, ifname, sizeof (ifr.ifr_name));
    ifr.ifr_mtu = mtu;
    if (ioctl(s, SIOCSIFMTU, (caddr_t) &ifr) < 0) {
	syslog(LOG_ERR, "ioctl(SIOCSIFMTU): %m");
	quit();
    }

    MAINDEBUG ((LOG_DEBUG, "send_config: asyncmap = %lx\n", asyncmap));
    if (ioctl(fd, PPPIOCSASYNCMAP, (caddr_t) &asyncmap) < 0) {
        syslog(LOG_ERR, "ioctl(PPPIOCSASYNCMAP): %m");
	quit();
    }
    
    if (ioctl(fd, PPPIOCGFLAGS, (caddr_t) &x) < 0) {
	syslog(LOG_ERR, "ioctl (PPPIOCGFLAGS): %m");
	quit();
    }

    x = pcomp  ? x | SC_COMP_PROT : x & ~SC_COMP_PROT;
    x = accomp ? x | SC_COMP_AC   : x & ~SC_COMP_AC;

    MAINDEBUG ((LOG_DEBUG, "send_config: flags = %x\n", x));
    if (ioctl(fd, PPPIOCSFLAGS, (caddr_t) &x) < 0) {
	syslog(LOG_ERR, "ioctl(PPPIOCSFLAGS): %m");
	quit();
    }
}

/*
 * ppp_set_xaccm - set the extended transmit ACCM for the interface.
 */
void
ppp_set_xaccm(unit, accm)
    int unit;
    ext_accm accm;
{
    MAINDEBUG ((LOG_DEBUG, "set_xaccm: %08lx %08lx %08lx %08lx\n",
		accm[0], accm[1], accm[2], accm[3]));
    if (ioctl(fd, PPPIOCSXASYNCMAP, accm) < 0 && errno != ENOTTY)
	syslog(LOG_WARNING, "ioctl(set extended ACCM): %m");
}

/*
 * ppp_recv_config - configure the receive-side characteristics of
 * the ppp interface.
 */
void ppp_recv_config (int unit,int mru,u_int32_t asyncmap,int pcomp,int accomp)
{
    u_int x;

    MAINDEBUG ((LOG_DEBUG, "recv_config: mru = %d\n", mru));
    if (ioctl(fd, PPPIOCSMRU, (caddr_t) &mru) < 0)
	syslog(LOG_ERR, "ioctl(PPPIOCSMRU): %m");

    MAINDEBUG ((LOG_DEBUG, "recv_config: asyncmap = %lx\n", asyncmap));
    if (ioctl(fd, PPPIOCRASYNCMAP, (caddr_t) &asyncmap) < 0) {
        syslog(LOG_ERR, "ioctl(PPPIOCRASYNCMAP): %m");
	quit();
    }
  
    if (ioctl(fd, PPPIOCGFLAGS, (caddr_t) &x) < 0) {
	syslog(LOG_ERR, "ioctl (PPPIOCGFLAGS): %m");
	quit();
    }

    x = !accomp? x | SC_REJ_COMP_AC: x &~ SC_REJ_COMP_AC;
    MAINDEBUG ((LOG_DEBUG, "recv_config: flags = %x\n", x));
    if (ioctl(fd, PPPIOCSFLAGS, (caddr_t) &x) < 0) {
	syslog(LOG_ERR, "ioctl(PPPIOCSFLAGS): %m");
	quit();
    }
}

/*
 * ccp_test - ask kernel whether a given compression method
 * is acceptable for use.
 */
int
ccp_test(unit, opt_ptr, opt_len, for_transmit)
    int unit, opt_len, for_transmit;
    u_char *opt_ptr;
{
    struct ppp_comp_data data;

    data.ptr = opt_ptr;
    data.length = opt_len;
    data.transmit = for_transmit;
    return ioctl(fd, PPPIOCSCOMPRESS, (caddr_t) &data) >= 0;
}

/*
 * ccp_flags_set - inform kernel about the current state of CCP.
 */
void
ccp_flags_set(unit, isopen, isup)
    int unit, isopen, isup;
{
    int x;

    if (ioctl(fd, PPPIOCGFLAGS, (caddr_t) &x) < 0) {
	syslog(LOG_ERR, "ioctl (PPPIOCGFLAGS): %m");
	return;
    }
    x = isopen? x | SC_CCP_OPEN: x &~ SC_CCP_OPEN;
    x = isup? x | SC_CCP_UP: x &~ SC_CCP_UP;
    if (ioctl(fd, PPPIOCSFLAGS, (caddr_t) &x) < 0)
	syslog(LOG_ERR, "ioctl(PPPIOCSFLAGS): %m");
}

/*
 * sifvjcomp - config tcp header compression
 */

int sifvjcomp (int u, int vjcomp, int cidcomp, int maxcid)
{
    u_int x;

    if (ioctl(fd, PPPIOCGFLAGS, (caddr_t) &x) < 0) {
	syslog(LOG_ERR, "ioctl (PPPIOCGFLAGS): %m");
	return 0;
    }

    x = vjcomp  ? x | SC_COMP_TCP     : x &~ SC_COMP_TCP;
    x = cidcomp ? x & ~SC_NO_TCP_CCID : x | SC_NO_TCP_CCID;

    if(ioctl(fd, PPPIOCSFLAGS, (caddr_t) &x) < 0) {
	syslog(LOG_ERR, "ioctl(PPPIOCSFLAGS): %m");
	return 0;
    }

    if (vjcomp) {
        if (ioctl (fd, PPPIOCSMAXCID, (caddr_t) &maxcid) < 0) {
	    syslog (LOG_ERR, "ioctl(PPPIOCSFLAGS): %m");
	    return 0;
        }
    }

    return 1;
}

/*
 * sifup - Config the interface up and enable IP packets to pass.
 */

int sifup (int u)
{
    struct ifreq ifr;

    strncpy(ifr.ifr_name, ifname, sizeof (ifr.ifr_name));
    if (ioctl(s, SIOCGIFFLAGS, (caddr_t) &ifr) < 0) {
	syslog(LOG_ERR, "ioctl (SIOCGIFFLAGS): %m");
	return 0;
    }

    ifr.ifr_flags |= (IFF_UP | IFF_POINTOPOINT);
    if (ioctl(s, SIOCSIFFLAGS, (caddr_t) &ifr) < 0) {
	syslog(LOG_ERR, "ioctl(SIOCSIFFLAGS): %m");
	return 0;
    }
    return 1;
}

/*
 * sifdown - Config the interface down and disable IP.
 */

int sifdown (int u)
{
    struct ifreq ifr;

    strncpy(ifr.ifr_name, ifname, sizeof (ifr.ifr_name));
    if (ioctl(s, SIOCGIFFLAGS, (caddr_t) &ifr) < 0) {
	syslog(LOG_ERR, "ioctl (SIOCGIFFLAGS): %m");
	return 0;
    }

    ifr.ifr_flags &= ~IFF_UP;
    ifr.ifr_flags |= IFF_POINTOPOINT;
    if (ioctl(s, SIOCSIFFLAGS, (caddr_t) &ifr) < 0) {
	syslog(LOG_ERR, "ioctl(SIOCSIFFLAGS): %m");
	return 0;
    }
    return 1;
}

/*
 * sifaddr - Config the interface IP addresses and netmask.
 */

int sifaddr (int unit, int our_adr, int his_adr, int net_mask)
{
    struct ifreq   ifr; 
    struct rtentry rt;
    
    SET_SA_FAMILY (ifr.ifr_addr,    AF_INET); 
    SET_SA_FAMILY (ifr.ifr_dstaddr, AF_INET); 
    SET_SA_FAMILY (ifr.ifr_netmask, AF_INET); 

    strncpy (ifr.ifr_name, ifname, sizeof (ifr.ifr_name));
/*
 *  Set our IP address
 */
    ((struct sockaddr_in *) &ifr.ifr_addr)->sin_addr.s_addr = our_adr;
    if (ioctl(s, SIOCSIFADDR, (caddr_t) &ifr) < 0) {
	if (errno != EEXIST)
	    syslog (LOG_ERR, "ioctl(SIOCAIFADDR): %m");
        else
	    syslog (LOG_WARNING, "ioctl(SIOCAIFADDR): Address already exists");
        return (0);
    } 
/*
 *  Set the gateway address
 */
    ((struct sockaddr_in *) &ifr.ifr_dstaddr)->sin_addr.s_addr = his_adr;
    if (ioctl(s, SIOCSIFDSTADDR, (caddr_t) &ifr) < 0) {
	syslog (LOG_ERR, "ioctl(SIOCSIFDSTADDR): %m"); 
	return (0);
    } 
/*
 *  Set the netmask
 */
    if (net_mask != 0) {
	((struct sockaddr_in *) &ifr.ifr_netmask)->sin_addr.s_addr = net_mask;
	if (ioctl(s, SIOCSIFNETMASK, (caddr_t) &ifr) < 0) {
	    syslog (LOG_ERR, "ioctl(SIOCSIFNETMASK): %m"); 
	    return (0);
        } 
    }
/*
 *  Add the device route
 */
    memset (&rt, '\0', sizeof (rt));

    SET_SA_FAMILY (rt.rt_dst,     AF_INET);
    SET_SA_FAMILY (rt.rt_gateway, AF_INET);
    rt.rt_dev = ifname;  /* MJC */

    ((struct sockaddr_in *) &rt.rt_gateway)->sin_addr.s_addr = 0;
    ((struct sockaddr_in *) &rt.rt_dst)->sin_addr.s_addr     = his_adr;
    rt.rt_flags = RTF_UP | RTF_HOST;

    if (ioctl(s, SIOCADDRT, &rt) < 0) {
        syslog (LOG_ERR, "ioctl(SIOCADDRT) device route: %m");
        return (0);
    }
    return 1;
}

/*
 * cifaddr - Clear the interface IP addresses, and delete routes
 * through the interface if possible.
 */

int cifaddr (int unit, int our_adr, int his_adr)
{
    struct rtentry rt;
/*
 *  Delete the route through the device
 */
    memset (&rt, '\0', sizeof (rt));

    SET_SA_FAMILY (rt.rt_dst,     AF_INET);
    SET_SA_FAMILY (rt.rt_gateway, AF_INET);
    rt.rt_dev = ifname;  /* MJC */

    ((struct sockaddr_in *) &rt.rt_gateway)->sin_addr.s_addr = 0;
    ((struct sockaddr_in *) &rt.rt_dst)->sin_addr.s_addr     = his_adr;
    rt.rt_flags = RTF_UP | RTF_HOST;

    if (ioctl(s, SIOCDELRT, &rt) < 0) {
        syslog (LOG_ERR, "ioctl(SIOCDELRT) device route: %m");
        return (0);
    }
    return 1;
}

/*
 * path_to_route - determine the path to the proc file system data
 */

FILE *route_fd = (FILE *) 0;
static char route_buffer [100];

static char *path_to_route (void);
static int open_route_table (void);
static void close_route_table (void);
static int read_route_table (struct rtentry *rt);
static int defaultroute_exists (void);

/*
 * path_to_route - find the path to the route tables in the proc file system
 */

static char *path_to_route (void)
{
    struct mntent *mntent;
    FILE *fp;

    fp = fopen (MOUNTED, "r");
    if (fp != 0) {
        while ((mntent = getmntent (fp)) != 0) {
	    if (strcmp (mntent->mnt_type, MNTTYPE_IGNORE) == 0)
	        continue;

	    if (strcmp (mntent->mnt_type, "proc") == 0) {
	        strncpy (route_buffer, mntent->mnt_dir,
			 sizeof (route_buffer)-10);
		route_buffer [sizeof (route_buffer)-10] = '\0';
		strcat (route_buffer, "/net/route");

		fclose (fp);
		return (route_buffer);
	    }
	}
	fclose (fp);
    }
    syslog (LOG_ERR, "proc file system not mounted");
    return 0;
}

/*
 * open_route_table - open the interface to the route table
 */

static int open_route_table (void)
{
    char *path;

    if (route_fd != (FILE *) 0)
        close_route_table();

    path = path_to_route();
    if (path == NULL)
        return 0;

    route_fd = fopen (path, "r");
    if (route_fd == (FILE *) 0) {
        syslog (LOG_ERR, "can not open %s: %m", path);
        return 0;
    }

    /* read and discard the header line. */
    if (fgets (route_buffer, sizeof (route_buffer), route_fd) == (char *) 0) {
        close_route_table();
	return 0;
    }
    return 1;
}

/*
 * close_route_table - close the interface to the route table
 */

static void close_route_table (void)
{
    if (route_fd != (FILE *) 0) {
        fclose (route_fd);
        route_fd = (FILE *) 0;
    }
}

/*
 * read_route_table - read the next entry from the route table
 */

static int read_route_table (struct rtentry *rt)
{
    static char delims[] = " \t\n";
    char *dev_ptr, *ptr, *dst_ptr, *gw_ptr, *flag_ptr;

    if (fgets (route_buffer, sizeof (route_buffer), route_fd) == (char *) 0)
        return 0;

    memset (rt, '\0', sizeof (struct rtentry));

    dev_ptr  = strtok (route_buffer, delims); /* interface name */
    dst_ptr  = strtok (NULL,         delims); /* destination address */
    gw_ptr   = strtok (NULL,         delims); /* gateway */
    flag_ptr = strtok (NULL,         delims); /* flags */
#if 0
    ptr      = strtok (NULL,         delims); /* reference count */
    ptr      = strtok (NULL,         delims); /* useage count */
    ptr      = strtok (NULL,         delims); /* metric */
    ptr      = strtok (NULL,         delims); /* mask */
#endif

    ((struct sockaddr_in *) &rt->rt_dst)->sin_addr.s_addr =
      strtoul (dst_ptr, NULL, 16);

    ((struct sockaddr_in *) &rt->rt_gateway)->sin_addr.s_addr =
      strtoul (gw_ptr, NULL, 16);

    rt->rt_flags = (short) strtoul (flag_ptr, NULL, 16);
    rt->rt_dev   = dev_ptr;

    return 1;
}

/*
 * defaultroute_exists - determine if there is a default route
 */

static int defaultroute_exists (void)
{
    struct rtentry rt;
    int    result = 0;

    if (!open_route_table())
        return 0;

    while (read_route_table(&rt) != 0) {
        if (rt.rt_flags & RTF_UP == 0)
	    continue;

        if (((struct sockaddr_in *) &rt.rt_dst)->sin_addr.s_addr == 0L) {
	    syslog (LOG_ERR,
		    "ppp not replacing existing default route to %s[%s]",
		    rt.rt_dev,
		    inet_ntoa (((struct sockaddr_in *) &rt.rt_gateway)->
			       sin_addr.s_addr));
	    result = 1;
	    break;
	}
    }
    close_route_table();
    return result;
}

/*
 * sifdefaultroute - assign a default route through the address given.
 */

int sifdefaultroute (int unit, int gateway)
{
    struct rtentry rt;

    if (defaultroute_exists())
        return 0;

    memset (&rt, '\0', sizeof (rt));
    SET_SA_FAMILY (rt.rt_dst,     AF_INET);
    SET_SA_FAMILY (rt.rt_gateway, AF_INET);
    ((struct sockaddr_in *) &rt.rt_gateway)->sin_addr.s_addr = gateway;
    
    rt.rt_flags = RTF_UP | RTF_GATEWAY;
    if (ioctl(s, SIOCADDRT, &rt) < 0) {
	syslog (LOG_ERR, "default route ioctl(SIOCADDRT): %m");
	return 0;
    }
    return 1;
}

/*
 * cifdefaultroute - delete a default route through the address given.
 */

int cifdefaultroute (int unit, int gateway)
{
    struct rtentry rt;
  
    SET_SA_FAMILY (rt.rt_dst,     AF_INET);
    SET_SA_FAMILY (rt.rt_gateway, AF_INET);
    ((struct sockaddr_in *) &rt.rt_gateway)->sin_addr.s_addr = gateway;
    
    rt.rt_flags = RTF_UP | RTF_GATEWAY;
    if (ioctl(s, SIOCDELRT, &rt) < 0) {
	syslog (LOG_ERR, "default route ioctl(SIOCDELRT): %m");
	return 0;
    }
    return 1;
}

/*
 * sifproxyarp - Make a proxy ARP entry for the peer.
 */

int sifproxyarp (int unit, u_int32_t his_adr)
{
    struct arpreq arpreq;

    memset (&arpreq, '\0', sizeof(arpreq));
/*
 * Get the hardware address of an interface on the same subnet
 * as our local address.
 */
    if (!get_ether_addr(his_adr, &arpreq.arp_ha)) {
	syslog(LOG_ERR, "Cannot determine ethernet address for proxy ARP");
	return 0;
    }
    
    SET_SA_FAMILY(arpreq.arp_pa, AF_INET);
    ((struct sockaddr_in *) &arpreq.arp_pa)->sin_addr.s_addr = his_adr;
    arpreq.arp_flags = ATF_PERM | ATF_PUBL;
    
    if (ioctl(s, SIOCSARP, (caddr_t)&arpreq) < 0) {
	syslog(LOG_ERR, "ioctl(SIOCSARP): %m");
	return 0;
    }
    return 1;
}

/*
 * cifproxyarp - Delete the proxy ARP entry for the peer.
 */

int cifproxyarp (int unit, u_int32_t his_adr)
{
    struct arpreq arpreq;
  
    memset (&arpreq, '\0', sizeof(arpreq));
    SET_SA_FAMILY(arpreq.arp_pa, AF_INET);
    
    ((struct sockaddr_in *) &arpreq.arp_pa)->sin_addr.s_addr = his_adr;
    if (ioctl(s, SIOCDARP, (caddr_t)&arpreq) < 0) {
	syslog(LOG_WARNING, "ioctl(SIOCDARP): %m");
	return 0;
    }
    return 1;
}
     
/*
 * get_ether_addr - get the hardware address of an interface on the
 * the same subnet as ipaddr.
 */

int get_ether_addr (u_int32_t ipaddr, struct sockaddr *hwaddr)
{
    struct ifreq *ifr, *ifend, *ifp;
    int i;
    u_int32_t ina, mask;
    struct sockaddr_dl *dla;
    struct ifreq ifreq;
    struct ifconf ifc;
    struct ifreq ifs[MAX_IFS];
    
    ifc.ifc_len = sizeof(ifs);
    ifc.ifc_req = ifs;
    if (ioctl(s, SIOCGIFCONF, &ifc) < 0) {
	syslog(LOG_ERR, "ioctl(SIOCGIFCONF): %m");
	return 0;
    }
    MAINDEBUG ((LOG_DEBUG, "proxy arp: scanning %d interfaces for IP %s",
		ifc.ifc_len / sizeof(struct ifreq), ip_ntoa(ipaddr)));
/*
 * Scan through looking for an interface with an Internet
 * address on the same subnet as `ipaddr'.
 */
    ifend = ifs + (ifc.ifc_len / sizeof(struct ifreq));
    for (ifr = ifc.ifc_req; ifr < ifend; ifr++) {
	if (ifr->ifr_addr.sa_family == AF_INET) {
	    ina = ((struct sockaddr_in *) &ifr->ifr_addr)->sin_addr.s_addr;
	    strncpy(ifreq.ifr_name, ifr->ifr_name, sizeof(ifreq.ifr_name));
            MAINDEBUG ((LOG_DEBUG, "proxy arp: examining interface %s",
			ifreq.ifr_name));
/*
 * Check that the interface is up, and not point-to-point
 * or loopback.
 */
	    if (ioctl(s, SIOCGIFFLAGS, &ifreq) < 0)
		continue;
	    if ((ifreq.ifr_flags &
		 (IFF_UP|IFF_BROADCAST|IFF_POINTOPOINT|IFF_LOOPBACK|IFF_NOARP))
		!= (IFF_UP|IFF_BROADCAST))
		continue;
/*
 * Get its netmask and check that it's on the right subnet.
 */
	    if (ioctl(s, SIOCGIFNETMASK, &ifreq) < 0)
	        continue;
	    mask = ((struct sockaddr_in *) &ifreq.ifr_addr)->sin_addr.s_addr;
	    MAINDEBUG ((LOG_DEBUG, "proxy arp: interface addr %s mask %lx",
			ip_ntoa(ina), ntohl(mask)));
	    if (((ipaddr ^ ina) & mask) != 0)
	        continue;
	    break;
	}
    }
    
    if (ifr >= ifend)
        return 0;

    syslog(LOG_INFO, "found interface %s for proxy arp", ifreq.ifr_name);
/*
 * Now get the hardware address.
 */
    if (ioctl (s, SIOCGIFHWADDR, &ifreq) < 0) {
        syslog(LOG_ERR, "SIOCGIFHWADDR(%s): %m", ifreq.ifr_name);
        return 0;
    }

    hwaddr->sa_family = ARPHRD_ETHER;
#ifndef old_ifr_hwaddr
    memcpy (&hwaddr->sa_data, &ifreq.ifr_hwaddr, ETH_ALEN);
#else
    memcpy (&hwaddr->sa_data, &ifreq.ifr_hwaddr.sa_data, ETH_ALEN);
#endif

    MAINDEBUG ((LOG_DEBUG,
		"proxy arp: found hwaddr %02x:%02x:%02x:%02x:%02x:%02x",
		(int) ((unsigned char *) &hwaddr->sa_data)[0],
		(int) ((unsigned char *) &hwaddr->sa_data)[1],
		(int) ((unsigned char *) &hwaddr->sa_data)[2],
		(int) ((unsigned char *) &hwaddr->sa_data)[3],
		(int) ((unsigned char *) &hwaddr->sa_data)[4],
		(int) ((unsigned char *) &hwaddr->sa_data)[5]));
    return 1;
}

/*
 * Internal routine to decode the version.modification.patch level
 */

static void decode_version (char *buf, int *version,
			    int *modification, int *patch)
{

  *version      = (int) strtoul (buf, &buf, 10);
  *modification = 0;
  *patch        = 0;

  if (*buf == '.') {
      ++buf;
      *modification = (int) strtoul (buf, &buf, 10);
      if (*buf == '.') {
	  ++buf;
	  *patch = (int) strtoul (buf, &buf, 10);
      }
  }

  if (*buf != '\0') {
      *version      =
      *modification =
      *patch        = 0;
  }
}

/*
 * ppp_available - check whether the system has any ppp interfaces
 * (in fact we check whether we can do an ioctl on ppp0).
 */

int ppp_available(void)
{
    int s, ok;
    struct ifreq ifr;
    int my_version,     my_modification,     my_patch;
/*
 * Open a socket for doing the ioctl operations.
 */    
    s = socket(AF_INET, SOCK_DGRAM, 0);
    if (s < 0)
	return 0;
    
    strncpy (ifr.ifr_name, "ppp0", sizeof (ifr.ifr_name));
    ok = ioctl(s, SIOCGIFFLAGS, (caddr_t) &ifr) >= 0;
/*
 * Ensure that the hardware address is for PPP and not something else
 */
    if (ok != 0)
        ok = ioctl (s, SIOCGIFHWADDR, (caddr_t) &ifr) >= 0;

    if (ok != 0 && ifr.ifr_hwaddr.sa_family != ARPHRD_PPP)
        ok = 0;
/*
 *  This is the PPP device. Validate the version of the driver at this
 *  point to ensure that this program will work with the driver.
 */
    if (ok != 0) {
        char   abBuffer [1024];
	int    size;

	ifr.ifr_data = abBuffer;
	size = ioctl (s, SIOCDEVPRIVATE, (caddr_t) &ifr);
	ok   = size >= 0;

	if (ok != 0) {
	    decode_version (abBuffer,
			    &driver_version,
			    &driver_modification,
			    &driver_patch);
	}
    }

    if (ok == 0) {
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
        ok = 0;
      
    /* The modification levels must be legal */
    if (driver_modification < my_modification)
        ok = 0;

    if (ok == 0) {
	fprintf(stderr, "Sorry - PPP driver version %d.%d.%d is out of date\n",
		driver_version, driver_modification, driver_patch);
    }

    close(s);
    return ok;
}

int
logwtmp(line, name, host)
	char *line, *name, *host;
{
    struct utmp ut;

    memset (&ut, 0, sizeof (ut));
    (void)strncpy(ut.ut_line, line, sizeof(ut.ut_line));
    (void)strncpy(ut.ut_name, name, sizeof(ut.ut_name));
    (void)strncpy(ut.ut_host, host, sizeof(ut.ut_host));
    (void)time(&ut.ut_time);
	
    pututline (&ut);		/* Write the line to the proper place */
    endutent();			/* Indicate operation is complete */
}
