/*
 * sys-ultrix.c - System-dependent procedures for setting up
 * PPP interfaces on Ultrix systems.
 *
 * Copyright (c) 1989 Carnegie Mellon University.
 * Copyright (c) 1995 The Australian National University.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms are permitted
 * provided that the above copyright notice and this paragraph are
 * duplicated in all such forms and that any documentation,
 * advertising materials, and other materials related to such
 * distribution and use acknowledge that the software was developed
 * by Carnegie Mellon University and The Australian National University.
 * The names of the Universities may not be used to endorse or promote
 * products derived from this software without specific prior written
 * permission.
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND WITHOUT ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, WITHOUT LIMITATION, THE IMPLIED
 * WARRANTIES OF MERCHANTIBILITY AND FITNESS FOR A PARTICULAR PURPOSE.
 */

#ifndef lint
static char rcsid[] = "$Id: sys-ultrix.c,v 1.28 1999/03/19 01:29:51 paulus Exp $";
#endif

/*
 * TODO:
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <fcntl.h>
#include <termios.h>
#include <utmp.h>
#include <sys/types.h>
#include <sys/file.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/time.h>
#include <sys/errno.h>
#include <sys/stat.h>

#include <net/if.h>
#include <net/ppp_defs.h>
#include <net/if_ppp.h>
#include <net/route.h>
#include <netinet/in.h>

#include "pppd.h"

static int initdisc = -1;	/* Initial TTY discipline for ppp_fd */
static int initfdflags = -1;	/* Initial file descriptor flags for ppp_fd */
static int ppp_fd = -1;		/* fd which is set to PPP discipline */

static int restore_term;	/* 1 => we've munged the terminal */
static struct termios inittermios; /* Initial TTY termios */
static struct winsize wsinfo;	/* Initial window size info */

static char *lock_file;		/* name of lock file created */

static int loop_slave = -1;
static int loop_master;
static char loop_name[20];

static unsigned char inbuf[512]; /* buffer for chars read from loopback */

static int sockfd;		/* socket for doing interface ioctls */

static fd_set in_fds;		/* set of fds that wait_input waits for */
static int max_in_fd;		/* highest fd set in in_fds */

static int if_is_up;		/* the interface is currently up */
static u_int32_t ifaddrs[2];	/* local and remote addresses */
static u_int32_t default_route_gateway;	/* gateway addr for default route */
static u_int32_t proxy_arp_addr;	/* remote addr for proxy arp */

/* Prototypes for procedures local to this file. */
static int translate_speed __P((int));
static int baud_rate_of __P((int));
static int get_ether_addr __P((u_int32_t, struct sockaddr *));


/*
 * sys_init - System-dependent initialization.
 */
void
sys_init()
{
    /* Get an internet socket for doing socket ioctl's on. */
    if ((sockfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0)
	fatal("Couldn't create IP socket: %m");

    FD_ZERO(&in_fds);
    max_in_fd = 0;
}

/*
 * sys_cleanup - restore any system state we modified before exiting:
 * mark the interface down, delete default route and/or proxy arp entry.
 * This shouldn't call die() because it's called from die().
 */
void
sys_cleanup()
{
    struct ifreq ifr;

    if (if_is_up) {
	strlcpy(ifr.ifr_name, ifname, sizeof(ifr.ifr_name));
	if (ioctl(sockfd, SIOCGIFFLAGS, &ifr) >= 0
	    && ((ifr.ifr_flags & IFF_UP) != 0)) {
	    ifr.ifr_flags &= ~IFF_UP;
	    ioctl(sockfd, SIOCSIFFLAGS, &ifr);
	}
    }
    if (ifaddrs[0])
	cifaddr(0, ifaddrs[0], ifaddrs[1]);
    if (default_route_gateway)
	cifdefaultroute(0, 0, default_route_gateway);
    if (proxy_arp_addr)
	cifproxyarp(0, proxy_arp_addr);
}

/*
 * sys_close - Clean up in a child process before execing.
 */
void
sys_close()
{
    close(sockfd);
    if (loop_slave >= 0) {
	close(loop_slave);
	close(loop_master);
    }
}

/*
 * sys_check_options - check the options that the user specified
 */
int
sys_check_options()
{
    if (demand) {
	option_error("Sorry - demand-dialling is not supported under Ultrix\n");
	return 0;
    }
    return 1;
}


/*
 * daemon - Detach us from the terminal session.
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

/*
 * ppp_available - check whether the system has any ppp interfaces
 * (in fact we check whether we can do an ioctl on ppp0).
 */
int
ppp_available()
{
    int s, ok;
    struct ifreq ifr;
    extern char *no_ppp_msg;

    if ((s = socket(AF_INET, SOCK_DGRAM, 0)) < 0)
	return 1;		/* can't tell */

    strlcpy(ifr.ifr_name, "ppp0", sizeof (ifr.ifr_name));
    ok = ioctl(s, SIOCGIFFLAGS, (caddr_t) &ifr) >= 0;
    close(s);

    no_ppp_msg = "\
This system lacks kernel support for PPP.  To include PPP support\n\
in the kernel, please follow the steps detailed in the README.ultrix\n\
file in the ppp-2.2 distribution.\n";
    return ok;
}

/*
 * establish_ppp - Turn the serial port into a ppp interface.
 */
int
establish_ppp(fd)
    int fd;
{
    int pppdisc = PPPDISC;
    int x;

    /*
     * Save the old line discipline of fd, and set it to PPP.
     */
    if (ioctl(fd, TIOCGETD, &initdisc) < 0)
	fatal("ioctl(TIOCGETD): %m");
    if (ioctl(fd, TIOCSETD, &pppdisc) < 0)
	fatal("ioctl(TIOCSETD): %m");

    /*
     * Find out which interface we were given.
     */
    if (ioctl(fd, PPPIOCGUNIT, &ifunit) < 0) {
	fatal("ioctl(PPPIOCGUNIT): %m");

    ppp_fd = fd;

    /*
     * Enable debug in the driver if requested.
     */
    if (kdebugflag) {
	if (ioctl(fd, PPPIOCGFLAGS, (caddr_t) &x) < 0) {
	    warn("ioctl (PPPIOCGFLAGS): %m");
	} else {
	    x |= (kdebugflag & 0xFF) * SC_DEBUG;
	    if (ioctl(fd, PPPIOCSFLAGS, (caddr_t) &x) < 0)
		warn("ioctl(PPPIOCSFLAGS): %m");
	}
    }

    /*
     * Set device for non-blocking reads.
     */
    if ((initfdflags = fcntl(fd, F_GETFL)) == -1
	|| fcntl(fd, F_SETFL, initfdflags | O_NONBLOCK) == -1) {
	warn("Couldn't set device to non-blocking mode: %m");
    }

    return fd;
}

/*
 * restore_loop - reattach the ppp unit to the loopback.
 */
void
restore_loop()
{
}

/*
 * disestablish_ppp - Restore the serial port to normal operation.
 * This shouldn't call die() because it's called from die().
 */
void
disestablish_ppp(fd)
     int fd;
{
    /* Reset non-blocking mode on fd. */
    if (initfdflags != -1 && fcntl(fd, F_SETFL, initfdflags) < 0)
	warn("Couldn't restore device fd flags: %m");
    initfdflags = -1;

    /* Restore old line discipline. */
    if (initdisc >= 0 && ioctl(fd, TIOCSETD, &initdisc) < 0)
	error("ioctl(TIOCSETD): %m");
    initdisc = -1;

    if (fd == ppp_fd)
	ppp_fd = -1;
}

/*
 * Check whether the link seems not to be 8-bit clean.
 */
void
clean_check()
{
    int x;
    char *s;

    if (ioctl(ppp_fd, PPPIOCGFLAGS, (caddr_t) &x) == 0) {
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
	    warn("Serial link is not 8-bit clean:");
	    warn("All received characters had %s", s);
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
    warn("speed %d not supported", bps);
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

/*
 * set_up_tty: Set up the serial port on `fd' for 8 bits, no parity,
 * at the requested speed, etc.  If `local' is true, set CLOCAL
 * regardless of whether the modem option was specified.
 */
void
set_up_tty(fd, local)
    int fd, local;
{
    int speed, x;
    struct termios tios;

    if (tcgetattr(fd, &tios) < 0)
	fatal("tcgetattr: %m");

    if (!restore_term) {
	inittermios = tios;
	ioctl(fd, TIOCGWINSZ, &wsinfo);
    }

    tios.c_cflag &= ~(CSIZE | CSTOPB | PARENB | CLOCAL);
#ifdef CRTSCTS
    if (crtscts > 0 && !local)
	tios.c_cflag |= CRTSCTS;
    else if (crtscts < 0)
	tios.c_cflag &= ~CRTSCTS;
#endif	/* CRTSCTS */

    tios.c_cflag |= CS8 | CREAD | HUPCL;
    if (local || !modem)
	tios.c_cflag |= CLOCAL;
    tios.c_iflag = IGNBRK | IGNPAR;
    tios.c_oflag = 0;
    tios.c_lflag = 0;
    tios.c_cc[VMIN] = 1;
    tios.c_cc[VTIME] = 0;

    if (crtscts == -2) {
	tios.c_iflag |= IXON | IXOFF;
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
	if (speed == B0)
	    fatal("Baud rate for %s is 0; need explicit baud rate", devnam);
    }

    if (tcsetattr(fd, TCSAFLUSH, &tios) < 0)
	fatal("tcsetattr: %m");

    x = 0;
    if (ioctl(fd, (crtscts > 0 || modem)? TIOCMODEM: TIOCNMODEM, &x) < 0)
	warn("TIOC(N)MODEM: %m");
    if (ioctl(fd, (local || !modem)? TIOCNCAR: TIOCCAR) < 0)
	warn("TIOC(N)CAR: %m");

    baud_rate = inspeed = baud_rate_of(speed);
    restore_term = 1;
}

/*
 * restore_tty - restore the terminal to the saved settings.
 */
void
restore_tty(fd)
    int fd;
{
    if (restore_term) {
	if (!default_device) {
	    /*
	     * Turn off echoing, because otherwise we can get into
	     * a loop with the tty and the modem echoing to each other.
	     * We presume we are the sole user of this tty device, so
	     * when we close it, it will revert to its defaults anyway.
	     */
	    inittermios.c_lflag &= ~(ECHO | ECHONL);
	}
	if (tcsetattr(fd, TCSAFLUSH, &inittermios) < 0)
	    if (errno != ENXIO)
		warn("tcsetattr: %m");
	ioctl(fd, TIOCSWINSZ, &wsinfo);
	restore_term = 0;
    }
}

/*
 * setdtr - control the DTR line on the serial port.
 * This is called from die(), so it shouldn't call die().
 */
void
setdtr(fd, on)
int fd, on;
{
    int modembits = TIOCM_DTR;

    ioctl(fd, (on? TIOCMBIS: TIOCMBIC), &modembits);
}


/*
 * open_ppp_loopback - open the device we use for getting
 * packets in demand mode, and connect it to a ppp interface.
 * Here we use would use a pty, except that Ultrix ptys are brain-dead.
 */
int
open_ppp_loopback()
{
    fatal("open_ppp_loopback called!");
    /* return loop_master; */
}


/*
 * output - Output PPP packet.
 */
void
output(unit, p, len)
    int unit;
    u_char *p;
    int len;
{
    if (debug)
	dbglog("sent %P", p, len);

    if (write(ttyfd, p, len) < 0) {
	if (errno != EIO)
	    error("write: %m");
    }
}


/*
 * wait_input - wait until there is data available,
 * for the length of time specified by *timo (indefinite
 * if timo is NULL).
 */
void
wait_input(timo)
    struct timeval *timo;
{
    fd_set ready;
    int n;

    ready = in_fds;
    n = select(ttyfd+1, &ready, NULL, &ready, timo);
    if (n < 0 && errno != EINTR)
	fatal("select: %m");
}


/*
 * add_fd - add an fd to the set that wait_input waits for.
 */
void add_fd(int fd)
{
    FD_SET(fd, &in_fds);
    if (fd > max_in_fd)
	max_in_fd = fd;
}

/*
 * remove_fd - remove an fd from the set that wait_input waits for.
 */
void remove_fd(int fd)
{
    FD_CLR(fd, &in_fds);
}

#if 0
/*
 * wait_loop_output - wait until there is data available on the
 * loopback, for the length of time specified by *timo (indefinite
 * if timo is NULL).
 */
void
wait_loop_output(timo)
    struct timeval *timo;
{
    wait_time(timo);
}


/*
 * wait_time - wait for a given length of time or until a
 * signal is received.
 */
void
wait_time(timo)
    struct timeval *timo;
{
    int n;

    n = select(0, NULL, NULL, NULL, timo);
    if (n < 0 && errno != EINTR)
	fatal("select: %m");
}
#endif

/*
 * read_packet - get a PPP packet from the serial device.
 */
int
read_packet(buf)
    u_char *buf;
{
    int len;

    if ((len = read(ttyfd, buf, PPP_MTU + PPP_HDRLEN)) < 0) {
	if (errno == EWOULDBLOCK || errno == EINTR)
	    return -1;
	fatal("read(fd): %m");
    }
    return len;
}


/*
 * get_loop_output - read characters from the loopback, form them
 * into frames, and detect when we want to bring the real link up.
 * Return value is 1 if we need to bring up the link, 0 otherwise.
 */
int
get_loop_output()
{
    return 0;
}


/*
 * ppp_send_config - configure the transmit characteristics of
 * the ppp interface.
 */
void
ppp_send_config(unit, mtu, asyncmap, pcomp, accomp)
    int unit, mtu;
    u_int32_t asyncmap;
    int pcomp, accomp;
{
    u_int x;

    if (ioctl(ppp_fd, PPPIOCSMTU, &mtu) < 0)
	fatal("ioctl(PPPIOCSMTU): %m");

    if (ioctl(ppp_fd, PPPIOCSASYNCMAP, (caddr_t) &asyncmap) < 0)
	fatal("ioctl(PPPIOCSASYNCMAP): %m");

    if (ioctl(ppp_fd, PPPIOCGFLAGS, (caddr_t) &x) < 0)
	fatal("ioctl (PPPIOCGFLAGS): %m");
    x = pcomp? x | SC_COMP_PROT: x &~ SC_COMP_PROT;
    x = accomp? x | SC_COMP_AC: x &~ SC_COMP_AC;
    if (ioctl(ppp_fd, PPPIOCSFLAGS, (caddr_t) &x) < 0)
	fatal("ioctl(PPPIOCSFLAGS): %m");
}


/*
 * ppp_set_xaccm - set the extended transmit ACCM for the interface.
 */
void
ppp_set_xaccm(unit, accm)
    int unit;
    ext_accm accm;
{
    if (ioctl(ppp_fd, PPPIOCSXASYNCMAP, accm) < 0 && errno != ENOTTY)
	warn("ioctl(set extended ACCM): %m");
}


/*
 * ppp_recv_config - configure the receive-side characteristics of
 * the ppp interface.
 */
void
ppp_recv_config(unit, mru, asyncmap, pcomp, accomp)
    int unit, mru;
    u_int32_t asyncmap;
    int pcomp, accomp;
{
    int x;

    if (ioctl(ppp_fd, PPPIOCSMRU, (caddr_t) &mru) < 0)
	fatal("ioctl(PPPIOCSMRU): %m");
    if (ioctl(ppp_fd, PPPIOCSRASYNCMAP, (caddr_t) &asyncmap) < 0)
	fatal("ioctl(PPPIOCSRASYNCMAP): %m");
    if (ioctl(ppp_fd, PPPIOCGFLAGS, (caddr_t) &x) < 0)
	fatal("ioctl (PPPIOCGFLAGS): %m");
    x = !accomp? x | SC_REJ_COMP_AC: x &~ SC_REJ_COMP_AC;
    if (ioctl(ppp_fd, PPPIOCSFLAGS, (caddr_t) &x) < 0)
	fatal("ioctl(PPPIOCSFLAGS): %m");
}

/*
 * ccp_test - ask kernel whether a given compression method
 * is acceptable for use.  Returns 1 if the method and parameters
 * are OK, 0 if the method is known but the parameters are not OK
 * (e.g. code size should be reduced), or -1 if the method is unknown.
 */
int
ccp_test(unit, opt_ptr, opt_len, for_transmit)
    int unit, opt_len, for_transmit;
    u_char *opt_ptr;
{
    struct ppp_option_data data;

    data.ptr = opt_ptr;
    data.length = opt_len;
    data.transmit = for_transmit;
    if (ioctl(ttyfd, PPPIOCSCOMPRESS, (caddr_t) &data) >= 0)
	return 1;
    return (errno == ENOBUFS)? 0: -1;
}

/*
 * ccp_flags_set - inform kernel about the current state of CCP.
 */
void
ccp_flags_set(unit, isopen, isup)
    int unit, isopen, isup;
{
    int x;

    if (ioctl(ppp_fd, PPPIOCGFLAGS, (caddr_t) &x) < 0) {
	error("ioctl (PPPIOCGFLAGS): %m");
	return;
    }
    x = isopen? x | SC_CCP_OPEN: x &~ SC_CCP_OPEN;
    x = isup? x | SC_CCP_UP: x &~ SC_CCP_UP;
    if (ioctl(ppp_fd, PPPIOCSFLAGS, (caddr_t) &x) < 0)
	error("ioctl(PPPIOCSFLAGS): %m");
}

/*
 * ccp_fatal_error - returns 1 if decompression was disabled as a
 * result of an error detected after decompression of a packet,
 * 0 otherwise.  This is necessary because of patent nonsense.
 */
int
ccp_fatal_error(unit)
    int unit;
{
    int x;

    if (ioctl(ppp_fd, PPPIOCGFLAGS, (caddr_t) &x) < 0) {
	error("ioctl(PPPIOCGFLAGS): %m");
	return 0;
    }
    return x & SC_DC_FERROR;
}

/*
 * get_idle_time - return how long the link has been idle.
 */
int
get_idle_time(u, ip)
    int u;
    struct ppp_idle *ip;
{
    return ioctl(ppp_fd, PPPIOCGIDLE, ip) >= 0;
}


/*
 * sifvjcomp - config tcp header compression
 */
int
sifvjcomp(u, vjcomp, cidcomp, maxcid)
    int u, vjcomp, cidcomp, maxcid;
{
    u_int x;

    if (ioctl(ppp_fd, PPPIOCGFLAGS, (caddr_t) &x) < 0) {
	error("ioctl (PPPIOCGFLAGS): %m");
	return 0;
    }
    x = vjcomp ? x | SC_COMP_TCP: x &~ SC_COMP_TCP;
    x = cidcomp? x & ~SC_NO_TCP_CCID: x | SC_NO_TCP_CCID;
    if (ioctl(ppp_fd, PPPIOCSFLAGS, (caddr_t) &x) < 0) {
	error("ioctl(PPPIOCSFLAGS): %m");
	return 0;
    }
    if (ioctl(ppp_fd, PPPIOCSMAXCID, (caddr_t) &maxcid) < 0) {
	error("ioctl(PPPIOCSFLAGS): %m");
	return 0;
    }
    return 1;
}

/*
 * sifup - Config the interface up and enable IP packets to pass.
 */
int
sifup(u)
    int u;
{
    struct ifreq ifr;

    strlcpy(ifr.ifr_name, ifname, sizeof (ifr.ifr_name));
    if (ioctl(sockfd, SIOCGIFFLAGS, (caddr_t) &ifr) < 0) {
	error("ioctl (SIOCGIFFLAGS): %m");
	return 0;
    }
    ifr.ifr_flags |= IFF_UP;
    if (ioctl(sockfd, SIOCSIFFLAGS, (caddr_t) &ifr) < 0) {
	error("ioctl(SIOCSIFFLAGS): %m");
	return 0;
    }
    if_is_up = 1;
    return 1;
}

/*
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
    npi.mode = mode;
    if (ioctl(ppp_fd, PPPIOCSNPMODE, &npi) < 0) {
	error("ioctl(set NP %d mode to %d): %m", proto, mode);
	return 0;
    }
    return 1;
}

/*
 * sifdown - Config the interface down and disable IP.
 */
int
sifdown(u)
    int u;
{
    struct ifreq ifr;
    int rv;
    struct npioctl npi;

    rv = 1;
    npi.protocol = PPP_IP;
    npi.mode = NPMODE_ERROR;
    ioctl(ppp_fd, PPPIOCSNPMODE, (caddr_t) &npi);
    /* ignore errors, because ppp_fd might have been closed by now. */

    strlcpy(ifr.ifr_name, ifname, sizeof (ifr.ifr_name));
    if (ioctl(sockfd, SIOCGIFFLAGS, (caddr_t) &ifr) < 0) {
	error("ioctl (SIOCGIFFLAGS): %m");
	rv = 0;
    } else {
	ifr.ifr_flags &= ~IFF_UP;
	if (ioctl(sockfd, SIOCSIFFLAGS, (caddr_t) &ifr) < 0) {
	    error("ioctl(SIOCSIFFLAGS): %m");
	    rv = 0;
	} else
	    if_is_up = 0;
    }
    return rv;
}

/*
 * SET_SA_FAMILY - set the sa_family field of a struct sockaddr,
 * if it exists.
 */
#define SET_SA_FAMILY(addr, family)             \
    BZERO((char *) &(addr), sizeof(addr));      \
    addr.sa_family = (family); 

/*
 * sifaddr - Config the interface IP addresses and netmask.
 */
int
sifaddr(u, o, h, m)
    int u;
    u_int32_t o, h, m;
{
    int ret;
    struct ifreq ifr;

    ret = 1;
    strlcpy(ifr.ifr_name, ifname, sizeof (ifr.ifr_name));
    SET_SA_FAMILY(ifr.ifr_addr, AF_INET);
    if (m != 0) {
        ((struct sockaddr_in *) &ifr.ifr_addr)->sin_addr.s_addr = m;
        info("Setting interface mask to %s\n", ip_ntoa(m));
        if (ioctl(sockfd, SIOCSIFNETMASK, (caddr_t) &ifr) < 0) {
            error("ioctl(SIOCSIFNETMASK): %m");
            ret = 0;
        }
    }
    ((struct sockaddr_in *) &ifr.ifr_addr)->sin_addr.s_addr = o;
    if (ioctl(sockfd, SIOCSIFADDR, (caddr_t) &ifr) < 0) {
        error("ioctl(SIOCSIFADDR): %m");
        ret = 0;
    }
    ((struct sockaddr_in *) &ifr.ifr_dstaddr)->sin_addr.s_addr = h;
    if (ioctl(sockfd, SIOCSIFDSTADDR, (caddr_t) &ifr) < 0) {
        error("ioctl(SIOCSIFDSTADDR): %m");
        ret = 0;
    }
    ifaddrs[0] = o;
    ifaddrs[1] = h;
    return ret;
}

/*
 * cifaddr - Clear the interface IP addresses, and delete routes
 * through the interface if possible.
 */
int
cifaddr(u, o, h)
    int u;
    u_int32_t o, h;
{
    struct rtentry rt;

    ifaddrs[0] = 0;
    BZERO(&rt, sizeof(rt));
    SET_SA_FAMILY(rt.rt_dst, AF_INET);
    ((struct sockaddr_in *) &rt.rt_dst)->sin_addr.s_addr = h;
    SET_SA_FAMILY(rt.rt_gateway, AF_INET);
    ((struct sockaddr_in *) &rt.rt_gateway)->sin_addr.s_addr = o;
    rt.rt_flags = RTF_HOST;
    if (ioctl(sockfd, SIOCDELRT, (caddr_t) &rt) < 0) {
        error("ioctl(SIOCDELRT): %m");
        return 0;
    }
    return 1;
}

/*
 * sifdefaultroute - assign a default route through the address given.
 */
int
sifdefaultroute(u, l, g)
    int u;
    u_int32_t l, g;
{
    struct rtentry rt;

    BZERO(&rt, sizeof(rt));
    SET_SA_FAMILY(rt.rt_dst, AF_INET);
    SET_SA_FAMILY(rt.rt_gateway, AF_INET);
    ((struct sockaddr_in *) &rt.rt_gateway)->sin_addr.s_addr = g;
    rt.rt_flags = RTF_GATEWAY;
    if (ioctl(sockfd, SIOCADDRT, &rt) < 0) {
        error("default route ioctl(SIOCADDRT): %m");
        return 0;
    }
    default_route_gateway = g;
    return 1;
}

/*
 * cifdefaultroute - delete a default route through the address given.
 */
int
cifdefaultroute(u, l, g)
    int u;
    u_int32_t l, g;
{
    struct rtentry rt;

    BZERO(&rt, sizeof(rt));
    SET_SA_FAMILY(rt.rt_dst, AF_INET);
    SET_SA_FAMILY(rt.rt_gateway, AF_INET);
    ((struct sockaddr_in *) &rt.rt_gateway)->sin_addr.s_addr = g;
    rt.rt_flags = RTF_GATEWAY;
    if (ioctl(sockfd, SIOCDELRT, &rt) < 0)
        warn("default route ioctl(SIOCDELRT): %m");
    default_route_gateway = 0;
    return 1;
}

/*
 * sifproxyarp - Make a proxy ARP entry for the peer.
 */
int
sifproxyarp(unit, hisaddr)
    int unit;
    u_int32_t hisaddr;
{
    struct arpreq arpreq;

    BZERO(&arpreq, sizeof(arpreq));

    /*
     * Get the hardware address of an interface on the same subnet
     * as our local address.
     */
    if (!get_ether_addr(hisaddr, &arpreq.arp_ha)) {
	error("Cannot determine ethernet address for proxy ARP");
	return 0;
    }

    SET_SA_FAMILY(arpreq.arp_pa, AF_INET);
    ((struct sockaddr_in *) &arpreq.arp_pa)->sin_addr.s_addr = hisaddr;
    arpreq.arp_flags = ATF_PERM | ATF_PUBL;
    if (ioctl(sockfd, SIOCSARP, (caddr_t)&arpreq) < 0) {
	error("Couldn't add proxy arp entry: %m");
	return 0;
    }

    proxy_arp_addr = hisaddr;
    return 1;
}

/*
 * cifproxyarp - Delete the proxy ARP entry for the peer.
 */
int
cifproxyarp(unit, hisaddr)
    int unit;
    u_int32_t hisaddr;
{
    struct arpreq arpreq;

    BZERO(&arpreq, sizeof(arpreq));
    SET_SA_FAMILY(arpreq.arp_pa, AF_INET);
    ((struct sockaddr_in *) &arpreq.arp_pa)->sin_addr.s_addr = hisaddr;
    if (ioctl(sockfd, SIOCDARP, (caddr_t)&arpreq) < 0) {
	warn("Couldn't delete proxy arp entry: %m");
	return 0;
    }
    proxy_arp_addr = 0;
    return 1;
}

/*
 * get_ether_addr - get the hardware address of an interface on the
 * the same subnet as ipaddr.
 */
#define MAX_IFS		32

static int
get_ether_addr(ipaddr, hwaddr)
    u_int32_t ipaddr;
    struct sockaddr *hwaddr;
{
    struct ifreq *ifr, *ifend;
    u_int32_t ina, mask;
    struct ifreq ifreq;
    struct ifconf ifc;
    struct ifreq ifs[MAX_IFS];
    struct ifdevea ifdevea;

    ifc.ifc_len = sizeof(ifs);
    ifc.ifc_req = ifs;
    if (ioctl(sockfd, SIOCGIFCONF, &ifc) < 0) {
	error("ioctl(SIOCGIFCONF): %m");
	return 0;
    }

    /*
     * Scan through looking for an interface with an Internet
     * address on the same subnet as `ipaddr'.
     */
    ifend = (struct ifreq *) (ifc.ifc_buf + ifc.ifc_len);
    for (ifr = ifc.ifc_req; ifr < ifend; ifr = (struct ifreq *)
	    ((char *)&ifr->ifr_addr + sizeof(struct sockaddr))) {
        if (ifr->ifr_addr.sa_family == AF_INET) {
            ina = ((struct sockaddr_in *) &ifr->ifr_addr)->sin_addr.s_addr;
            strlcpy(ifreq.ifr_name, ifr->ifr_name, sizeof(ifreq.ifr_name));
            /*
             * Check that the interface is up, and not point-to-point
             * or loopback.
             */
            if (ioctl(sockfd, SIOCGIFFLAGS, &ifreq) < 0)
                continue;
            if ((ifreq.ifr_flags &
                 (IFF_UP|IFF_BROADCAST|IFF_POINTOPOINT|IFF_LOOPBACK|IFF_NOARP))
                 != (IFF_UP|IFF_BROADCAST))
                continue;
            /*
             * Get its netmask and check that it's on the right subnet.
             */
            if (ioctl(sockfd, SIOCGIFNETMASK, &ifreq) < 0)
                continue;
            mask = ((struct sockaddr_in *) &ifreq.ifr_addr)->sin_addr.s_addr;
            if ((ipaddr & mask) != (ina & mask))
                continue;

	    break;
	}
    }

    if (ifr >= ifend)
	return 0;
    info("found interface %s for proxy arp", ifr->ifr_name);

    /*
     * Grab the physical address for this interface.
     */
    strlcpy(ifdevea.ifr_name, ifr->ifr_name, sizeof(ifdevea.ifr_name));
    if (ioctl(sockfd, SIOCRPHYSADDR, &ifdevea) < 0) {
	error("Couldn't get h/w address for %s: %m", ifr->ifr_name);
	return 0;
    }

    hwaddr->sa_family = AF_UNSPEC;
    BCOPY(ifdevea.current_pa, hwaddr->sa_data, 6);
    return 1;
}

/*
 * Return user specified netmask, modified by any mask we might determine
 * for address `addr' (in network byte order).
 * Here we scan through the system's list of interfaces, looking for
 * any non-point-to-point interfaces which might appear to be on the same
 * network as `addr'.  If we find any, we OR in their netmask to the
 * user-specified netmask.
 */
u_int32_t
GetMask(addr)
    u_int32_t addr;
{
    u_int32_t mask, nmask, ina;
    struct ifreq *ifr, *ifend, ifreq;
    struct ifconf ifc;
    struct ifreq ifs[MAX_IFS];

    addr = ntohl(addr);
    if (IN_CLASSA(addr))	/* determine network mask for address class */
	nmask = IN_CLASSA_NET;
    else if (IN_CLASSB(addr))
	nmask = IN_CLASSB_NET;
    else
	nmask = IN_CLASSC_NET;
    /* class D nets are disallowed by bad_ip_adrs */
    mask = netmask | htonl(nmask);

    /*
     * Scan through the system's network interfaces.
     */
    ifc.ifc_len = sizeof(ifs);
    ifc.ifc_req = ifs;
    if (ioctl(sockfd, SIOCGIFCONF, &ifc) < 0) {
	warn("ioctl(SIOCGIFCONF): %m");
	return mask;
    }
    ifend = (struct ifreq *) (ifc.ifc_buf + ifc.ifc_len);
    for (ifr = ifc.ifc_req; ifr < ifend; ifr = (struct ifreq *)
	 	((char *)&ifr->ifr_addr + sizeof(struct sockaddr))) {
	/*
	 * Check the interface's internet address.
	 */
	if (ifr->ifr_addr.sa_family != AF_INET)
	    continue;
	ina = ((struct sockaddr_in *) &ifr->ifr_addr)->sin_addr.s_addr;
	if ((ntohl(ina) & nmask) != (addr & nmask))
	    continue;
	/*
	 * Check that the interface is up, and not point-to-point or loopback.
	 */
	strlcpy(ifreq.ifr_name, ifr->ifr_name, sizeof(ifreq.ifr_name));
	if (ioctl(sockfd, SIOCGIFFLAGS, &ifreq) < 0)
	    continue;
	if ((ifreq.ifr_flags & (IFF_UP|IFF_POINTOPOINT|IFF_LOOPBACK))
	    != IFF_UP)
	    continue;
	/*
	 * Get its netmask and OR it into our mask.
	 */
	if (ioctl(sockfd, SIOCGIFNETMASK, &ifreq) < 0)
	    continue;
	mask |= ((struct sockaddr_in *)&ifreq.ifr_addr)->sin_addr.s_addr;
    }

    return mask;
}

/*
 * have_route_to - determine if the system has any route to
 * a given IP address.
 * For demand mode to work properly, we have to ignore routes
 * through our own interface.
 */
int have_route_to(u_int32_t addr)
{
    return -1;
}


/*
 * Use the hostid as part of the random number seed.
 */
int
get_host_seed()
{
    return gethostid();
}


/*
  Seems like strdup() is not part of string package in Ultrix.
  If I understood the man-page on the sun this should work.

  Robert Olsson
*/

char *strdup( in ) char *in;
{
  char* dup;
  if(! (dup = (char *) malloc( strlen( in ) +1 ))) return NULL;
  (void) strcpy( dup, in );
  return dup;
}

/*
 * This logwtmp() implementation is subject to the following copyright:
 *
 * Copyright (c) 1988 The Regents of the University of California.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms are permitted
 * provided that the above copyright notice and this paragraph are
 * duplicated in all such forms and that any documentation,
 * advertising materials, and other materials related to such
 * distribution and use acknowledge that the software was developed
 * by the University of California, Berkeley.  The name of the
 * University may not be used to endorse or promote products derived
 * from this software without specific prior written permission.
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND WITHOUT ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, WITHOUT LIMITATION, THE IMPLIED
 * WARRANTIES OF MERCHANTIBILITY AND FITNESS FOR A PARTICULAR PURPOSE.
 */

#define	WTMPFILE	"/usr/adm/wtmp"

void
logwtmp(line, name, host)
    const char *line, *name, *host;
{
    int fd;
    struct stat buf;
    struct utmp ut;

    if ((fd = open(WTMPFILE, O_WRONLY|O_APPEND, 0)) < 0)
	return;
    if (!fstat(fd, &buf)) {
	strlcpy(ut.ut_line, line, sizeof(ut.ut_line));
	strlcpy(ut.ut_name, name, sizeof(ut.ut_name));
	strlcpy(ut.ut_host, host, sizeof(ut.ut_host));
	(void)time(&ut.ut_time);
	if (write(fd, (char *)&ut, sizeof(struct utmp)) != sizeof(struct utmp))
	    (void)ftruncate(fd, buf.st_size);
    }
    close(fd);
}

/*
 * Routines for locking and unlocking the serial device, moved here
 * from chat.c.
 */

#define LOCK_PREFIX	"/usr/spool/uucp/LCK.."

/*
 * lock - create a lock file for the named device
 */
int
lock(dev)
    char *dev;
{
    int fd, pid, n;
    char *p;
    size_t l;

    if ((p = strrchr(dev, '/')) != NULL)
	dev = p + 1;
    l = strlen(LOCK_PREFIX) + strlen(dev) + 1;
    lock_file = malloc(l);
    if (lock_file == NULL)
	novm("lock file name");
    slprintf(lock_file, l, "%s%s, LOCK_PREFIX, dev);

    while ((fd = open(lock_file, O_EXCL | O_CREAT | O_RDWR, 0644)) < 0) {
	if (errno == EEXIST
	    && (fd = open(lock_file, O_RDONLY, 0)) >= 0) {
	    /* Read the lock file to find out who has the device locked */
	    n = read(fd, &pid, sizeof(pid));
	    if (n <= 0) {
		error("Can't read pid from lock file %s", lock_file);
		close(fd);
	    } else {
		if (kill(pid, 0) == -1 && errno == ESRCH) {
		    /* pid no longer exists - remove the lock file */
		    if (unlink(lock_file) == 0) {
			close(fd);
			notice("Removed stale lock on %s (pid %d)",
			       dev, pid);
			continue;
		    } else
			warn("Couldn't remove stale lock on %s",
			       dev);
		} else
		    notice("Device %s is locked by pid %d",
			   dev, pid);
	    }
	    close(fd);
	} else
	    error("Can't create lock file %s: %m", lock_file);
	free(lock_file);
	lock_file = NULL;
	return -1;
    }

    pid = getpid();
    write(fd, &pid, sizeof pid);

    close(fd);
    return 0;
}

/*
 * unlock - remove our lockfile
 */
void
unlock()
{
    if (lock_file) {
	unlink(lock_file);
	free(lock_file);
	lock_file = NULL;
    }
}
