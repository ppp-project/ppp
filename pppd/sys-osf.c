/*
 * System-dependent procedures for pppd under Digital UNIX (OSF/1).
 *
 * Copyright (c) 1994 The Australian National University.
 * All rights reserved.
 *
 * Permission to use, copy, modify, and distribute this software and its
 * documentation is hereby granted, provided that the above copyright
 * notice appears in all copies.  This software is provided without any
 * warranty, express or implied. The Australian National University
 * makes no representations about the suitability of this software for
 * any purpose.
 *
 * IN NO EVENT SHALL THE AUSTRALIAN NATIONAL UNIVERSITY BE LIABLE TO ANY
 * PARTY FOR DIRECT, INDIRECT, SPECIAL, INCIDENTAL, OR CONSEQUENTIAL DAMAGES
 * ARISING OUT OF THE USE OF THIS SOFTWARE AND ITS DOCUMENTATION, EVEN IF
 * THE AUSTRALIAN NATIONAL UNIVERSITY HAVE BEEN ADVISED OF THE POSSIBILITY
 * OF SUCH DAMAGE.
 *
 * THE AUSTRALIAN NATIONAL UNIVERSITY SPECIFICALLY DISCLAIMS ANY WARRANTIES,
 * INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY
 * AND FITNESS FOR A PARTICULAR PURPOSE.  THE SOFTWARE PROVIDED HEREUNDER IS
 * ON AN "AS IS" BASIS, AND THE AUSTRALIAN NATIONAL UNIVERSITY HAS NO
 * OBLIGATION TO PROVIDE MAINTENANCE, SUPPORT, UPDATES, ENHANCEMENTS,
 * OR MODIFICATIONS.
 */

#ifndef lint
static char rcsid[] = "$Id: sys-osf.c,v 1.24 1999/04/01 07:20:10 paulus Exp $";
#endif

#include <stdio.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <termios.h>
#include <signal.h>
#include <malloc.h>
#include <utmp.h>
#include <sys/types.h>
#include <sys/param.h>
#include <sys/socket.h>
#include <sys/stream.h>
#include <sys/stropts.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/poll.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <net/if_dl.h>
#include <net/if_arp.h>
#include <net/route.h>
#include <net/ppp_defs.h>
#include <net/pppio.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "pppd.h"

static int	pppfd;
static int	fdmuxid = -1;
static int	iffd;
static int	sockfd;

static int	restore_term;
static struct termios inittermios;
static struct winsize wsinfo;	/* Initial window size info */
static pid_t	tty_sid;	/* PID of our session leader */

extern u_char	inpacket_buf[];	/* borrowed from main.c */

static int	link_mtu, link_mru;

#define NMODULES	32
static int	tty_nmodules;
static char	tty_modules[NMODULES][FMNAMESZ+1];

static int closed_stdio;
static int initfdflags = -1;
static int orig_ttyfd = -1;

static int	if_is_up;	/* Interface has been marked up */
static u_int32_t ifaddrs[2];	/* local and remote addresses */
static u_int32_t default_route_gateway;	/* Gateway for default route added */
static u_int32_t proxy_arp_addr;	/* Addr for proxy arp entry added */

#define MAX_POLLFDS	32
static struct pollfd pollfds[MAX_POLLFDS];
static int n_pollfds;

/* Prototypes for procedures local to this file. */
static int translate_speed __P((int));
static int baud_rate_of __P((int));
static int get_ether_addr __P((u_int32_t, struct sockaddr *));
static int strioctl __P((int, int, void *, int, int));


/*
 * sys_init - System-dependent initialization.
 */
void
sys_init()
{
    int x;

    openlog("pppd", LOG_PID | LOG_NDELAY, LOG_PPP);
    setlogmask(LOG_UPTO(LOG_INFO));
    if (debug)
	setlogmask(LOG_UPTO(LOG_DEBUG));

    /* Get an internet socket for doing socket ioctl's on. */
    if ((sockfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0)
	fatal("Couldn't create IP socket: %m");

    if (default_device)
	tty_sid = getsid((pid_t)0);

    /*
     * Open the ppp device.
     */
    pppfd = open("/dev/streams/ppp", O_RDWR | O_NONBLOCK, 0);
    if (pppfd < 0)
	fatal("Can't open /dev/streams/ppp: %m");
    if (kdebugflag) {
	x = PPPDBG_LOG + PPPDBG_DRIVER;
	strioctl(pppfd, PPPIO_DEBUG, &x, sizeof(int), 0);
    }

    /* Assign a new PPA and get its unit number. */
    if (strioctl(pppfd, PPPIO_NEWPPA, &ifunit, 0, sizeof(int)) < 0)
	fatal("Can't create new PPP interface: %m");

    /*
     * Open the ppp device again and push the if_ppp module on it.
     */
    iffd = open("/dev/streams/ppp", O_RDWR, 0);
    if (iffd < 0)
	fatal("Can't open /dev/streams/ppp (2): %m");
    if (kdebugflag) {
	x = PPPDBG_LOG + PPPDBG_DRIVER;
	strioctl(iffd, PPPIO_DEBUG, &x, sizeof(int), 0);
    }
    if (strioctl(iffd, PPPIO_ATTACH, &ifunit, sizeof(int), 0) < 0)
	fatal("Couldn't attach ppp interface to device: %m");
    if (ioctl(iffd, I_PUSH, "if_ppp") < 0)
	fatal("Can't push ppp interface module: %m");
    if (kdebugflag) {
	x = PPPDBG_LOG + PPPDBG_IF;
	strioctl(iffd, PPPIO_DEBUG, &x, sizeof(int), 0);
    }
    if (strioctl(iffd, PPPIO_NEWPPA, &ifunit, sizeof(int), 0) < 0)
	fatal("Couldn't create ppp interface unit: %m");
    x = PPP_IP;
    if (strioctl(iffd, PPPIO_BIND, &x, sizeof(int), 0) < 0)
	fatal("Couldn't bind ppp interface to IP SAP: %m");

    n_pollfds = 0;
}

/*
 * sys_cleanup - restore any system state we modified before exiting:
 * mark the interface down, delete default route and/or proxy arp entry.
 * This shouldn't call die() because it's called from die().
 */
void
sys_cleanup()
{
    if (if_is_up)
	sifdown(0);
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
    close(iffd);
    close(pppfd);
    close(sockfd);
    closelog();
}

/*
 * sys_check_options - check the options that the user specified
 */
int
sys_check_options()
{
    return 1;
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

/*
 * ppp_available - check whether the system has any ppp interfaces
 */
int
ppp_available()
{
    struct stat buf;

    return stat("/dev/streams/ppp", &buf) >= 0;
}

char pipename[] = "/dev/streams/pipe";

/*
 *  streampipe -- Opens a STREAMS based pipe.  Used by streamify().
 */

int 
streampipe(int fd[2])
{
    if ((fd[0]=open(pipename, O_RDWR)) == -1)
	return(-1);
    else if ((fd[1]=open(pipename, O_RDWR)) == -1) {
	close(fd[0]);
	return(-1);
    } else if (ioctl(fd[0], I_PIPE, fd[1]) != 0) {
	close(fd[0]);
	close(fd[1]);
	return(-1);
    } else {
	return(ioctl(fd[0], I_PUSH, "pipemod"));
    }
}

/*
 *  streamify -- Needed for Digital UNIX, since some tty devices are not STREAMS
 *               modules (but ptys are, and pipes can be).
 */

#define BUFFSIZE 1000     /*  Size of buffer for streamify()  */

int 
streamify(int fd)
{
    int fdes[2];
    fd_set readfds;
    int ret, fret, rret, maxfd;
    static char buffer[BUFFSIZE];
    struct sigaction sa;

    if (streampipe(fdes) != 0)
	error("streampipe(): %m\n");
    else if (isastream(fdes[0]) == 1) {
	if ((fret=fork()) < 0) {
	    error("fork(): %m\n");
	} else if (fret == 0) {
	    /*  Process to forward things from pipe to tty  */
            sigemptyset(&(sa.sa_mask));
	    sa.sa_handler = SIG_DFL;
	    sa.sa_flags = 0;
	    sigaction(SIGHUP, &sa, NULL);   /*  Go back to default actions */
	    sigaction(SIGINT, &sa, NULL);   /*  for changed signals.  */
	    sigaction(SIGTERM, &sa, NULL);
	    sigaction(SIGCHLD, &sa, NULL);
	    sigaction(SIGUSR1, &sa, NULL);
	    sigaction(SIGUSR2, &sa, NULL);
	    close(fdes[0]);

	    maxfd = (fdes[1]>fd)?fdes[1]:fd;
	    while (1) {
		FD_ZERO(&readfds);
		FD_SET(fdes[1], &readfds);
		FD_SET(fd, &readfds);
		ret = select(maxfd+1, &readfds, NULL, NULL, NULL);
		if (FD_ISSET(fd, &readfds)) {
		    rret = read(fd, buffer, BUFFSIZE);
		    if (rret == 0) {
			SYSDEBUG(("slave died:  EOF on tty."));
			exit(0);
		    } else {
			write(fdes[1], buffer, rret);
		    }
		}
		if (FD_ISSET(fdes[1], &readfds)) {
		    rret = read(fdes[1], buffer, BUFFSIZE);
		    if (rret == 0) {
			SYSDEBUG(("slave died:  EOF on pipe."));
			exit(0);
		    } else {
			write(fd, buffer, rret);
		    }
		}
	    }
	} else {
	    close(fdes[1]);
	    orig_ttyfd = fd;
	    return(fdes[0]);
        }
    }

    return(-1);
}

/*
 * establish_ppp - Turn the serial port into a ppp interface.
 */
int
establish_ppp(fd)
    int fd;
{
    int i;

    if (isastream(fd) != 1) {
	if ((ttyfd = fd = streamify(fd)) < 0)
	    fatal("Couldn't get a STREAMS module!\n");
    }

    /* Pop any existing modules off the tty stream. */
    for (i = 0;; ++i) {
	if (ioctl(fd, I_LOOK, tty_modules[i]) < 0
	    || ioctl(fd, I_POP, 0) < 0)
	    break;
        error("popping module %s\n", tty_modules[i]);
    }

    tty_nmodules = i;

    /* Push the async hdlc module and the compressor module. */
    if (ioctl(fd, I_PUSH, "ppp_ahdl") < 0)
	fatal("Couldn't push PPP Async HDLC module: %m");
    if (ioctl(fd, I_PUSH, "ppp_comp") < 0)
	error("Couldn't push PPP compression module: %m");

    /* read mode, message non-discard mode */
    if (ioctl(fd, I_SRDOPT, RMSGN|RPROTNORM) < 0)
        fatal("ioctl(I_SRDOPT, RMSGN): %m");

    /* Link the serial port under the PPP multiplexor. */
    if ((fdmuxid = ioctl(pppfd, I_LINK, fd)) < 0)
	fatal("Can't link tty to PPP mux: %m");

    /* close stdin, stdout, stderr if they might refer to the device */
    if (default_device && !closed_stdio) {
        int i;

        for (i = 0; i <= 2; ++i)
            if (i != fd && i != sockfd)
                close(i);
        closed_stdio = 1;
    }

    /*
     * Set device for non-blocking reads.
     * XXX why do we need to do this?  don't we use pppfd not fd?
     */
    if ((initfdflags = fcntl(fd, F_GETFL)) == -1
        || fcntl(fd, F_SETFL, initfdflags | O_NONBLOCK) == -1) {
        warn("Couldn't set device to non-blocking mode: %m");
    }

    return pppfd;
}

/*
 * restore_loop - reattach the ppp unit to the loopback.
 * This doesn't need to do anything because disestablish_ppp does it.
 */
void
restore_loop()
{
}

/*
 * disestablish_ppp - Restore the serial port to normal operation.
 * It attempts to reconstruct the stream with the previously popped
 * modules.  This shouldn't call die() because it's called from die().
 */
void
disestablish_ppp(fd)
    int fd;
{
    int i;

    if (fdmuxid >= 0) {
	if (ioctl(pppfd, I_UNLINK, fdmuxid) < 0) {
	    if (!hungup)
		error("Can't unlink tty from PPP mux: %m");
	}
	fdmuxid = -1;

        /* Reset non-blocking mode on the file descriptor. */
        if (initfdflags != -1 && fcntl(fd, F_SETFL, initfdflags) < 0)
            warn("Couldn't restore device fd flags: %m");
        initfdflags = -1;

	if (!hungup) {
	    while (ioctl(fd, I_POP, 0) >= 0)
		;
	    for (i = tty_nmodules - 1; i >= 0; --i)
		if (ioctl(fd, I_PUSH, tty_modules[i]) < 0)
		    error("Couldn't restore tty module %s: %m",
			   tty_modules[i]);
	}

	if (hungup && default_device && tty_sid > 0) {
	    /*
	     * If we have received a hangup, we need to send a SIGHUP
	     * to the terminal's controlling process.  The reason is
	     * that the original stream head for the terminal hasn't
	     * seen the M_HANGUP message (it went up through the ppp
	     * driver to the stream head for our fd to /dev/ppp).
	     */
	    dbglog("sending hangup to %d", tty_sid);
	    if (kill(tty_sid, SIGHUP) < 0)
		error("couldn't kill pgrp: %m");
	}
	if (orig_ttyfd >= 0) {
	    close(fd);
	    (void)wait((void *)0);
	    ttyfd = orig_ttyfd;
	    orig_ttyfd = -1;
	}
    }
}

/*
 * Check whether the link seems not to be 8-bit clean.
 */
void
clean_check()
{
    int x;
    char *s;

    if (strioctl(pppfd, PPPIO_GCLEAN, &x, 0, sizeof(x)) < 0)
	return;
    s = NULL;
    switch (~x) {
    case RCV_B7_0:
	s = "bit 7 set to 1";
	break;
    case RCV_B7_1:
	s = "bit 7 set to 0";
	break;
    case RCV_EVNP:
	s = "odd parity";
	break;
    case RCV_ODDP:
	s = "even parity";
	break;
    }
    if (s != NULL) {
	warn("Serial link is not 8-bit clean:");
	warn("All received characters had %s", s);
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
static int
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
static int
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
    int speed;
    struct termios tios;

    if (tcgetattr(fd, &tios) < 0)
	fatal("tcgetattr: %m");

    if (!restore_term) {
	inittermios = tios;
	ioctl(fd, TIOCGWINSZ, &wsinfo);
    }

    tios.c_cflag &= ~(CSIZE | CSTOPB | PARENB | CLOCAL);
    if (crtscts > 0)
	tios.c_cflag |= CRTSCTS;
    else if (crtscts < 0)
	tios.c_cflag &= ~CRTSCTS;

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
	 * We can't proceed if the serial port speed is 0,
	 * since that implies that the serial port is disabled.
	 */
	if (speed == B0)
	    fatal("Baud rate for %s is 0; need explicit baud rate", devnam);
    }

    if (tcsetattr(fd, TCSAFLUSH, &tios) < 0)
	fatal("tcsetattr: %m");

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
	    if (!hungup && errno != ENXIO)
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
 * open_loopback - open the device we use for getting packets
 * in demand mode.  Under Digital Unix, we use our existing fd
 * to the ppp driver.
 */
int
open_ppp_loopback()
{
    return pppfd;
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
    struct strbuf data;
    int retries;
    struct pollfd pfd;

    if (debug)
	dbglog("sent %P", p, len);

    data.len = len;
    data.buf = (caddr_t) p;
    retries = 4;
    while (putmsg(pppfd, NULL, &data, 0) < 0) {
	if (--retries < 0 || (errno != EWOULDBLOCK && errno != EAGAIN)) {
	    if (errno != ENXIO)
		error("Couldn't send packet: %m");
	    break;
	}
	pfd.fd = pppfd;
	pfd.events = POLLOUT;
	poll(&pfd, 1, 250);	/* wait for up to 0.25 seconds */
    }
}


/*
 * wait_input - wait until there is data available on fd,
 * for the length of time specified by *timo (indefinite
 * if timo is NULL).
 */
void
wait_input(timo)
    struct timeval *timo;
{
    int t;

    t = timo == NULL? -1: timo->tv_sec * 1000 + timo->tv_usec / 1000;
    if (poll(pollfds, n_pollfds, t) < 0 && errno != EINTR)
	fatal("poll: %m");
}

/*
 * add_fd - add an fd to the set that wait_input waits for.
 */
void add_fd(fd)
    int fd;
{
    int n;

    for (n = 0; n < n_pollfds; ++n)
	if (pollfds[n].fd == fd)
	    return;
    if (n_pollfds < MAX_POLLFDS) {
	pollfds[n_pollfds].fd = fd;
	pollfds[n_pollfds].events = POLLIN | POLLPRI | POLLHUP;
	++n_pollfds;
    } else
	error("Too many inputs!");
}

/*
 * remove_fd - remove an fd from the set that wait_input waits for.
 */
void remove_fd(fd)
    int fd;
{
    int n;

    for (n = 0; n < n_pollfds; ++n) {
	if (pollfds[n].fd == fd) {
	    while (++n < n_pollfds)
		pollfds[n-1] = pollfds[n];
	    --n_pollfds;
	    break;
	}
    }
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
    wait_input(timo);
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
    struct strbuf ctrl, data;
    int flags, len;
    unsigned char ctrlbuf[64];

    for (;;) {
	data.maxlen = PPP_MRU + PPP_HDRLEN;
	data.buf = (caddr_t) buf;
	ctrl.maxlen = sizeof(ctrlbuf);
	ctrl.buf = (caddr_t) ctrlbuf;
	flags = 0;
	len = getmsg(pppfd, &ctrl, &data, &flags);
	if (len < 0) {
	    if (errno = EAGAIN || errno == EWOULDBLOCK || errno == EINTR)
		return -1;
	    fatal("Error reading packet: %m");
	}

	if (ctrl.len <= 0)
	    return data.len;

	/*
	 * Got a M_PROTO or M_PCPROTO message.  Huh?
	 */
	if (debug)
	    dbglog("got ctrl msg len=%d", ctrl.len);

    }
}

/*
 * get_loop_output - get outgoing packets from the ppp device,
 * and detect when we want to bring the real link up.
 * Return value is 1 if we need to bring up the link, 0 otherwise.
 */
int
get_loop_output()
{
    int len;
    int rv = 0;

    while ((len = read_packet(inpacket_buf)) > 0) {
	if (loop_frame(inpacket_buf, len))
	    rv = 1;
    }
    return rv;
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
    int cf[2];

    link_mtu = mtu;
    if (strioctl(pppfd, PPPIO_MTU, &mtu, sizeof(mtu), 0) < 0) {
	if (hungup && errno == ENXIO)
	    return;
	error("Couldn't set MTU: %m");
    }
    if (strioctl(pppfd, PPPIO_XACCM, &asyncmap, sizeof(asyncmap), 0) < 0) {
	error("Couldn't set transmit ACCM: %m");
    }
    cf[0] = (pcomp? COMP_PROT: 0) + (accomp? COMP_AC: 0);
    cf[1] = COMP_PROT | COMP_AC;
    if (strioctl(pppfd, PPPIO_CFLAGS, cf, sizeof(cf), sizeof(int)) < 0) {
	error("Couldn't set prot/AC compression: %m");
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
    if (strioctl(pppfd, PPPIO_XACCM, accm, sizeof(ext_accm), 0) < 0) {
	if (!hungup || errno != ENXIO)
	    warn("Couldn't set extended ACCM: %m");
    }
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
    int cf[2];

    link_mru = mru;
    if (strioctl(pppfd, PPPIO_MRU, &mru, sizeof(mru), 0) < 0) {
	if (hungup && errno == ENXIO)
	    return;
	error("Couldn't set MRU: %m");
    }
    if (strioctl(pppfd, PPPIO_RACCM, &asyncmap, sizeof(asyncmap), 0) < 0) {
	error("Couldn't set receive ACCM: %m");
    }
    cf[0] = (pcomp? DECOMP_PROT: 0) + (accomp? DECOMP_AC: 0);
    cf[1] = DECOMP_PROT | DECOMP_AC;
    if (strioctl(pppfd, PPPIO_CFLAGS, cf, sizeof(cf), sizeof(int)) < 0) {
	error("Couldn't set prot/AC decompression: %m");
    }
}

/*
 * ccp_test - ask kernel whether a given compression method
 * is acceptable for use.
 *
 * In Digital UNIX the memory buckets for chunks >16K are not
 * primed when the system comes up.  That means we're not
 * likely to get the memory needed for the compressor on
 * the first try.  The way we work around this is to have
 * the driver spin off a thread to go get the memory for us
 * (we can't block at that point in a streams context.)
 *
 * This code synchronizes with the thread when it has returned
 * with the memory we need.  The driver will continue to return
 * with EAGAIN until the thread comes back.  We give up here
 * if after 10 attempts in one second we still don't have memory.
 * It's up to the driver to not lose track of that memory if
 * thread takes too long to return.
 */
int
ccp_test(unit, opt_ptr, opt_len, for_transmit)
    int unit, opt_len, for_transmit;
    u_char *opt_ptr;
{
    struct timeval tval;
    int i;

    tval.tv_sec = 0;
    tval.tv_usec = 100000;
    for (i = 0; i < 10; ++i) {
        if (strioctl(pppfd, (for_transmit? PPPIO_XCOMP: PPPIO_RCOMP),
	    opt_ptr, opt_len, 0) >= 0) {
	    return 1;
	}
	if (errno != EAGAIN)
	    break;
        wait_time(&tval);
    }
    if (errno != 0)
	error("hard failure trying to get memory for a compressor: %m");
    return (errno == ENOSR)? 0: -1;
}

/*
 * ccp_flags_set - inform kernel about the current state of CCP.
 */
void
ccp_flags_set(unit, isopen, isup)
    int unit, isopen, isup;
{
    int cf[2];

    cf[0] = (isopen? CCP_ISOPEN: 0) + (isup? CCP_ISUP: 0);
    cf[1] = CCP_ISOPEN | CCP_ISUP | CCP_ERROR | CCP_FATALERROR;
    if (strioctl(pppfd, PPPIO_CFLAGS, cf, sizeof(cf), sizeof(int)) < 0) {
	if (!hungup || errno != ENXIO)
	    error("Couldn't set kernel CCP state: %m");
    }
}

/*
 * get_idle_time - return how long the link has been idle.
 */
int
get_idle_time(u, ip)
    int u;
    struct ppp_idle *ip;
{
    return strioctl(pppfd, PPPIO_GIDLE, ip, 0, sizeof(struct ppp_idle)) >= 0;
}

/*
 * get_ppp_stats - return statistics for the link.
 */
int
get_ppp_stats(u, stats)
    int u;
    struct pppd_stats *stats;
{
    struct ppp_stats s;

    if (strioctl(pppfd, PPPIO_GETSTAT, &s, 0, sizeof(s)) < 0) {
	error("Couldn't get link statistics: %m");
	return 0;
    }
    stats->bytes_in = s.p.ppp_ibytes;
    stats->bytes_out = s.p.ppp_obytes;
    return 1;
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
    int cf[2];

    cf[0] = cf[1] = 0;
    if (strioctl(pppfd, PPPIO_CFLAGS, cf, sizeof(cf), sizeof(int)) < 0) {
	if (errno != ENXIO && errno != EINVAL)
	    error("Couldn't get compression flags: %m");
	return 0;
    }
    return cf[0] & CCP_FATALERROR;
}

/*
 * sifvjcomp - config tcp header compression
 */
int
sifvjcomp(u, vjcomp, xcidcomp, xmaxcid)
    int u, vjcomp, xcidcomp, xmaxcid;
{
    int cf[2];
    char maxcid[2];

    if (vjcomp) {
	maxcid[0] = xcidcomp;
	maxcid[1] = 15;		/* XXX should be rmaxcid */
	if (strioctl(pppfd, PPPIO_VJINIT, maxcid, sizeof(maxcid), 0) < 0) {
	    error("Couldn't initialize VJ compression: %m");
	}
    }

    cf[0] = (vjcomp? COMP_VJC + DECOMP_VJC: 0)	/* XXX this is wrong */
	+ (xcidcomp? COMP_VJCCID + DECOMP_VJCCID: 0);
    cf[1] = COMP_VJC + DECOMP_VJC + COMP_VJCCID + DECOMP_VJCCID;
    if (strioctl(pppfd, PPPIO_CFLAGS, cf, sizeof(cf), sizeof(int)) < 0) {
	if (vjcomp)
	    error("Couldn't enable VJ compression: %m");
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

    strlcpy(ifr.ifr_name, ifname, sizeof(ifr.ifr_name));
    if (ioctl(sockfd, SIOCGIFFLAGS, &ifr) < 0) {
	error("Couldn't mark interface up (get): %m");
	return 0;
    }
    ifr.ifr_flags |= IFF_UP;
    if (ioctl(sockfd, SIOCSIFFLAGS, &ifr) < 0) {
	error("Couldn't mark interface up (set): %m");
	return 0;
    }
    if_is_up = 1;
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

    strlcpy(ifr.ifr_name, ifname, sizeof(ifr.ifr_name));
    if (ioctl(sockfd, SIOCGIFFLAGS, &ifr) < 0) {
	error("Couldn't mark interface down (get): %m");
	return 0;
    }
    if ((ifr.ifr_flags & IFF_UP) != 0) {
	ifr.ifr_flags &= ~IFF_UP;
	if (ioctl(sockfd, SIOCSIFFLAGS, &ifr) < 0) {
	    error("Couldn't mark interface down (set): %m");
	    return 0;
	}
    }
    if_is_up = 0;
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
    int npi[2];

    npi[0] = proto;
    npi[1] = (int) mode;
    if (strioctl(pppfd, PPPIO_NPMODE, npi, 2 * sizeof(int), 0) < 0) {
	error("ioctl(set NP %d mode to %d): %m", proto, mode);
	return 0;
    }
    return 1;
}

#define INET_ADDR(x)	(((struct sockaddr_in *) &(x))->sin_addr.s_addr)

/*
 * SET_SA_FAMILY - initialize a struct sockaddr, setting the sa_family field.
 */
#define SET_SA_FAMILY(addr, family)             \
    BZERO((char *) &(addr), sizeof(addr));      \
    addr.sa_family = (family);                  \
    addr.sa_len = sizeof ((addr))

/*
 * sifaddr - Config the interface IP addresses and netmask.
 */
int
sifaddr(u, o, h, m)
    int u;
    u_int32_t o, h, m;
{
    struct ifreq ifr;
    struct ifaliasreq addreq;
    int ret;

    ret = 1;

    /* flush old address, if any
     */
    bzero(&ifr, sizeof (ifr));
    strlcpy(ifr.ifr_name, ifname, sizeof (ifr.ifr_name));
    SET_SA_FAMILY(ifr.ifr_addr, AF_INET);
    ((struct sockaddr_in *) &ifr.ifr_addr)->sin_addr.s_addr = o;
    if ((ioctl(sockfd, (int)SIOCDIFADDR, (caddr_t) &ifr) < 0)
        && errno != EADDRNOTAVAIL) {
        error("ioctl(SIOCDIFADDR): %m");
        ret = 0;
    }

    bzero(&addreq, sizeof (addreq));
    strlcpy(addreq.ifra_name, ifname, sizeof (addreq.ifra_name));
    SET_SA_FAMILY(addreq.ifra_addr, AF_INET);
    SET_SA_FAMILY(addreq.ifra_broadaddr, AF_INET);
    ((struct sockaddr_in *)&addreq.ifra_addr)->sin_addr.s_addr = o;
    ((struct sockaddr_in *)&addreq.ifra_broadaddr)->sin_addr.s_addr = h;

    if (m != 0) {
        ((struct sockaddr_in *)&addreq.ifra_mask)->sin_addr.s_addr = m;
        addreq.ifra_mask.sa_len = sizeof (struct sockaddr);
        info("Setting interface mask to %s\n", ip_ntoa(m));
    }

    /* install new src/dst and (possibly) netmask
     */
    if (ioctl(sockfd, SIOCPIFADDR, &addreq) < 0) {
        error("ioctl(SIOCPIFADDR): %m");
        ret = 0;
    }

    ifr.ifr_metric = link_mtu;
    if (ioctl(sockfd, SIOCSIPMTU, &ifr) < 0) {
	error("Couldn't set IP MTU: %m");
        ret = 0;
    }

    ifaddrs[0] = o;
    ifaddrs[1] = h;
    return (ret);
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
    struct ifreq ifr;

    ifaddrs[0] = 0;
    ifaddrs[1] = 0;
    bzero(&ifr, sizeof (ifr));
    strlcpy(ifr.ifr_name, ifname, sizeof (ifr.ifr_name));
    SET_SA_FAMILY(ifr.ifr_addr, AF_INET);
    ((struct sockaddr_in *) &ifr.ifr_addr)->sin_addr.s_addr = o;
    if (ioctl(sockfd, (int)SIOCDIFADDR, (caddr_t) &ifr) < 0) {
        error("ioctl(SIOCDIFADDR): %m");
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
    struct ortentry rt;

    BZERO(&rt, sizeof(rt));
    SET_SA_FAMILY(rt.rt_dst, AF_INET);
    SET_SA_FAMILY(rt.rt_gateway, AF_INET);
    ((struct sockaddr_in *) &rt.rt_gateway)->sin_addr.s_addr = g;
    rt.rt_flags = RTF_GATEWAY;
    if (ioctl(sockfd, (int)SIOCADDRT, &rt) < 0) {
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
    struct ortentry rt;

    BZERO(&rt, sizeof(rt));
    SET_SA_FAMILY(rt.rt_dst, AF_INET);
    SET_SA_FAMILY(rt.rt_gateway, AF_INET);
    ((struct sockaddr_in *) &rt.rt_gateway)->sin_addr.s_addr = g;
    rt.rt_flags = RTF_GATEWAY;
    if (ioctl(sockfd, (int)SIOCDELRT, &rt) < 0) {
        error("default route ioctl(SIOCDELRT): %m");
        return 0;
    }
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
        warn("Cannot determine ethernet address for proxy ARP");
        return 0;
    }

    SET_SA_FAMILY(arpreq.arp_pa, AF_INET);
    ((struct sockaddr_in *) &arpreq.arp_pa)->sin_addr.s_addr = hisaddr;
    arpreq.arp_flags = ATF_PERM | ATF_PUBL;
    if (ioctl(sockfd, (int)SIOCSARP, (caddr_t)&arpreq) < 0) {
        error("ioctl(SIOCSARP): %m");
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
    if (ioctl(sockfd, (int)SIOCDARP, (caddr_t)&arpreq) < 0) {
        error("ioctl(SIOCDARP): %m");
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
    struct ifdevea ifdevreq;

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
    for (ifr = ifc.ifc_req; ifr < ifend; ifr++) {
        if (ifr->ifr_addr.sa_family == AF_INET) {

            /*
             * Check that the interface is up, and not point-to-point
             * or loopback.
             */
            strlcpy(ifreq.ifr_name, ifr->ifr_name, sizeof(ifreq.ifr_name));
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
            ina = ((struct sockaddr_in *) &ifr->ifr_addr)->sin_addr.s_addr;
            mask = ((struct sockaddr_in *) &ifreq.ifr_addr)->sin_addr.s_addr;
            if ((ipaddr & mask) != (ina & mask))
                continue;

            break;
        } else {
	    if (ifr->ifr_addr.sa_len > sizeof (ifr->ifr_addr))
		ifr = (struct ifreq *)((caddr_t)ifr + (ifr->ifr_addr.sa_len - sizeof (ifr->ifr_addr)));
	}
    }

    if (ifr >= ifend)
	return 0;
    info("found interface %s for proxy arp", ifr->ifr_name);

    strlcpy(ifdevreq.ifr_name, ifr->ifr_name, sizeof(ifdevreq.ifr_name));

    if (ioctl(sockfd, (int)SIOCRPHYSADDR, &ifdevreq) < 0) {
        perror("ioctl(SIOCRPHYSADDR)");
        return(0);
    }

    hwaddr->sa_family = AF_UNSPEC;
    memcpy(hwaddr->sa_data, ifdevreq.current_pa, sizeof(ifdevreq.current_pa));
    return 1;
}

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
    ifc.ifc_len = MAX_IFS * sizeof(struct ifreq);
    ifc.ifc_req = (struct ifreq *)alloca(ifc.ifc_len);
    if (ifc.ifc_req == 0)
	return mask;
    if (ioctl(sockfd, SIOCGIFCONF, &ifc) < 0) {
	warn("Couldn't get system interface list: %m");
	return mask;
    }
    ifend = (struct ifreq *) (ifc.ifc_buf + ifc.ifc_len);
    for (ifr = ifc.ifc_req; ifr < ifend; ifr++) {
	/*
	 * Check the interface's internet address.
	 */
	if (ifr->ifr_addr.sa_family == AF_INET) {
	    ina = INET_ADDR(ifr->ifr_addr);
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
	    mask |= INET_ADDR(ifreq.ifr_addr);
	    break;
	} else {
	    if (ifr->ifr_addr.sa_len > sizeof (ifr->ifr_addr))
		ifr = (struct ifreq *)((caddr_t)ifr + (ifr->ifr_addr.sa_len - sizeof (ifr->ifr_addr)));
	}
    }

    return mask;
}

/*
 * have_route_to - determine if the system has any route to
 * a given IP address.  `addr' is in network byte order.
 * For demand mode to work properly, we have to ignore routes
 * through our own interface.
 */
int have_route_to(u_int32_t addr)
{
	char buf[sizeof(struct rt_msghdr) + (sizeof(struct sockaddr_in))];
	int status;
	int s, n;
	struct rt_msghdr *rtm;
	struct sockaddr_in *sin;
	int msglen = sizeof(*rtm) + (sizeof(*sin));
	char *cp;
	char msg[2048];

	rtm = (struct rt_msghdr *)buf;
	memset(rtm, 0, msglen);
	rtm->rtm_msglen = msglen;
	rtm->rtm_version = RTM_VERSION;
	rtm->rtm_type = RTM_GET;
	rtm->rtm_addrs = RTA_DST;
	/* rtm->rtm_addrs, rtm_flags  should be set on output */

	sin = (struct sockaddr_in *)((u_char *)rtm + sizeof(*rtm));
	sin->sin_len = sizeof(*sin);
	sin->sin_family = AF_INET;
	sin->sin_addr.s_addr = addr;

        status = 0;

	if ((s = socket(PF_ROUTE, SOCK_RAW, 0)) < 0)
		return -1;
	if (write(s, (char *)rtm, msglen) != msglen) {
		close(s);
		return status == ESRCH? 0: -1;
	}

	n = read(s, msg, 2048);
	close(s);
	if (n <= 0)
		return -1;

	rtm = (struct rt_msghdr *) msg;
	if (rtm->rtm_version != RTM_VERSION)
		return -1;

	/* here we try to work out if the route is through our own interface */
	cp = (char *)(rtm + 1);
	if (rtm->rtm_addrs & RTA_DST) {
		struct sockaddr *sa = (struct sockaddr *) cp;
		cp = (char *)(((unsigned long)cp + sa->sa_len
			       + sizeof(long) - 1) & ~(sizeof(long) - 1));
	}
	if (rtm->rtm_addrs & RTA_GATEWAY) {
		sin = (struct sockaddr_in *) cp;
		if (sin->sin_addr.s_addr == ifaddrs[0]
		    || sin->sin_addr.s_addr == ifaddrs[1])
			return 0; 	/* route is through our interface */
	}

	return 1;
}

static int
strioctl(fd, cmd, ptr, ilen, olen)
    int fd, cmd, ilen, olen;
    void *ptr;
{
    struct strioctl str;

    str.ic_cmd = cmd;
    str.ic_timout = 0;
    str.ic_len = ilen;
    str.ic_dp = ptr;
    if (ioctl(fd, I_STR, &str) == -1)
	return -1;
    if (str.ic_len != olen)
	dbglog("strioctl: expected %d bytes, got %d for cmd %x\n",
	       olen, str.ic_len, cmd);
    return 0;
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
 * get_pty - get a pty master/slave pair and chown the slave side
 * to the uid given.  Assumes slave_name points to >= 12 bytes of space.
 */
int
get_pty(master_fdp, slave_fdp, slave_name, uid)
    int *master_fdp;
    int *slave_fdp;
    char *slave_name;
    int uid;
{
    int i, mfd, sfd;
    char pty_name[12];
    struct termios tios;

    sfd = -1;
    for (i = 0; i < 64; ++i) {
	slprintf(pty_name, sizeof(pty_name), "/dev/pty%c%x",
		 'p' + i / 16, i % 16);
	mfd = open(pty_name, O_RDWR, 0);
	if (mfd >= 0) {
	    pty_name[5] = 't';
	    sfd = open(pty_name, O_RDWR | O_NOCTTY, 0);
	    if (sfd >= 0)
		break;
	    close(mfd);
	}
    }
    if (sfd < 0)
	return 0;

    strlcpy(slave_name, pty_name, 12);
    *master_fdp = mfd;
    *slave_fdp = sfd;
    fchown(sfd, uid, -1);
    fchmod(sfd, S_IRUSR | S_IWUSR);
    if (tcgetattr(sfd, &tios) == 0) {
	tios.c_cflag &= ~(CSIZE | CSTOPB | PARENB);
	tios.c_cflag |= CS8 | CREAD;
	tios.c_iflag  = IGNPAR | CLOCAL;
	tios.c_oflag  = 0;
	tios.c_lflag  = 0;
	if (tcsetattr(sfd, TCSAFLUSH, &tios) < 0)
	    warn("couldn't set attributes on pty: %m");
    } else
	warn("couldn't get attributes on pty: %m");

    return 1;
}

/*
 * Code for locking/unlocking the serial device.
 * This code is derived from chat.c.
 */

#if !defined(HDB) && !defined(SUNOS3)
#define	HDB	1		/* ascii lock files are the default */
#endif

#ifndef LOCK_DIR
# if HDB
#  define	PIDSTRING
#  define	LOCK_PREFIX	"/usr/spool/locks/LCK.."
# else /* HDB */
#  define	LOCK_PREFIX	"/usr/spool/uucp/LCK.."
# endif /* HDB */
#endif /* LOCK_DIR */

static char *lock_file;		/* name of lock file created */

/*
 * lock - create a lock file for the named device.
 */
int
lock(dev)
    char *dev;
{
    char hdb_lock_buffer[12];
    int fd, pid, n;
    char *p;
    size_t l;

    if ((p = strrchr(dev, '/')) != NULL)
	dev = p + 1;
    l = strlen(LOCK_PREFIX) + strlen(dev) + 1;
    lock_file = malloc(l);
    if (lock_file == NULL)
	novm("lock file name");
    slprintf(lock_file, l, "%s%s", LOCK_PREFIX, dev);

    while ((fd = open(lock_file, O_EXCL | O_CREAT | O_RDWR, 0644)) < 0) {
	if (errno == EEXIST
	    && (fd = open(lock_file, O_RDONLY, 0)) >= 0) {
	    /* Read the lock file to find out who has the device locked */
#ifdef PIDSTRING
	    n = read(fd, hdb_lock_buffer, 11);
	    if (n > 0) {
		hdb_lock_buffer[n] = 0;
		pid = atoi(hdb_lock_buffer);
	    }
#else
	    n = read(fd, &pid, sizeof(pid));
#endif
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

#ifdef PIDSTRING
    slprintf(hdb_lock_buffer, sizeof(hdb_lock_buffer), "%10d\n", getpid());
    write(fd, hdb_lock_buffer, 11);
#else
    pid = getpid();
    write(fd, &pid, sizeof pid);
#endif

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

int
set_filters(pass, active)
    struct bpf_program *pass, *active;
{
    return 1;
}

int
bpf_compile(program, buf, optimize)
    struct bpf_program *program;
    char *buf;
    int optimize;
{
    return 0;
}

char *
bpf_geterr()
{
    return 0;
}

u_int
bpf_filter(pc, p, wirelen, buflen)
    struct bpf_insn *pc;
    u_char *p;
    u_int wirelen;
    u_int buflen;
{
    return 0;
}
