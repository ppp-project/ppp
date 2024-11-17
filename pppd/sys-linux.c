/*
 * sys-linux.c - System-dependent procedures for setting up
 * PPP interfaces on Linux systems
 *
 * Copyright (c) 1994-2004 Paul Mackerras. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. The name(s) of the authors of this software must not be used to
 *    endorse or promote products derived from this software without
 *    prior written permission.
 *
 * 3. Redistributions of any form whatsoever must retain the following
 *    acknowledgment:
 *    "This product includes software developed by Paul Mackerras
 *     <paulus@ozlabs.org>".
 *
 * THE AUTHORS OF THIS SOFTWARE DISCLAIM ALL WARRANTIES WITH REGARD TO
 * THIS SOFTWARE, INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
 * AND FITNESS, IN NO EVENT SHALL THE AUTHORS BE LIABLE FOR ANY
 * SPECIAL, INDIRECT OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN
 * AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING
 * OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 *
 * Derived from main.c and pppd.h, which are:
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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <sys/utsname.h>
#include <sys/sysmacros.h>
#include <sys/param.h>

#include <errno.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <syslog.h>
#include <string.h>
#include <time.h>
#include <memory.h>
#ifdef HAVE_UTMP_H
#include <utmp.h>
#endif
#include <mntent.h>
#include <signal.h>
#include <fcntl.h>
#include <ctype.h>
#include <unistd.h>
#include <limits.h>

/* This is in netdevice.h. However, this compile will fail miserably if
   you attempt to include netdevice.h because it has so many references
   to __memcpy functions which it should not attempt to do. So, since I
   really don't use it, but it must be defined, define it now. */

#ifndef MAX_ADDR_LEN
#define MAX_ADDR_LEN 7
#endif

#if !defined(__GLIBC__) || __GLIBC__ >= 2
#include <asm/types.h>		/* glibc 2 conflicts with linux/types.h */
#include <net/if.h>
#include <net/if_arp.h>
#include <net/route.h>
#include <netinet/if_ether.h>
#else
#include <linux/types.h>
#include <linux/if.h>
#include <linux/if_arp.h>
#include <linux/route.h>
#include <linux/if_ether.h>
#endif
#include <netinet/in.h>
#include <arpa/inet.h>

#include <linux/ppp-ioctl.h>

#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <linux/if_link.h>
#include <linux/if_addr.h>

/* glibc versions prior to 2.24 do not define SOL_NETLINK */
#ifndef SOL_NETLINK
#define SOL_NETLINK 270
#endif

/* linux kernel versions prior to 4.3 do not define/support NETLINK_CAP_ACK */
#ifndef NETLINK_CAP_ACK
#define NETLINK_CAP_ACK 10
#endif

/* linux kernel versions prior to 4.7 do not define/support IFLA_PPP_DEV_FD */
#ifndef IFLA_PPP_MAX
/* IFLA_PPP_DEV_FD is declared as enum when IFLA_PPP_MAX is defined */
#define IFLA_PPP_DEV_FD 1
#endif

#include "pppd-private.h"
#include "options.h"
#include "fsm.h"
#include "ipcp.h"

#ifdef PPP_WITH_IPV6CP
#include "eui64.h"
#endif /* PPP_WITH_IPV6CP */

#include "multilink.h"

#ifdef PPP_WITH_FILTER
#include <pcap-bpf.h>
#include <linux/filter.h>
#endif /* PPP_WITH_FILTER */

#ifdef LOCKLIB
#include <sys/locks.h>
#endif

/*
 * Instead of system header file <termios.h> use local "termios_linux.h" header
 * file as it provides additional support for arbitrary baud rates via BOTHER.
 */
#include "termios_linux.h"

#ifdef PPP_WITH_IPV6CP
#ifndef _LINUX_IN6_H
/*
 *    This is in linux/include/net/ipv6.h.
 */

struct in6_ifreq {
    struct in6_addr ifr6_addr;
    __u32 ifr6_prefixlen;
    unsigned int ifr6_ifindex;
};
#endif

#define IN6_LLADDR_FROM_EUI64(sin6, eui64) do {			\
	memset(&(sin6).s6_addr, 0, sizeof(struct in6_addr));	\
	(sin6).s6_addr16[0] = htons(0xfe80);			\
	eui64_copy(eui64, (sin6).s6_addr32[2]);			\
	} while (0)

static const eui64_t nulleui64;
#endif /* PPP_WITH_IPV6CP */

/* We can get an EIO error on an ioctl if the modem has hung up */
#define ok_error(num) ((num)==EIO)

static int tty_disc = N_TTY;	/* The TTY discipline */
static int ppp_disc = N_PPP;	/* The PPP discpline */
static int initfdflags = -1;	/* Initial file descriptor flags for fd */
static int ppp_fd = -1;		/* fd which is set to PPP discipline */
static int sock_fd = -1;	/* socket for doing interface ioctls */
static int slave_fd = -1;	/* pty for old-style demand mode, slave */
static int master_fd = -1;	/* pty for old-style demand mode, master */
#ifdef PPP_WITH_IPV6CP
static int sock6_fd = -1;
#endif /* PPP_WITH_IPV6CP */

/*
 * For the old-style kernel driver, this is the same as ppp_fd.
 * For the new-style driver, it is the fd of an instance of /dev/ppp
 * which is attached to the ppp unit and is used for controlling it.
 */
int ppp_dev_fd = -1;		/* fd for /dev/ppp (new style driver) */

static int chindex;		/* channel index (new style driver) */

static fd_set in_fds;		/* set of fds that wait_input waits for */
static int max_in_fd;		/* highest fd set in in_fds */

static int has_proxy_arp       = 0;
static int driver_version      = 0;
static int driver_modification = 0;
static int driver_patch        = 0;
static int driver_is_old       = 0;
static int restore_term        = 0;	/* 1 => we've munged the terminal */
static struct termios inittermios;	/* Initial TTY termios */

int new_style_driver = 0;

static char loop_name[20];
static unsigned char inbuf[512]; /* buffer for chars read from loopback */

static int	if_is_up;	/* Interface has been marked up */
static int	if6_is_up;	/* Interface has been marked up for IPv6, to help differentiate */
static int	have_default_route;	/* Gateway for default route added */
static int	have_default_route6;	/* Gateway for default IPv6 route added */
static struct	rtentry old_def_rt;	/* Old default route */
static int	default_rt_repl_rest;	/* replace and restore old default rt */
static u_int32_t proxy_arp_addr;	/* Addr for proxy arp entry added */
static char proxy_arp_dev[16];		/* Device for proxy arp entry */
static u_int32_t our_old_addr;		/* for detecting address changes */
static int	dynaddr_set;		/* 1 if ip_dynaddr set */
static int	looped;			/* 1 if using loop */
static int	link_mtu;		/* mtu for the link (not bundle) */

static struct utsname utsname;	/* for the kernel version */
static int kernel_version;
#define KVERSION(j,n,p)	((j)*1000000 + (n)*1000 + (p))

#define MAX_IFS		100

#define FLAGS_GOOD (IFF_UP          | IFF_BROADCAST)
#define FLAGS_MASK (IFF_UP          | IFF_BROADCAST | \
		    IFF_POINTOPOINT | IFF_LOOPBACK  | IFF_NOARP)

#define SIN_ADDR(x)	(((struct sockaddr_in *) (&(x)))->sin_addr.s_addr)

/* Prototypes for procedures local to this file. */
static int modify_flags(int fd, int clear_bits, int set_bits);
static int translate_speed (int bps);
static int baud_rate_of (int speed);
static void close_route_table (void);
static int open_route_table (void);
static int read_route_table (struct rtentry *rt);
static int defaultroute_exists (struct rtentry *rt, int metric);
static int defaultroute6_exists (struct in6_rtmsg *rt, int metric);
static int get_ether_addr (u_int32_t ipaddr, struct sockaddr *hwaddr,
			   char *name, int namelen);
static void decode_version (char *buf, int *version, int *mod, int *patch);
static int set_kdebugflag(int level);
static int ppp_registered(void);
static int make_ppp_unit(void);
static int setifstate (int u, int state);

extern u_char	inpacket_buf[];	/* borrowed from main.c */

extern int dfl_route_metric;

/*
 * SET_SA_FAMILY - set the sa_family field of a struct sockaddr,
 * if it exists.
 */

#define SET_SA_FAMILY(addr, family)			\
    memset ((char *) &(addr), '\0', sizeof(addr));	\
    addr.sa_family = (family);


/*
 * rtnetlink_msg - send rtnetlink message, receive response
 * and return received error code:
 * 0              - success
 * positive value - error during sending / receiving message
 * negative value - rtnetlink responce error code
 */
static int rtnetlink_msg(const char *desc, int *shared_fd, void *nlreq, size_t nlreq_len, void *nlresp_data, size_t *nlresp_size, unsigned nlresp_type)
{
    struct nlresp_hdr {
        struct nlmsghdr nlh;
        struct nlmsgerr nlerr;
    } nlresp_hdr;
    struct sockaddr_nl nladdr;
    struct iovec iov[2];
    struct msghdr msg;
    ssize_t nlresp_len;
    int one;
    int fd;

    if (shared_fd && *shared_fd >= 0) {
        fd = *shared_fd;
    } else {
        fd = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
        if (fd < 0) {
            error("rtnetlink_msg: socket(NETLINK_ROUTE): %m (line %d)", __LINE__);
            return 1;
        }

        /*
         * Tell kernel to not send to us payload of acknowledgment error message.
         * NETLINK_CAP_ACK option is supported since Linux kernel version 4.3 and
         * older kernel versions always send full payload in acknowledgment netlink
         * message. We ignore payload of this message as we need only error code,
         * to check if our set remote peer address request succeeded or failed.
         * So ignore return value from the following setsockopt() call as setting
         * option NETLINK_CAP_ACK means for us just a kernel hint / optimization.
         */
        one = 1;
        setsockopt(fd, SOL_NETLINK, NETLINK_CAP_ACK, &one, sizeof(one));

        memset(&nladdr, 0, sizeof(nladdr));
        nladdr.nl_family = AF_NETLINK;

        if (bind(fd, (struct sockaddr *)&nladdr, sizeof(nladdr)) < 0) {
            error("rtnetlink_msg: bind(AF_NETLINK): %m (line %d)", __LINE__);
            close(fd);
            return 1;
        }

        if (shared_fd)
            *shared_fd = fd;
    }

    memset(&nladdr, 0, sizeof(nladdr));
    nladdr.nl_family = AF_NETLINK;

    memset(&iov[0], 0, sizeof(iov[0]));
    iov[0].iov_base = nlreq;
    iov[0].iov_len = nlreq_len;

    memset(&msg, 0, sizeof(msg));
    msg.msg_name = &nladdr;
    msg.msg_namelen = sizeof(nladdr);
    msg.msg_iov = &iov[0];
    msg.msg_iovlen = 1;

    if (sendmsg(fd, &msg, 0) < 0) {
        error("rtnetlink_msg: sendmsg(%s): %m (line %d)", desc, __LINE__);
        if (!shared_fd)
            close(fd);
        return 1;
    }

    memset(iov, 0, sizeof(iov));
    iov[0].iov_base = &nlresp_hdr;
    if (nlresp_size && *nlresp_size > sizeof(nlresp_hdr)) {
        iov[0].iov_len = offsetof(struct nlresp_hdr, nlerr);
        iov[1].iov_base = nlresp_data;
        iov[1].iov_len = *nlresp_size;
    } else {
        iov[0].iov_len = sizeof(nlresp_hdr);
    }

    memset(&msg, 0, sizeof(msg));
    msg.msg_name = &nladdr;
    msg.msg_namelen = sizeof(nladdr);
    msg.msg_iov = iov;
    msg.msg_iovlen = (nlresp_size && *nlresp_size > sizeof(nlresp_hdr)) ? 2 : 1;

    nlresp_len = recvmsg(fd, &msg, 0);

    if (!shared_fd)
        close(fd);

    if (nlresp_len < 0) {
        error("rtnetlink_msg: recvmsg(%s): %m (line %d)", desc, __LINE__);
        return 1;
    }

    if (nladdr.nl_family != AF_NETLINK) {
        error("rtnetlink_msg: recvmsg(%s): Not a netlink packet (line %d)", desc, __LINE__);
        return 1;
    }

    if (!nlresp_size) {
        if ((size_t)nlresp_len < sizeof(nlresp_hdr) || nlresp_hdr.nlh.nlmsg_len < sizeof(nlresp_hdr)) {
            error("rtnetlink_msg: recvmsg(%s): Acknowledgment netlink packet too short (line %d)", desc, __LINE__);
            return 1;
        }

        /* acknowledgment packet for NLM_F_ACK is NLMSG_ERROR */
        if (nlresp_hdr.nlh.nlmsg_type != NLMSG_ERROR) {
            error("rtnetlink_msg: recvmsg(%s): Not an acknowledgment netlink packet (line %d)", desc, __LINE__);
            return 1;
        }
    }

    if (nlresp_size) {
        if (*nlresp_size > sizeof(nlresp_hdr))
            memcpy((unsigned char *)&nlresp_hdr + offsetof(struct nlresp_hdr, nlerr), nlresp_data, sizeof(nlresp_hdr.nlerr));
        else
            memcpy(nlresp_data, (unsigned char *)&nlresp_hdr + offsetof(struct nlresp_hdr, nlerr), *nlresp_size);
    }

    /* error == 0 indicates success, negative value is errno code */
    if (nlresp_hdr.nlh.nlmsg_type == NLMSG_ERROR && nlresp_hdr.nlerr.error)
        return nlresp_hdr.nlerr.error;

    if (nlresp_size) {
        if (nlresp_hdr.nlh.nlmsg_type != nlresp_type) {
            error("rtnetlink_msg: recvmsg(%s): Not a netlink packet of type 0x%x (line %d)", desc, nlresp_type, __LINE__);
            return 1;
        }
        *nlresp_size = nlresp_len - offsetof(struct nlresp_hdr, nlerr);
    }

    return 0;
}

/*
 * Determine if the PPP connection should still be present.
 */

extern int hungup;

/* new_fd is the fd of a tty */
static void set_ppp_fd (int new_fd)
{
	ppp_fd = new_fd;
	if (!new_style_driver)
		ppp_dev_fd = new_fd;
}

static int still_ppp(void)
{
	if (new_style_driver)
		return !hungup && ppp_fd >= 0;
	if (!hungup || ppp_fd == slave_fd)
		return 1;
	if (slave_fd >= 0) {
		set_ppp_fd(slave_fd);
		return 1;
	}
	return 0;
}

/*
 * modify_flags - set and clear flag bits controlling the kernel
 * PPP driver.
 */
static int modify_flags(int fd, int clear_bits, int set_bits)
{
	int flags;

	if (ioctl(fd, PPPIOCGFLAGS, &flags) == -1)
		goto err;
	flags = (flags & ~clear_bits) | set_bits;
	if (ioctl(fd, PPPIOCSFLAGS, &flags) == -1)
		goto err;

	return 0;

 err:
	if (errno != EIO)
		error("Failed to set PPP kernel option flags: %m");
	return -1;
}

/********************************************************************
 *
 * sys_init - System-dependent initialization.
 */

void sys_init(void)
{
    /* Get an internet socket for doing socket ioctls. */
    sock_fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock_fd < 0)
	fatal("Couldn't create IP socket: %m(%d)", errno);

#ifdef PPP_WITH_IPV6CP
    sock6_fd = socket(AF_INET6, SOCK_DGRAM, 0);
    if (sock6_fd < 0)
	sock6_fd = -errno;	/* save errno for later */
#endif

    FD_ZERO(&in_fds);
    max_in_fd = 0;
}

/********************************************************************
 *
 * sys_cleanup - restore any system state we modified before exiting:
 * mark the interface down, delete default route and/or proxy arp entry.
 * This shouldn't call die() because it's called from die().
 */

void sys_cleanup(void)
{
/*
 * Take down the device
 */
    if (if_is_up) {
	if_is_up = 0;
	sifdown(0);
    }
#ifdef PPP_WITH_IPV6CP
    if (if6_is_up)
	sif6down(0);
#endif

/*
 * Delete any routes through the device.
 */
    if (have_default_route)
	cifdefaultroute(0, 0, 0);
#ifdef PPP_WITH_IPV6CP
    if (have_default_route6)
	cif6defaultroute(0, nulleui64, nulleui64);
#endif

    if (has_proxy_arp)
	cifproxyarp(0, proxy_arp_addr);
}

/********************************************************************
 *
 * ppp_sys_close - Clean up in a child process before execing.
 */
void
ppp_sys_close(void)
{
    if (new_style_driver && ppp_dev_fd >= 0)
	close(ppp_dev_fd);
    if (sock_fd >= 0)
	close(sock_fd);
#ifdef PPP_WITH_IPV6CP
    if (sock6_fd >= 0)
	close(sock6_fd);
#endif
    if (slave_fd >= 0)
	close(slave_fd);
    if (master_fd >= 0)
	close(master_fd);
}

/********************************************************************
 *
 * set_kdebugflag - Define the debugging level for the kernel
 */

static int set_kdebugflag (int requested_level)
{
    if (ppp_dev_fd < 0)
	return 1;
    if (ioctl(ppp_dev_fd, PPPIOCSDEBUG, &requested_level) < 0) {
	if ( ! ok_error (errno) )
	    error("ioctl(PPPIOCSDEBUG): %m (line %d)", __LINE__);
	return (0);
    }
    return (1);
}

/********************************************************************
 *
 * tty_establish_ppp - Turn the serial port into a ppp interface.
 */

int tty_establish_ppp (int tty_fd)
{
    int ret_fd;

/*
 * Ensure that the tty device is in exclusive mode.
 */
    if (ioctl(tty_fd, TIOCEXCL, 0) < 0) {
	if ( ! ok_error ( errno ))
	    warn("Couldn't make tty exclusive: %m");
    }
/*
 * Demand mode - prime the old ppp device to relinquish the unit.
 */
    if (!new_style_driver && looped
	&& ioctl(slave_fd, PPPIOCXFERUNIT, 0) < 0) {
	error("ioctl(transfer ppp unit): %m, line %d", __LINE__);
	return -1;
    }
/*
 * Set the current tty to the PPP discpline
 */

#ifndef N_SYNC_PPP
#define N_SYNC_PPP 14
#endif
    ppp_disc = (new_style_driver && ppp_sync_serial())? N_SYNC_PPP: N_PPP;
    if (ioctl(tty_fd, TIOCSETD, &ppp_disc) < 0) {
	if ( ! ok_error (errno) ) {
	    error("Couldn't set tty to PPP discipline: %m");
	    return -1;
	}
    }

    ret_fd = ppp_generic_establish(tty_fd);

#define SC_RCVB	(SC_RCV_B7_0 | SC_RCV_B7_1 | SC_RCV_EVNP | SC_RCV_ODDP)
#define SC_LOGB	(SC_DEBUG | SC_LOG_INPKT | SC_LOG_OUTPKT | SC_LOG_RAWIN \
		 | SC_LOG_FLUSH)

    if (ret_fd >= 0) {
	modify_flags(ppp_fd, SC_RCVB | SC_LOGB,
		     (kdebugflag * SC_DEBUG) & SC_LOGB);
    } else {
	if (ioctl(tty_fd, TIOCSETD, &tty_disc) < 0 && !ok_error(errno))
	    warn("Couldn't reset tty to normal line discipline: %m");
    }

    return ret_fd;
}

/********************************************************************
 *
 * generic_establish_ppp - Turn the fd into a ppp interface.
 */
int ppp_generic_establish (int fd)
{
    int x;

    if (new_style_driver) {
	int flags;

	/* If a ppp_fd is already open, close it first */
	if (ppp_fd >= 0) {
	    close(ppp_fd);
	    remove_fd(ppp_fd);
	    ppp_fd = -1;
	}

	/* Open an instance of /dev/ppp and connect the channel to it */
	if (ioctl(fd, PPPIOCGCHAN, &chindex) == -1) {
	    error("Couldn't get channel number: %m");
	    goto err;
	}
	dbglog("using channel %d", chindex);
	fd = open("/dev/ppp", O_RDWR);
	if (fd < 0) {
	    error("Couldn't reopen /dev/ppp: %m");
	    goto err;
	}
	(void) fcntl(fd, F_SETFD, FD_CLOEXEC);
	if (ioctl(fd, PPPIOCATTCHAN, &chindex) < 0) {
	    error("Couldn't attach to channel %d: %m", chindex);
	    goto err_close;
	}
	flags = fcntl(fd, F_GETFL);
	if (flags == -1 || fcntl(fd, F_SETFL, flags | O_NONBLOCK) == -1)
	    warn("Couldn't set /dev/ppp (channel) to nonblock: %m");
	set_ppp_fd(fd);

	if (!looped)
	    ifunit = -1;
	if (!looped && !multilink) {
	    /*
	     * Create a new PPP unit.
	     */
	    if (make_ppp_unit() < 0)
		goto err_close;
	}

	if (looped)
	    modify_flags(ppp_dev_fd, SC_LOOP_TRAFFIC, 0);

	if (!multilink) {
	    add_fd(ppp_dev_fd);
	    if (ioctl(fd, PPPIOCCONNECT, &ifunit) < 0) {
		error("Couldn't attach to PPP unit %d: %m", ifunit);
		goto err_close;
	    }
	}

    } else {
	/*
	 * Old-style driver: find out which interface we were given.
	 */
	set_ppp_fd (fd);
	if (ioctl(fd, PPPIOCGUNIT, &x) < 0) {
	    if (ok_error (errno))
		goto err;
	    fatal("ioctl(PPPIOCGUNIT): %m (line %d)", __LINE__);
	}
	/* Check that we got the same unit again. */
	if (looped && x != ifunit)
	    fatal("transfer_ppp failed: wanted unit %d, got %d", ifunit, x);
	ifunit = x;

	/*
	 * Fetch the initial file flags and reset blocking mode on the file.
	 */
	initfdflags = fcntl(fd, F_GETFL);
	if (initfdflags == -1 ||
	    fcntl(fd, F_SETFL, initfdflags | O_NONBLOCK) == -1) {
	    if ( ! ok_error (errno))
		warn("Couldn't set device to non-blocking mode: %m");
	}
    }

    /*
     * Enable debug in the driver if requested.
     */
    if (!looped)
	set_kdebugflag (kdebugflag);

    looped = 0;

    return ppp_fd;

 err_close:
    close(fd);
 err:
    return -1;
}

/********************************************************************
 *
 * tty_disestablish_ppp - Restore the serial port to normal operation.
 * This shouldn't call die() because it's called from die().
 */

void tty_disestablish_ppp(int tty_fd)
{
    if (!hungup) {
/*
 * Flush the tty output buffer so that the TIOCSETD doesn't hang.
 */
	if (tcflush(tty_fd, TCIOFLUSH) < 0)
	{
	    warn("tcflush failed: %m");
	    goto flushfailed;
	}
/*
 * Restore the previous line discipline
 */
	if (ioctl(tty_fd, TIOCSETD, &tty_disc) < 0) {
	    if ( ! ok_error (errno))
		error("ioctl(TIOCSETD, N_TTY): %m (line %d)", __LINE__);
	}

	if (ioctl(tty_fd, TIOCNXCL, 0) < 0) {
	    if ( ! ok_error (errno))
		warn("ioctl(TIOCNXCL): %m (line %d)", __LINE__);
	}

	/* Reset non-blocking mode on fd. */
	if (initfdflags != -1 && fcntl(tty_fd, F_SETFL, initfdflags) < 0) {
	    if ( ! ok_error (errno))
		warn("Couldn't restore device fd flags: %m");
	}
    }
flushfailed:
    initfdflags = -1;

    ppp_generic_disestablish(tty_fd);
}

/********************************************************************
 *
 * ppp_generic_disestablish - Restore device components to normal
 * operation, and reconnect the ppp unit to the loopback if in demand
 * mode.  This shouldn't call die() because it's called from die().
 */
void ppp_generic_disestablish(int dev_fd)
{
    if (new_style_driver) {
	close(ppp_fd);
	ppp_fd = -1;
	if (demand) {
	    modify_flags(ppp_dev_fd, 0, SC_LOOP_TRAFFIC);
	    looped = 1;
	} else if (!mp_on() && ppp_dev_fd >= 0) {
	    close(ppp_dev_fd);
	    remove_fd(ppp_dev_fd);
	    ppp_dev_fd = -1;
	}
    } else {
	/* old-style driver */
	if (demand)
	    set_ppp_fd(slave_fd);
	else
	    ppp_dev_fd = -1;
    }
}

/*
 * make_ppp_unit_rtnetlink - register a new ppp network interface for ppp_dev_fd
 * with specified req_ifname via rtnetlink. Interface name req_ifname must not
 * be empty. Custom ppp unit id req_unit is ignored and kernel choose some free.
 */
static int make_ppp_unit_rtnetlink(void)
{
    struct {
        struct nlmsghdr nlh;
        struct ifinfomsg ifm;
        struct {
            struct rtattr rta;
            char ifname[IFNAMSIZ];
        } ifn;
        struct {
            struct rtattr rta;
            struct {
                struct rtattr rta;
                char ifkind[sizeof("ppp")];
            } ifik;
            struct {
                struct rtattr rta;
                struct {
                    struct rtattr rta;
                    union {
                        int ppp_dev_fd;
                    } ppp;
                } ifdata[1];
            } ifid;
        } ifli;
    } nlreq;
    int resp;

    memset(&nlreq, 0, sizeof(nlreq));
    nlreq.nlh.nlmsg_len = sizeof(nlreq);
    nlreq.nlh.nlmsg_type = RTM_NEWLINK;
    nlreq.nlh.nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK | NLM_F_EXCL | NLM_F_CREATE;
    nlreq.ifm.ifi_family = AF_UNSPEC;
    nlreq.ifm.ifi_type = ARPHRD_NETROM;
    nlreq.ifn.rta.rta_len = sizeof(nlreq.ifn);
    nlreq.ifn.rta.rta_type = IFLA_IFNAME;
    strlcpy(nlreq.ifn.ifname, req_ifname, sizeof(nlreq.ifn.ifname));
    nlreq.ifli.rta.rta_len = sizeof(nlreq.ifli);
    nlreq.ifli.rta.rta_type = IFLA_LINKINFO;
    nlreq.ifli.ifik.rta.rta_len = sizeof(nlreq.ifli.ifik);
    nlreq.ifli.ifik.rta.rta_type = IFLA_INFO_KIND;
    strcpy(nlreq.ifli.ifik.ifkind, "ppp");
    nlreq.ifli.ifid.rta.rta_len = sizeof(nlreq.ifli.ifid);
    nlreq.ifli.ifid.rta.rta_type = IFLA_INFO_DATA;
    nlreq.ifli.ifid.ifdata[0].rta.rta_len = sizeof(nlreq.ifli.ifid.ifdata[0]);
    nlreq.ifli.ifid.ifdata[0].rta.rta_type = IFLA_PPP_DEV_FD;
    nlreq.ifli.ifid.ifdata[0].ppp.ppp_dev_fd = ppp_dev_fd;

    /*
     * See kernel function ppp_nl_newlink(), which may return -EBUSY to prevent
     * possible deadlock in kernel and ask userspace to retry request again.
     */
    do {
        resp = rtnetlink_msg("RTM_NEWLINK/NLM_F_CREATE", NULL, &nlreq, sizeof(nlreq), NULL, NULL, 0);
    } while (resp == -EBUSY);

    if (resp) {
        /*
         * Linux kernel versions prior to 4.7 do not support creating ppp
         * interfaces via rtnetlink API and therefore error response is
         * expected. On older kernel versions do not show this error message.
         * When error is different than EEXIST then pppd tries to fallback to
         * the old ioctl method.
         */
        errno = (resp < 0) ? -resp : EINVAL;
        if (kernel_version >= KVERSION(4,7,0))
            error("Couldn't create ppp interface %s: %m", req_ifname);
        return 0;
    }

    return 1;
}

/*
 * make_ppp_unit - make a new ppp unit for ppp_dev_fd.
 * Assumes new_style_driver.
 */
static int make_ppp_unit(void)
{
	int x, flags;

	if (ppp_dev_fd >= 0) {
		dbglog("in make_ppp_unit, already had /dev/ppp open?");
		close(ppp_dev_fd);
	}
	ppp_dev_fd = open("/dev/ppp", O_RDWR);
	if (ppp_dev_fd < 0)
		fatal("Couldn't open /dev/ppp: %m");
	flags = fcntl(ppp_dev_fd, F_GETFL);
	if (flags == -1
	    || fcntl(ppp_dev_fd, F_SETFL, flags | O_NONBLOCK) == -1)
		warn("Couldn't set /dev/ppp to nonblock: %m");

	/*
	 * Via rtnetlink it is possible to create ppp network interface with
	 * custom ifname atomically. But it is not possible to specify custom
	 * ppp unit id.
	 *
	 * Tools like systemd, udev or NetworkManager are trying to query
	 * interface attributes based on interface name immediately when new
	 * network interface is created. And therefore immediate interface
	 * renaming is causing issues.
	 *
	 * So use rtnetlink API only when user requested custom ifname. It will
	 * avoid system issues with interface renaming.
	 */
	if (req_unit == -1 && req_ifname[0] != '\0' && kernel_version >= KVERSION(2,1,16)) {
	    if (make_ppp_unit_rtnetlink()) {
		if (ioctl(ppp_dev_fd, PPPIOCGUNIT, &ifunit))
		    fatal("Couldn't retrieve PPP unit id: %m");
		return 0;
	    }
	    /*
	     * If interface with requested name already exist return error
	     * otherwise fallback to old ioctl method.
	     */
	    if (errno == EEXIST)
		return -1;
	}

	ifunit = req_unit;
	x = ioctl(ppp_dev_fd, PPPIOCNEWUNIT, &ifunit);
	if (x < 0 && req_unit >= 0 && errno == EEXIST) {
		warn("Couldn't allocate PPP unit %d as it is already in use", req_unit);
		ifunit = -1;
		x = ioctl(ppp_dev_fd, PPPIOCNEWUNIT, &ifunit);
	}
	if (x < 0 && errno == EEXIST) {
		srand(time(NULL) * getpid());
		ifunit = rand() % 10000;
		x = ioctl(ppp_dev_fd, PPPIOCNEWUNIT, &ifunit);
	}
	if (x < 0)
		error("Couldn't create new ppp unit: %m");

	if (x == 0 && req_ifname[0] != '\0') {
		struct ifreq ifr;
		char t[IFNAMSIZ];
		memset(&ifr, 0, sizeof(struct ifreq));
		slprintf(t, sizeof(t), "%s%d", PPP_DRV_NAME, ifunit);
		strlcpy(ifr.ifr_name, t, IFNAMSIZ);
		strlcpy(ifr.ifr_newname, req_ifname, IFNAMSIZ);
		x = ioctl(sock_fd, SIOCSIFNAME, &ifr);
		if (x < 0)
		    error("Couldn't rename interface %s to %s: %m", t, req_ifname);
		else
		    info("Renamed interface %s to %s", t, req_ifname);
	}

	return x;
}

/*
 * cfg_bundle - configure the existing bundle.
 * Used in demand mode.
 */
void cfg_bundle(int mrru, int mtru, int rssn, int tssn)
{
	if (!new_style_driver)
		return;

	/* set the mrru, mtu and flags */
	if (ioctl(ppp_dev_fd, PPPIOCSMRRU, &mrru) < 0)
		error("Couldn't set MRRU: %m");

	modify_flags(ppp_dev_fd, SC_MP_SHORTSEQ|SC_MP_XSHORTSEQ|SC_MULTILINK,
		     ((rssn? SC_MP_SHORTSEQ: 0) | (tssn? SC_MP_XSHORTSEQ: 0)
		      | (mrru? SC_MULTILINK: 0)));

	/* connect up the channel */
	if (ioctl(ppp_fd, PPPIOCCONNECT, &ifunit) < 0)
		fatal("Couldn't attach to PPP unit %d: %m", ifunit);
	add_fd(ppp_dev_fd);
}

/*
 * make_new_bundle - create a new PPP unit (i.e. a bundle)
 * and connect our channel to it.  This should only get called
 * if `multilink' was set at the time establish_ppp was called.
 * In demand mode this uses our existing bundle instead of making
 * a new one.
 */
void make_new_bundle(int mrru, int mtru, int rssn, int tssn)
{
	if (!new_style_driver)
		return;

	/* make us a ppp unit */
	if (make_ppp_unit() < 0)
		die(1);

	/* set the mrru and flags */
	cfg_bundle(mrru, mtru, rssn, tssn);
}

/*
 * bundle_attach - attach our link to a given PPP unit.
 * We assume the unit is controlled by another pppd.
 */
int bundle_attach(int ifnum)
{
	int master_fd;

	if (!new_style_driver)
		return -1;

	master_fd = open("/dev/ppp", O_RDWR);
	if (master_fd < 0)
		fatal("Couldn't open /dev/ppp: %m");
	if (ioctl(master_fd, PPPIOCATTACH, &ifnum) < 0) {
		if (errno == ENXIO) {
			close(master_fd);
			return 0;	/* doesn't still exist */
		}
		fatal("Couldn't attach to interface unit %d: %m\n", ifnum);
	}
	if (ioctl(ppp_fd, PPPIOCCONNECT, &ifnum) < 0)
		fatal("Couldn't connect to interface unit %d: %m", ifnum);
	modify_flags(master_fd, 0, SC_MULTILINK);
	close(master_fd);

	ifunit = ifnum;
	return 1;
}

/*
 * destroy_bundle - tell the driver to destroy our bundle.
 */
void destroy_bundle(void)
{
	if (ppp_dev_fd >= 0) {
		close(ppp_dev_fd);
		remove_fd(ppp_dev_fd);
		ppp_dev_fd = -1;
	}
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

    if (still_ppp()) {
	if (ioctl(ppp_fd, PPPIOCGFLAGS, (caddr_t) &x) == 0) {
	    s = NULL;
	    switch (~x & (SC_RCV_B7_0|SC_RCV_B7_1|SC_RCV_EVNP|SC_RCV_ODDP)) {
	    case SC_RCV_B7_0:
		s = "all had bit 7 set to 1";
		break;

	    case SC_RCV_B7_1:
		s = "all had bit 7 set to 0";
		break;

	    case SC_RCV_EVNP:
		s = "all had odd parity";
		break;

	    case SC_RCV_ODDP:
		s = "all had even parity";
		break;
	    }

	    if (s != NULL) {
		warn("Receive serial link is not 8-bit clean:");
		warn("Problem: %s", s);
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
#ifdef B76800
    { 76800, B76800 },
#endif
#ifdef B115200
    { 115200, B115200 },
#endif
#ifdef B153600
    { 153600, B153600 },
#endif
#ifdef EXTA
    { 19200, EXTA },
#endif
#ifdef EXTB
    { 38400, EXTB },
#endif
#ifdef B230400
    { 230400, B230400 },
#endif
#ifdef B307200
    { 307200, B307200 },
#endif
#ifdef B460800
    { 460800, B460800 },
#endif
#ifdef B500000
    { 500000, B500000 },
#endif
#ifdef B576000
    { 576000, B576000 },
#endif
#ifdef B614400
    { 614400, B614400 },
#endif
#ifdef B921600
    { 921600, B921600 },
#endif
#ifdef B1000000
    { 1000000, B1000000 },
#endif
#ifdef B1152000
    { 1152000, B1152000 },
#endif
#ifdef B1500000
    { 1500000, B1500000 },
#endif
#ifdef B2000000
    { 2000000, B2000000 },
#endif
#ifdef B2500000
    { 2500000, B2500000 },
#endif
#ifdef B3000000
    { 3000000, B3000000 },
#endif
#ifdef B3500000
    { 3500000, B3500000 },
#endif
#ifdef B4000000
    { 4000000, B4000000 },
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

    if (bps != 0) {
	for (speedp = speeds; speedp->speed_int; speedp++) {
	    if (bps == speedp->speed_int)
		return speedp->speed_val;
	}
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

    if (speed != 0) {
	for (speedp = speeds; speedp->speed_int; speedp++) {
	    if (speed == speedp->speed_val)
		return speedp->speed_int;
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

void set_up_tty(int tty_fd, int local)
{
    int speed;
    struct termios tios;

    setdtr(tty_fd, 1);
    if (tcgetattr(tty_fd, &tios) < 0) {
	if (!ok_error(errno))
	    fatal("tcgetattr: %m (line %d)", __LINE__);
	return;
    }

    if (!restore_term)
	inittermios = tios;

    tios.c_cflag     &= ~(CSIZE | CSTOPB | PARENB | CLOCAL);
    tios.c_cflag     |= CS8 | CREAD | HUPCL;

    tios.c_iflag      = IGNBRK | IGNPAR;
    tios.c_oflag      = 0;
    tios.c_lflag      = 0;
    tios.c_cc[VMIN]   = 1;
    tios.c_cc[VTIME]  = 0;

    if (local || !modem)
	tios.c_cflag ^= (CLOCAL | HUPCL);

    switch (crtscts) {
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

    if (stop_bits >= 2)
	tios.c_cflag |= CSTOPB;

    if (inspeed) {
	speed = translate_speed(inspeed);
	if (speed) {
	    cfsetospeed (&tios, speed);
	    cfsetispeed (&tios, speed);
	    speed = cfgetospeed(&tios);
	    baud_rate = baud_rate_of(speed);
	} else {
#ifdef BOTHER
	    tios.c_cflag &= ~CBAUD;
	    tios.c_cflag |= BOTHER;
	    tios.c_ospeed = inspeed;
#ifdef IBSHIFT
	    /* B0 sets input baudrate to the output baudrate */
	    tios.c_cflag &= ~(CBAUD << IBSHIFT);
	    tios.c_cflag |= B0 << IBSHIFT;
	    tios.c_ispeed = inspeed;
#endif
	    baud_rate = inspeed;
#else
	    baud_rate = 0;
#endif
	}
    }
    else {
	speed = cfgetospeed(&tios);
	baud_rate = baud_rate_of(speed);
#ifdef BOTHER
	if (!baud_rate)
	    baud_rate = tios.c_ospeed;
#endif
    }

/*
 * We can't proceed if the serial port baud rate is unknown,
 * since that implies that the serial port is disabled.
 */
    if (!baud_rate) {
	if (inspeed)
	    fatal("speed %d not supported", inspeed);
	else
	    fatal("Baud rate for %s is 0; need explicit baud rate", devnam);
    }

    while (tcsetattr(tty_fd, TCSAFLUSH, &tios) < 0 && !ok_error(errno))
	if (errno != EINTR)
	    fatal("tcsetattr: %m (line %d)", __LINE__);
    restore_term = 1;
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
    if (restore_term) {
	restore_term = 0;
/*
 * Turn off echoing, because otherwise we can get into
 * a loop with the tty and the modem echoing to each other.
 * We presume we are the sole user of this tty device, so
 * when we close it, it will revert to its defaults anyway.
 */
	if (!default_device)
	    inittermios.c_lflag &= ~(ECHO | ECHONL);

	if (tcsetattr(tty_fd, TCSAFLUSH, &inittermios) < 0) {
	    if (! ok_error (errno))
		warn("tcsetattr: %m (line %d)", __LINE__);
	}
    }
}

/********************************************************************
 *
 * output - Output PPP packet.
 */

void output (int unit, unsigned char *p, int len)
{
    int fd = ppp_fd;
    int proto;

    dump_packet("sent", p, len);
    if (snoop_send_hook) snoop_send_hook(p, len);

    if (len < PPP_HDRLEN)
	return;
    if (new_style_driver) {
	p += 2;
	len -= 2;
	proto = (p[0] << 8) + p[1];
	if (ppp_dev_fd >= 0 && !(proto >= 0xc000 || proto == PPP_CCPFRAG))
	    fd = ppp_dev_fd;
    }
    if (write(fd, p, len) < 0) {
	if (errno == EWOULDBLOCK || errno == EAGAIN || errno == ENOBUFS
	    || errno == ENXIO || errno == EIO || errno == EINTR)
	    warn("write: warning: %m (%d)", errno);
	else
	    error("write: %m (%d)", errno);
    }
}

/********************************************************************
 *
 * wait_input - wait until there is data available,
 * for the length of time specified by *timo (indefinite
 * if timo is NULL).
 */

void wait_input(struct timeval *timo)
{
    fd_set ready, exc;
    int n;

    ready = in_fds;
    exc = in_fds;
    n = select(max_in_fd + 1, &ready, NULL, &exc, timo);
    if (n < 0 && errno != EINTR)
	fatal("select: %m");
}

/*
 * add_fd - add an fd to the set that wait_input waits for.
 */
void add_fd(int fd)
{
    if (fd >= FD_SETSIZE)
	fatal("internal error: file descriptor too large (%d)", fd);
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


/********************************************************************
 *
 * read_packet - get a PPP packet from the serial device.
 */

int read_packet (unsigned char *buf)
{
    int len, nr;

    len = PPP_MRU + PPP_HDRLEN;
    if (new_style_driver) {
	*buf++ = PPP_ALLSTATIONS;
	*buf++ = PPP_UI;
	len -= 2;
    }
    nr = -1;
    if (ppp_fd >= 0) {
	nr = read(ppp_fd, buf, len);
	if (nr < 0 && errno != EWOULDBLOCK && errno != EAGAIN
	    && errno != EIO && errno != EINTR)
	    error("read: %m");
	if (nr < 0 && errno == ENXIO)
	    return 0;
    }
    if (nr < 0 && new_style_driver && ppp_dev_fd >= 0 && !bundle_eof) {
	/* N.B. we read ppp_fd first since LCP packets come in there. */
	nr = read(ppp_dev_fd, buf, len);
	if (nr < 0 && errno != EWOULDBLOCK && errno != EAGAIN
	    && errno != EIO && errno != EINTR)
	    error("read /dev/ppp: %m");
	if (nr < 0 && errno == ENXIO)
	    nr = 0;
	if (nr == 0 && mp_on()) {
	    remove_fd(ppp_dev_fd);
	    bundle_eof = 1;
	}
    }
    if (new_style_driver && ppp_fd < 0 && ppp_dev_fd < 0)
	nr = 0;
    return (new_style_driver && nr > 0)? nr+2: nr;
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
    int n;

    if (new_style_driver) {
	while ((n = read_packet(inpacket_buf)) > 0)
	    if (loop_frame(inpacket_buf, n))
		rv = 1;
	return rv;
    }

    while ((n = read(master_fd, inbuf, sizeof(inbuf))) > 0)
	if (loop_chars(inbuf, n))
	    rv = 1;

    if (n == 0)
	fatal("eof on loopback");

    if (errno != EWOULDBLOCK && errno != EAGAIN)
	fatal("read from loopback: %m(%d)", errno);

    return rv;
}

/*
 * netif_set_mtu - set the MTU on the PPP network interface.
 */
void
ppp_set_mtu(int unit, int mtu)
{
    struct ifreq ifr;

    memset (&ifr, '\0', sizeof (ifr));
    strlcpy(ifr.ifr_name, ifname, sizeof (ifr.ifr_name));
    ifr.ifr_mtu = mtu;

    if (ifunit >= 0 && ioctl(sock_fd, SIOCSIFMTU, (caddr_t) &ifr) < 0)
	error("ioctl(SIOCSIFMTU): %m (line %d)", __LINE__);
}

/*
 * netif_get_mtu - get the MTU on the PPP network interface.
 */
int
ppp_get_mtu(int unit)
{
    struct ifreq ifr;

    memset (&ifr, '\0', sizeof (ifr));
    strlcpy(ifr.ifr_name, ifname, sizeof (ifr.ifr_name));

    if (ifunit >= 0 && ioctl(sock_fd, SIOCGIFMTU, (caddr_t) &ifr) < 0) {
	error("ioctl(SIOCGIFMTU): %m (line %d)", __LINE__);
	return 0;
    }
    return ifr.ifr_mtu;
}

/********************************************************************
 *
 * tty_send_config - configure the transmit characteristics of
 * the ppp interface.
 */

void tty_send_config(int mtu, u_int32_t asyncmap, int pcomp, int accomp)
{
	int x;

	if (!still_ppp())
		return;
	link_mtu = mtu;
	if (ioctl(ppp_fd, PPPIOCSASYNCMAP, (caddr_t) &asyncmap) < 0) {
		if (errno != EIO && errno != ENOTTY)
			error("Couldn't set transmit async character map: %m");
		++error_count;
		return;
	}

	x = (pcomp? SC_COMP_PROT: 0) | (accomp? SC_COMP_AC: 0)
	    | (ppp_sync_serial()? SC_SYNC: 0);
	modify_flags(ppp_fd, SC_COMP_PROT|SC_COMP_AC|SC_SYNC, x);
}

/********************************************************************
 *
 * tty_set_xaccm - set the extended transmit ACCM for the interface.
 */

void tty_set_xaccm (ext_accm accm)
{
    if (!still_ppp())
	return;
    if (ioctl(ppp_fd, PPPIOCSXASYNCMAP, accm) < 0 && errno != ENOTTY) {
	if ( ! ok_error (errno))
	    warn("ioctl(set extended ACCM): %m (line %d)", __LINE__);
    }
}

/********************************************************************
 *
 * tty_recv_config - configure the receive-side characteristics of
 * the ppp interface.
 */

void tty_recv_config(int mru, u_int32_t asyncmap, int pcomp, int accomp)
{
/*
 * If we were called because the link has gone down then there is nothing
 * which may be done. Just return without incident.
 */
	if (!still_ppp())
		return;
/*
 * Set the receiver parameters
 */
	if (ioctl(ppp_fd, PPPIOCSMRU, (caddr_t) &mru) < 0) {
		if (errno != EIO && errno != ENOTTY)
			error("Couldn't set channel receive MRU: %m");
	}
	if (new_style_driver && ppp_dev_fd >= 0
	    && ioctl(ppp_dev_fd, PPPIOCSMRU, (caddr_t) &mru) < 0)
		error("Couldn't set MRU in generic PPP layer: %m");

	if (ioctl(ppp_fd, PPPIOCSRASYNCMAP, (caddr_t) &asyncmap) < 0) {
		if (errno != EIO && errno != ENOTTY)
			error("Couldn't set channel receive asyncmap: %m");
	}
}

/********************************************************************
 *
 * ccp_test - ask kernel whether a given compression method
 * is acceptable for use.
 */

int
ccp_test(int unit, u_char *opt_ptr, int opt_len, int for_transmit)
{
    struct ppp_option_data data;

    memset (&data, '\0', sizeof (data));
    data.ptr      = opt_ptr;
    data.length   = opt_len;
    data.transmit = for_transmit;

    if (ioctl(ppp_dev_fd, PPPIOCSCOMPRESS, (caddr_t) &data) >= 0)
	return 1;

    return (errno == ENOBUFS)? 0: -1;
}

/********************************************************************
 *
 * ccp_flags_set - inform kernel about the current state of CCP.
 */

void ccp_flags_set (int unit, int isopen, int isup)
{
	int x;

	x = (isopen? SC_CCP_OPEN: 0) | (isup? SC_CCP_UP: 0);
	if (still_ppp() && ppp_dev_fd >= 0)
		modify_flags(ppp_dev_fd, SC_CCP_OPEN|SC_CCP_UP, x);
}

#ifdef PPP_WITH_FILTER
/*
 * set_filters - set the active and pass filters in the kernel driver.
 */
int set_filters(struct bpf_program *pass, struct bpf_program *active)
{
	struct sock_fprog fp;

	fp.len = pass->bf_len;
	fp.filter = (struct sock_filter *) pass->bf_insns;
	if (ioctl(ppp_dev_fd, PPPIOCSPASS, &fp) < 0) {
		if (errno == ENOTTY)
			warn("kernel does not support PPP filtering");
		else
			error("Couldn't set pass-filter in kernel: %m");
		return 0;
	}
	fp.len = active->bf_len;
	fp.filter = (struct sock_filter *) active->bf_insns;
	if (ioctl(ppp_dev_fd, PPPIOCSACTIVE, &fp) < 0) {
		error("Couldn't set active-filter in kernel: %m");
		return 0;
	}
	return 1;
}
#endif /* PPP_WITH_FILTER */

/********************************************************************
 *
 * get_idle_time - return how long the link has been idle.
 */
int
get_idle_time(int u, struct ppp_idle *ip)
{
    return ioctl(ppp_dev_fd, PPPIOCGIDLE, ip) >= 0;
}

/********************************************************************
 *
 * get_ppp_stats_iocl - return statistics for the link, using the ioctl() method,
 * this only supports 32-bit counters, so need to count the wraps.
 */
static int
get_ppp_stats_ioctl(int u, struct pppd_stats *stats)
{
    static u_int32_t previbytes = 0;
    static u_int32_t prevobytes = 0;
    static u_int32_t iwraps = 0;
    static u_int32_t owraps = 0;

    struct ifreq req;
    struct ppp_stats data;

    memset (&req, 0, sizeof (req));

    req.ifr_data = (caddr_t) &data;
    strlcpy(req.ifr_name, ifname, sizeof(req.ifr_name));
    if (ioctl(sock_fd, SIOCGPPPSTATS, &req) < 0) {
	error("Couldn't get PPP statistics: %m");
	return 0;
    }
    stats->bytes_in = data.p.ppp_ibytes;
    stats->bytes_out = data.p.ppp_obytes;
    stats->pkts_in = data.p.ppp_ipackets;
    stats->pkts_out = data.p.ppp_opackets;

    if (stats->bytes_in < previbytes)
	++iwraps;
    if (stats->bytes_out < prevobytes)
	++owraps;

    previbytes = stats->bytes_in;
    prevobytes = stats->bytes_out;

    stats->bytes_in += (uint64_t)iwraps << 32;
    stats->bytes_out += (uint64_t)owraps << 32;

    return 1;
}

/********************************************************************
 * get_ppp_stats_rtnetlink - return statistics for the link, using rtnetlink
 * This provides native 64-bit counters.
 */
static int
get_ppp_stats_rtnetlink(int u, struct pppd_stats *stats)
{
#ifdef RTM_NEWSTATS
    static int fd = -1;

    struct {
        struct nlmsghdr nlh;
        struct if_stats_msg ifsm;
    } nlreq;
    struct {
        struct rtmsg rth;
        struct {
            /* We only case about these first fields from rtnl_link_stats64 */
            uint64_t rx_packets;
            uint64_t tx_packets;
            uint64_t rx_bytes;
            uint64_t tx_bytes;
        } stats;
    } nlresp_data;
    size_t nlresp_size;
    int resp;

    memset(&nlreq, 0, sizeof(nlreq));
    nlreq.nlh.nlmsg_len = sizeof(nlreq);
    nlreq.nlh.nlmsg_type = RTM_GETSTATS;
    nlreq.nlh.nlmsg_flags = NLM_F_REQUEST;
    nlreq.ifsm.ifindex = if_nametoindex(ifname);
    nlreq.ifsm.filter_mask = IFLA_STATS_LINK_64;

    nlresp_size = sizeof(nlresp_data);
    resp = rtnetlink_msg("RTM_GETSTATS/NLM_F_REQUEST", &fd, &nlreq, sizeof(nlreq), &nlresp_data, &nlresp_size, RTM_NEWSTATS);
    if (resp) {
        errno = (resp < 0) ? -resp : EINVAL;
        if (kernel_version >= KVERSION(4,7,0))
            error("get_ppp_stats_rtnetlink: %m (line %d)", __LINE__);
        goto err;
    }

    if (nlresp_size < sizeof(nlresp_data)) {
	error("get_ppp_stats_rtnetlink: Obtained an insufficiently sized rtnl_link_stats64 struct from the kernel (line %d).", __LINE__);
	goto err;
    }

    stats->bytes_in  = nlresp_data.stats.rx_bytes;
    stats->bytes_out = nlresp_data.stats.tx_bytes;
    stats->pkts_in   = nlresp_data.stats.rx_packets;
    stats->pkts_out  = nlresp_data.stats.tx_packets;

    return 1;
err:
    close(fd);
    fd = -1;
#endif
    return 0;
}

/********************************************************************
 * get_ppp_stats_sysfs - return statistics for the link, using the files in sysfs,
 * this provides native 64-bit counters.
 */
static int
get_ppp_stats_sysfs(int u, struct pppd_stats *stats)
{
    char fname[PATH_MAX+1];
    char buf[21], *err; /* 2^64 < 10^20 */
    int blen, fd, rlen;
    unsigned long long val;

    struct {
	const char* fname;
	void* ptr;
	unsigned size;
    } slist[] = {
#define statfield(fn, field)	{ .fname = #fn, .ptr = &stats->field, .size = sizeof(stats->field) }
	statfield(rx_bytes, bytes_in),
	statfield(tx_bytes, bytes_out),
	statfield(rx_packets, pkts_in),
	statfield(tx_packets, pkts_out),
#undef statfield
    };

    blen = snprintf(fname, sizeof(fname), "/sys/class/net/%s/statistics/", ifname);
    if (blen >= sizeof(fname))
	return 0; /* ifname max 15, so this should be impossible */

    for (int i = 0; i < sizeof(slist) / sizeof(*slist); ++i) {
	if (snprintf(fname + blen, sizeof(fname) - blen, "%s", slist[i].fname) >= sizeof(fname) - blen) {
	    fname[blen] = 0;
	    error("sysfs stats: filename %s/%s overflowed PATH_MAX", fname, slist[i].fname);
	    return 0;
	}

	fd = open(fname, O_RDONLY);
	if (fd < 0) {
	    error("%s: %m", fname);
	    return 0;
	}

	rlen = read(fd, buf, sizeof(buf) - 1);
	close(fd);
	if (rlen < 0) {
	    error("%s: %m", fname);
	    return 0;
	}
	/* trim trailing \n if present */
	while (rlen > 0 && buf[rlen-1] == '\n')
	    rlen--;
	buf[rlen] = 0;

	errno = 0;
	val = strtoull(buf, &err, 10);
	if (*buf < '0' || *buf > '9' || errno != 0 || *err) {
	    error("string to number conversion error converting %s (from %s) for remaining string %s%s%s",
		    buf, fname, err, errno ? ": " : "", errno ? strerror(errno) : "");
	    return 0;
	}
	switch (slist[i].size) {
#define stattype(type)	case sizeof(type): *(type*)slist[i].ptr = (type)val; break
	    stattype(uint64_t);
	    stattype(uint32_t);
	    stattype(uint16_t);
	    stattype(uint8_t);
#undef stattype
	default:
	    error("Don't know how to store stats for %s of size %u", slist[i].fname, slist[i].size);
	    return 0;
	}
    }

    return 1;
}

/********************************************************************
 * Periodic timer function to be used to keep stats up to date in case of ioctl
 * polling.
 *
 * Given the 25s interval this should be fine up to data rates of 1.37Gbps.
 * If you do change the timer, remember to also bring the get_ppp_stats (which
 * sets up the initial trigger) as well.
 */
static void
ppp_stats_poller(void* u)
{
    struct pppd_stats dummy;
    get_ppp_stats_ioctl((long)u, &dummy);
    TIMEOUT(ppp_stats_poller, u, 25);
}

/********************************************************************
 * get_ppp_stats - return statistics for the link.
 */
int get_ppp_stats(int u, struct pppd_stats *stats)
{
    static int (*func)(int, struct pppd_stats*) = NULL;

    if (!func) {
	if (get_ppp_stats_rtnetlink(u, stats)) {
	    func = get_ppp_stats_rtnetlink;
	    return 1;
	}
	if (get_ppp_stats_sysfs(u, stats)) {
	    func = get_ppp_stats_sysfs;
	    return 1;
	}
	warn("statistics falling back to ioctl which only supports 32-bit counters");
	func = get_ppp_stats_ioctl;
	TIMEOUT(ppp_stats_poller, (void*)(long)u, 25);
    }

    return func(u, stats);
}

/********************************************************************
 *
 * ccp_fatal_error - returns 1 if decompression was disabled as a
 * result of an error detected after decompression of a packet,
 * 0 otherwise.  This is necessary because of patent nonsense.
 */

int ccp_fatal_error (int unit)
{
	int flags;

	if (ioctl(ppp_dev_fd, PPPIOCGFLAGS, &flags) < 0) {
		error("Couldn't read compression error flags: %m");
		flags = 0;
	}
	return flags & SC_DC_FERROR;
}

/********************************************************************
 *
 * path_to_procfs - find the path to the proc file system mount point
 */
static char proc_path[MAXPATHLEN];
static int proc_path_len;

static char *path_to_procfs(const char *tail)
{
    struct mntent *mntent;
    FILE *fp;

    if (proc_path_len == 0) {
	/* Default the mount location of /proc */
	strlcpy (proc_path, "/proc", sizeof(proc_path));
	proc_path_len = 5;
	fp = fopen(MOUNTED, "r");
	if (fp != NULL) {
	    while ((mntent = getmntent(fp)) != NULL) {
		if (strcmp(mntent->mnt_type, MNTTYPE_IGNORE) == 0)
		    continue;
		if (strcmp(mntent->mnt_type, "proc") == 0) {
		    strlcpy(proc_path, mntent->mnt_dir, sizeof(proc_path));
		    proc_path_len = strlen(proc_path);
		    break;
		}
	    }
	    fclose (fp);
	}
    }

    strlcpy(proc_path + proc_path_len, tail,
	    sizeof(proc_path) - proc_path_len);
    return proc_path;
}

/*
 * /proc/net/route parsing stuff.
 */
#define ROUTE_MAX_COLS	12
FILE *route_fd = (FILE *) 0;
static char route_buffer[512];
static int route_dev_col, route_dest_col, route_gw_col;
static int route_flags_col, route_metric_col, route_mask_col;
static int route_num_cols;

static int open_route_table (void);
static void close_route_table (void);
static int read_route_table (struct rtentry *rt);

/********************************************************************
 *
 * close_route_table - close the interface to the route table
 */

static void close_route_table (void)
{
    if (route_fd != (FILE *) 0) {
	fclose (route_fd);
	route_fd = (FILE *) 0;
    }
}

/********************************************************************
 *
 * open_route_table - open the interface to the route table
 */
static char route_delims[] = " \t\n";

static int open_route_table (void)
{
    char *path;

    close_route_table();

    path = path_to_procfs("/net/route");
    route_fd = fopen (path, "r");
    if (route_fd == NULL) {
	error("can't open routing table %s: %m", path);
	return 0;
    }

    route_dev_col = 0;		/* default to usual columns */
    route_dest_col = 1;
    route_gw_col = 2;
    route_flags_col = 3;
    route_metric_col = 6;
    route_mask_col = 7;
    route_num_cols = 8;

    /* parse header line */
    if (fgets(route_buffer, sizeof(route_buffer), route_fd) != 0) {
	char *p = route_buffer, *q;
	int col;
	for (col = 0; col < ROUTE_MAX_COLS; ++col) {
	    int used = 1;
	    if ((q = strtok(p, route_delims)) == 0)
		break;
	    if (strcasecmp(q, "iface") == 0)
		route_dev_col = col;
	    else if (strcasecmp(q, "destination") == 0)
		route_dest_col = col;
	    else if (strcasecmp(q, "gateway") == 0)
		route_gw_col = col;
	    else if (strcasecmp(q, "flags") == 0)
		route_flags_col = col;
	    else if (strcasecmp(q, "mask") == 0)
		route_mask_col = col;
	    else
		used = 0;
	    if (used && col >= route_num_cols)
		route_num_cols = col + 1;
	    p = NULL;
	}
    }

    return 1;
}

/********************************************************************
 *
 * read_route_table - read the next entry from the route table
 */

static int read_route_table(struct rtentry *rt)
{
    char *cols[ROUTE_MAX_COLS], *p;
    int col;

    memset (rt, '\0', sizeof (struct rtentry));

    if (fgets (route_buffer, sizeof (route_buffer), route_fd) == (char *) 0)
	return 0;

    p = route_buffer;
    for (col = 0; col < route_num_cols; ++col) {
	cols[col] = strtok(p, route_delims);
	if (cols[col] == NULL)
	    return 0;		/* didn't get enough columns */
	p = NULL;
    }

    SET_SA_FAMILY (rt->rt_dst,     AF_INET);
    SET_SA_FAMILY (rt->rt_gateway, AF_INET);

    SIN_ADDR(rt->rt_dst) = strtoul(cols[route_dest_col], NULL, 16);
    SIN_ADDR(rt->rt_gateway) = strtoul(cols[route_gw_col], NULL, 16);
    SIN_ADDR(rt->rt_genmask) = strtoul(cols[route_mask_col], NULL, 16);

    rt->rt_flags = (short) strtoul(cols[route_flags_col], NULL, 16);
    rt->rt_metric = (short) strtoul(cols[route_metric_col], NULL, 10);
    rt->rt_dev   = cols[route_dev_col];

    return 1;
}

/********************************************************************
 *
 * defaultroute_exists - determine if there is a default route
 * with the given metric (or negative for any)
 */

static int defaultroute_exists (struct rtentry *rt, int metric)
{
    int result = 0;

    if (!open_route_table())
	return 0;

    while (read_route_table(rt) != 0) {
	if ((rt->rt_flags & RTF_UP) == 0)
	    continue;

	if (kernel_version > KVERSION(2,1,0) && SIN_ADDR(rt->rt_genmask) != 0)
	    continue;
	if (SIN_ADDR(rt->rt_dst) == 0L && (metric < 0
					   || rt->rt_metric == metric)) {
	    result = 1;
	    break;
	}
    }

    close_route_table();
    return result;
}

/*
 * have_route_to - determine if the system has any route to
 * a given IP address.  `addr' is in network byte order.
 * Return value is 1 if yes, 0 if no, -1 if don't know.
 * For demand mode to work properly, we have to ignore routes
 * through our own interface.
 */
int have_route_to(u_int32_t addr)
{
    struct rtentry rt;
    int result = 0;

    if (!open_route_table())
	return -1;		/* don't know */

    while (read_route_table(&rt)) {
	if ((rt.rt_flags & RTF_UP) == 0 || strcmp(rt.rt_dev, ifname) == 0)
	    continue;
	if ((addr & SIN_ADDR(rt.rt_genmask)) == SIN_ADDR(rt.rt_dst)) {
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
 *
 * If the global default_rt_repl_rest flag is set, then this function
 * already replaced the original system defaultroute with some other
 * route and it should just replace the current defaultroute with
 * another one, without saving the current route. Use: demand mode,
 * when pppd sets first a defaultroute it it's temporary ppp0 addresses
 * and then changes the temporary addresses to the addresses for the real
 * ppp connection when it has come up.
 */

int sifdefaultroute (int unit, u_int32_t ouraddr, u_int32_t gateway, bool replace)
{
    struct rtentry rt, tmp_rt;
    struct rtentry *del_rt = NULL;

    if (default_rt_repl_rest) {
	/* We have already replaced the original defaultroute, if we
	 * are called again, we will delete the current default route
	 * and set the new default route in this function.
	 * - this is normally only the case the doing demand: */
	if (defaultroute_exists(&tmp_rt, -1))
	    del_rt = &tmp_rt;
    } else if (!replace) {
	/*
	 * We don't want to replace an existing route.
	 * We may however add our route along an existing route with a different
	 * metric.
	 */
	if (defaultroute_exists(&rt, dfl_route_metric) && strcmp(rt.rt_dev, ifname) != 0) {
	   if (rt.rt_flags & RTF_GATEWAY)
	       error("not replacing existing default route via %I with metric %d",
		     SIN_ADDR(rt.rt_gateway), dfl_route_metric);
	   else
	       error("not replacing existing default route through %s with metric %d",
		     rt.rt_dev, dfl_route_metric);
	   return 0;
	}
    } else if (defaultroute_exists(&old_def_rt, -1           ) &&
			    strcmp( old_def_rt.rt_dev, ifname) != 0) {
	/*
	 * We want to replace an existing route and did not replace an existing
	 * default route yet, let's check if we should save and replace an
	 * existing default route:
	 */
	u_int32_t old_gateway = SIN_ADDR(old_def_rt.rt_gateway);

	if (old_gateway != gateway) {
	    if (!replace) {
		error("not replacing default route to %s [%I]",
			old_def_rt.rt_dev, old_gateway);
		return 0;
	    } else {
		/* we need to copy rt_dev because we need it permanent too: */
		char * tmp_dev = malloc(strlen(old_def_rt.rt_dev)+1);
		strcpy(tmp_dev, old_def_rt.rt_dev);
		old_def_rt.rt_dev = tmp_dev;

		notice("replacing old default route to %s [%I]",
			old_def_rt.rt_dev, old_gateway);
		default_rt_repl_rest = 1;
		del_rt = &old_def_rt;
	    }
	}
    }

    memset (&rt, 0, sizeof (rt));
    SET_SA_FAMILY (rt.rt_dst, AF_INET);

    rt.rt_dev = ifname;
    rt.rt_metric = dfl_route_metric + 1; /* +1 for binary compatibility */

    if (kernel_version > KVERSION(2,1,0)) {
	SET_SA_FAMILY (rt.rt_genmask, AF_INET);
	SIN_ADDR(rt.rt_genmask) = 0L;
    }

    rt.rt_flags = RTF_UP;
    if (ioctl(sock_fd, SIOCADDRT, &rt) < 0) {
	if ( ! ok_error ( errno ))
	    error("default route ioctl(SIOCADDRT): %m");
	return 0;
    }
    if (default_rt_repl_rest && del_rt)
	if (ioctl(sock_fd, SIOCDELRT, del_rt) < 0) {
	    if ( ! ok_error ( errno ))
		error("del old default route ioctl(SIOCDELRT): %m(%d)", errno);
	    return 0;
	}

    have_default_route = 1;
    return 1;
}

/********************************************************************
 *
 * cifdefaultroute - delete a default route through the address given.
 */

int cifdefaultroute (int unit, u_int32_t ouraddr, u_int32_t gateway)
{
    struct rtentry rt;

    have_default_route = 0;

    memset (&rt, '\0', sizeof (rt));
    SET_SA_FAMILY (rt.rt_dst,     AF_INET);
    SET_SA_FAMILY (rt.rt_gateway, AF_INET);

    rt.rt_dev = ifname;
    rt.rt_metric = dfl_route_metric + 1; /* +1 for binary compatibility */

    if (kernel_version > KVERSION(2,1,0)) {
	SET_SA_FAMILY (rt.rt_genmask, AF_INET);
	SIN_ADDR(rt.rt_genmask) = 0L;
    }

    rt.rt_flags = RTF_UP;
    if (ioctl(sock_fd, SIOCDELRT, &rt) < 0 && errno != ESRCH) {
	if (still_ppp()) {
	    if ( ! ok_error ( errno ))
		error("default route ioctl(SIOCDELRT): %m");
	    return 0;
	}
    }
    if (default_rt_repl_rest) {
	notice("restoring old default route to %s [%I]",
			old_def_rt.rt_dev, SIN_ADDR(old_def_rt.rt_gateway));
	if (ioctl(sock_fd, SIOCADDRT, &old_def_rt) < 0) {
	    if ( ! ok_error ( errno ))
		error("restore default route ioctl(SIOCADDRT): %m(%d)", errno);
	    return 0;
	}
	default_rt_repl_rest = 0;
    }

    return 1;
}

#ifdef PPP_WITH_IPV6CP
/*
 * /proc/net/ipv6_route parsing stuff.
 */
static int route_dest_plen_col;
static int open_route6_table (void);
static int read_route6_table (struct in6_rtmsg *rt);

/********************************************************************
 *
 * open_route6_table - open the interface to the route table
 */
static int open_route6_table (void)
{
    char *path;

    close_route_table();

    path = path_to_procfs("/net/ipv6_route");
    route_fd = fopen (path, "r");
    if (route_fd == NULL) {
	error("can't open routing table %s: %m", path);
	return 0;
    }

    /* default to usual columns */
    route_dest_col = 0;
    route_dest_plen_col = 1;
    route_gw_col = 4;
    route_metric_col = 5;
    route_flags_col = 8;
    route_dev_col = 9;
    route_num_cols = 10;

    return 1;
}

/********************************************************************
 *
 * read_route6_table - read the next entry from the route table
 */

static void hex_to_in6_addr(struct in6_addr *addr, const char *s)
{
    char hex8[9];
    unsigned i;
    uint32_t v;

    hex8[8] = 0;
    for (i = 0; i < 4; i++) {
	memcpy(hex8, s + 8*i, 8);
	v = strtoul(hex8, NULL, 16);
	addr->s6_addr32[i] = v;
    }
}

static int read_route6_table(struct in6_rtmsg *rt)
{
    char *cols[ROUTE_MAX_COLS], *p;
    int col;

    memset (rt, '\0', sizeof (struct in6_rtmsg));

    if (fgets (route_buffer, sizeof (route_buffer), route_fd) == (char *) 0)
	return 0;

    p = route_buffer;
    for (col = 0; col < route_num_cols; ++col) {
	cols[col] = strtok(p, route_delims);
	if (cols[col] == NULL)
	    return 0;		/* didn't get enough columns */
	p = NULL;
    }

    hex_to_in6_addr(&rt->rtmsg_dst, cols[route_dest_col]);
    rt->rtmsg_dst_len = strtoul(cols[route_dest_plen_col], NULL, 16);
    hex_to_in6_addr(&rt->rtmsg_gateway, cols[route_gw_col]);

    rt->rtmsg_metric = strtoul(cols[route_metric_col], NULL, 16);
    rt->rtmsg_flags = strtoul(cols[route_flags_col], NULL, 16);
    rt->rtmsg_ifindex = if_nametoindex(cols[route_dev_col]);

    return 1;
}

/********************************************************************
 *
 * defaultroute6_exists - determine if there is a default route
 */

static int defaultroute6_exists (struct in6_rtmsg *rt, int metric)
{
    int result = 0;

    if (!open_route6_table())
	return 0;

    while (read_route6_table(rt) != 0) {
	if ((rt->rtmsg_flags & RTF_UP) == 0)
	    continue;

	if (rt->rtmsg_dst_len != 0)
	    continue;
	if (rt->rtmsg_dst.s6_addr32[0] == 0L
	 && rt->rtmsg_dst.s6_addr32[1] == 0L
	 && rt->rtmsg_dst.s6_addr32[2] == 0L
	 && rt->rtmsg_dst.s6_addr32[3] == 0L
	 && (metric < 0 || rt->rtmsg_metric == metric)) {
	    result = 1;
	    break;
	}
    }

    close_route_table();
    return result;
}

/********************************************************************
 *
 * sif6defaultroute - assign a default route through the address given.
 *
 * If the global default_rt_repl_rest flag is set, then this function
 * already replaced the original system defaultroute with some other
 * route and it should just replace the current defaultroute with
 * another one, without saving the current route. Use: demand mode,
 * when pppd sets first a defaultroute it it's temporary ppp0 addresses
 * and then changes the temporary addresses to the addresses for the real
 * ppp connection when it has come up.
 */

int sif6defaultroute (int unit, eui64_t ouraddr, eui64_t gateway)
{
    struct in6_rtmsg rt;
    char buf[IF_NAMESIZE];

    if (defaultroute6_exists(&rt, dfl_route_metric) &&
	    rt.rtmsg_ifindex != if_nametoindex(ifname)) {
	if (rt.rtmsg_flags & RTF_GATEWAY)
	    error("not replacing existing default route via gateway");
	else
	    error("not replacing existing default route through %s",
		  if_indextoname(rt.rtmsg_ifindex, buf));
	return 0;
    }

    memset (&rt, 0, sizeof (rt));

    rt.rtmsg_ifindex = if_nametoindex(ifname);
    rt.rtmsg_metric = dfl_route_metric + 1; /* +1 for binary compatibility */
    rt.rtmsg_dst_len = 0;

    rt.rtmsg_flags = RTF_UP;
    if (ioctl(sock6_fd, SIOCADDRT, &rt) < 0) {
	if ( ! ok_error ( errno ))
	    error("default route ioctl(SIOCADDRT): %m");
	return 0;
    }

    have_default_route6 = 1;
    return 1;
}

/********************************************************************
 *
 * cif6defaultroute - delete a default route through the address given.
 */

int cif6defaultroute (int unit, eui64_t ouraddr, eui64_t gateway)
{
    struct in6_rtmsg rt;

    have_default_route6 = 0;

    memset (&rt, '\0', sizeof (rt));

    rt.rtmsg_ifindex = if_nametoindex(ifname);
    rt.rtmsg_metric = dfl_route_metric + 1; /* +1 for binary compatibility */
    rt.rtmsg_dst_len = 0;

    rt.rtmsg_flags = RTF_UP;
    if (ioctl(sock6_fd, SIOCDELRT, &rt) < 0 && errno != ESRCH) {
	if (still_ppp()) {
	    if ( ! ok_error ( errno ))
		error("default route ioctl(SIOCDELRT): %m");
	    return 0;
	}
    }

    return 1;
}
#endif /* PPP_WITH_IPV6CP */

/********************************************************************
 *
 * sifproxyarp - Make a proxy ARP entry for the peer.
 */

int sifproxyarp (int unit, u_int32_t his_adr)
{
    struct arpreq arpreq;
    char *forw_path;

    if (has_proxy_arp == 0) {
	memset (&arpreq, '\0', sizeof(arpreq));

	SET_SA_FAMILY(arpreq.arp_pa, AF_INET);
	SIN_ADDR(arpreq.arp_pa) = his_adr;
	arpreq.arp_flags = ATF_PERM | ATF_PUBL;
/*
 * Get the hardware address of an interface on the same subnet
 * as our local address.
 */
	if (!get_ether_addr(his_adr, &arpreq.arp_ha, proxy_arp_dev,
			    sizeof(proxy_arp_dev))) {
	    error("Cannot determine ethernet address for proxy ARP");
	    return 0;
	}
	strlcpy(arpreq.arp_dev, proxy_arp_dev, sizeof(arpreq.arp_dev));

	if (ioctl(sock_fd, SIOCSARP, (caddr_t)&arpreq) < 0) {
	    if ( ! ok_error ( errno ))
		error("ioctl(SIOCSARP): %m");
	    return 0;
	}
	proxy_arp_addr = his_adr;
	has_proxy_arp = 1;

	if (tune_kernel) {
	    forw_path = path_to_procfs("/sys/net/ipv4/ip_forward");
	    if (forw_path != 0) {
		int fd = open(forw_path, O_WRONLY);
		if (fd >= 0) {
		    if (write(fd, "1", 1) != 1)
			error("Couldn't enable IP forwarding: %m");
		    close(fd);
		}
	    }
	}
    }

    return 1;
}

/********************************************************************
 *
 * cifproxyarp - Delete the proxy ARP entry for the peer.
 */

int cifproxyarp (int unit, u_int32_t his_adr)
{
    struct arpreq arpreq;

    if (has_proxy_arp) {
	has_proxy_arp = 0;
	memset (&arpreq, '\0', sizeof(arpreq));
	SET_SA_FAMILY(arpreq.arp_pa, AF_INET);
	SIN_ADDR(arpreq.arp_pa) = his_adr;
	arpreq.arp_flags = ATF_PERM | ATF_PUBL;
	strlcpy(arpreq.arp_dev, proxy_arp_dev, sizeof(arpreq.arp_dev));

	if (ioctl(sock_fd, SIOCDARP, (caddr_t)&arpreq) < 0) {
	    if ( ! ok_error ( errno ))
		warn("ioctl(SIOCDARP): %m");
	    return 0;
	}
    }
    return 1;
}

/********************************************************************
 *
 * get_ether_addr - get the hardware address of an interface on the
 * the same subnet as ipaddr.
 */

static int get_ether_addr (u_int32_t ipaddr,
			   struct sockaddr *hwaddr,
			   char *name, int namelen)
{
    struct ifreq *ifr, *ifend;
    u_int32_t ina, mask;
    char *aliasp;
    struct ifreq ifreq, bestifreq;
    struct ifconf ifc;
    struct ifreq ifs[MAX_IFS];

    u_int32_t bestmask=0;
    int found_interface = 0;

    ifc.ifc_len = sizeof(ifs);
    ifc.ifc_req = ifs;
    if (ioctl(sock_fd, SIOCGIFCONF, &ifc) < 0) {
	if ( ! ok_error ( errno ))
	    error("ioctl(SIOCGIFCONF): %m (line %d)", __LINE__);
	return 0;
    }

/*
 * Scan through looking for an interface with an Internet
 * address on the same subnet as `ipaddr'.
 */
    ifend = ifs + (ifc.ifc_len / sizeof(struct ifreq));
    for (ifr = ifc.ifc_req; ifr < ifend; ifr++) {
	if (ifr->ifr_addr.sa_family == AF_INET) {
	    ina = SIN_ADDR(ifr->ifr_addr);
	    strlcpy(ifreq.ifr_name, ifr->ifr_name, sizeof(ifreq.ifr_name));
/*
 * Check that the interface is up, and not point-to-point
 * nor loopback.
 */
	    if (ioctl(sock_fd, SIOCGIFFLAGS, &ifreq) < 0)
		continue;

	    if (((ifreq.ifr_flags ^ FLAGS_GOOD) & FLAGS_MASK) != 0)
		continue;
/*
 * Get its netmask and check that it's on the right subnet.
 */
	    if (ioctl(sock_fd, SIOCGIFNETMASK, &ifreq) < 0)
		continue;

	    mask = SIN_ADDR(ifreq.ifr_addr);

	    if (((ipaddr ^ ina) & mask) != 0)
		continue; /* no match */
	    /* matched */
	    if (mask >= bestmask) {
		/* Compare using >= instead of > -- it is possible for
		   an interface to have a netmask of 0.0.0.0 */
		found_interface = 1;
		bestifreq = ifreq;
		bestmask = mask;
	    }
	}
    }

    if (!found_interface) return 0;

    strlcpy(name, bestifreq.ifr_name, namelen);

    /* trim off the :1 in eth0:1 */
    aliasp = strchr(name, ':');
    if (aliasp != 0)
	*aliasp = 0;

    info("found interface %s for proxy arp", name);
/*
 * Now get the hardware address.
 */
    memset (&bestifreq.ifr_hwaddr, 0, sizeof (struct sockaddr));
    if (ioctl (sock_fd, SIOCGIFHWADDR, &bestifreq) < 0) {
	error("SIOCGIFHWADDR(%s): %m", bestifreq.ifr_name);
	return 0;
    }

    memcpy (hwaddr,
	    &bestifreq.ifr_hwaddr,
	    sizeof (struct sockaddr));

    return 1;
}

/*
 * get_if_hwaddr - get the hardware address for the specified
 * network interface device.
 */
int
get_if_hwaddr(u_char *addr, char *name)
{
	struct ifreq ifreq;
	int ret, sock_fd;

	sock_fd = socket(AF_INET, SOCK_DGRAM, 0);
	if (sock_fd < 0)
		return -1;
	memset(&ifreq.ifr_hwaddr, 0, sizeof(struct sockaddr));
	strlcpy(ifreq.ifr_name, name, sizeof(ifreq.ifr_name));
	ret = ioctl(sock_fd, SIOCGIFHWADDR, &ifreq);
	close(sock_fd);
	if (ret >= 0)
		memcpy(addr, ifreq.ifr_hwaddr.sa_data, 6);
	return ret;
}

/*
 * get_first_ether_hwaddr - get the hardware address for the first
 * ethernet-style interface on this system.
 */
int
get_first_ether_hwaddr(u_char *addr)
{
	struct if_nameindex *if_ni, *i;
	struct ifreq ifreq;
	int ret, sock_fd;

	sock_fd = socket(AF_INET, SOCK_DGRAM, 0);
	if (sock_fd < 0)
		return -1;

	if_ni = if_nameindex();
	if (!if_ni) {
		close(sock_fd);
		return -1;
	}

	ret = -1;

	for (i = if_ni; !(i->if_index == 0 && i->if_name == NULL); i++) {
		memset(&ifreq.ifr_hwaddr, 0, sizeof(struct sockaddr));
		strlcpy(ifreq.ifr_name, i->if_name, sizeof(ifreq.ifr_name));
		ret = ioctl(sock_fd, SIOCGIFHWADDR, &ifreq);
		if (ret >= 0 && ifreq.ifr_hwaddr.sa_family == ARPHRD_ETHER) {
			memcpy(addr, ifreq.ifr_hwaddr.sa_data, 6);
			break;
		}
		ret = -1;
	}

	if_freenameindex(if_ni);
	close(sock_fd);

	return ret;
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
    if (ioctl(sock_fd, SIOCGIFCONF, &ifc) < 0) {
	if ( ! ok_error ( errno ))
	    warn("ioctl(SIOCGIFCONF): %m (line %d)", __LINE__);
	return mask;
    }

    ifend = (struct ifreq *) (ifc.ifc_buf + ifc.ifc_len);
    for (ifr = ifc.ifc_req; ifr < ifend; ifr++) {
/*
 * Check the interface's internet address.
 */
	if (ifr->ifr_addr.sa_family != AF_INET)
	    continue;
	ina = SIN_ADDR(ifr->ifr_addr);
	if (((ntohl(ina) ^ addr) & nmask) != 0)
	    continue;
/*
 * Check that the interface is up, and not point-to-point nor loopback.
 */
	strlcpy(ifreq.ifr_name, ifr->ifr_name, sizeof(ifreq.ifr_name));
	if (ioctl(sock_fd, SIOCGIFFLAGS, &ifreq) < 0)
	    continue;

	if (((ifreq.ifr_flags ^ FLAGS_GOOD) & FLAGS_MASK) != 0)
	    continue;
/*
 * Get its netmask and OR it into our mask.
 */
	if (ioctl(sock_fd, SIOCGIFNETMASK, &ifreq) < 0)
	    continue;
	mask |= SIN_ADDR(ifreq.ifr_addr);
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
    char *endp;

    *version      = (int) strtoul (buf, &endp, 10);
    *modification = 0;
    *patch        = 0;

    if (endp != buf && *endp == '.') {
	buf = endp + 1;
	*modification = (int) strtoul (buf, &endp, 10);
	if (endp != buf && *endp == '.') {
	    buf = endp + 1;
	    *patch = (int) strtoul (buf, &buf, 10);
	}
    }
}

/********************************************************************
 *
 * Procedure to determine if the PPP line discipline is registered.
 */

static int
ppp_registered(void)
{
    int local_fd;
    int mfd = -1;
    int ret = 0;
    char slave[16];

    /*
     * We used to open the serial device and set it to the ppp line
     * discipline here, in order to create a ppp unit.  But that is
     * not a good idea - the user might have specified a device that
     * they can't open (permission, or maybe it doesn't really exist).
     * So we grab a pty master/slave pair and use that.
     */
    if (!get_pty(&mfd, &local_fd, slave, 0)) {
	no_ppp_msg = "Couldn't determine if PPP is supported (no free ptys)";
	return 0;
    }

    /*
     * Try to put the device into the PPP discipline.
     */
    if (ioctl(local_fd, TIOCSETD, &ppp_disc) < 0) {
	error("ioctl(TIOCSETD(PPP)): %m (line %d)", __LINE__);
    } else
	ret = 1;

    close(local_fd);
    close(mfd);
    return ret;
}

/********************************************************************
 *
 * ppp_check_kernel_support - check whether the system has any ppp interfaces
 * (in fact we check whether we can do an ioctl on ppp0).
 */

int ppp_check_kernel_support(void)
{
    int s, ok, fd;
    struct ifreq ifr;
    int    size;
    int    my_version, my_modification, my_patch;
    int osmaj, osmin, ospatch;

    /* get the kernel version now, since we are called before sys_init */
    uname(&utsname);
    osmaj = osmin = ospatch = 0;
    sscanf(utsname.release, "%d.%d.%d", &osmaj, &osmin, &ospatch);
    kernel_version = KVERSION(osmaj, osmin, ospatch);

    fd = open("/dev/ppp", O_RDWR);
    if (fd >= 0) {
	new_style_driver = 1;

	/* XXX should get from driver */
	driver_version = 2;
	driver_modification = 4;
	driver_patch = 0;
	close(fd);
	return 1;
    }

    if (kernel_version >= KVERSION(2,3,13)) {
	error("Couldn't open the /dev/ppp device: %m");
	if (errno == ENOENT)
	    no_ppp_msg =
		"You need to create the /dev/ppp device node by\n"
		"executing the following command as root:\n"
		"	mknod /dev/ppp c 108 0\n";
	else if (errno == ENODEV || errno == ENXIO)
	    no_ppp_msg =
		"Please load the ppp_generic kernel module.\n";
	return 0;
    }

    /* we are running on a really really old kernel */
    no_ppp_msg =
	"This system lacks kernel support for PPP.  This could be because\n"
	"the PPP kernel module could not be loaded, or because PPP was not\n"
	"included in the kernel configuration.  If PPP was included as a\n"
	"module, try `/sbin/modprobe -v ppp'.  If that fails, check that\n"
	"ppp.o exists in /lib/modules/`uname -r`/net.\n"
	"See README.linux file in the ppp distribution for more details.\n";

/*
 * Open a socket for doing the ioctl operations.
 */
    s = socket(AF_INET, SOCK_DGRAM, 0);
    if (s < 0)
	return 0;

    strlcpy (ifr.ifr_name, "ppp0", sizeof (ifr.ifr_name));
    ok = ioctl(s, SIOCGIFFLAGS, (caddr_t) &ifr) >= 0;
/*
 * If the device did not exist then attempt to create one by putting the
 * current tty into the PPP discipline. If this works then obtain the
 * flags for the device again.
 */
    if (!ok) {
	if (ppp_registered()) {
	    strlcpy (ifr.ifr_name, "ppp0", sizeof (ifr.ifr_name));
	    ok = ioctl(s, SIOCGIFFLAGS, (caddr_t) &ifr) >= 0;
	}
    }
/*
 * Ensure that the hardware address is for PPP and not something else
 */
    if (ok)
	ok = ioctl (s, SIOCGIFHWADDR, (caddr_t) &ifr) >= 0;

    if (ok && ((ifr.ifr_hwaddr.sa_family & ~0xFF) != ARPHRD_PPP))
	ok = 0;

/*
 *  This is the PPP device. Validate the version of the driver at this
 *  point to ensure that this program will work with the driver.
 */
    if (ok) {
	char   abBuffer [1024];

	ifr.ifr_data = abBuffer;
	size = ioctl (s, SIOCGPPPVER, (caddr_t) &ifr);
	if (size < 0) {
	    error("Couldn't read driver version: %m");
	    ok = 0;
	    no_ppp_msg = "Sorry, couldn't verify kernel driver version\n";

	} else {
	    decode_version(abBuffer,
			   &driver_version,
			   &driver_modification,
			   &driver_patch);
/*
 * Validate the version of the driver against the version that we used.
 */
	    decode_version(VERSION,
			   &my_version,
			   &my_modification,
			   &my_patch);

	    /* The version numbers must match */
	    if (driver_version != my_version)
		ok = 0;

	    /* The modification levels must be legal */
	    if (driver_modification < 3) {
		if (driver_modification >= 2) {
		    /* we can cope with 2.2.0 and above */
		    driver_is_old = 1;
		} else {
		    ok = 0;
		}
	    }

	    if (!ok) {
		slprintf(route_buffer, sizeof(route_buffer),
			 "Sorry - PPP driver version %d.%d.%d is out of date\n",
			 driver_version, driver_modification, driver_patch);

		no_ppp_msg = route_buffer;
	    }
	}
    }
    close(s);
    return ok;
}

#ifndef HAVE_LOGWTMP
/********************************************************************
 *
 * Update the wtmp file with the appropriate user name and tty device.
 */

void logwtmp (const char *line, const char *name, const char *host)
{
    struct utmp ut, *utp;
    pid_t  mypid = getpid();
#if __GLIBC__ < 2
    int    wtmp;
#endif

/*
 * Update the signon database for users.
 * Christoph Lameter: Copied from poeigl-1.36 Jan 3, 1996
 */
    utmpname(_PATH_UTMP);
    setutent();
    while ((utp = getutent()) && (utp->ut_pid != mypid))
	/* nothing */;

    if (utp)
	memcpy(&ut, utp, sizeof(ut));
    else
	/* some gettys/telnetds don't initialize utmp... */
	memset(&ut, 0, sizeof(ut));

    if (ut.ut_id[0] == 0)
	strncpy(ut.ut_id, line + 3, sizeof(ut.ut_id));

    strncpy(ut.ut_user, name, sizeof(ut.ut_user));
    strncpy(ut.ut_line, line, sizeof(ut.ut_line));

    time(&ut.ut_time);

    ut.ut_type = USER_PROCESS;
    ut.ut_pid  = mypid;

    /* Insert the host name if one is supplied */
    if (*host)
	strncpy (ut.ut_host, host, sizeof(ut.ut_host));

    /* Insert the IP address of the remote system if IP is enabled */
    if (ipcp_protent.enabled_flag && ipcp_hisoptions[0].neg_addr)
	memcpy(&ut.ut_addr, (char *) &ipcp_hisoptions[0].hisaddr,
		 sizeof(ut.ut_addr));

    /* CL: Makes sure that the logout works */
    if (*host == 0 && *name==0)
	ut.ut_host[0]=0;

    pututline(&ut);
    endutent();
/*
 * Update the wtmp file.
 */
#if __GLIBC__ >= 2
    updwtmp(_PATH_WTMP, &ut);
#else
    wtmp = open(_PATH_WTMP, O_APPEND|O_WRONLY);
    if (wtmp >= 0) {
	flock(wtmp, LOCK_EX);

	if (write (wtmp, (char *)&ut, sizeof(ut)) != sizeof(ut))
	    warn("error writing %s: %m", _PATH_WTMP);

	flock(wtmp, LOCK_UN);

	close (wtmp);
    }
#endif
}
#endif /* HAVE_LOGWTMP */

/********************************************************************
 *
 * sifvjcomp - config tcp header compression
 */

int sifvjcomp (int u, int vjcomp, int cidcomp, int maxcid)
{
	u_int x;

	if (vjcomp) {
		if (ioctl(ppp_dev_fd, PPPIOCSMAXCID, (caddr_t) &maxcid) < 0) {
			error("Couldn't set up TCP header compression: %m");
			vjcomp = 0;
		}
	}

	x = (vjcomp? SC_COMP_TCP: 0) | (cidcomp? 0: SC_NO_TCP_CCID);
	modify_flags(ppp_dev_fd, SC_COMP_TCP|SC_NO_TCP_CCID, x);

	return 1;
}

/********************************************************************
 *
 * sifup - Config the interface up and enable IP packets to pass.
 */

int sifup(int u)
{
    int ret;

    if ((ret = setifstate(u, 1)))
	if_is_up++;

    return ret;
}

/********************************************************************
 *
 * sifdown - Disable the indicated protocol and config the interface
 *	     down if there are no remaining protocols.
 */

int sifdown (int u)
{
    if (if_is_up && --if_is_up > 0)
	return 1;

#ifdef PPP_WITH_IPV6CP
    if (if6_is_up)
	return 1;
#endif /* PPP_WITH_IPV6CP */

    return setifstate(u, 0);
}

#ifdef PPP_WITH_IPV6CP
/********************************************************************
 *
 * sif6up - Config the interface up for IPv6
 */

int sif6up(int u)
{
    int ret;

    if ((ret = setifstate(u, 1)))
	if6_is_up = 1;

    return ret;
}

/********************************************************************
 *
 * sif6down - Disable the IPv6CP protocol and config the interface
 *	      down if there are no remaining protocols.
 */

int sif6down (int u)
{
    if6_is_up = 0;

    if (if_is_up)
	return 1;

    return setifstate(u, 0);
}
#endif /* PPP_WITH_IPV6CP */

/********************************************************************
 *
 * setifstate - Config the interface up or down
 */

static int setifstate (int u, int state)
{
    struct ifreq ifr;

    memset (&ifr, '\0', sizeof (ifr));
    strlcpy(ifr.ifr_name, ifname, sizeof (ifr.ifr_name));
    if (ioctl(sock_fd, SIOCGIFFLAGS, (caddr_t) &ifr) < 0) {
	if (! ok_error (errno))
	    error("ioctl (SIOCGIFFLAGS): %m (line %d)", __LINE__);
	return 0;
    }

    if (state)
	ifr.ifr_flags |= IFF_UP;
    else
	ifr.ifr_flags &= ~IFF_UP;
    ifr.ifr_flags |= IFF_POINTOPOINT;
    if (ioctl(sock_fd, SIOCSIFFLAGS, (caddr_t) &ifr) < 0) {
	if (! ok_error (errno))
	    error("ioctl(SIOCSIFFLAGS): %m (line %d)", __LINE__);
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

    strlcpy (ifr.ifr_name, ifname, sizeof (ifr.ifr_name));
/*
 *  Set our IP address
 */
    SIN_ADDR(ifr.ifr_addr) = our_adr;
    if (ioctl(sock_fd, SIOCSIFADDR, (caddr_t) &ifr) < 0) {
	if (errno != EEXIST) {
	    if (! ok_error (errno))
		error("ioctl(SIOCSIFADDR): %m (line %d)", __LINE__);
	}
	else {
	    warn("ioctl(SIOCSIFADDR): Address already exists");
	}
	return (0);
    }
/*
 *  Set the gateway address
 */
    if (his_adr != 0) {
	SIN_ADDR(ifr.ifr_dstaddr) = his_adr;
	if (ioctl(sock_fd, SIOCSIFDSTADDR, (caddr_t) &ifr) < 0) {
	    if (! ok_error (errno))
		error("ioctl(SIOCSIFDSTADDR): %m (line %d)", __LINE__);
	    return (0);
	}
    }
/*
 *  Set the netmask.
 *  For recent kernels, force the netmask to 255.255.255.255.
 */
    if (kernel_version >= KVERSION(2,1,16))
	net_mask = ~0L;
    if (net_mask != 0) {
	SIN_ADDR(ifr.ifr_netmask) = net_mask;
	if (ioctl(sock_fd, SIOCSIFNETMASK, (caddr_t) &ifr) < 0) {
	    if (! ok_error (errno))
		error("ioctl(SIOCSIFNETMASK): %m (line %d)", __LINE__);
	    return (0);
	}
    }
/*
 *  Add the device route
 */
    if (kernel_version < KVERSION(2,1,16)) {
	SET_SA_FAMILY (rt.rt_dst,     AF_INET);
	SET_SA_FAMILY (rt.rt_gateway, AF_INET);
	rt.rt_dev = ifname;

	SIN_ADDR(rt.rt_gateway) = 0L;
	SIN_ADDR(rt.rt_dst)     = his_adr;
	rt.rt_flags = RTF_UP | RTF_HOST;

	if (kernel_version > KVERSION(2,1,0)) {
	    SET_SA_FAMILY (rt.rt_genmask, AF_INET);
	    SIN_ADDR(rt.rt_genmask) = -1L;
	}

	if (ioctl(sock_fd, SIOCADDRT, &rt) < 0) {
	    if (! ok_error (errno))
		error("ioctl(SIOCADDRT) device route: %m (line %d)", __LINE__);
	    return (0);
	}
    }

    /* set ip_dynaddr in demand mode if address changes */
    if (demand && tune_kernel && !dynaddr_set
	&& our_old_addr && our_old_addr != our_adr) {
	/* set ip_dynaddr if possible */
	char *path;
	int fd;

	path = path_to_procfs("/sys/net/ipv4/ip_dynaddr");
	if (path != 0 && (fd = open(path, O_WRONLY)) >= 0) {
	    if (write(fd, "1", 1) != 1)
		error("Couldn't enable dynamic IP addressing: %m");
	    close(fd);
	}
	dynaddr_set = 1;	/* only 1 attempt */
    }
    our_old_addr = 0;

    return 1;
}

/********************************************************************
 *
 * cifaddr - Clear the interface IP addresses, and delete routes
 * through the interface if possible.
 */

int cifaddr (int unit, u_int32_t our_adr, u_int32_t his_adr)
{
    struct ifreq ifr;

    if (kernel_version < KVERSION(2,1,16)) {
/*
 *  Delete the route through the device
 */
	struct rtentry rt;
	memset (&rt, '\0', sizeof (rt));

	SET_SA_FAMILY (rt.rt_dst,     AF_INET);
	SET_SA_FAMILY (rt.rt_gateway, AF_INET);
	rt.rt_dev = ifname;

	SIN_ADDR(rt.rt_gateway) = 0;
	SIN_ADDR(rt.rt_dst)     = his_adr;
	rt.rt_flags = RTF_UP | RTF_HOST;

	if (kernel_version > KVERSION(2,1,0)) {
	    SET_SA_FAMILY (rt.rt_genmask, AF_INET);
	    SIN_ADDR(rt.rt_genmask) = -1L;
	}

	if (ioctl(sock_fd, SIOCDELRT, &rt) < 0 && errno != ESRCH) {
	    if (still_ppp() && ! ok_error (errno))
		error("ioctl(SIOCDELRT) device route: %m (line %d)", __LINE__);
	    return (0);
	}
    }

    /* This way it is possible to have an IPv6-only interface */
    memset(&ifr, 0, sizeof(ifr));
    SET_SA_FAMILY(ifr.ifr_addr, AF_INET);
    strlcpy(ifr.ifr_name, ifname, sizeof(ifr.ifr_name));

    if (ioctl(sock_fd, SIOCSIFADDR, (caddr_t) &ifr) < 0) {
	if (! ok_error (errno)) {
	    error("ioctl(SIOCSIFADDR): %m (line %d)", __LINE__);
	    return 0;
	}
    }

    our_old_addr = our_adr;

    return 1;
}

#ifdef PPP_WITH_IPV6CP
/********************************************************************
 *
 * sif6addr_rtnetlink - Config the interface with both IPv6 link-local addresses via rtnetlink
 */
static int sif6addr_rtnetlink(unsigned int iface, eui64_t our_eui64, eui64_t his_eui64)
{
    struct {
        struct nlmsghdr nlh;
        struct ifaddrmsg ifa;
        struct {
            struct rtattr rta;
            struct in6_addr addr;
        } addrs[2];
    } nlreq;
    int resp;

    memset(&nlreq, 0, sizeof(nlreq));
    nlreq.nlh.nlmsg_len = sizeof(nlreq);
    nlreq.nlh.nlmsg_type = RTM_NEWADDR;
    nlreq.nlh.nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK | NLM_F_EXCL | NLM_F_CREATE;
    nlreq.ifa.ifa_family = AF_INET6;
    nlreq.ifa.ifa_prefixlen = 128;
    nlreq.ifa.ifa_flags = IFA_F_NODAD | IFA_F_PERMANENT;
    nlreq.ifa.ifa_scope = RT_SCOPE_LINK;
    nlreq.ifa.ifa_index = iface;
    nlreq.addrs[0].rta.rta_len = sizeof(nlreq.addrs[0]);
    nlreq.addrs[0].rta.rta_type = IFA_LOCAL;
    IN6_LLADDR_FROM_EUI64(nlreq.addrs[0].addr, our_eui64);
    nlreq.addrs[1].rta.rta_len = sizeof(nlreq.addrs[1]);
    nlreq.addrs[1].rta.rta_type = IFA_ADDRESS;

    /*
     * To set only local address, older kernel expects that local address is
     * in IFA_ADDRESS field (not IFA_LOCAL). New kernels with support for peer
     * address, ignore IFA_ADDRESS if is same as IFA_LOCAL. So for backward
     * compatibility when setting only local address, set it via both IFA_LOCAL
     * and IFA_ADDRESS fields. Same logic is implemented in 'ip address' command
     * from iproute2 project.
     */
    if (!eui64_iszero(his_eui64))
        IN6_LLADDR_FROM_EUI64(nlreq.addrs[1].addr, his_eui64);
    else
        IN6_LLADDR_FROM_EUI64(nlreq.addrs[1].addr, our_eui64);

    resp = rtnetlink_msg("RTM_NEWADDR/NLM_F_CREATE", NULL, &nlreq, sizeof(nlreq), NULL, NULL, 0);
    if (resp) {
        /*
         * Linux kernel versions prior 3.11 do not support setting IPv6 peer
         * addresses and error response is expected. On older kernel versions
         * do not show this error message. On error pppd tries to fallback to
         * the old IOCTL method.
         */
        errno = (resp < 0) ? -resp : EINVAL;
        if (kernel_version >= KVERSION(3,11,0))
            error("sif6addr_rtnetlink: %m (line %d)", __LINE__);
        return 0;
    }

    return 1;
}

/********************************************************************
 *
 * sif6addr - Config the interface with an IPv6 link-local address
 */
int sif6addr (int unit, eui64_t our_eui64, eui64_t his_eui64)
{
    struct in6_ifreq ifr6;
    struct ifreq ifr;
    struct in6_rtmsg rt6;
    int ret;

    if (sock6_fd < 0) {
	errno = -sock6_fd;
	error("IPv6 socket creation failed: %m");
	return 0;
    }
    memset(&ifr, 0, sizeof (ifr));
    strlcpy(ifr.ifr_name, ifname, sizeof(ifr.ifr_name));
    if (ioctl(sock6_fd, SIOCGIFINDEX, (caddr_t) &ifr) < 0) {
	error("sif6addr: ioctl(SIOCGIFINDEX): %m (line %d)", __LINE__);
	return 0;
    }

    if (kernel_version >= KVERSION(2,1,16)) {
        /* Set both local address and remote peer address (with route for it) via rtnetlink */
        ret = sif6addr_rtnetlink(ifr.ifr_ifindex, our_eui64, his_eui64);
    } else {
        ret = 0;
    }

    /*
     * Linux kernel versions prior 3.11 do not support setting IPv6 peer address
     * via rtnetlink. So if sif6addr_rtnetlink() fails then try old IOCTL method.
     */
    if (!ret) {
        /* Local interface */
        memset(&ifr6, 0, sizeof(ifr6));
        IN6_LLADDR_FROM_EUI64(ifr6.ifr6_addr, our_eui64);
        ifr6.ifr6_ifindex = ifr.ifr_ifindex;
        ifr6.ifr6_prefixlen = 128;

        if (ioctl(sock6_fd, SIOCSIFADDR, &ifr6) < 0) {
            error("sif6addr: ioctl(SIOCSIFADDR): %m (line %d)", __LINE__);
            return 0;
        }
    }

    if (!ret && !eui64_iszero(his_eui64)) {
        /*
         * Linux kernel does not provide AF_INET6 ioctl SIOCSIFDSTADDR for
         * setting remote peer host address, so set only route to remote host.
         */

        /* Route to remote host */
        memset(&rt6, 0, sizeof(rt6));
        IN6_LLADDR_FROM_EUI64(rt6.rtmsg_dst, his_eui64);
        rt6.rtmsg_flags = RTF_UP;
        rt6.rtmsg_dst_len = 128;
        rt6.rtmsg_ifindex = ifr.ifr_ifindex;
        rt6.rtmsg_metric = 1;

        if (ioctl(sock6_fd, SIOCADDRT, &rt6) < 0) {
            error("sif6addr: ioctl(SIOCADDRT): %m (line %d)", __LINE__);
            return 0;
        }
    }

    return 1;
}


/********************************************************************
 *
 * cif6addr - Remove IPv6 address from interface
 */
int cif6addr (int unit, eui64_t our_eui64, eui64_t his_eui64)
{
    struct ifreq ifr;
    struct in6_ifreq ifr6;

    if (sock6_fd < 0) {
	errno = -sock6_fd;
	error("IPv6 socket creation failed: %m");
	return 0;
    }
    memset(&ifr, 0, sizeof(ifr));
    strlcpy(ifr.ifr_name, ifname, sizeof(ifr.ifr_name));
    if (ioctl(sock6_fd, SIOCGIFINDEX, (caddr_t) &ifr) < 0) {
	error("cif6addr: ioctl(SIOCGIFINDEX): %m (line %d)", __LINE__);
	return 0;
    }

    memset(&ifr6, 0, sizeof(ifr6));
    IN6_LLADDR_FROM_EUI64(ifr6.ifr6_addr, our_eui64);
    ifr6.ifr6_ifindex = ifr.ifr_ifindex;
    ifr6.ifr6_prefixlen = 128;

    if (ioctl(sock6_fd, SIOCDIFADDR, &ifr6) < 0) {
	if (errno != EADDRNOTAVAIL) {
	    if (! ok_error (errno))
		error("cif6addr: ioctl(SIOCDIFADDR): %m (line %d)", __LINE__);
	}
	else {
	    warn("cif6addr: ioctl(SIOCDIFADDR): No such address");
	}
	return (0);
    }
    return 1;
}
#endif /* PPP_WITH_IPV6CP */

/*
 * get_pty - get a pty master/slave pair and chown the slave side
 * to the uid given.  Assumes slave_name points to >= 16 bytes of space.
 */
int
get_pty(int *master_fdp, int *slave_fdp, char *slave_name, int uid)
{
    int i, mfd, ret, sfd = -1;
    char pty_name[16];
    struct termios tios;

#ifdef TIOCGPTN
    /*
     * Try the unix98 way first.
     */
    mfd = open("/dev/ptmx", O_RDWR);
    if (mfd >= 0) {
	int ptn;
	if (ioctl(mfd, TIOCGPTN, &ptn) >= 0) {
	    slprintf(pty_name, sizeof(pty_name), "/dev/pts/%d", ptn);
	    chmod(pty_name, S_IRUSR | S_IWUSR);
#ifdef TIOCSPTLCK
	    ptn = 0;
	    if (ioctl(mfd, TIOCSPTLCK, &ptn) < 0)
		warn("Couldn't unlock pty slave %s: %m", pty_name);
#endif
	    if ((sfd = open(pty_name, O_RDWR | O_NOCTTY)) < 0)
	    {
		warn("Couldn't open pty slave %s: %m", pty_name);
		close(mfd);
	    }
	}
    }
#endif /* TIOCGPTN */

    if (sfd < 0) {
	/* the old way - scan through the pty name space */
	for (i = 0; i < 64; ++i) {
	    slprintf(pty_name, sizeof(pty_name), "/dev/pty%c%x",
		     'p' + i / 16, i % 16);
	    mfd = open(pty_name, O_RDWR, 0);
	    if (mfd >= 0) {
		pty_name[5] = 't';
		sfd = open(pty_name, O_RDWR | O_NOCTTY, 0);
		if (sfd >= 0) {
		    ret = fchown(sfd, uid, -1);
		    if (ret != 0) {
			warn("Couldn't change ownership of %s, %m", pty_name);
		    }
		    ret = fchmod(sfd, S_IRUSR | S_IWUSR);
		    if (ret != 0) {
			warn("Couldn't change permissions of %s, %m", pty_name);
		    }
		    break;
		}
		close(mfd);
	    }
	}
    }

    if (sfd < 0)
	return 0;

    strlcpy(slave_name, pty_name, 16);
    *master_fdp = mfd;
    *slave_fdp = sfd;
    if (tcgetattr(sfd, &tios) == 0) {
	tios.c_cflag &= ~(CSIZE | CSTOPB | PARENB);
	tios.c_cflag |= CS8 | CREAD | CLOCAL;
	tios.c_iflag  = IGNPAR;
	tios.c_oflag  = 0;
	tios.c_lflag  = 0;
	if (tcsetattr(sfd, TCSAFLUSH, &tios) < 0)
	    warn("couldn't set attributes on pty: %m");
    } else
	warn("couldn't get attributes on pty: %m");

    return 1;
}

/********************************************************************
 *
 * open_loopback - open the device we use for getting packets
 * in demand mode.  Under Linux, we use a pty master/slave pair.
 */
int
open_ppp_loopback(void)
{
    int flags;

    looped = 1;
    if (new_style_driver) {
	/* allocate ourselves a ppp unit */
	if (make_ppp_unit() < 0)
	    die(1);
	modify_flags(ppp_dev_fd, 0, SC_LOOP_TRAFFIC);
	set_kdebugflag(kdebugflag);
	ppp_fd = -1;
	return ppp_dev_fd;
    }

    if (!get_pty(&master_fd, &slave_fd, loop_name, 0))
	fatal("No free pty for loopback");

    set_ppp_fd(slave_fd);

    flags = fcntl(master_fd, F_GETFL);
    if (flags == -1 ||
	fcntl(master_fd, F_SETFL, flags | O_NONBLOCK) == -1)
	warn("couldn't set master loopback to nonblock: %m");

    flags = fcntl(ppp_fd, F_GETFL);
    if (flags == -1 ||
	fcntl(ppp_fd, F_SETFL, flags | O_NONBLOCK) == -1)
	warn("couldn't set slave loopback to nonblock: %m");

    if (ioctl(ppp_fd, TIOCSETD, &ppp_disc) < 0)
	fatal("ioctl(TIOCSETD): %m (line %d)", __LINE__);
/*
 * Find out which interface we were given.
 */
    if (ioctl(ppp_fd, PPPIOCGUNIT, &ifunit) < 0)
	fatal("ioctl(PPPIOCGUNIT): %m (line %d)", __LINE__);
/*
 * Enable debug in the driver if requested.
 */
    set_kdebugflag (kdebugflag);

    return master_fd;
}

/********************************************************************
 *
 * sifnpmode - Set the mode for handling packets for a given NP.
 */

int
sifnpmode(int u, int proto, enum NPmode mode)
{
    struct npioctl npi;

    npi.protocol = proto;
    npi.mode     = mode;
    if (ioctl(ppp_dev_fd, PPPIOCSNPMODE, (caddr_t) &npi) < 0) {
	if (! ok_error (errno))
	    error("ioctl(PPPIOCSNPMODE, %d, %d): %m", proto, mode);
	return 0;
    }
    return 1;
}

/*
 * Use the hostname as part of the random number seed.
 */
int
get_host_seed(void)
{
    int h;
    const char *p;

    h = 407;
    for (p = hostname; *p != 0; ++p)
	h = h * 37 + *p;
    return h;
}

/********************************************************************
 *
 * sys_check_options - check the options that the user specified
 */

int
sys_check_options(void)
{
    if (demand && driver_is_old) {
	ppp_option_error("demand dialling is not supported by kernel driver "
		     "version %d.%d.%d", driver_version, driver_modification,
		     driver_patch);
	return 0;
    }
    if (multilink && !new_style_driver) {
	warn("Warning: multilink is not supported by the kernel driver");
	multilink = 0;
    }
    return 1;
}

/********************************************************************
 *
 * get_time - Get current time, monotonic if possible.
 */
int
ppp_get_time(struct timeval *tv)
{
/* Old glibc (< 2.3.4) does define CLOCK_MONOTONIC, but kernel may have it.
 * Runtime checking makes it safe. */
#ifndef CLOCK_MONOTONIC
#define CLOCK_MONOTONIC 1
#endif
    static int monotonic = -1;
    struct timespec ts;
    int ret;

    if (monotonic) {
	ret = clock_gettime(CLOCK_MONOTONIC, &ts);
	if (ret == 0) {
	    monotonic = 1;
	    if (tv) {
		tv->tv_sec = ts.tv_sec;
		tv->tv_usec = ts.tv_nsec / 1000;
	    }
	    return ret;
	} else if (monotonic > 0)
	    return ret;

	monotonic = 0;
	warn("Couldn't use monotonic clock source: %m");
    }

    return gettimeofday(tv, NULL);
}
