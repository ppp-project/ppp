/*
 * INET		An implementation of the TCP/IP protocol suite for the LINUX
 *		operating system.  INET is implemented using the  BSD Socket
 *		interface as the means of communication with the user level.
 *
 *		Global definitions for the IP router interface.
 *
 * Version:	@(#)route.h	1.0.3	05/27/93
 *
 * Authors:	Original taken from Berkeley UNIX 4.3, (c) UCB 1986-1988
 *		for the purposes of compatibility only.
 *
 *		Fred N. van Kempen, <waltje@uWalt.NL.Mugnet.ORG>
 *
 *		This program is free software; you can redistribute it and/or
 *		modify it under the terms of the GNU General Public License
 *		as published by the Free Software Foundation; either version
 *		2 of the License, or (at your option) any later version.
 */
#ifndef _LINUX_ROUTE_H
#define _LINUX_ROUTE_H

#include <linux/if.h>


/* This structure gets passed by the SIOCADDRT and SIOCDELRT calls. */
struct rtentry 
{
	unsigned long	rt_hash;	/* hash key for lookups		*/
	struct sockaddr	rt_dst;		/* target address		*/
	struct sockaddr	rt_gateway;	/* gateway addr (RTF_GATEWAY)	*/
	struct sockaddr	rt_genmask;	/* target network mask (IP)	*/
	short		rt_flags;
	short		rt_refcnt;
	unsigned long	rt_use;
	struct ifnet	*rt_ifp;
	short		rt_metric;	/* +1 for binary compatibility!	*/
	char		*rt_dev;	/* forcing the device at add	*/
	unsigned long	rt_mss;		/* per route MTU/Window 	*/
	unsigned long	rt_window;	/* Window clamping 		*/
	unsigned short	rt_irtt;	/* Initial RTT			*/
};


#define	RTF_UP		0x0001		/* route usable		  	  */
#define	RTF_GATEWAY	0x0002		/* destination is a gateway	  */
#define	RTF_HOST	0x0004		/* host entry (net otherwise)	  */
#define RTF_REINSTATE	0x0008		/* reinstate route after tmout	  */
#define	RTF_DYNAMIC	0x0010		/* created dyn. (by redirect)	  */
#define	RTF_MODIFIED	0x0020		/* modified dyn. (by redirect)	  */
#define RTF_MSS		0x0040		/* specific MSS for this route	  */
#define RTF_WINDOW	0x0080		/* per route window clamping	  */
#define RTF_IRTT	0x0100		/* Initial round trip time	  */
#define RTF_REJECT	0x0200		/* Reject route			  */

/*
 *	This structure is passed from the kernel to user space by netlink
 *	routing/device announcements
 */

struct netlink_rtinfo
{
	unsigned long	rtmsg_type;
	struct sockaddr rtmsg_dst;
	struct sockaddr rtmsg_gateway;
	struct sockaddr rtmsg_genmask;
	short 		rtmsg_flags;
	short		rtmsg_metric;
	char		rtmsg_device[16];
};

#define RTMSG_NEWROUTE		0x01
#define RTMSG_DELROUTE		0x02
#define RTMSG_NEWDEVICE		0x11
#define RTMSG_DELDEVICE		0x12

#endif	/* _LINUX_ROUTE_H */

