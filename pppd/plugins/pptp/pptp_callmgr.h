/* pptp_callmgr.h ... Call manager for PPTP connections.
 *                    Handles TCP port 1723 protocol.
 *                    C. Scott Ananian <cananian@alumni.princeton.edu>
 *
 * $Id: pptp_callmgr.h,v 1.3 2003/02/17 00:22:17 quozl Exp $
 */

int callmgr_main(int pcallid,
		struct in_addr inetaddr,
		char phonenr[],
		int window);

void callmgr_name_unixsock(struct sockaddr_un *where,
			   struct in_addr inetaddr,
			   struct in_addr localbind);
