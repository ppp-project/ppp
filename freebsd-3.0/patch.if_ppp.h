--- sys.stable/net/if_ppp.h	Sat Oct 18 04:02:39 1997
+++ /usr/src/synclink/bsd3/if_ppp.h	Fri Apr 16 12:54:12 1999
@@ -53,6 +53,7 @@
 #define SC_RCV_B7_1	0x02000000	/* have rcvd char with bit 7 = 1 */
 #define SC_RCV_EVNP	0x04000000	/* have rcvd char with even parity */
 #define SC_RCV_ODDP	0x08000000	/* have rcvd char with odd parity */
+#define SC_SYNC		0x00200000	/* synchronous HDLC */
 #define	SC_MASK		0x0fff00ff	/* bits that user can change */
 
 /*
