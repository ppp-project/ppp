--- sys.stable/net/if_ppp.h	Fri Apr 16 16:14:37 1999
+++ /usr/src/synclink/bsd2/if_ppp.h	Tue Apr 20 15:30:48 1999
@@ -53,6 +53,7 @@
 #define SC_RCV_B7_1	0x02000000	/* have rcvd char with bit 7 = 1 */
 #define SC_RCV_EVNP	0x04000000	/* have rcvd char with even parity */
 #define SC_RCV_ODDP	0x08000000	/* have rcvd char with odd parity */
+#define SC_SYNC		0x00200000	/* synchronous HDLC */
 #define	SC_MASK		0x0fff00ff	/* bits that user can change */
 
 /*
