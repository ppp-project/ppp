--- ttycom.h	Mon Jun 17 08:08:09 1996
+++ ttycom.h.new	Fri Apr  9 08:22:06 1999
@@ -133,9 +133,13 @@
 #define	TIOCDSIMICROCODE _IO('t', 85)		/* download microcode to
 						 * DSI Softmodem */
 
+#define	TIOCRCVFRAME	_IOW('t', 69, struct mbuf *)	/* data frame received */
+#define	TIOCXMTFRAME	_IOW('t', 68, struct mbuf *)	/* data frame transmit */
+
 #define	TTYDISC		0		/* termios tty line discipline */
 #define	TABLDISC	3		/* tablet discipline */
 #define	SLIPDISC	4		/* serial IP discipline */
 #define	PPPDISC		5		/* PPP discipline */
+#define	HDLCDISC	6		/* HDLC discipline */
 
 #endif /* !_SYS_TTYCOM_H_ */
