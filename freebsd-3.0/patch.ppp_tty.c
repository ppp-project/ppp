--- sys.stable/net/ppp_tty.c	Sun Jan 17 14:53:47 1999
+++ /usr/src/synclink/bsd3/ppp_tty.c	Fri Apr 16 12:54:20 1999
@@ -110,7 +110,10 @@
 static int	pppinput __P((int c, struct tty *tp));
 static int	pppstart __P((struct tty *tp));
 
+static void	ppprcvframe __P((struct ppp_softc *sc, struct mbuf *m));
+
 static u_short	pppfcs __P((u_short fcs, u_char *cp, int len));
+static void	pppsyncstart __P((register struct ppp_softc *sc));
 static void	pppasyncstart __P((struct ppp_softc *));
 static void	pppasyncctlp __P((struct ppp_softc *));
 static void	pppasyncrelinq __P((struct ppp_softc *));
@@ -118,6 +121,7 @@
 static void	ppp_timeout __P((void *));
 static void	pppgetm __P((struct ppp_softc *sc));
 static void	ppplogchar __P((struct ppp_softc *, int));
+static void	pppdumpframe __P((struct ppp_softc *sc,struct mbuf* m,int xmit));
 
 /* XXX called from if_ppp.c - layering violation */
 void		pppasyncattach __P((void *));
@@ -471,6 +475,10 @@
 
     error = 0;
     switch (cmd) {
+    case TIOCRCVFRAME:
+    	ppprcvframe(sc,*((struct mbuf **)data));
+	break;
+	
     case PPPIOCSASYNCMAP:
 	if ((error = suser(p->p_ucred, &p->p_acflag)) != 0)
 	    break;
@@ -515,6 +523,111 @@
     return error;
 }
 
+/* receive a complete ppp frame from device in synchronous
+ * hdlc mode. caller gives up ownership of mbuf
+ */
+static void ppprcvframe(struct ppp_softc *sc, struct mbuf *m)
+{
+	int len, s;
+	struct mbuf *n;
+	u_char hdr[4];
+	int hlen,count;
+		
+	for (n=m,len=0;n != NULL;n = n->m_next)
+		len += n->m_len;
+	if (len==0) {
+		m_freem(m);
+		return;
+	}
+	
+	/* extract PPP header from mbuf chain (1 to 4 bytes) */
+	for (n=m,hlen=0;n!=NULL && hlen<sizeof(hdr);n=n->m_next) {
+		count = (sizeof(hdr)-hlen) < n->m_len ?
+				sizeof(hdr)-hlen : n->m_len;
+		bcopy(mtod(n,u_char*),&hdr[hlen],count);
+		hlen+=count;
+	}
+	
+	s = spltty();
+	
+	/* if AFCF compressed then prepend AFCF */
+	if (hdr[0] != PPP_ALLSTATIONS) {
+		if (sc->sc_flags & SC_REJ_COMP_AC) {
+			if (sc->sc_flags & SC_DEBUG)
+				printf("ppp%d: garbage received: 0x%x (need 0xFF)\n",
+					sc->sc_if.if_unit, hdr[0]);
+				goto bail;
+			}
+		M_PREPEND(m,2,M_DONTWAIT);		
+		if (m==NULL) {
+			splx(s);
+			return;
+		}
+		hdr[3] = hdr[1];
+		hdr[2] = hdr[0];
+		hdr[0] = PPP_ALLSTATIONS;
+		hdr[1] = PPP_UI;
+		len += 2;
+	}
+
+	/* if protocol field compressed, add MSB of protocol field = 0 */
+	if (hdr[2] & 1) {
+		/* a compressed protocol */
+		M_PREPEND(m,1,M_DONTWAIT);		
+		if (m==NULL) {
+			splx(s);
+			return;
+		}
+		hdr[3] = hdr[2];
+		hdr[2] = 0;
+		len++;
+	} 
+	
+	/* valid LSB of protocol field has bit0 set */
+	if (!(hdr[3] & 1)) {
+		if (sc->sc_flags & SC_DEBUG)
+			printf("ppp%d: bad protocol %x\n", sc->sc_if.if_unit,
+				(hdr[2] << 8) + hdr[3]);
+			goto bail;
+	}
+	
+	/* packet beyond configured mru? */
+	if (len > sc->sc_mru + PPP_HDRLEN) {
+		if (sc->sc_flags & SC_DEBUG)
+			printf("ppp%d: packet too big\n", sc->sc_if.if_unit);
+		goto bail;
+	}
+	
+	/* add expanded 4 byte header to mbuf chain */
+	for (n=m,hlen=0;n!=NULL && hlen<sizeof(hdr);n=n->m_next) {
+		count = (sizeof(hdr)-hlen) < n->m_len ?
+				sizeof(hdr)-hlen : n->m_len;
+		bcopy(&hdr[hlen],mtod(n,u_char*),count);
+		hlen+=count;
+	}
+	
+	/* if_ppp.c requires the PPP header and IP header */
+	/* to be contiguous */
+	count = len < MHLEN ? len : MHLEN;
+	if (m->m_len < count) {
+		m = m_pullup(m,count);
+		if (m==NULL)
+			goto bail;
+	}
+	
+	sc->sc_stats.ppp_ibytes += len;
+	
+	if (sc->sc_flags & SC_LOG_RAWIN)
+		pppdumpframe(sc,m,0);
+    
+	ppppktin(sc, m, 0);
+	splx(s);
+	return;
+bail:	
+	m_freem(m);
+	splx(s);
+}
+
 /*
  * FCS lookup table as calculated by genfcstab.
  */
@@ -564,6 +677,39 @@
     return (fcs);
 }
 
+/* This gets called at splsoftnet from pppasyncstart at various times
+ * when there is data ready to be sent.
+ */
+static void pppsyncstart(register struct ppp_softc *sc)
+{
+	struct tty *tp = (struct tty *) sc->sc_devp;
+	struct mbuf *m, *n;
+	int len;
+    
+	for(m = sc->sc_outm;;) {
+		if (m == NULL) {
+			m = ppp_dequeue(sc);	/* get new packet */
+			if (m == NULL)
+				break;		/* no more packets */
+			if (sc->sc_flags & SC_DEBUG)
+				pppdumpframe(sc,m,1);
+		}
+		microtime(&sc->sc_if.if_lastchange);
+		for(n=m,len=0;n!=NULL;n=n->m_next)
+			len += n->m_len;
+			
+		/* call device driver IOCTL to transmit a frame */
+		if ((*cdevsw[major(tp->t_dev)]->d_ioctl)
+			(tp->t_dev,TIOCXMTFRAME,(caddr_t)&m,0,0)) {
+			/* busy or error, set as current packet */
+			sc->sc_outm = m;
+			break;
+		}
+		sc->sc_outm = m = NULL;
+		sc->sc_stats.ppp_obytes += len;
+	}
+}
+
 /*
  * This gets called at splsoftnet from if_ppp.c at various times
  * when there is data ready to be sent.
@@ -580,6 +726,11 @@
     struct mbuf *m2;
     int s;
 
+    if (sc->sc_flags & SC_SYNC){
+	pppsyncstart(sc);
+	return;
+    }
+    
     idle = 0;
     /* XXX assumes atomic access to *tp although we're not at spltty(). */
     while (CCOUNT(&tp->t_outq) < PPP_HIWAT) {
@@ -1123,6 +1274,44 @@
 		sc->sc_rawin_count, sc->sc_rawin, " ");
 	sc->sc_rawin_count = 0;
     }
+}
+
+static void pppdumpframe(struct ppp_softc *sc,struct mbuf* m,int xmit)
+{
+	int i,lcount,copycount,count;
+	char lbuf[16];
+	char *data;
+	
+	if (m == NULL)
+		return;
+		
+	for(count=m->m_len,data=mtod(m,char*);m != NULL;) {
+		/* build a line of output */
+		for(lcount=0;lcount < sizeof(lbuf);lcount += copycount) {
+			if (!count) {
+				m = m->m_next;
+				if (m == NULL)
+					break;
+				count = m->m_len;
+				data  = mtod(m,char*);
+			}
+			copycount = (count > sizeof(lbuf)-lcount) ?
+					sizeof(lbuf)-lcount : count;
+			bcopy(data,&lbuf[lcount],copycount);
+			data  += copycount;
+			count -= copycount;
+		}
+
+		/* output line (hex 1st, then ascii) */		
+		printf("ppp%d %s:",sc->sc_if.if_unit,xmit ? "output":"input ");
+		for(i=0;i<lcount;i++)
+			printf("%02x ",(u_char)lbuf[i]);
+		for(;i<sizeof(lbuf);i++)
+			printf("   ");
+		for(i=0;i<lcount;i++)
+			printf("%c",(lbuf[i]>=040 && lbuf[i]<=0176)?lbuf[i]:'.');
+		printf("\n");
+	}
 }
 
 #endif	/* NPPP > 0 */
