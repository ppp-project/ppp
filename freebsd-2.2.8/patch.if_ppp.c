--- sys.stable/net/if_ppp.c	Fri Apr 16 16:14:37 1999
+++ /usr/src/synclink/bsd2/if_ppp.c	Tue Apr 13 09:54:07 1999
@@ -930,7 +930,6 @@
     struct ppp_softc *sc;
 {
     int s = splimp();
-
     sc->sc_flags &= ~SC_TBUSY;
     schednetisr(NETISR_PPP);
     splx(s);
@@ -1082,7 +1081,7 @@
     for (i = 0; i < NPPP; ++i, ++sc) {
 	s = splimp();
 	if (!(sc->sc_flags & SC_TBUSY)
-	    && (sc->sc_if.if_snd.ifq_head || sc->sc_fastq.ifq_head)) {
+	    && (sc->sc_if.if_snd.ifq_head || sc->sc_fastq.ifq_head || sc->sc_outm)) {
 	    sc->sc_flags |= SC_TBUSY;
 	    splx(s);
 	    (*sc->sc_start)(sc);
