--- sys.stable/net/if_ppp.c	Sat Jun 20 11:28:01 1998
+++ /usr/src/synclink/bsd3/if_ppp.c	Fri Apr 16 12:54:12 1999
@@ -1084,7 +1084,7 @@
     for (i = 0; i < NPPP; ++i, ++sc) {
 	s = splimp();
 	if (!(sc->sc_flags & SC_TBUSY)
-	    && (sc->sc_if.if_snd.ifq_head || sc->sc_fastq.ifq_head)) {
+	    && (sc->sc_if.if_snd.ifq_head || sc->sc_fastq.ifq_head || sc->sc_outm)) {
 	    sc->sc_flags |= SC_TBUSY;
 	    splx(s);
 	    (*sc->sc_start)(sc);
