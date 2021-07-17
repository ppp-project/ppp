noinst_PROGRAMS = pppgetpass.vt
man8_MANS = pppgetpass.8

pppgetpass_vt_SOURCES = pppgetpass.vt.c
pppgetpass_vt_CFLAGS = -Wno-unused-result

if WITH_GTK
noinst_PROGRAMS += pppgetpass.gtk

pppgetpass_gtk_SOURCES = pppgetpass.gtk.c
pppgetpass_gtk_CFLAGS  = -Wno-deprecated-declarations -Wno-discarded-qualifiers
pppgetpass_gtk_CFLAGS += @GLIB_CFLAGS@ @GTK_CFLAGS@
pppgetpass_gtk_LDADD   = @GLIB_LIBS@ @GTK_LIBS@
endif

EXTRA_DIST = \
    pppgetpass.sh \
    $(man8_MANS)
