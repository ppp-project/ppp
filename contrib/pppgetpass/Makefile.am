noinst_PROGRAMS = pppgetpass.vt

pppgetpass_vt_SOURCES = pppgetpass.vt.c
pppgetpass_vt_CPPFLAGS = -Wno-unused-result

if WITH_GTK
noinst_PROGRAMS += pppgetpass.gtk

pppgetpass_gtk_SOURCES = pppgetpass.gtk.c
pppgetpass_gtk_CPPFLAGS = -Wno-deprecated-declarations -Wno-discarded-qualifiers
pppgetpass_gtk_CPPFLAGS += $(GLIB_CFLAGS) $(GTK_CFLAGS)
pppgetpass_gtk_LDADD = $(GLIB_LIBS) $(GTK_LIBS)
endif

EXTRA_DIST = \
    pppgetpass.sh \
    pppgetpass.8
