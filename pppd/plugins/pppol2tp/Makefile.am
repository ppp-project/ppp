pppd_plugin_LTLIBRARIES = pppol2tp.la openl2tp.la
pppd_plugindir = $(PPPD_PLUGIN_DIR)

noinst_HEADERS = \
    l2tp_event.h

pppol2tp_la_CPPFLAGS = -I${top_srcdir}
pppol2tp_la_LDFLAGS = -module -avoid-version
pppol2tp_la_SOURCES = pppol2tp.c

openl2tp_la_CPPFLAGS = -I${top_srcdir}
openl2tp_la_LDFLAGS = -module -avoid-version
openl2tp_la_SOURCES = openl2tp.c
