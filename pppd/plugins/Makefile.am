pppd_plugin_LTLIBRARIES = minconn.la passwordfd.la winbind.la
pppd_plugindir = $(PPPD_PLUGIN_DIR)

PLUGIN_CPPFLAGS = -I${top_srcdir}
PLUGIN_LDFLAGS = -module -avoid-version

minconn_la_CPPFLAGS = $(PLUGIN_CPPFLAGS)
minconn_la_LDFLAGS = $(PLUGIN_LDFLAGS)
minconn_la_SOURCES = minconn.c

passwordfd_la_CPPFLAGS = $(PLUGIN_CPPFLAGS)
passwordfd_la_LDFLAGS = $(PLUGIN_LDFLAGS)
passwordfd_la_SOURCES = passwordfd.c

winbind_la_CPPFLAGS = $(PLUGIN_CPPFLAGS)
winbind_la_LDFLAGS = $(PLUGIN_LDFLAGS)
winbind_la_SOURCES = winbind.c

if !SUNOS
SUBDIRS = pppoe pppoatm pppol2tp radius
endif
