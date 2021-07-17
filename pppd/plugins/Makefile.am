pppd_plugin_LTLIBRARIES = minconn.la passprompt.la passwordfd.la winbind.la
pppd_plugindir = $(PPPD_PLUGIN_DIR)

PLUGIN_CFLAGS = -I${top_srcdir}/include -I${top_srcdir}/pppd
PLUGIN_LDFLAGS = -module -avoid-version

minconn_la_CFLAGS = $(PLUGIN_CFLAGS)
minconn_la_LDFLAGS = $(PLUGIN_LDFLAGS)
minconn_la_SOURCES = minconn.c

passprompt_la_CFLAGS = $(PLUGIN_CFLAGS)
passprompt_la_LDFLAGS = $(PLUGIN_LDFLAGS)
passprompt_la_SOURCES = passprompt.c

passwordfd_la_CFLAGS = $(PLUGIN_CFLAGS)
passwordfd_la_LDFLAGS = $(PLUGIN_LDFLAGS)
passwordfd_la_SOURCES = passwordfd.c

winbind_la_CFLAGS = $(PLUGIN_CFLAGS)
winbind_la_LDFLAGS = $(PLUGIN_LDFLAGS)
winbind_la_SOURCES = winbind.c

if !SUNOS
SUBDIRS = pppoe pppoatm pppol2tp radius
endif
