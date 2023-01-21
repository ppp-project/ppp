pppd_plugin_LTLIBRARIES = pppoe.la 
pppd_plugindir = $(PPPD_PLUGIN_DIR)
sbin_PROGRAMS = pppoe-discovery
dist_man8_MANS = pppoe-discovery.8

noinst_HEADERS = \
    pppoe.h

pppoe_la_CPPFLAGS = -I${top_srcdir} -DSYSCONFDIR=\"${sysconfdir}\" -DPLUGIN
pppoe_la_LDFLAGS = -module -avoid-version
pppoe_la_SOURCES = plugin.c discovery.c if.c common.c

pppoe_discovery_CPPFLAGS = -I${top_srcdir}
pppoe_discovery_SOURCES = pppoe-discovery.c discovery.c if.c common.c
