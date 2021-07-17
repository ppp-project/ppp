pppd_plugin_LTLIBRARIES = pppoe.la 
pppd_plugindir = $(PPPD_PLUGIN_DIR)
sbin_PROGRAMS = pppoe-discovery
dist_man8_MANS = pppoe-discovery.8

noinst_HEADERS = \
    pppoe.h

pppoe_la_CPPFLAGS = -I${top_srcdir} -I${top_srcdir}/include
pppoe_la_LDFLAGS = -module -avoid-version
pppoe_la_SOURCES = plugin.c discovery.c if.c common.c

pppoe_discovery_CPPFLAGS = -I${top_srcdir} -I${top_srcdir}/include
pppoe_discovery_SOURCES = pppoe-discovery.c debug.c

install-exec-hook:
	(mkdir -p $(DESTDIR)/$(pppd_plugindir); \
        cd $(DESTDIR)$(pppd_plugindir); \
        $(LN_S) -f pppoe.so rp-pppoe.so)

uninstall-hook:
	(cd $(DESTDIR)$(pppd_plugindir); rm -f rp-pppoe.so)
