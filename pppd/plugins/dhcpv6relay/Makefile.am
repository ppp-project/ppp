pppd_plugin_LTLIBRARIES = dhcpv6relay.la
pppd_plugindir = $(PPPD_PLUGIN_DIR)

noinst_HEADERS = dhcpv6relay.h

dhcpv6relay_la_CPPFLAGS = -I${top_srcdir} -DSYSCONFDIR=\"${sysconfdir}\" -DPLUGIN
dhcpv6relay_la_LDFLAGS = -module -avoid-version
dhcpv6relay_la_SOURCES = dhcpv6relay.c
