pppd_plugin_LTLIBRARIES = radius.la radattr.la radrealms.la
pppd_plugindir = $(PPPD_PLUGIN_DIR)

noinst_LTLIBRARIES = libradiusclient.la
dist_man8_MANS = pppd-radius.8 pppd-radattr.8
noinst_HEADERS = \
    includes.h \
    options.h \
    pathnames.h \
    radiusclient.h

EXTRA_FILES = \
    COPYRIGHT

EXTRA_ETC = \
    etc/dictionary \
    etc/dictionary.ascend \
    etc/dictionary.compat \
    etc/dictionary.merit \
    etc/dictionary.microsoft \
    etc/issue \
    etc/port-id-map \
    etc/radiusclient.conf \
    etc/radiusclient.conf.in \
    etc/realms \
    etc/servers

RADIUS_CPPFLAGS = -I${top_srcdir} -DRC_LOG_FACILITY=LOG_DAEMON
RADIUS_LDFLAGS = -module -avoid-version $(LDFLAGS)

radius_la_CPPFLAGS = $(RADIUS_CPPFLAGS)
radius_la_LDFLAGS = $(RADIUS_LDFLAGS)
radius_la_SOURCES = radius.c
radius_la_LIBADD = libradiusclient.la

radattr_la_CPPFLAGS = $(RADIUS_CPPFLAGS)
radattr_la_LDFLAGS = $(RADIUS_LDFLAGS)
radattr_la_SOURCES = radattr.c

radrealms_la_CPPFLAGS = $(RADIUS_CPPFLAGS)
radrealms_la_LDFLAGS = $(RADIUS_LDFLAGS)
radrealms_la_SOURCES = radrealms.c

libradiusclient_la_SOURCES = \
    avpair.c buildreq.c config.c dict.c ip_util.c \
	clientid.c sendserver.c lock.c util.c md5.c
libradiusclient_la_CPPFLAGS = $(RADIUS_CPPFLAGS) -DSYSCONFDIR=\"${sysconfdir}\"

EXTRA_DIST = \
    $(EXTRA_FILES) \
    $(EXTRA_ETC)
