pppd_plugin_LTLIBRARIES = radius.la radattr.la radrealms.la
pppd_plugindir = $(PPPD_PLUGIN_DIR)

noinst_LTLIBRARIES = libradiusclient.la
man8_MANS = pppd-radius.8 pppd-radattr.8
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

RADIUS_CFLAGS = -I${top_srcdir}/include -I${top_srcdir}/pppd -DRC_LOG_FACILITY=LOG_DAEMON
RADIUS_LDFLAGS = -module -avoid-version @LDFLAGS@

radius_la_CFLAGS = $(RADIUS_CFLAGS)
radius_la_LDFLAGS = $(RADIUS_LDFLAGS)
radius_la_SOURCES = radius.c
radius_la_LIBADD = libradiusclient.la
if WITH_OPENSSL
radius_la_LIBADD += @OPENSSL_LIBS@
endif

radattr_la_CFLAGS = $(RADIUS_CFLAGS)
radattr_la_LDFLAGS = $(RADIUS_LDFLAGS)
radattr_la_SOURCES = radattr.c

radrealms_la_CFLAGS = $(RADIUS_CFLAGS)
radrealms_la_LDFLAGS = $(RADIUS_LDFLAGS)
radrealms_la_SOURCES = radrealms.c

libradiusclient_la_SOURCES = \
    avpair.c buildreq.c config.c dict.c ip_util.c \
	clientid.c sendserver.c lock.c util.c
libradiusclient_la_CFLAGS = $(RADIUS_CFLAGS)

if !WITH_OPENSSL
libradiusclient_la_SOURCES += md5.c
else
if OPENSSL_HAVE_MD5
libradiusclient_la_SOURCES += md5.c
else
libradiusclient_la_CFLAGS += @OPENSSL_INCLUDES@
endif
endif

EXTRA_DIST = \
    $(man8_MANS) \
    $(EXTRA_FILES) \
    $(EXTRA_ETC)
