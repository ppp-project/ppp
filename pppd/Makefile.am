sbin_PROGRAMS = pppd
dist_man8_MANS = pppd.8
check_PROGRAMS =

utest_chap_SOURCES = chap_ms.c pppcrypt.c utils.c
utest_chap_CPPFLAGS = -DUNIT_TEST
utest_chap_LDFLAGS =

utest_peap_SOURCES = peap.c utils.c mppe.c
utest_peap_CPPFLAGS = -DUNIT_TEST -I${top_srcdir}/include
utest_peap_LDFLAGS =

if WITH_SRP
sbin_PROGRAMS += srp-entry
dist_man8_MANS += srp-entry.8
endif

pkgconfigdir   = $(libdir)/pkgconfig
pkgconfig_DATA = pppd.pc

pppd_includedir = $(includedir)/pppd
pppd_include_HEADERS = \
    cbcp.h \
    ccp.h \
    chap-md5.h \
    chap_ms.h \
    chap-new.h \
    eap.h \
    eap-tls.h \
    ecp.h \
    eui64.h \
    fsm.h \
    ipcp.h \
    ipv6cp.h \
    lcp.h \
    magic.h \
    md4.h \
    md5.h \
    mppe.h \
    patchlevel.h \
    pathnames.h \
    peap.h \
    pppcrypt.h \
    pppd.h \
    pppdconf.h \
    session.h \
    sha1.h \
    spinlock.h \
    tls.h \
    tdb.h \
    upap.h 

pppd_SOURCES = \
    auth.c \
    ccp.c \
    chap-md5.c \
    chap-new.c \
    demand.c \
    eap.c \
    ecp.c \
    fsm.c \
    ipcp.c \
    lcp.c \
    magic.c \
    main.c \
    options.c \
    session.c \
    tty.c \
    upap.c \
    utils.c

pppd_CPPFLAGS = -I${top_srcdir}/include -DPPPD_RUNTIME_DIR='"@PPPD_RUNTIME_DIR@"' -DPPPD_LOGFILE_DIR='"@PPPD_LOGFILE_DIR@"'
pppd_LDFLAGS =
pppd_LIBS =

if LINUX
pppd_SOURCES += sys-linux.c termios_linux.h
pppd_LIBS += $(CRYPT_LIBS) $(UTIL_LIBS)
endif

if SUNOS
pppd_SOURCES += sys-solaris.c
pppd_LIBS += -lsocket -lnsl
endif

if WITH_CHAPMS
pppd_SOURCES += chap_ms.c
pppd_SOURCES += pppcrypt.c
check_PROGRAMS += utest_chap
else
if WITH_SRP
pppd_SOURCES += pppcrypt.c
endif
endif

if WITH_CBCP
pppd_SOURCES += cbcp.c
endif

if WITH_MPPE
pppd_SOURCES += mppe.c
endif

if WITH_FILTER
pppd_CPPFLAGS += $(PCAP_CFLAGS)
pppd_LDFLAGS += $(PCAP_LDFLAGS)
pppd_LIBS += $(PCAP_LIBS)
endif

if WITH_PLUGINS
pppd_CPPFLAGS += -DPPPD_PLUGIN_DIR='"@PPPD_PLUGIN_DIR@"'
pppd_LIBS += -ldl
if LINUX
pppd_LDFLAGS += -Wl,-E
endif
endif

if WITH_MULTILINK
pppd_SOURCES += multilink.c
endif

if WITH_TDB
pppd_SOURCES += tdb.c spinlock.c
endif

if WITH_INET6
pppd_SOURCES += ipv6cp.c eui64.c
endif

if WITH_PAM
pppd_LIBS += -lpam -ldl
endif

if WITH_EAPTLS
pppd_SOURCES += eap-tls.c tls.c
else
if WITH_PEAP
pppd_SOURCES += tls.c
endif
endif

if WITH_PEAP
pppd_SOURCES += peap.c
check_PROGRAMS += utest_peap
endif

noinst_LTLIBRARIES = libppp_crypt.la
libppp_crypt_la_SOURCES=

if !WITH_OPENSSL
libppp_crypt_la_SOURCES += md4.c md5.c sha1.c
else
libppp_crypt_la_CPPFLAGS=$(OPENSSL_INCLUDES)
libppp_crypt_la_LDFLAGS=$(OPENSSL_LDFLAGS)
libppp_crypt_la_LIBADD=$(OPENSSL_LIBS)
if !OPENSSL_HAVE_SHA
libppp_crypt_la_SOURCES += sha1.c
endif
if !OPENSSL_HAVE_MD5
libppp_crypt_la_SOURCES += md5.c
endif
if !OPENSSL_HAVE_MD4
libppp_crypt_la_SOURCES += md4.c
endif
endif

utest_peap_LDADD = libppp_crypt.la
utest_chap_LDADD = libppp_crypt.la
pppd_LIBS += libppp_crypt.la

if WITH_SYSTEMD
pppd_LIBS += -lsystemd
endif

if WITH_SRP
srp_entry_SOURCES = srp-entry.c
srp_entry_CPPFLAGS = $(OPENSSL_INCLUDES) $(SRP_CFLAGS)
srp_entry_LDADD = $(SRP_LIBS) $(OPENSSL_LIBS)
srp_entry_LDFLAGS = $(OPENSSL_LDFLAGS) $(SRP_LDFLAGS)

pppd_CPPFLAGS += $(SRP_CFLAGS)
pppd_LDFLAGS += $(SRP_LDFLAGS)
pppd_LIBS += $(SRP_LIBS)
endif

pppd_LDADD = $(pppd_LIBS)

EXTRA_DIST = \
    ppp.pam

TESTS = $(check_PROGRAMS)

