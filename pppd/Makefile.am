sbin_PROGRAMS = pppd
dist_man8_MANS = pppd.8
check_PROGRAMS =

utest_chap_SOURCES = chap_ms.c utils.c crypto_ms.c
utest_chap_CPPFLAGS = -DUNIT_TEST
utest_chap_LDFLAGS =

utest_peap_SOURCES = peap.c utils.c mppe.c
utest_peap_CPPFLAGS = -DUNIT_TEST
utest_peap_LDFLAGS =

utest_crypto_SOURCES = crypto.c utils.c
utest_crypto_CPPFLAGS = -DUNIT_TEST
utest_crypto_LDFLAGS =

utest_pppcrypt_SOURCES = crypto_ms.c
utest_pppcrypt_CPPFLAGS = -DUNIT_TEST_MSCRYPTO
utest_pppcrypt_LDFLAGS =

check_PROGRAMS += utest_crypto

utest_utils_SOURCES = utils.c utils_utest.c
utest_utils_CPPFLAGS = -DUNIT_TEST
utest_utils_LDFLAGS =

check_PROGRAMS += utest_utils

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
    chap.h \
    chap_ms.h \
    crypto.h \
    crypto_ms.h \
    eap.h \
    ecp.h \
    eui64.h \
    fsm.h \
    ipcp.h \
    ipv6cp.h \
    lcp.h \
    magic.h \
    mppe.h \
    multilink.h \
    pppd.h \
    options.h \
    pppdconf.h \
    session.h \
    upap.h 

# Headers to be distributed, but not installed in /usr/include/pppd
noinst_HEADERS = \
    chap-md5.h \
    crypto-priv.h \
    eap-tls.h \
    pathnames.h \
    peap.h \
    pppd-private.h \
    spinlock.h \
    tls.h \
    tdb.h

pppd_SOURCES = \
    auth.c \
    ccp.c \
    chap-md5.c \
    chap.c \
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

# Things produced by the build process, to be installed but not distributed
BUILT_SOURCE = \
    pppdconf.h

pppd_CPPFLAGS = -DSYSCONFDIR=\"${sysconfdir}\" -DPPPD_RUNTIME_DIR='"@PPPD_RUNTIME_DIR@"' -DPPPD_LOGFILE_DIR='"@PPPD_LOGFILE_DIR@"'
pppd_LDFLAGS =
pppd_LIBS =

if PPP_WITH_SYSTEM_CA_PATH
pppd_CPPFLAGS += -DSYSTEM_CA_PATH='"@SYSTEM_CA_PATH@"'
endif

if LINUX
pppd_SOURCES += sys-linux.c
noinst_HEADERS += termios_linux.h
pppd_LIBS += $(CRYPT_LIBS) $(UTIL_LIBS)
endif

if SUNOS
pppd_SOURCES += sys-solaris.c
pppd_CPPFLAGS += -I${top_srcdir}/include
pppd_LIBS += -lsocket -lnsl
endif

if PPP_WITH_CHAPMS
pppd_SOURCES += chap_ms.c crypto_ms.c
check_PROGRAMS += utest_chap
check_PROGRAMS += utest_pppcrypt
else
if WITH_SRP
pppd_SOURCES += crypto_ms.c
check_PROGRAMS += utest_pppcrypt
endif
endif

if PPP_WITH_CBCP
pppd_SOURCES += cbcp.c
endif

if PPP_WITH_MPPE
pppd_SOURCES += mppe.c
endif

if PPP_WITH_FILTER
pppd_CPPFLAGS += $(PCAP_CFLAGS)
pppd_LDFLAGS += $(PCAP_LDFLAGS)
pppd_LIBS += $(PCAP_LIBS)
endif

if PPP_WITH_PLUGINS
pppd_CPPFLAGS += -DPPPD_PLUGIN_DIR='"@PPPD_PLUGIN_DIR@"'
pppd_LIBS += -ldl
if LINUX
pppd_LDFLAGS += -Wl,-E
endif
endif

if PPP_WITH_MULTILINK
pppd_SOURCES += multilink.c
endif

if PPP_WITH_TDB
pppd_SOURCES += tdb.c spinlock.c
endif

if PPP_WITH_IPV6CP
pppd_SOURCES += ipv6cp.c eui64.c
endif

if PPP_WITH_PAM
pppd_CPPFLAGS += $(PAM_CFLAGS)
pppd_LIBS += $(PAM_LIBS) -ldl
pppd_LDFLAGS += $(PAM_LDFLAGS)
endif

if PPP_WITH_EAPTLS
pppd_SOURCES += eap-tls.c tls.c
else
if PPP_WITH_PEAP
pppd_SOURCES += tls.c
endif
endif

if PPP_WITH_PEAP
pppd_SOURCES += peap.c
check_PROGRAMS += utest_peap
endif

noinst_LTLIBRARIES = libppp_crypto.la
libppp_crypto_la_SOURCES=crypto.c ppp-md5.c ppp-md4.c ppp-sha1.c ppp-des.c

if PPP_WITH_OPENSSL
pppd_CPPFLAGS += $(OPENSSL_INCLUDES)

libppp_crypto_la_CPPFLAGS=$(OPENSSL_INCLUDES)
libppp_crypto_la_LDFLAGS=$(OPENSSL_LDFLAGS)
libppp_crypto_la_LIBADD=$(OPENSSL_LIBS)
endif

utest_peap_LDADD = libppp_crypto.la
utest_chap_LDADD = libppp_crypto.la
utest_crypto_LDADD = libppp_crypto.la
utest_pppcrypt_LDADD = libppp_crypto.la

pppd_LIBS += libppp_crypto.la

if WITH_SYSTEMD
pppd_CPPFLAGS += $(SYSTEMD_CFLAGS)
pppd_LIBS += $(SYSTEMD_LIBS)
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

