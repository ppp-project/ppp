ACLOCAL_AMFLAGS="-Im4"

SUBDIRS = chat contrib pppd pppstats pppdump

if PPP_WITH_PLUGINS
SUBDIRS += pppd/plugins
endif

DIST_SUBDIRS = $(SUBDIRS) include scripts

install-data-hook:
	(cd $(DESTDIR)/$(sysconfdir)/$(PACKAGE) ; \
	 chmod 600 chap-secrets pap-secrets eaptls-server eaptls-client)

sampledir = $(sysconfdir)/$(PACKAGE)
sample_DATA = \
    etc.ppp/options \
    etc.ppp/chap-secrets \
    etc.ppp/pap-secrets \
    etc.ppp/eaptls-server \
    etc.ppp/eaptls-client \
    etc.ppp/openssl.cnf

EXTRA_README = \
    Changes-2.3 \
    FAQ \
    README \
    README.cbcp \
    README.eap-srp \
    README.eap-tls \
    README.linux \
    README.MPPE \
    README.MSCHAP80 \
    README.MSCHAP81 \
    README.pppoe \
    README.pppol2tp \
    README.pwfd \
    README.sol2 \
    PLUGINS \
    SETUP \
    Submitting-patches.md

EXTRA_DIST= \
    $(sample_DATA) \
    $(EXTRA_README)
