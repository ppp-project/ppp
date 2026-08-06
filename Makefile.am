ACLOCAL_AMFLAGS="-Im4"

SUBDIRS = chat pppd pppstats pppdump

if PPP_WITH_PLUGINS
SUBDIRS += pppd/plugins
endif

DIST_SUBDIRS = $(SUBDIRS) include scripts

install-data-hook:
	(cd $(DESTDIR)/$(sysconfdir)/$(PACKAGE) ; \
	 chmod 600 chap-secrets.example pap-secrets.example \
	 eaptls-server.example eaptls-client.example)

sampledir = $(sysconfdir)/$(PACKAGE)
sample_DATA = \
    etc.ppp/options.example \
    etc.ppp/chap-secrets.example \
    etc.ppp/pap-secrets.example \
    etc.ppp/eaptls-server.example \
    etc.ppp/eaptls-client.example \
    etc.ppp/openssl.cnf.example

EXTRA_README = \
    Changes-2.3 \
    Changes-2.4 \
    FAQ \
    LICENSE.BSD \
    LICENSE.GPL-2 \
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
    SECURITY.md \
    SETUP \
    Submitting-patches.md \
    autogen.sh

EXTRA_DIST= \
    $(sample_DATA) \
    $(EXTRA_README) \
    sample \
    runtests.py \
    testsuite/README.md \
    testsuite/exitcodes.py \
    testsuite/pppfns.py \
    testsuite/00-version_test.py \
    testsuite/auth-chap_test.py \
    testsuite/auth-pap_test.py \
    testsuite/data-transfer_test.py \
    testsuite/link-up_test.py \
    testsuite/mtu-negotiation_test.py \
    testsuite/ping_test.py

# Integration tests: bring up pairs of pppd instances and verify link
# negotiation, IP routing, authentication etc. Needs root or passwordless
# sudo plus kernel ppp support, so it is not part of "make check".
check-integration: all
	python3 $(top_srcdir)/runtests.py --tooldir $(abs_top_builddir) --srcdir $(abs_top_srcdir)

.PHONY: check-integration
