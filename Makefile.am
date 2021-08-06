ACLOCAL_AMFLAGS="-Im4"

SUBDIRS = chat contrib pppd pppstats pppdump

if PPP_WITH_PLUGINS
SUBDIRS += pppd/plugins
endif

DIST_SUBDIRS = $(SUBDIRS) common include modules scripts

#
# *HACK*
#   This is to work around the kernel module for PPP on Sun Solaris
if SUNOS
all-am:
	(cd solaris ; $(MAKE) -f Makefile)

clean-generic:
	(cd solaris ; $(MAKE) -f Makefile clean)

install-am:
	(cd solaris ; $(MAKE) -f Makefile install)
endif

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

EXTRA_SOLARIS = \
    solaris/Makedefs \
    solaris/Makedefs.gcc \
    solaris/Makedefs.sol2 \
    solaris/Makefile.sol2 \
    solaris/Makefile.sol2-64 \
    solaris/Makefile.sol2-64x \
    solaris/Makefile.sol2gcc \
    solaris/Makefile.sol2gcc-64 \
    solaris/Makefile.sol2gcc-64x \
    solaris/Makefile.top \
    solaris/ppp_ahdlc.c \
    solaris/ppp_ahdlc_mod.c \
    solaris/ppp.c \
    solaris/ppp_comp.c \
    solaris/ppp_comp_mod.c \
    solaris/ppp.conf \
    solaris/ppp_mod.c \
    solaris/ppp_mod.h

EXTRA_DIST= \
    $(sample_DATA) \
    $(EXTRA_README) \
    $(EXTRA_SOLARIS)
