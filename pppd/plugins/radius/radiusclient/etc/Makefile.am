#
# $Id: Makefile.am,v 1.4 2002/10/05 17:49:00 fcusack Exp $
#
# Copyright (C) 1997,1998 Lars Fenneberg
#
# See the file COPYRIGHT for the respective terms and conditions. 
# If the file is missing contact me at lf@elemental.net 
# and I'll send you a copy.
#

AUTOMAKE_OPTIONS = foreign

CLEANFILES = *~ radiusclient.conf

sbindir = @sbindir@
pkgsysconfdir = @pkgsysconfdir@
pkgsysconf_DATA = issue port-id-map radiusclient.conf \
	dictionary dictionary.ascend dictionary.compat dictionary.merit \
	dictionary.microsoft

EXTRA_DIST = issue port-id-map dictionary dictionary.ascend \
	dictionary.compat dictionary.merit dictionary.microsoft \
	realms servers radiusclient.conf.in

radiusclient.conf: radiusclient.conf.in
	sed -e 's|@sbin''dir@|$(sbindir)|g' \
	    -e 's|@pkgsysconf''dir@|$(pkgsysconfdir)|g' \
	    <$(srcdir)/radiusclient.conf.in >radiusclient.conf

install-data-local: realms servers
	$(mkinstalldirs) $(pkgsysconfdir); \
        echo " $(INSTALL) -m600 $(srcdir)/realms $(pkgsysconfdir)/realms"; \
        $(INSTALL) -m600 $(srcdir)/realms $(pkgsysconfdir)/realms; \
        echo " $(INSTALL) -m600 $(srcdir)/servers $(pkgsysconfdir)/servers"; \
        $(INSTALL) -m600 $(srcdir)/servers $(pkgsysconfdir)/servers

uninstall-local:
	rm -f $(pkgsysconfdir)/realms
	rm -f $(pkgsysconfdir)/servers
