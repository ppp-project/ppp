#
# $Id: Makefile.am,v 1.1 2002/01/22 16:03:04 dfs Exp $
#
# Copyright (C) 1995,1997,1998 Lars Fenneberg
#
# See the file COPYRIGHT for the respective terms and conditions. 
# If the file is missing contact me at lf@elemental.net 
# and I'll send you a copy.
#

AUTOMAKE_OPTIONS = foreign

pkgsysconfdir=@pkgsysconfdir@

DEFS = @DEFS@ -DRC_CONFIG_FILE=\"${pkgsysconfdir}/radiusclient.conf\" \
	      -DRC_SECURE_PATH=\"@RC_SECURE_PATH@\"
INCLUDES = -I$(srcdir) -I$(top_srcdir)/include -I$(top_builddir)
LDADD = ../lib/libradiusclient.la

CLEANFILES = *~

noinst_HEADERS = radlogin.h

sbin_PROGRAMS = radlogin radstatus radacct radexample
radlogin_SOURCES = radlogin.c radius.c local.c
radacct_SOURCES = radacct.c
radstatus_SOURCES = radstatus.c
radexample_SOURCES = radexample.c
