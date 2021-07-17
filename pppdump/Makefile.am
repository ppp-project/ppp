sbin_PROGRAMS = pppdump
man8_MANS = pppdump.8

pppdump_SOURCES = pppdump.c bsd-comp.c deflate.c zlib.c
pppdump_CFLAGS = -I${top_srcdir}/include/net

noinst_HEADERS = \
    ppp-comp.h \
    zlib.h

EXTRA_DIST = \
    $(man8_MANS)
