sbin_PROGRAMS = pppdump
dist_man8_MANS = pppdump.8

pppdump_SOURCES = pppdump.c bsd-comp.c deflate.c zlib.c
pppdump_CFLAGS = -I${top_srcdir}/include/net

noinst_HEADERS = \
    ppp-comp.h \
    zlib.h
