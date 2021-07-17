sbin_PROGRAMS = pppstats
man8_MANS = pppstats.8

pppstats_SOURCES = pppstats.c
pppstats_CFLAGS =

if LINUX
pppstats_CFLAGS += -I${top_srcdir}/include
endif

if SUNOS
pppstats_CFLAGS += -DSTREAMS
endif

EXTRA_DIST = \
    $(man8_MANS)
