sbin_PROGRAMS = pppstats
dist_man8_MANS = pppstats.8

pppstats_SOURCES = pppstats.c
pppstats_CFLAGS =
pppstats_CPPFLAGS =

if LINUX
pppstats_CFLAGS += -I${top_srcdir}/include
endif

if SUNOS
pppstats_CPPFLAGS += -DSTREAMS
endif
