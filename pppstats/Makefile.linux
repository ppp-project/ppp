#
# pppstats makefile
# $Id: Makefile.linux,v 1.5 2002/10/27 12:56:26 fcusack Exp $
#

PPPSTATSRCS = pppstats.c
PPPSTATOBJS = pppstats.o

#CC = gcc
COPTS = -O
COMPILE_FLAGS = -I../include
LIBS =

INSTALL= install -o root -g daemon

CFLAGS = $(COPTS) $(COMPILE_FLAGS)

all: pppstats

install: pppstats
	-mkdir -p $(MANDIR)/man8
	$(INSTALL) -s -c pppstats $(BINDIR)/pppstats
	$(INSTALL) -c -m 444 pppstats.8 $(MANDIR)/man8/pppstats.8

pppstats: $(PPPSTATSRCS)
	$(CC) $(CFLAGS) -o pppstats pppstats.c $(LIBS)

clean:
	rm -f pppstats *~ #* core

depend:
	cpp -M $(CFLAGS) $(PPPSTATSRCS) >.depend
#	makedepend $(CFLAGS) $(PPPSTATSRCS)
