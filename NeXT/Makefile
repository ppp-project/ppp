#
# Makefile for NeXT OS 3.2
#
# $Id: Makefile,v 1.1 1995/12/18 03:29:50 paulus Exp $
#

#ARCHFLAGS = -arch i386 -arch m68k -arch hppa -arch sparc
#ARCHFLAGS = -arch i386 -arch m68k
#ARCHFLAGS = -arch i386
ARCHFLAGS = 

BINDIR = /usr/local/ppp/bin
MANDIR = /usr/local/ppp/man
ETCDIR = /etc/ppp
#
# If you change this pathname, you must also change the path
# in and rc.local (or rc.ppp).
#
LKS_DIR=/usr/local/ppp/reloc

IFLAGS = -I. -I.. -I../pppd

#
# NUM_PPP=x      The number of ppp interfaces you want to create
# VJC            If defined, enables VJ header compression
# PPP_COMPRESS   If defined, enables BSD packet compression
# HAS_BROKEN_TIOCSPGRP Fixes broken IOCTL with NeXT serial drivers
# ADD_ERRORS     If defined adds pseudo-random errors to packets.
#                (Only really used for robustness testing.)
# OLD_MUX        Fixes double buffer problem with the MuX serial
#                driver.
# NBPFILTER       If defined, adds hooks for the Berkley Packet Filter
#                If this symbol is defined, you must load the
#                bpf_reloc LKS _BEFORE_ you load the ppp_reloc LKS.
#                See the ./bpf directory for more information.    
#
# OPTIMIZE_PPPREND Enable an optimization supported by the NeXT serial
#                  drivers.  Basically they buffer characters for an
#                  interrupt and call ppprend.

DFLAGS = -DINET -DKERNEL -DMACH -DNBPFILTER \
	-DNUM_PPP=2 -DVJC -DPPP_COMPRESS \
	-DDEBUG -DHAS_BROKEN_TIOCSPGRP -DOLD_MUX \
	-DOPTIMIZE_PPPREND 


CFLAGS = -O $(ARCHFLAGS) $(DFLAGS) $(IFLAGS) 

OBJS = bsd-comp.o if_ppp.o ppp_tty.o vjcompress.o random.o
SRCS = $(OBJS:.o=.c)


#
# Default target
#
all:	ppp_reloc
	cd bpf; $(MAKE) ARCHFLAGS="$(ARCHFLAGS)" all


install: all
	/bin/mkdirs $(ETCDIR) $(LKS_DIR)
	install -c -m 644 -o root -g daemon ppp_reloc $(LKS_DIR)
	touch $(ETCDIR)/options
	cd bpf; $(MAKE) ARCHFLAGS="$(ARCHFLAGS)" install

ppp_reloc:	$(OBJS) Load_Commands.sect Unload_Commands.sect
	kl_ld $(ARCHFLAGS) -n ppp -l Load_Commands.sect -u Unload_Commands.sect \
	       -i instance -o $@ $(OBJS)

clean:
	rm -f ppp_reloc ppp_loadable core make $(OBJS) *~ #* .depend
	cd bpf; $(MAKE) clean

depend:
	cc -M $(CFLAGS) $(SRCS)  >.depend

$(SRCS): if_pppvar.h nbq.h inlines.h

#.depend:	$(SRCS) $(PPPSTATSRCS)
#	cc -M $(CFLAGS) $(SRCS) >.depend
#	@echo Check dependencies if needed

FORCE:

#include	.depend
