#
# Makefile for NeXT OS 3.2
#
# $Id: Makefile,v 1.3 1998/03/26 02:51:37 paulus Exp $
#

#ARCHFLAGS = -arch i386 -arch m68k
ARCHFLAGS =

BINDIR = /usr/local/ppp/bin
MANDIR = /usr/local/ppp/man
ETCDIR = /usr/local/ppp/etc

#
# If you change this pathname, you must also change the path
# in and rc.local (or rc.ppp).
#
LKS_DIR=/usr/local/ppp/reloc

#
# NUM_PPP=x      The number of ppp interfaces you want to create
#
# VJC            If defined, enables VJ header compression
#
# PPP_COMPRESS   If defined, enables BSD packet compression
#
# HAS_BROKEN_TIOCSPGRP Fixes broken IOCTL with NeXT serial drivers
#
# OLD_MUX        Fixes double buffer problem with the MuX serial
#                driver.
#
# OPTIMIZE_PPPREND Enable an optimization supported by the NeXT serial
#                  drivers.  Basically they buffer characters for an
#                  interrupt and call ppprend.
#
# NEW_CLOCAL     Used to enable the new code that sets CLOCAL.  Else,
#                the old code is used.
#

DFLAGS = -D_POSIX_SOURCE -DINET -DKERNEL -DMACH -DPOSIX_KERN \
	-DNUM_PPP=2 -DVJC -DPPP_COMPRESS \
	-DDEBUG -DNEW_CLOCAL -DOPTIMIZE_PPPREND

IFLAGS = -I. -I../include -I../pppd

CFLAGS = -O -g -pipe $(ARCHFLAGS) $(DFLAGS) $(IFLAGS) 

OBJS = bsd-comp.o if_ppp.o ppp_tty.o vjcompress.o
SRCS = $(OBJS:.o=.c)


#
# Default target
#
all:	ppp_reloc


install: all
	/bin/mkdirs $(ETCDIR) $(LKS_DIR)
	if (test ! -r /etc/ppp)	then (ln -s $(ETCDIR) /etc/ppp)	fi
	install -c -m 644 -o root -g daemon ppp_reloc $(LKS_DIR)
	touch $(ETCDIR)/options

ppp_reloc:	$(OBJS) Load_Commands.sect Unload_Commands.sect
	kl_ld $(ARCHFLAGS) -n ppp -l Load_Commands.sect -u Unload_Commands.sect \
	       -d ppp_loadable -i instance -o $@ $(OBJS)

clean:
	rm -f ppp_reloc ppp_loadable core make $(OBJS) *~ 


$(SRCS): if_pppvar.h nbq.h inlines.h Makefile
