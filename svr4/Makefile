#
# Makefile for STREAMS modules for Solaris 2.
#
# $Id: Makefile,v 1.5 1995/06/01 06:18:48 paulus Exp $
#

CFLAGS= -D_KERNEL -I.. -O
CC=	gcc

all:	ppp ppp_ahdl ppp_comp

ppp:	ppp.o
	ld -r -o ppp ppp.o

ppp_ahdl: ppp_ahdlc.o
	ld -r -o ppp_ahdl ppp_ahdlc.o

ppp_comp: ppp_comp.o bsd-comp.o vjcompress.o
	ld -r -o ppp_comp ppp_comp.o bsd-comp.o vjcompress.o

bsd-comp.o: ../modules/bsd-comp.c
	$(CC) $(CFLAGS) -c $?
vjcompress.o: ../modules/vjcompress.c
	$(CC) $(CFLAGS) -c $?

install: all
	cp ppp ppp.conf /kernel/drv
	cp ppp_comp ppp_ahdl /kernel/strmod
	if grep clone:ppp /etc/minor_perm; then :; else \
	  echo clone:ppp 0644 root sys >>/etc/minor_perm; fi
	/usr/sbin/add_drv ppp

clean:
	rm -f ppp ppp_comp ppp_ahdl *.o *~ core
