#
# Makefile for STREAMS modules for Solaris 2.
#
# $Id: Makefile,v 1.2 1995/05/19 03:27:52 paulus Exp $
#

CFLAGS= -D_KERNEL -I..
CC=	gcc

all:	ppp ppp_ahdl ppp_comp

ppp:	ppp.o
	ld -r -o ppp ppp.o

ppp_ahdl: ppp_ahdlc.o
	ld -r -o ppp_ahdl ppp_ahdlc.o

ppp_comp: ppp_comp.o bsd-comp.o vjcompress.o
	ld -r -o ppp_comp ppp_comp.o bsd-comp.o vjcompress.o

install: all
	cp ppp ppp.conf /kernel/drv
	cp ppp_comp ppp_ahdl /kernel/strmod
	/usr/sbin/add_drv ppp

clean:
	rm -f ppp ppp_comp ppp_ahdl *.o *~ core
