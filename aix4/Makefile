#
# Makefile for AIX 4.1
#
#
# $Id: Makefile,v 1.1 1994/12/05 00:29:21 paulus Exp $
#
#ifndef DRIVERS
DRIVERS=/usr/lib/drivers
#endif

CC=xlc
IFLAGS = -I..
DFLAGS = -D_KERNEL -DINET -DPPP_VD -DNUM_PPP=5 -DDEBUGS -DPPP_STATS -DVJC
CFLAGS = $(DFLAGS) $(IFLAGS)

KIMP = -bI:/lib/pse.exp -bI:/lib/kernex.exp -bI:/lib/syscalls.exp
NETIMP = -bI:/lib/netinet.exp
KLIBS = /lib/libsys.a /lib/libcsys.a


OBJ = vjcompress.o ppp_if.o ppp_async.o bsd-comp.o ppp_comp.o

all: ppp_if ppp_async ppp_comp

ppp_if: ppp_if.o vjcompress.o
	ld -o ppp_if ppp_if.o -e ppp_load -bE:ppp_if.exp vjcompress.o ${KIMP} ${NETIMP} ${KLIBS}

ppp_async: ppp_async.o
	ld -o ppp_async ppp_async.o -e ppp_async_load -bE:ppp_async.exp ${KIMP} ${NETIMP} ${KLIBS}

ppp_comp: ppp_comp.o bsd-comp.o
	ld -o ppp_comp ppp_comp.o -e pppcomp_load bsd-comp.o ${KIMP} ${NETIMP} ${KLIBS}

vjcompress.o: vjcompress.c
bsd-comp.o: bsd-comp.c
ppp_if.o: ppp_if.c
ppp_async.o: ppp_async.c
ppp_comp.o: ppp_comp.c

install: all
	install -f ${DRIVERS} -M 500 ppp_if
	install -f ${DRIVERS} -M 500 ppp_async
	install -f ${DRIVERS} -M 500 ppp_comp
	grep "strload -m ${DRIVERS}/ppp_if" /etc/rc.tcpip || { \
	    echo strload -m ${DRIVERS}/ppp_if; \
	    echo strload -m ${DRIVERS}/ppp_async; \
	    echo strload -m ${DRIVERS}/ppp_comp; \
	} >>/etc/rc.tcpip

clean:
	rm -f $(OBJ) ppp_if ppp_async ppp_comp
