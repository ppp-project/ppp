#
# Makefile for STREAMS modules for SunOS 4.
#
# $Id: Makefile,v 1.3 1996/05/28 00:50:24 paulus Exp $
#

ARCH:sh = /bin/arch -k
#CC = gcc

BINDIR = /usr/local/etc
INSTALL = install -o root -g daemon

# Defining __$(ARCH)__ is for gcc's broken version of sun/vddrv.h.
DEFINES= -DKERNEL -D_KERNEL -DSUNOS4 -D$(ARCH) -D__$(ARCH)__ -DDEBUG -DNO_DLPI
CFLAGS= $(DEFINES) -I.. -O

MODULES= ppp_mod.o ppp_ahdl_mod.o ppp_comp_mod.o if_ppp_mod.o

all:	$(MODULES)

ppp_mod.o:	ppp.o bpf_filter.o ppp_vdcmd.o
	ld -r -o ppp_mod.o ppp.o bpf_filter.o ppp_vdcmd.o

ppp_ahdl_mod.o: ppp_ahdlc.o ppp_ahdlc_vdcmd.o
	ld -r -o ppp_ahdl_mod.o ppp_ahdlc.o ppp_ahdlc_vdcmd.o

COMP_OBJS = ppp_comp.o bsd-comp.o deflate.o zlib.o vjcompress.o \
	ppp_comp_vdcmd.o
ppp_comp_mod.o: $(COMP_OBJS)
	ld -r -o $@ $(COMP_OBJS)

bpf_filter.o: ../modules/bpf_filter.c
	$(CC) $(CFLAGS) -c $?
bsd-comp.o: ../modules/bsd-comp.c
	$(CC) $(CFLAGS) -c $?
deflate.o: ../modules/deflate.c
	$(CC) $(CFLAGS) -c $?
ppp.o:	../modules/ppp.c
	$(CC) $(CFLAGS) -c $?
ppp_ahdlc.o: ../modules/ppp_ahdlc.c
	$(CC) $(CFLAGS) -c $?
ppp_comp.o: ../modules/ppp_comp.c
	$(CC) $(CFLAGS) -c $?
vjcompress.o: ../modules/vjcompress.c
	$(CC) $(CFLAGS) -c $?
zlib.o:	../common/zlib.c
	$(CC) $(CFLAGS) -c $?

if_ppp_mod.o:	if_ppp.o if_ppp_vdcmd.o
	ld -r -o if_ppp_mod.o if_ppp.o if_ppp_vdcmd.o

install: all
	$(INSTALL) $(MODULES) $(BINDIR)
	./ppp.INSTALL

clean:
	rm -f ppp ppp_comp ppp_ahdl *.o *~ core
