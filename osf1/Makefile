#
# Dummy Makefile for OSF/1
#
# $Id: Makefile,v 1.6 1999/04/27 22:24:23 varadhan Exp $
#

KOBJ = if_ppp.o ppp_comp.o ppp_init.o vjcompress.o bsd-comp.o deflate.o\
       ppp.o ppp_ahdlc.o zlib.o

install: 
	@echo
	@echo ' Proceeding to build the kernel. You must have followed the 
	@echo ' instructions in README.osf prior to this step'
	@echo
	./makevers
	cp ../modules/bsd-comp.c ../modules/deflate.c ../modules/ppp.c \
	../modules/ppp_ahdlc.c ../modules/ppp_comp.c ../modules/ppp_mod.h \
	../modules/vjcompress.c  $(STREAMSDIR)
	cp ../modules/if_ppp.c $(STREAMSDIR)
	cp ppp_init.c $(STREAMSDIR)
	cp ../common/zlib.c ../common/zlib.h $(STREAMSDIR)
	cp ../include/net/ppp-comp.h ../include/net/ppp_defs.h \
	../include/net/pppio.h ../include/net/vjcompress.h $(INCLNETDIR)
#
# The following assumes that OS version is at least 4.0
#
	@( cd /usr/sys/conf; \
	   ../bin/sourceconfig BINARY; \
	   cd /usr/sys/BINARY ; \
	   make $(KOBJ); \
	   make MODULE_ppp; \
	   cp /usr/sys/BINARY/ppp.mod /sys/BINARY/ppp.mod; \
	   echo ;\
	   echo 'Please modify lockinfo.c and run doconfig to build kernel now.' )
