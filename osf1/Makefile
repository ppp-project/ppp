#
# Dummy Makefile for OSF/1
#
# $Id: Makefile,v 1.3 1996/06/26 00:55:19 paulus Exp $
#

install: 
	@echo
	@echo '        Follow the instructions in README.osf to make the kernel'
	@echo '        drivers for OSF/1.'
	@echo
	./makevers
	cp ../modules/bsd-comp.c ../modules/deflate.c ../modules/ppp.c \
	../modules/ppp_ahdlc.c ../modules/ppp_comp.c ../modules/ppp_mod.h \
	../modules/vjcompress.c ./ppp_osf.h /sys/streamsm
	cp ../sunos4/if_ppp.c /sys/streamsm
	cp ppp_init.c /sys/streamsm
	cp ../common/zlib.c ../common/zlib.h /sys/streamsm
	cp ../net/if_ppp.h ../net/ppp-comp.h ../net/ppp_defs.h \
	../net/pppio.h ../net/vjcompress.h /sys/include/net
