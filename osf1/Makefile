#
# Dummy Makefile for OSF/1
#
# $Id: Makefile,v 1.2 1995/06/01 06:18:23 paulus Exp $
#

install: 
	@echo
	@echo '        Follow the instructions in README.osf to make the kernel'
	@echo '        drivers for OSF/1.'
	@echo
	cp ../modules/bsd-comp.c ../modules/vjcompress.c /sys/streamsm
	cp ../sunos/ppp_async.c ../sunos/ppp_comp.c /sys/streamsm
	cp ../sunos/ppp_if.c ppp_init.c /sys/streamsm
	cp ../net/if_ppp.h ../net/ppp-comp.h ../net/ppp_defs.h /sys/include/net
	cp ../net/ppp_str.h ../net/slcompress.h /sys/include/net
	cp ../net/vjcompress.h /sys/include/net
