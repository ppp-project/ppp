#
# Dummy Makefile for OSF/1
#
# $Id: Makefile,v 1.1 1995/05/01 02:17:20 paulus Exp $
#

install: 
	@echo
	@echo '        Follow the instructions in README.osf to make the kernel'
	@echo '        drivers for OSF/1.'
	@echo
	cp bsd-comp.c ppp_async.c ppp_comp.c /sys/streamsm
	cp ppp_if.c ppp_init.c vjcompress.c /sys/streamsm
	cp ../net/if_ppp.h ../net/ppp-comp.h ../net/ppp_defs.h /sys/include/net
	cp ../net/ppp_str.h ../net/slcompress.h /sys/include/net
	cp ../net/vjcompress.h /sys/include/net
