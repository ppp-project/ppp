# Makefile for RADIUS plugin
#
# Copyright 2002 Roaring Penguin Software Inc.
#

MANDIR=/usr/man
PLUGIN=radius.so radattr.so radrealms.so
CFLAGS=-I../.. -I../../../include -Iradiusclient/include -O2

# Uncomment the next line to include support for Microsoft's
# MS-CHAP authentication protocol.
CHAPMS=y
# Uncomment the next line to include support for MPPE.
MPPE=y
# Uncomment the next lint to include support for traffic limiting
MAXOCTETS=y

ifdef CHAPMS
CFLAGS += -DCHAPMS=1
ifdef MPPE
CFLAGS += -DMPPE=1
endif
endif
ifdef MAXOCTETS
CFLAGS += -DMAXOCTETS=1
endif

all: $(PLUGIN)

install: all
	$(MAKE) $(MFLAGS) -C radiusclient install
	$(INSTALL) -d -m 755 $(LIBDIR)
	$(INSTALL) -s -c -m 755 radius.so $(LIBDIR)
	$(INSTALL) -s -c -m 755 radattr.so $(LIBDIR)
	$(INSTALL) -s -c -m 755 radrealms.so $(LIBDIR)
	$(INSTALL) -c -m 444 pppd-radius.8 $(MANDIR)/man8
	$(INSTALL) -c -m 444 pppd-radattr.8 $(MANDIR)/man8

radius.so: radiusclient/lib/.libs/libradiusclient.a radius.o
	gcc -o radius.so -shared radius.o radiusclient/lib/.libs/libradiusclient.a

radattr.so: radattr.o
	gcc -o radattr.so -shared radattr.o

radrealms.so: radrealms.o
	gcc -o radrealms.so -shared radrealms.o

radius.o: radius.c
	gcc $(CFLAGS) -c -o radius.o -fPIC radius.c

radattr.o: radattr.c
	gcc $(CFLAGS) -c -o radattr.o -fPIC radattr.c

radrealms.o: radrealms.c
	gcc $(CFLAGS) -c -o radrealms.o -fPIC radrealms.c

radiusclient/lib/.libs/libradiusclient.a:
	test -r radiusclient/Makefile ||           \
		(cd radiusclient;                  \
		 ./configure --prefix=/usr         \
			     --sysconfdir=/etc     \
			     --enable-shared       \
			     --enable-static)
	$(MAKE) -C radiusclient

clean:
	$(MAKE) $(MFLAGS) -C radiusclient clean
	rm -f *.o *.so

distclean:
	rm -f *.o *.so
	$(MAKE) $(MFLAGS) -C radiusclient distclean

dist-clean: distclean
