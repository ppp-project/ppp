CC	= gcc
CFLAGS	= -g -O2 -I.. -I../../include
LDFLAGS	= -shared

all:	minconn.so

minconn.so: minconn.c
	$(CC) -o $@ $(LDFLAGS) $(CFLAGS) minconn.c
