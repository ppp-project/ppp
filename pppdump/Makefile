CFLAGS= -O -I../include/net
OBJS = pppdump.o bsd-comp.o deflate.o zlib.o

all:	pppdump

pppdump: $(OBJS)
	$(CC) -o pppdump $(OBJS)

clean:
	rm -f pppdump $(OBJS) *~

install:
