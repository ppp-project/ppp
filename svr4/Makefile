CFLAGS= -D_KERNEL -I../current
CC=	gcc

all:	ppp x ppp_ahdlc

ppp:	ppp.o
	ld -r -o ppp ppp.o

ppp_ahdlc: ppp_ahdlc.o
	ld -r -o ppp_ahdlc ppp_ahdlc.o

x:	x.c
	$(CC) -I../current -g -o x x.c
