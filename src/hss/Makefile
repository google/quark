CC = gcc
CFLAGS   = -g -Wall -Wextra -I. -I../common
all: libhssVerify.a

verify.o: verify.c
	$(CC) $(CFLAGS) -c verify.c

libhssVerify.a: verify.o
	ar qc libhssVerify.a verify.o
	ranlib libhssVerify.a

clean:
	-rm -f  *.o *.a
