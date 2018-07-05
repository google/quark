CC = gcc
CFLAGS   = -g -Wall -Wextra -I. -I../common
all: libxmssmtVerify.a

verify.o: verify.c
	$(CC) $(CFLAGS) -c verify.c

libxmssmtVerify.a: verify.o
	ar qc libxmssmtVerify.a verify.o
	ranlib libxmssmtVerify.a

clean:
	-rm -f  *.o *.a
