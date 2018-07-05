CC = gcc
CFLAGS   = -g -Wall -Wextra -I.
all: libquarkCommon.a

endian_utils.o: endian_utils.c
	$(CC) $(CFLAGS) -c endian_utils.c

hash_wrappers.o: hash_wrappers.c
	$(CC) $(CFLAGS) -c hash_wrappers.c

sha256.o: sha256.c
	$(CC) $(CFLAGS) -c sha256.c

libquarkCommon.a: endian_utils.o hash_wrappers.o sha256.o
	ar qc libquarkCommon.a endian_utils.o hash_wrappers.o sha256.o
	ranlib libquarkCommon.a

clean:
	-rm -f  *.o *.a
