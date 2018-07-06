CC = gcc
SRC_COMMON = ../common

all: libhssVerify.a

libhssVerify.a: verify.o endian_utils.o hash_wrappers.o sha256.o
	ar qc libhssVerify.a verify.o endian_utils.o hash_wrappers.o sha256.o
	ranlib libhssVerify.a

CFLAGS   = -g -Wall -Wextra -I$(SRC_COMMON) -I.

verify.o: verify.c
	$(CC) $(CFLAGS) -c verify.c

endian_utils.o: $(SRC_COMMON)/endian_utils.c
	$(CC) $(CFLAGS) -c $(SRC_COMMON)/endian_utils.c

hash_wrappers.o: $(SRC_COMMON)/hash_wrappers.c
	$(CC) $(CFLAGS) -c $(SRC_COMMON)/hash_wrappers.c

sha256.o: $(SRC_COMMON)/sha256.c
	$(CC) $(CFLAGS) -c $(SRC_COMMON)/sha256.c
	
clean:
	-rm -f  *.o *.a
