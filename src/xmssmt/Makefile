CC = gcc
SRC_COMMON = ../common

all: libxmssmtVerify.a

libxmssmtVerify.a: verify.o endian_utils.o hash_wrappers.o sha256.o
	ar qc libxmssmtVerify.a verify.o endian_utils.o hash_wrappers.o sha256.o
	ranlib libxmssmtVerify.a

CFLAGS   = -g -Wall -Wextra -I$(COMMON_DIR) -I.

verify.o: verify.c
	$(CC) $(CFLAGS) -c verify.c

endian_utils.o: $(SRC_COMMON)/endian_utils.c $(SRC_COMMON)/endian_utils.h
	$(CC) $(CFLAGS) -c $(SRC_COMMON)/endian_utils.c

hash_wrappers.o: $(SRC_COMMON)/hash_wrappers.c $(SRC_COMMON)/hash_wrappers.h
	$(CC) $(CFLAGS) -c $(SRC_COMMON)/hash_wrappers.c

sha256.o: $(SRC_COMMON)/sha256.c $(SRC_COMMON)/sha256.h
	$(CC) $(CFLAGS) -c $(SRC_COMMON)/sha256.c

clean:
	-rm -f  *.o *.a
