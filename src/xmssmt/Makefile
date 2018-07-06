CC = gcc
COMMON_DIR = ../common

all: libxmssmtVerify.a

libxmssmtVerify.a: verify.o endian_utils.o hash_wrappers.o sha256.o
	ar qc libxmssmtVerify.a verify.o endian_utils.o hash_wrappers.o sha256.o
	ranlib libxmssmtVerify.a

CFLAGS   = -g -Wall -Wextra -I$(COMMON_DIR) -I.

verify.o: verify.c
	$(CC) $(CFLAGS) -c verify.c

endian_utils.o: $(COMMON_DIR)/endian_utils.c
	$(CC) $(CFLAGS) -c $(COMMON_DIR)/endian_utils.c

hash_wrappers.o: $(COMMON_DIR)/hash_wrappers.c
	$(CC) $(CFLAGS) -c $(COMMON_DIR)/hash_wrappers.c

sha256.o: $(COMMON_DIR)/sha256.c
	$(CC) $(CFLAGS) -c $(COMMON_DIR)/sha256.c

clean:
	-rm -f  *.o *.a
