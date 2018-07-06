CC = gcc
SRC_COMMON = ../../src/common
SRC_XMSS    = ../../src/xmssmt
SRC_TST    = ../common

COMMON_OBJS = verify.o sha256.o endian_utils.o hash_wrappers.o

CFLAGS   = -g -Wall -Wextra -I. -I$(SRC_COMMON) -I$(SRC_XMSS) -I$(SRC_TST)
LDFLAGS  = -L.

TEST     = test
KAT      = kat

all: $(TEST) $(KAT)

test.o: test.c
	$(CC) $(CFLAGS) -c test.c

test: test.o $(COMMON_OBJS)
	$(CC) $(LDFLAGS) -o $(TEST) test.o $(COMMON_OBJS)

kat.o: kat.c
	$(CC) $(CFLAGS) -c kat.c

kat: kat.o quark_misc.o $(COMMON_OBJS)
	$(CC) $(LDFLAGS) -o $(KAT) kat.o quark_misc.o $(COMMON_OBJS)

quark_misc.o: quark_misc.c
	$(CC) $(CFLAGS) -c quark_misc.c

verify.o: $(SRC_XMSS)/verify.c
	$(CC) $(CFLAGS) -c $(SRC_XMSS)/verify.c

endian_utils.o: $(SRC_COMMON)/endian_utils.c
	$(CC) $(CFLAGS) -c $(SRC_COMMON)/endian_utils.c

hash_wrappers.o: $(SRC_COMMON)/hash_wrappers.c
	$(CC) $(CFLAGS) -c $(SRC_COMMON)/hash_wrappers.c

sha256.o: $(SRC_COMMON)/sha256.c
	$(CC) $(CFLAGS) -c $(SRC_COMMON)/sha256.c

clean:
	-rm -f $(EXEC) $(TEST) $(KAT) *.o
