CC = gcc
SRC_COMMON = ../../src/common
SRC_XMSS    = ../../src/xmssmt
SRC_TST    = ../common

TEST_VECTORS = \
	xmss_ref_10.h \
	xmss_ref_16.h \
	xmss_ref_20.h \
	xmss_ref_001.h \
	xmssmt_ref_20_2.h \
	xmssmt_ref_20_4.h \
	xmssmt_ref_40_2.h \
	xmssmt_ref_40_4.h \
	xmssmt_ref_40_8.h \
	xmssmt_ref_60_3.h \
	xmssmt_ref_60_6.h \
	xmssmt_ref_60_12.h \
	xmssmt_ref_001.h

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

kat.o: kat.c $(TEST_VECTORS)
	$(CC) $(CFLAGS) -c kat.c

kat: kat.o quark_misc.o $(COMMON_OBJS)
	$(CC) $(LDFLAGS) -o $(KAT) kat.o quark_misc.o $(COMMON_OBJS)

quark_misc.o: quark_misc.c quark_misc.h
	$(CC) $(CFLAGS) -c quark_misc.c

verify.o: $(SRC_XMSS)/verify.c $(SRC_XMSS)/verify.h
	$(CC) $(CFLAGS) -c $(SRC_XMSS)/verify.c

endian_utils.o: $(SRC_COMMON)/endian_utils.c $(SRC_COMMON)/endian_utils.h
	$(CC) $(CFLAGS) -c $(SRC_COMMON)/endian_utils.c

hash_wrappers.o: $(SRC_COMMON)/hash_wrappers.c $(SRC_COMMON)/hash_wrappers.h
	$(CC) $(CFLAGS) -c $(SRC_COMMON)/hash_wrappers.c

sha256.o: $(SRC_COMMON)/sha256.c $(SRC_COMMON)/sha256.h
	$(CC) $(CFLAGS) -c $(SRC_COMMON)/sha256.c

clean:
	-rm -f $(EXEC) $(TEST) $(KAT) *.o
