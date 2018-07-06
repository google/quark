CC = gcc
SRC_COMMON = ../../src/common
SRC_HSS    = ../../src/hss
SRC_TST    = ../common

COMMON_OBJS = verify.o sha256.o endian_utils.o hash_wrappers.o
TEST_VECTORS = \
    hss_vectors_001.h \
	hss_ref_20_2.h \
	hss_ref_20_4.h \
	hss_ref_40_2.h \
	hss_ref_40_4.h \
	hss_ref_40_8.h \
	hss_ref_60_3.h \
	hss_ref_60_6.h

CFLAGS   = -g -Wall -Wextra -I. -I$(SRC_COMMON) -I$(SRC_HSS) -I$(SRC_TST)
LDFLAGS  = -L.

EXEC     = demo
TEST     = test
KAT      = kat

all: $(EXEC) $(TEST) $(KAT)

demo.o: demo.c
	$(CC) $(CFLAGS) -c demo.c

demo: demo.o $(COMMON_OBJS)
	$(CC) $(LDFLAGS) -o $(EXEC) demo.o $(COMMON_OBJS)

test.o: test.c $(TEST_VECTORS)
	$(CC) $(CFLAGS) -c test.c

test: test.o $(COMMON_OBJS)
	$(CC) $(LDFLAGS) -o $(TEST) test.o $(COMMON_OBJS)

kat.o: kat.c  $(TEST_VECTORS)
	$(CC) $(CFLAGS) -c kat.c

kat: kat.o $(COMMON_OBJS)
	$(CC) $(LDFLAGS) -o $(KAT) kat.o $(COMMON_OBJS)

verify.o: $(SRC_HSS)/verify.c $(SRC_HSS)/verify.h
	$(CC) $(CFLAGS) -c $(SRC_HSS)/verify.c

endian_utils.o: $(SRC_COMMON)/endian_utils.c $(SRC_COMMON)/endian_utils.h
	$(CC) $(CFLAGS) -c $(SRC_COMMON)/endian_utils.c

hash_wrappers.o: $(SRC_COMMON)/hash_wrappers.c $(SRC_COMMON)/hash_wrappers.h
	$(CC) $(CFLAGS) -c $(SRC_COMMON)/hash_wrappers.c

sha256.o: $(SRC_COMMON)/sha256.c $(SRC_COMMON)/sha256.h
	$(CC) $(CFLAGS) -c $(SRC_COMMON)/sha256.c

clean:
	-rm -f $(EXEC) $(TEST) $(KAT) *.o
