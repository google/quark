CC = gcc
CFLAGS   = -g -Wall -Wextra -I.
LDFLAGS  = -L.
EXEC     = demo
TEST     = test
KAT      = kat

all: $(EXEC) $(TEST) $(KAT)

quark_verify.o: quark_verify.c quark_verify.h ../common/quark_hash.h ../common/quark_endian.h
	$(CC) $(CFLAGS) -c quark_verify.c

quark_endian.o: ../common/quark_endian.c ../common/quark_endian.h
	$(CC) $(CFLAGS) -c ../common/quark_endian.c

quark_hash.o: ../common/quark_hash.c ../common/quark_endian.h
	$(CC) $(CFLAGS) -c ../common/quark_hash.c

quark_sha256.o: ../common/quark_sha256.c ../common/quark_sha256.h ../common/quark_endian.h
	$(CC) $(CFLAGS) -c ../common/quark_sha256.c

test.o: test.c quark_verify.h ../common/quark_endian.h ../common/quark_hash.h ../common/quark_sha256.h
	$(CC) $(CFLAGS) -c test.c

test: test.o quark_verify.o quark_endian.o quark_hash.o quark_sha256.o
	$(CC) $(CFLAGS) -o $(TEST) test.o quark_verify.o quark_endian.o quark_hash.o quark_sha256.o

demo.o: demo.c quark_verify.h ../common/quark_endian.h ../common/quark_hash.h ../common/quark_sha256.h
	$(CC) $(CFLAGS) -c demo.c

demo: demo.o quark_verify.o quark_endian.o quark_hash.o quark_sha256.o
	$(CC) $(CFLAGS) -o $(EXEC) demo.o quark_verify.o quark_endian.o quark_hash.o quark_sha256.o

kat.o: kat.c quark_verify.h ../common/quark_endian.h ../common/quark_hash.h ../common/quark_sha256.h
	$(CC) $(CFLAGS) -c kat.c

kat: kat.o quark_verify.o quark_endian.o quark_hash.o quark_sha256.o
	$(CC) $(CFLAGS) -o $(KAT) kat.o quark_verify.o quark_endian.o quark_hash.o quark_sha256.o

clean:
	-rm -f $(EXEC) $(TEST) $(KAT) *.o
