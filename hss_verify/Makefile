CC = gcc
CFLAGS   = -g -Wall -Wextra -I.
LDFLAGS  = -L.
EXEC     = demo
TEST     = test
KAT      = kat

all: $(EXEC) $(TEST) $(KAT)

c4a_verify.o: c4a_verify.c c4a_verify.h c4a_hash.h c4a_endian.h
	$(CC) $(CFLAGS) -c c4a_verify.c

c4a_endian.o: c4a_endian.c c4a_endian.h
	$(CC) $(CFLAGS) -c c4a_endian.c

c4a_hash.o: c4a_hash.c c4a_endian.h
	$(CC) $(CFLAGS) -c c4a_hash.c

c4a_sha256.o: c4a_sha256.c c4a_sha256.h c4a_endian.h
	$(CC) $(CFLAGS) -c c4a_sha256.c

test.o: test.c c4a_verify.h c4a_endian.h c4a_hash.h c4a_sha256.h
	$(CC) $(CFLAGS) -c test.c

test: test.o c4a_verify.o c4a_endian.o c4a_hash.o c4a_sha256.o
	$(CC) $(CFLAGS) -o $(TEST) test.o c4a_verify.o c4a_endian.o c4a_hash.o c4a_sha256.o

demo.o: demo.c c4a_verify.h c4a_endian.h c4a_hash.h c4a_sha256.h
	$(CC) $(CFLAGS) -c demo.c

demo: demo.o c4a_verify.o c4a_endian.o c4a_hash.o c4a_sha256.o
	$(CC) $(CFLAGS) -o $(EXEC) demo.o c4a_verify.o c4a_endian.o c4a_hash.o c4a_sha256.o

kat.o: kat.c c4a_verify.h c4a_endian.h c4a_hash.h c4a_sha256.h
	$(CC) $(CFLAGS) -c kat.c

kat: kat.o c4a_verify.o c4a_endian.o c4a_hash.o c4a_sha256.o
	$(CC) $(CFLAGS) -o $(KAT) kat.o c4a_verify.o c4a_endian.o c4a_hash.o c4a_sha256.o

clean:
	-rm -f $(EXEC) $(TEST) $(KAT) *.o
