CC = gcc
CFLAGS   = -g -Wall -Wextra -I.
LDFLAGS  = -L.
EXEC     = verify
KAT      = kat

all: $(KAT) $(EXEC)

c4a_misc.o: c4a_misc.c c4a_verify.h c4a_hash.h c4a_endian.h
	$(CC) $(CFLAGS) -c c4a_misc.c

c4a_verify.o: c4a_verify.c c4a_verify.h c4a_hash.h c4a_endian.h
	$(CC) $(CFLAGS) -c c4a_verify.c

c4a_endian.o: c4a_endian.c c4a_endian.h
	$(CC) $(CFLAGS) -c c4a_endian.c

c4a_hash.o: c4a_hash.c c4a_endian.h
	$(CC) $(CFLAGS) -c c4a_hash.c

c4a_sha256.o: c4a_sha256.c c4a_sha256.h c4a_endian.h
	$(CC) $(CFLAGS) -c c4a_sha256.c

verify.o: verify.c c4a_verify.h c4a_endian.h c4a_hash.h c4a_sha256.h c4a_misc.h
	$(CC) $(CFLAGS) -c verify.c

verify: verify.o c4a_verify.o c4a_endian.o c4a_hash.o c4a_sha256.o c4a_misc.o
	$(CC) $(CFLAGS) -o $(EXEC) verify.o c4a_verify.o c4a_endian.o c4a_hash.o c4a_sha256.o c4a_misc.o

kat.o: kat.c c4a_verify.h c4a_endian.h c4a_hash.h c4a_sha256.h c4a_misc.h
	$(CC) $(CFLAGS) -c kat.c

kat: kat.o c4a_verify.o c4a_endian.o c4a_misc.o c4a_sha256.o
	$(CC) $(CFLAGS) -o $(KAT) kat.o c4a_verify.o c4a_endian.o c4a_misc.o c4a_sha256.o
clean:
	-rm -f $(EXEC) $(KAT) *.o
