CC = gcc
CFLAGS   = -g -Wall -Wextra -I.
LDFLAGS  = -L.
EXEC     = verify
KAT      = kat

all: $(KAT) $(EXEC)

quark_misc.o: quark_misc.c quark_verify.h ../common/quark_hash.h ../common/quark_endian.h
	$(CC) $(CFLAGS) -c quark_misc.c

quark_verify.o: quark_verify.c quark_verify.h ../common/quark_hash.h ../common/quark_endian.h
	$(CC) $(CFLAGS) -c quark_verify.c

quark_endian.o: ../common/quark_endian.c ../common/quark_endian.h
	$(CC) $(CFLAGS) -c ../common/quark_endian.c

quark_hash.o: ../common/quark_hash.c ../common/quark_endian.h
	$(CC) $(CFLAGS) -c ../common/quark_hash.c

quark_sha256.o: ../common/quark_sha256.c ../common/quark_sha256.h ../common/quark_endian.h
	$(CC) $(CFLAGS) -c ../common/quark_sha256.c

verify.o: verify.c quark_verify.h ../common/quark_endian.h ../common/quark_hash.h ../common/quark_sha256.h quark_misc.h
	$(CC) $(CFLAGS) -c verify.c

verify: verify.o quark_verify.o quark_endian.o quark_hash.o quark_sha256.o quark_misc.o
	$(CC) $(CFLAGS) -o $(EXEC) verify.o quark_verify.o quark_endian.o quark_hash.o quark_sha256.o quark_misc.o

kat.o: kat.c quark_verify.h ../common/quark_endian.h ../common/quark_hash.h ../common/quark_sha256.h quark_misc.h
	$(CC) $(CFLAGS) -c kat.c

kat: kat.o quark_verify.o quark_endian.o quark_misc.o quark_sha256.o
	$(CC) $(CFLAGS) -o $(KAT) kat.o quark_verify.o quark_endian.o quark_misc.o quark_sha256.o
clean:
	-rm -f $(EXEC) $(KAT) *.o
