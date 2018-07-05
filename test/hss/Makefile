CC = gcc
CFLAGS   = -g -Wall -Wextra -I. -I../../src/common -I../../src/hss
LDFLAGS  = -L. -L../../src/common -L../../src/hss
LIBS  = -lhssVerify -lquarkCommon
EXEC     = demo
TEST     = test
KAT      = kat

all: $(EXEC) $(TEST) $(KAT)

demo.o: demo.c
	$(CC) $(CFLAGS) -c demo.c

demo: demo.o
	$(CC) $(LDFLAGS) -o $(EXEC) demo.o $(LIBS)

test.o: test.c
	$(CC) $(CFLAGS) -c test.c

test: test.o
	$(CC) $(LDFLAGS) -o $(TEST) test.o $(LIBS)

kat.o: kat.c
	$(CC) $(CFLAGS) -c kat.c

kat: kat.o
	$(CC) $(LDFLAGS) -o $(KAT) kat.o $(LIBS)

clean:
	-rm -f $(EXEC) $(TEST) $(KAT) *.o *.a
