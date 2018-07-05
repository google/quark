CC = gcc
COMMON_SRC  = ../../src/common
XMSSMT_SRC  = ../../src/xmssmt
CFLAGS   = -g -Wall -Wextra -I. -I$(COMMON_SRC) -I$(XMSSMT_SRC)
LDFLAGS  = -L. -L$(COMMON_SRC) -L$(XMSSMT_SRC)
LIBS  = -lxmssmtVerify -lquarkCommon
TEST     = test
KAT      = kat

all: $(TEST) $(KAT)

test.o: test.c
	$(CC) $(CFLAGS) -c test.c

test: test.o
	$(CC) $(LDFLAGS) -o $(TEST) test.o $(LIBS)

kat.o: kat.c
	$(CC) $(CFLAGS) -c kat.c

kat: kat.o
	$(CC) $(LDFLAGS) -o $(KAT) kat.o $(LIBS)

clean:
	-rm -f $(EXEC) $(KAT) *.o *.a