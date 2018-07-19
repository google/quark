# Copyright 2018 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License

CC = gcc
SRC_COMMON = ../common

all: libxmssmtVerify.a

libxmssmtVerify.a: verify.o endian_utils.o hash_wrappers.o sha256.o
	ar qc libxmssmtVerify.a verify.o endian_utils.o hash_wrappers.o sha256.o
	ranlib libxmssmtVerify.a

CFLAGS   = -g -Wall -Wextra -Werror -I$(SRC_COMMON) -I.

verify.o: verify.c
	$(CC) $(CFLAGS) -c verify.c

endian_utils.o: $(SRC_COMMON)/endian_utils.c $(SRC_COMMON)/endian_utils.h
	$(CC) $(CFLAGS) -c $(SRC_COMMON)/endian_utils.c

hash_wrappers.o: $(SRC_COMMON)/hash_wrappers.c $(SRC_COMMON)/hash_wrappers.h
	$(CC) $(CFLAGS) -c $(SRC_COMMON)/hash_wrappers.c

sha256.o: $(SRC_COMMON)/sha256.c $(SRC_COMMON)/sha256.h
	$(CC) $(CFLAGS) -c $(SRC_COMMON)/sha256.c

clean:
	-rm -f  *.o *.a
