#CC=C:\msys64\ucrt64\bin\gcc.exe
CC=/usr/bin/gcc
CFLAGS += -O3 -march=native -fomit-frame-pointer -I.
LDFLAGS=-lcrypto

SOURCES= cbd.c fips202.c indcpa.c kem.c ntt.c poly.c polyvec.c reduce.c rng.c verify.c symmetric-shake.c tests/my_test.c tests/test_ntt.c tests/test_hash.c tests/test_mul.c tests/test_utils.c tests/test_maincompute.c
HEADERS= api.h cbd.h fips202.h indcpa.h ntt.h params.h poly.h polyvec.h reduce.h rng.h verify.h symmetric.h tests/test_ntt.h tests/test_hash.h tests/test_mul.h tests/test_utils.h tests/test_maincompute.h

my_test: $(HEADERS) $(SOURCES)
	$(CC) $(CFLAGS) -o $@ $(SOURCES) $(LDFLAGS)

.PHONY: clean

clean:
	-rm PQCgenKAT_kem

