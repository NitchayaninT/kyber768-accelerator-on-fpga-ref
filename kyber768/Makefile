#CC=C:\msys64\ucrt64\bin\gcc.exe
CC=/usr/bin/gcc
CFLAGS += -O3 -march=native -fomit-frame-pointer -I.
LDFLAGS=-lcrypto

SOURCES= cbd.c fips202.c indcpa.c kem.c ntt.c poly.c polyvec.c reduce.c rng.c verify.c symmetric-shake.c tests/my_test.c tests/test_ntt.c tests/test_hash.c tests/test_mul.c tests/test_utils.c tests/test_maincompute.c tests/test_encryption.c
HEADERS= api.h cbd.h fips202.h indcpa.h ntt.h params.h poly.h polyvec.h reduce.h rng.h verify.h symmetric.h tests/test_ntt.h tests/test_hash.h tests/test_mul.h tests/test_utils.h tests/test_maincompute.h tests/test_encryption.h

my_test: $(HEADERS) $(SOURCES)
	$(CC) $(CFLAGS) -o $@ $(SOURCES) $(LDFLAGS)

SPEED_SOURCES= cbd.c fips202.c indcpa.c kem.c kex.c ntt.c poly.c polyvec.c reduce.c rng.c verify.c symmetric-shake.c speed_print.c test_speed.c

speed: $(SPEED_SOURCES) cpucycles.h kex.h api.h
	$(CC) $(CFLAGS) -o $@ $(SPEED_SOURCES) $(LDFLAGS)

KAT_OUTDIR = /home/pakin/Data/Projects/kyber/test/kat
GEN_KAT_SOURCES = cbd.c fips202.c indcpa.c kem.c ntt.c poly.c polyvec.c reduce.c rng.c verify.c symmetric-shake.c tests/gen_kat_vectors.c

gen_kat: $(GEN_KAT_SOURCES)
	$(CC) $(CFLAGS) -o gen_kat_bin $(GEN_KAT_SOURCES) $(LDFLAGS)
	mkdir -p $(KAT_OUTDIR)
	./gen_kat_bin $(KAT_OUTDIR)
	rm -f gen_kat_bin

.PHONY: clean speed gen_kat

clean:
	-rm PQCgenKAT_kem

