#include "test_encryption.h"
#include <string.h>
#include <stdlib.h>
#include <time.h>

#define NTESTS 1000

static inline uint64_t cpucycles(void) {
    uint32_t lo, hi;
    __asm__ volatile ("rdtsc" : "=a"(lo), "=d"(hi));
    return ((uint64_t)hi << 32) | lo;
}

static int cmp_u64(const void *a, const void *b) {
    uint64_t x = *(const uint64_t *)a, y = *(const uint64_t *)b;
    return (x > y) - (x < y);
}

static void print_hex(const char *label, const uint8_t *buf, size_t n) {
    printf("%s", label);
    for (size_t i = 0; i < n; i++) printf("%02x", buf[i]);
    printf("\n");
}

/* Time crypto_kem_enc over NTESTS runs. Reports median/min cycles and avg us. */
void test_encryption_timing(void) {
    uint8_t pk[KYBER_PUBLICKEYBYTES];
    uint8_t sk[KYBER_SECRETKEYBYTES];
    uint8_t ct[KYBER_CIPHERTEXTBYTES];
    uint8_t ss[KYBER_SYMBYTES];
    uint64_t cycles[NTESTS];
    uint64_t t0, t1;
    struct timespec ts0, ts1;

    crypto_kem_keypair(pk, sk);

    /* warmup */
    for (int i = 0; i < 20; i++)
        crypto_kem_enc(ct, ss, pk);

    /* cycle measurement: start/end bracket each call */
    for (int i = 0; i < NTESTS; i++) {
        t0 = cpucycles();
        crypto_kem_enc(ct, ss, pk);
        t1 = cpucycles();
        cycles[i] = t1 - t0;
    }
    qsort(cycles, NTESTS, sizeof(uint64_t), cmp_u64);

    /* wall-clock measurement */
    clock_gettime(CLOCK_MONOTONIC, &ts0);
    for (int i = 0; i < NTESTS; i++)
        crypto_kem_enc(ct, ss, pk);
    clock_gettime(CLOCK_MONOTONIC, &ts1);

    double total_ns = (ts1.tv_sec - ts0.tv_sec) * 1e9
                    + (ts1.tv_nsec - ts0.tv_nsec);

    printf("=== Kyber768 Encapsulation Timing (%d runs) ===\n", NTESTS);
    printf("cycles  median : %llu\n", (unsigned long long)cycles[NTESTS / 2]);
    printf("cycles  min    : %llu\n", (unsigned long long)cycles[0]);
    printf("cycles  max    : %llu\n", (unsigned long long)cycles[NTESTS - 1]);
    printf("wall    avg    : %.2f us\n\n", total_ns / NTESTS / 1000.0);
}

/* Single deterministic run — prints intermediate values in the same format
 * as encryption_top_tb.sv so results can be compared against RTL simulation. */
void test_encryption_verify(void) {
    /* Seed NIST RNG deterministically (entropy_input = 0x00,0x01,...,0x2f) */
    uint8_t entropy[48];
    for (int i = 0; i < 48; i++) entropy[i] = (uint8_t)i;
    randombytes_init(entropy, NULL, 256);

    uint8_t pk[KYBER_PUBLICKEYBYTES];
    uint8_t sk[KYBER_SECRETKEYBYTES];
    crypto_kem_keypair(pk, sk);

    /* --- replicate crypto_kem_enc internals step by step --- */
    uint8_t rand_m[KYBER_SYMBYTES];
    randombytes(rand_m, KYBER_SYMBYTES);    /* random seed → r_in in RTL */

    uint8_t msg[KYBER_SYMBYTES];
    hash_h(msg, rand_m, KYBER_SYMBYTES);    /* msg = SHA3-256(r_in) */

    uint8_t h_pk[KYBER_SYMBYTES];
    hash_h(h_pk, pk, KYBER_PUBLICKEYBYTES); /* H(pk) */

    uint8_t buf[2 * KYBER_SYMBYTES];
    memcpy(buf,              msg,  KYBER_SYMBYTES);
    memcpy(buf + KYBER_SYMBYTES, h_pk, KYBER_SYMBYTES);

    uint8_t kr[2 * KYBER_SYMBYTES];
    hash_g(kr, buf, 2 * KYBER_SYMBYTES);    /* G(msg || H(pk)) */

    uint8_t ct[KYBER_CIPHERTEXTBYTES];
    indcpa_enc(ct, msg, pk, kr + KYBER_SYMBYTES); /* encrypt */

    uint8_t h_ct[KYBER_SYMBYTES];
    hash_h(h_ct, ct, KYBER_CIPHERTEXTBYTES); /* H(ct) */

    uint8_t kdf_in[2 * KYBER_SYMBYTES];
    memcpy(kdf_in,              kr,   KYBER_SYMBYTES); /* pre_k */
    memcpy(kdf_in + KYBER_SYMBYTES, h_ct, KYBER_SYMBYTES); /* H(ct) */

    uint8_t ss[KYBER_SYMBYTES];
    kdf(ss, kdf_in, 2 * KYBER_SYMBYTES);

    printf("=== Encryption Verify (compare with encryption_top_tb.sv) ===\n");
    print_hex("r_in (raw rand): ", rand_m, KYBER_SYMBYTES);
    print_hex("msg_latched:     ", msg,    KYBER_SYMBYTES);
    print_hex("hash_ek_latched: ", h_pk,   KYBER_SYMBYTES);
    print_hex("pre_k (kr[0]):   ", kr,     KYBER_SYMBYTES);
    print_hex("coin  (kr[32]):  ", kr + KYBER_SYMBYTES, KYBER_SYMBYTES);
    print_hex("ct (first 32B):  ", ct,     32);
    print_hex("H(ct):           ", h_ct,   KYBER_SYMBYTES);
    print_hex("ss:              ", ss,     KYBER_SYMBYTES);
    printf("\n");
}
