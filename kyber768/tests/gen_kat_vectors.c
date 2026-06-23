/*
 * Generates 20 Kyber768 KAT encryption vectors for FPGA verification.
 *
 * Replays the PQCgenKAT_kem.c DRBG sequence to capture r_in (raw
 * randomness before SHA3-256), pk, ct, ss, and pre_k for each test.
 *
 * Usage: ./gen_kat_vectors [output_dir]
 */
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include "params.h"
#include "rng.h"
#include "kem.h"
#include "fips202.h"
#include "indcpa.h"
#include "symmetric.h"

#define NUM_TESTS 20

static void write_hex_line(FILE *f, const uint8_t *data, size_t len) {
    for (size_t i = 0; i < len; i++)
        fprintf(f, "%02x", data[i]);
    fprintf(f, "\n");
}

int main(int argc, char *argv[]) {
    const char *outdir = argc > 1 ? argv[1] : ".";
    char path[1024];

    uint8_t entropy_input[48];
    uint8_t seed[48];
    uint8_t pk[KYBER_PUBLICKEYBYTES];
    uint8_t sk[KYBER_SECRETKEYBYTES];
    uint8_t r_in[KYBER_SYMBYTES];   /* raw randomness = FPGA r_in port */
    uint8_t buf[2*KYBER_SYMBYTES];
    uint8_t kr[2*KYBER_SYMBYTES];   /* kr[0:31]=pre_k, kr[32:63]=coin */
    uint8_t kr2[2*KYBER_SYMBYTES];
    uint8_t ct[KYBER_CIPHERTEXTBYTES];
    uint8_t ss[KYBER_SYMBYTES];

#define OPEN(var, name)                                      \
    snprintf(path, sizeof(path), "%s/%s", outdir, name);     \
    var = fopen(path, "w");                                  \
    if (!var) { perror(path); return 1; }

    FILE *f_pk, *f_rin, *f_ct, *f_ss, *f_prek;
    OPEN(f_pk,   "kat_pk.mem")
    OPEN(f_rin,  "kat_r_in.mem")
    OPEN(f_ct,   "kat_ct.mem")
    OPEN(f_ss,   "kat_ss.mem")
    OPEN(f_prek, "kat_pre_k.mem")

    /* Mirror PQCgenKAT_kem.c outer DRBG initialization */
    for (int i = 0; i < 48; i++)
        entropy_input[i] = i;
    randombytes_init(entropy_input, NULL, 256);

    for (int count = 0; count < NUM_TESTS; count++) {
        /* Advance outer DRBG, then reinit inner DRBG with new seed */
        randombytes(seed, 48);
        randombytes_init(seed, NULL, 256);

        /* Generate keypair (consumes 2 inner randombytes calls) */
        crypto_kem_keypair(pk, sk);

        /* Capture raw randomness — this is r_in for the FPGA */
        randombytes(r_in, KYBER_SYMBYTES);

        /* Replicate crypto_kem_enc to derive expected outputs */
        memcpy(buf, r_in, KYBER_SYMBYTES);
        hash_h(buf, buf, KYBER_SYMBYTES);                        /* SHA3-256(r_in) = msg_latched */
        hash_h(buf + KYBER_SYMBYTES, pk, KYBER_PUBLICKEYBYTES);  /* H(pk) */
        hash_g(kr, buf, 2*KYBER_SYMBYTES);                       /* G(msg||H(pk)) -> pre_k, coin */

        indcpa_enc(ct, buf, pk, kr + KYBER_SYMBYTES);

        /* Compute ss = KDF(pre_k || H(ct)) */
        memcpy(kr2, kr, KYBER_SYMBYTES);
        hash_h(kr2 + KYBER_SYMBYTES, ct, KYBER_CIPHERTEXTBYTES);
        kdf(ss, kr2, 2*KYBER_SYMBYTES);

        write_hex_line(f_pk,   pk,   KYBER_PUBLICKEYBYTES);
        write_hex_line(f_rin,  r_in, KYBER_SYMBYTES);
        write_hex_line(f_ct,   ct,   KYBER_CIPHERTEXTBYTES);
        write_hex_line(f_ss,   ss,   KYBER_SYMBYTES);
        write_hex_line(f_prek, kr,   KYBER_SYMBYTES);  /* kr[0:31] = pre_k */

        fprintf(stderr, "[%2d] r_in=%02x%02x... ss=%02x%02x...\n",
                count, r_in[0], r_in[1], ss[0], ss[1]);
    }

    fclose(f_pk); fclose(f_rin); fclose(f_ct); fclose(f_ss); fclose(f_prek);
    fprintf(stdout, "Generated %d vectors in %s/\n", NUM_TESTS, outdir);
    return 0;
}
