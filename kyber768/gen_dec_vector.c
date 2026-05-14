/*
Goal: use c code to generate pk,sk,ct,ss to compare with verilog decryption top module
input:
    ct     = 1088 bytes (8704/8)
    sk     = 2400 bytes (19200/8)
output:
    ss     = 32 bytes (256/8)
step:
    1. create pk and sk
    2. creates ct and sender shared secret ss_enc using pk
    3. decrypt ct using sk and creates receiver shared secret ss_dec
    4. ss_dec should match with verilog output
command i use:
    cd C:\Users\Tony\kyber\kyber768-accelerator-on-fpga-ref\kyber768
    C:\msys64\ucrt64\bin\gcc.exe -O3 -o gen_dec_vector.exe gen_dec_vector.c cbd.c fips202.c indcpa.c kem.c ntt.c poly.c polyvec.c reduce.c rng.c verify.c symmetric-shake.c -lcrypto
    .\gen_dec_vector.exe
*/
#include <stdio.h>
#include <stdint.h>
//include the official kyber function
#include "api.h"
#include "rng.h"
#include "indcpa.h"
#include "symmetric.h"
#include <string.h>
#include "poly.h"
#include "polyvec.h"

static void write_mem(const char *filename, const uint8_t *buf, int len)
{
    FILE *f = fopen(filename, "w");
    if (!f) {
        printf("Cannot open %s\n", filename);
        return;
    }
    //writes one byte per line
    for (int i = 0; i < len; i++) {
        fprintf(f, "%02x\n", buf[i]);
    }

    fclose(f);
}

static void write_hexline(const char *filename, const uint8_t *buf, int len)
{
    FILE *f = fopen(filename, "w");
    if (!f) {
        printf("Cannot open %s\n", filename);
        return;
    }

    for (int i = 0; i < len; i++) {
        fprintf(f, "%02x", buf[i]);
    }
    fprintf(f, "\n");

    fclose(f);
}

int main(void)
{
    // 1. checking whether ss_dec is equal to ss in veriog
    uint8_t pk[CRYPTO_PUBLICKEYBYTES];
    uint8_t sk[CRYPTO_SECRETKEYBYTES];
    uint8_t ct[CRYPTO_CIPHERTEXTBYTES];
    uint8_t ss_enc[CRYPTO_BYTES];
    uint8_t ss_dec[CRYPTO_BYTES];
    // 2. check whether m_dec is equal to m_prime to see whether the bug
    uint8_t m_dec[KYBER_INDCPA_MSGBYTES];
    uint8_t entropy[48];
    // 3. check c'(kr[32:63]),pre−k'(kr[0:31]), Ct' 
    uint8_t buf[2*KYBER_SYMBYTES];
    uint8_t kr[2*KYBER_SYMBYTES];
    uint8_t ct_prime[CRYPTO_CIPHERTEXTBYTES];

    for (int i = 0; i < 48; i++) {
        entropy[i] = i;
    }
    
    randombytes_init(entropy, NULL, 256);

    crypto_kem_keypair(pk, sk);
    crypto_kem_enc(ct, ss_enc, pk);
    crypto_kem_dec(ss_dec, ct, sk);
    indcpa_dec(m_dec, ct, sk);

    // pre−k', copies 32 bytes from m_dec into the first half of buf. buf[0:31] = m_dec[0:31]
    memcpy(buf, m_dec, KYBER_SYMBYTES);
    // c', copies 32 bytes from the secret key into the second half of buf 
    // buf[32:63] = sk[2336:2367] = H(pk)
    memcpy(buf + KYBER_SYMBYTES,
       sk + KYBER_SECRETKEYBYTES - 2*KYBER_SYMBYTES,
       KYBER_SYMBYTES);
    // kr = SHA3-512(buf) (buf is pre-k,m')
    hash_g(kr, buf, 2*KYBER_SYMBYTES);
    // ct_prime = indcpa_enc(m_dec, pk, kr[32:63])
    indcpa_enc(ct_prime, m_dec, pk, kr + KYBER_SYMBYTES);
    //  check r,e1,e2 in pre_encryption in encryption_top in 4. Decode decompress msg
    /*polyvec sp, ep;
    poly epp;
    uint8_t nonce = 0;
    for (int i = 0; i < KYBER_K; i++)
        poly_getnoise_eta1(sp.vec + i, kr + KYBER_SYMBYTES, nonce++);

    for (int i = 0; i < KYBER_K; i++)
        poly_getnoise_eta2(ep.vec + i, kr + KYBER_SYMBYTES, nonce++);

    poly_getnoise_eta2(&epp, kr + KYBER_SYMBYTES, nonce++);
    
    printf("C r[0][0..7] = ");
    for (int i = 0; i < 8; i++) printf("%d ", sp.vec[0].coeffs[i]);
    printf("\n");

    printf("C e1[0][0..7] = ");
    for (int i = 0; i < 8; i++) printf("%d ", ep.vec[0].coeffs[i]);
    printf("\n");

    printf("C e2[0..7] = ");
    for (int i = 0; i < 8; i++) printf("%d ", epp.coeffs[i]);
    printf("\n");*/
    //If t_vec or rho mismatches, the bug is decode_pk. (5. Decode PK to get seed (rho) and t trans) in pre_encryption
    polyvec pkpv;
    uint8_t seed[KYBER_SYMBYTES];

    polyvec_frombytes(&pkpv, pk);

    for (int i = 0; i < KYBER_SYMBYTES; i++)
        seed[i] = pk[KYBER_POLYVECBYTES + i];

    printf("C t_vec[0][0..7] = ");
    for (int i = 0; i < 8; i++)
        printf("%d ", pkpv.vec[0].coeffs[i]);
    printf("\n");

    printf("C rho = ");
    for (int i = 0; i < KYBER_SYMBYTES; i++)
        printf("%02x", seed[i]);
    printf("\n");

    write_mem("pk.mem", pk, CRYPTO_PUBLICKEYBYTES);
    write_mem("sk.mem", sk, CRYPTO_SECRETKEYBYTES);
    write_mem("ct.mem", ct, CRYPTO_CIPHERTEXTBYTES);
    write_mem("ss_expected.mem", ss_dec, CRYPTO_BYTES);
    write_hexline("pk.hex", pk, CRYPTO_PUBLICKEYBYTES);
    write_hexline("sk.hex", sk, CRYPTO_SECRETKEYBYTES);
    write_hexline("ct.hex", ct, CRYPTO_CIPHERTEXTBYTES);
    write_hexline("ss_expected.hex", ss_dec, CRYPTO_BYTES);
    
    write_mem("m_expected.mem", m_dec, KYBER_INDCPA_MSGBYTES);
    write_hexline("m_expected.hex", m_dec, KYBER_INDCPA_MSGBYTES);

    write_mem("pre_k_prime_expected.mem", kr, KYBER_SYMBYTES);
    write_mem("c_prime_expected.mem", kr + KYBER_SYMBYTES, KYBER_SYMBYTES);
    write_mem("ct_prime_expected.mem", ct_prime, CRYPTO_CIPHERTEXTBYTES);

    
    printf("Generated decryption vector:\n");
    printf("  pk bytes = %d\n", CRYPTO_PUBLICKEYBYTES);
    printf("  sk bytes = %d\n", CRYPTO_SECRETKEYBYTES);
    printf("  ct bytes = %d\n", CRYPTO_CIPHERTEXTBYTES);
    printf("  ss bytes = %d\n", CRYPTO_BYTES);
    

    return 0;
}
