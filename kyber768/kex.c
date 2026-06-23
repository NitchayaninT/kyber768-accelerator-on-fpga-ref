#include "kex.h"
#include "kem.h"
#include "indcpa.h"
#include "symmetric.h"
#include "rng.h"
#include <string.h>

/* Unilateral authenticated key exchange (UAKE) */

int kex_uake_initA(uint8_t *send, uint8_t *tk, uint8_t *sk, const uint8_t *pkb) {
    /* send = ephemeral pk_a || ct_a;  tk = ephemeral sk_a */
    uint8_t esk[KYBER_SECRETKEYBYTES];
    crypto_kem_keypair(send, esk);
    crypto_kem_enc(send + KYBER_PUBLICKEYBYTES, tk, pkb);
    memcpy(sk, esk, KYBER_SECRETKEYBYTES);
    return 0;
}

int kex_uake_sharedB(uint8_t *send, uint8_t *k, const uint8_t *recv, const uint8_t *sk) {
    uint8_t buf[2 * KYBER_SYMBYTES];
    crypto_kem_dec(buf, recv + KYBER_PUBLICKEYBYTES, sk);
    crypto_kem_enc(send, buf + KYBER_SYMBYTES, recv);
    sha3_256(k, buf, 2 * KYBER_SYMBYTES);
    return 0;
}

int kex_uake_sharedA(uint8_t *k, const uint8_t *recv, const uint8_t *tk, const uint8_t *sk) {
    uint8_t buf[2 * KYBER_SYMBYTES];
    crypto_kem_dec(buf, recv, sk);
    memcpy(buf + KYBER_SYMBYTES, tk, KYBER_SYMBYTES);
    sha3_256(k, buf, 2 * KYBER_SYMBYTES);
    return 0;
}

/* Authenticated key exchange (AKE) */

int kex_ake_initA(uint8_t *send, uint8_t *tk, uint8_t *sk, const uint8_t *pkb) {
    uint8_t esk[KYBER_SECRETKEYBYTES];
    crypto_kem_keypair(send, esk);
    crypto_kem_enc(send + KYBER_PUBLICKEYBYTES, tk, pkb);
    memcpy(sk, esk, KYBER_SECRETKEYBYTES);
    return 0;
}

int kex_ake_sharedB(uint8_t *send, uint8_t *k, const uint8_t *recv,
                    const uint8_t *sk, const uint8_t *pk) {
    uint8_t buf[3 * KYBER_SYMBYTES];
    crypto_kem_dec(buf, recv + KYBER_PUBLICKEYBYTES, sk);
    crypto_kem_enc(send, buf + KYBER_SYMBYTES, recv);
    crypto_kem_enc(send + KYBER_CIPHERTEXTBYTES, buf + 2 * KYBER_SYMBYTES, pk);
    sha3_256(k, buf, 3 * KYBER_SYMBYTES);
    return 0;
}

int kex_ake_sharedA(uint8_t *k, const uint8_t *recv, const uint8_t *tk,
                    const uint8_t *sk, const uint8_t *pkb) {
    (void)pkb;
    uint8_t buf[3 * KYBER_SYMBYTES];
    crypto_kem_dec(buf, recv, sk);
    crypto_kem_dec(buf + KYBER_SYMBYTES, recv + KYBER_CIPHERTEXTBYTES, sk);
    memcpy(buf + 2 * KYBER_SYMBYTES, tk, KYBER_SYMBYTES);
    sha3_256(k, buf, 3 * KYBER_SYMBYTES);
    return 0;
}
