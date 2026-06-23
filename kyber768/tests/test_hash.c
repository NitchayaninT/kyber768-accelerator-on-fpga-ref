#include "test_hash.h"
#include "fips202.h"
#include "params.h"
#include <string.h>

/* Print n bytes as hex (byte 0 first — matches Verilog print_bytes task) */
static void print_hex(const uint8_t *buf, size_t n)
{
    for (size_t i = 0; i < n; i++) printf("%02x", buf[i]);
    printf("\n");
}

// testing sponge_controller.sv
// test case 1 : SHA3-256 all zeros
// test case 2 : SHA3-512 all zeros
// test case 3 : SHAKE-128 all zeros
// test case 4 : SHAKE-256 all zeros

// test case 5 : SHA3-256(PK)
// test case 6 : SHA3-256(ct)
// test case 7 : MATRIX GEN seed = all zeroes
/* Tests matching hash_controller_tb.sv exactly:
 * Test 1: SHA3-256(empty)   Test 2: SHA3-256("abc")
 * Test 3: SHAKE128(empty)   Test 4: SHAKE128 matrix_gen (34B zero seed) */
void test_hash_controller() {
    printf("=== test_hash_controller ===\n\n");

    uint8_t out[4 * SHAKE128_RATE];

    // Test 1: SHA3-256(empty = 0 bytes)
    printf("=== Test 1: SHA3-256 empty string ===\n");
    sha3_256(out, NULL, 0);
    printf("got:      "); print_hex(out, 32);
    printf("expected: a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a\n\n");

    // Test 2: SHA3-256("abc")
    printf("=== Test 2: SHA3-256 'abc' (3 bytes) ===\n");
    uint8_t abc[3] = {0x61, 0x62, 0x63};
    sha3_256(out, abc, 3);
    printf("got:      "); print_hex(out, 32);
    printf("expected: 3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532\n\n");

    // Test 3: SHAKE128(empty = 0 bytes), 168 bytes output, first 32 printed
    printf("=== Test 3: SHAKE128 empty string (no matrix_gen) ===\n");
    shake128(out, SHAKE128_RATE, NULL, 0);
    printf("got:      "); print_hex(out, 32);
    printf("expected: 7f9c2ba4e88f827d616045507605853ed73b8093f6efbc88eb1a6eacfa66ef26\n\n");

    // Test 4: SHAKE128 matrix_gen — 34 zero bytes, 4 squeeze blocks
    printf("=== Test 4: SHAKE128 matrix_gen (34B zero seed, 4 squeezes) ===\n");
    uint8_t seed34[34];
    memset(seed34, 0, sizeof(seed34));
    keccak_state st;
    shake128_absorb(&st, seed34, 34);
    shake128_squeezeblocks(out, 4, &st);
    printf("squeeze0: "); print_hex(out, 32);
    printf("squeeze1: "); print_hex(out + SHAKE128_RATE, 32);
    printf("\n");
}

void test_sponge_controller(){
  printf("=== test sponge_controller ===\n");
  printf("Input: 32 zero bytes (KYBER_SYMBYTES)\n\n");

  uint8_t msg_in[KYBER_SYMBYTES];  // 32 zero bytes
  memset(msg_in, 0, sizeof(msg_in));

  uint8_t out_32[32];                    // SHA3-256 output
  uint8_t out_64[64];                    // SHA3-512 output
  uint8_t out_shake[SHAKE128_RATE];      // 1 SHAKE squeeze block (168 bytes)
  uint8_t out_matrix[4 * SHAKE128_RATE]; // 4 SHAKE128 squeeze blocks for matrix gen

  // Test 1: SHA3-256(32 zero bytes)
  printf("--- Test 1: SHA3-256(32 zero bytes) ---\n");
  sha3_256(out_32, msg_in, sizeof(msg_in));
  printf("out: "); print_hex(out_32, 32);
  printf("\n");

  // Test 2: SHA3-512(32 zero bytes)
  printf("--- Test 2: SHA3-512(32 zero bytes) ---\n");
  sha3_512(out_64, msg_in, sizeof(msg_in));
  printf("out: "); print_hex(out_64, 64);
  printf("\n");

  // Test 3: SHAKE128(32 zero bytes) — 1 squeeze block (168 bytes)
  printf("--- Test 3: SHAKE128(32 zero bytes, 1 block = %d bytes) ---\n", SHAKE128_RATE);
  shake128(out_shake, SHAKE128_RATE, msg_in, sizeof(msg_in));
  printf("out: "); print_hex(out_shake, SHAKE128_RATE);
  printf("\n");

  // Test 4: SHAKE256(32 zero bytes) — 1 squeeze block (136 bytes)
  printf("--- Test 4: SHAKE256(32 zero bytes, 1 block = %d bytes) ---\n", SHAKE256_RATE);
  shake256(out_shake, SHAKE256_RATE, msg_in, sizeof(msg_in));
  printf("out: "); print_hex(out_shake, SHAKE256_RATE);
  printf("\n");

  // Test 5: SHA3-256(zero PK)
  printf("--- Test 5: SHA3-256(zero PK = %d bytes) ---\n", KYBER_PUBLICKEYBYTES);
  uint8_t pk[KYBER_PUBLICKEYBYTES];
  memset(pk, 0, sizeof(pk));
  sha3_256(out_32, pk, KYBER_PUBLICKEYBYTES);
  printf("out: "); print_hex(out_32, 32);
  printf("\n");

  // Test 6: SHA3-256(zero ct)
  printf("--- Test 6: SHA3-256(zero ct = %d bytes) ---\n", KYBER_CIPHERTEXTBYTES);
  uint8_t ct[KYBER_CIPHERTEXTBYTES];
  memset(ct, 0, sizeof(ct));
  sha3_256(out_32, ct, KYBER_CIPHERTEXTBYTES);
  printf("out: "); print_hex(out_32, 32);
  printf("\n");

  // Test 7: SHAKE128 matrix gen — seed=all zeros, i=0, j=0 → 3 squeeze blocks
  // kyber_shake128_absorb absorbs seed||i||j (34 bytes), matching sponge_controller matrix_gen=1
  printf("--- Test 7: SHAKE128 matrix gen (seed=0, i=0, j=0) ---\n");
  keccak_state xof_st;
  uint8_t seed[KYBER_SYMBYTES];
  memset(seed, 0, sizeof(seed));
  kyber_shake128_absorb(&xof_st, seed, 0, 0);
  shake128_squeezeblocks(out_matrix, 4, &xof_st);
  for (int b = 0; b < 4; b++) {
    printf("squeeze[%d]: ", b);
    print_hex(out_matrix + b * SHAKE128_RATE, SHAKE128_RATE);
  }
  printf("\n");
}
