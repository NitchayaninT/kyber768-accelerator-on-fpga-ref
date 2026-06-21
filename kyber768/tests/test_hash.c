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

/* ------------------------------------------------------------------ *
 * test_sponge_controller                                               *
 *                                                                      *
 * Reference vectors for sponge_controller.sv's block-at-a-time        *
 * interface.  For each test case, prints the pre-padded block_in and   *
 * the squeezed block_out in "Verilog %h bus order" so the values can   *
 * be pasted directly into sponge_controller_tb.sv or compared with     *
 * $display output.                                                      *
 *                                                                      *
 * Verilog %h bus order = MSB byte first.  For a [N*8-1:0] bus where   *
 * bus[7:0] = byte 0, $display("%h", bus) prints byte N-1 first.        *
 *                                                                      *
 * All four hash modes are covered:                                     *
 *   mode 00 = SHA3-256  (rate=136 B, domain=0x06)                     *
 *   mode 01 = SHA3-512  (rate= 72 B, domain=0x06)                     *
 *   mode 10 = SHAKE128  (rate=168 B, domain=0x1F)                     *
 *   mode 11 = SHAKE256  (rate=136 B, domain=0x1F)                     *
 * ------------------------------------------------------------------ */
void test_sponge_controller(void)
{
    printf("=== test_sponge_controller ===\n\n");

    /* --------------------------------------------------------------- *
     * Test 1: SHA3-256, empty input (mode=00)                          *
     * Single block, last_block=1.                                       *
     * Matches sponge_controller_tb Test 1.                             *
     * --------------------------------------------------------------- */
    {
        uint8_t block_in[SHA3_256_RATE];
        uint8_t hash[32];

        printf("-- Test 1: SHA3-256 empty string (mode=00) --\n");
        printf("  hash_mode=2'b00  rate=%d B  domain=0x06  last_block=1\n",
               SHA3_256_RATE);

        build_padded_block(block_in, SHA3_256_RATE, NULL, 0, 0x06);
        print_verilog_h("block_in[1087:0]", block_in, SHA3_256_RATE);

        sha3_256(hash, NULL, 0);
        print_verilog_h("block_out[255:0]", hash, 32);
        printf("  standard hash    = ");
        for (int i = 0; i < 32; i++) printf("%02x", hash[i]);
        printf("\n\n");
    }

    /* --------------------------------------------------------------- *
     * Test 2: SHA3-512, empty input (mode=01)                          *
     * Single block, last_block=1.                                       *
     * --------------------------------------------------------------- */
    {
        uint8_t block_in[SHA3_512_RATE];
        uint8_t hash[64];

        printf("-- Test 2: SHA3-512 empty string (mode=01) --\n");
        printf("  hash_mode=2'b01  rate=%d B  domain=0x06  last_block=1\n",
               SHA3_512_RATE);

        build_padded_block(block_in, SHA3_512_RATE, NULL, 0, 0x06);
        print_verilog_h("block_in[575:0]", block_in, SHA3_512_RATE);

        sha3_512(hash, NULL, 0);
        print_verilog_h("block_out[511:0]", hash, 64);
        printf("  standard hash    = ");
        for (int i = 0; i < 64; i++) printf("%02x", hash[i]);
        printf("\n\n");
    }

    /* --------------------------------------------------------------- *
     * Test 3: SHAKE128, 34 zero bytes, matrix_gen=1 (mode=10)          *
     * 3 squeeze rounds (matrix generation for A^T[0][0] with           *
     * seed=zeros, matching sponge_controller_tb Test 2 and the         *
     * existing test_permutation input).                                 *
     * --------------------------------------------------------------- */
    {
        uint8_t msg[KYBER_SYMBYTES + 2]; /* 32 + 2 = 34 bytes */
        uint8_t block_in[SHAKE128_RATE];
        uint8_t out[SHAKE128_RATE];
        keccak_state state;

        memset(msg, 0, sizeof(msg));

        printf("-- Test 3: SHAKE128 34-byte zero input, matrix_gen=1 (mode=10) --\n");
        printf("  hash_mode=2'b10  rate=%d B  domain=0x1F"
               "  last_block=1  matrix_gen=1\n", SHAKE128_RATE);

        build_padded_block(block_in, SHAKE128_RATE, msg, sizeof(msg), 0x1F);
        print_verilog_h("block_in[1343:0]", block_in, SHAKE128_RATE);
        printf("\n");

        shake128_absorb(&state, msg, sizeof(msg));
        for (int sq = 0; sq < 3; sq++) {
            shake128_squeezeblocks(out, 1, &state);
            printf("  squeeze %d:\n", sq + 1);
            /* block_out[255:0] matches what sponge_controller_tb prints */
            print_verilog_h("block_out[255:0]", out, 32);
            /* Full rate block for complete hardware comparison */
            print_verilog_h("block_out[1343:0]", out, SHAKE128_RATE);
        }
        printf("\n");
    }

    /* --------------------------------------------------------------- *
     * Test 4: SHAKE256, 32 zero bytes (mode=11)                        *
     * Single squeeze, last_block=1.                                     *
     * Models noise/coins generation in pre_encryption.sv.              *
     * --------------------------------------------------------------- */
    {
        uint8_t msg[KYBER_SYMBYTES]; /* 32 bytes */
        uint8_t block_in[SHAKE256_RATE];
        uint8_t out[SHAKE256_RATE];
        keccak_state state;

        memset(msg, 0, sizeof(msg));

        printf("-- Test 4: SHAKE256 32-byte zero input (mode=11) --\n");
        printf("  hash_mode=2'b11  rate=%d B  domain=0x1F  last_block=1\n",
               SHAKE256_RATE);

        build_padded_block(block_in, SHAKE256_RATE, msg, sizeof(msg), 0x1F);
        print_verilog_h("block_in[1087:0]", block_in, SHAKE256_RATE);

        shake256_absorb(&state, msg, sizeof(msg));
        shake256_squeezeblocks(out, 1, &state);
        print_verilog_h("block_out[1087:0]", out, SHAKE256_RATE);
        printf("  standard out     = ");
        for (int i = 0; i < SHAKE256_RATE; i++) printf("%02x", out[i]);
        printf("\n\n");
    }

    /* --------------------------------------------------------------- *
     * Test 5: SHA3-256, 1184-byte zero PK (mode=00, 9 blocks)          *
     * Multi-block absorb: 8 full 136-byte blocks + 1 padded block.     *
     * Models the PK hash (SHA3-256(public_key)) in pre_encryption.sv.  *
     *   blocks 1–8: 136 zero bytes (full blocks, no padding)           *
     *   block  9  : 96 payload bytes + padding (last_block=1)          *
     * --------------------------------------------------------------- */
    {
        const int pk_len       = 1184;
        const int n_full       = pk_len / SHA3_256_RATE;           /* 8  */
        const int last_payload = pk_len - n_full * SHA3_256_RATE;  /* 96 */
        uint8_t pk[1184];
        uint8_t full_block[SHA3_256_RATE];
        uint8_t block9[SHA3_256_RATE];
        uint8_t hash[32];

        memset(pk, 0, sizeof(pk));
        memset(full_block, 0, sizeof(full_block));

        printf("-- Test 5: SHA3-256 1184-byte zero PK (mode=00, 9 blocks) --\n");
        printf("  hash_mode=2'b00  rate=%d B  domain=0x06\n", SHA3_256_RATE);
        printf("  blocks 1..%d: %d-byte all-zero full blocks (no padding)\n",
               n_full, SHA3_256_RATE);
        print_verilog_h("full_blk[1087:0]", full_block, SHA3_256_RATE);

        printf("  block 9 (last_block=1, %d payload bytes):\n", last_payload);
        build_padded_block(block9, SHA3_256_RATE,
                           pk + n_full * SHA3_256_RATE,
                           (size_t)last_payload, 0x06);
        print_verilog_h("block9_in[1087:0]", block9, SHA3_256_RATE);

        sha3_256(hash, pk, (size_t)pk_len);
        print_verilog_h("block_out[255:0]", hash, 32);
        printf("  standard hash    = ");
        for (int i = 0; i < 32; i++) printf("%02x", hash[i]);
        printf("\n\n");
    }
}
