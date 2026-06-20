#include "test_hash.h"
#include <string.h>

/* ------------------------------------------------------------------ *
 * Helpers shared by test_sponge_controller                             *
 * ------------------------------------------------------------------ */

/* Print n bytes MSB-first: matches Verilog $display("%h", bus[n*8-1:0]).
   bus[7:0] = b[0] (LSByte), so %h shows b[n-1]...b[0]. */
static void print_verilog_h(const char *label, const uint8_t *b, int n)
{
    printf("  %-22s = ", label);
    for (int i = n - 1; i >= 0; i--)
        printf("%02x", b[i]);
    printf("\n");
}

/* Build one pre-padded sponge block for the sponge_controller block_in port.
 * Applies Keccak multi-rate padding:
 *   b[0..mlen-1] = msg bytes
 *   b[mlen]      = domain  (XOR'd in; if mlen==rate-1 this byte is also OR'd with 0x80)
 *   b[rate-1]   |= 0x80    (multi-rate padding MSB)
 * buf must be exactly rate bytes; callers are responsible for zeroing it first. */
static void build_padded_block(uint8_t *buf, int rate,
                               const uint8_t *msg, size_t mlen,
                               uint8_t domain)
{
    memset(buf, 0, (size_t)rate);
    if (msg && mlen)
        memcpy(buf, msg, mlen);
    buf[mlen]     = domain;
    buf[rate - 1] |= 0x80;
}

/* Print 25-lane Keccak state as 1600 bits in two formats:
   (1) per-lane uint64 (little-endian within each lane)
   (2) flat byte stream s[0][0..7] ... s[24][0..7] matching the Verilog
       state bus where bits[63:0] = s[0], bits[127:64] = s[1], etc. */
static void print_keccak_state(const char *label, const uint64_t s[25])
{
    printf("%s:\n", label);
    for (int i = 0; i < 25; i++)
        printf("  s[%2d] = %016" PRIx64 "\n", i, s[i]);

    /* Flat 200-byte little-endian stream (s[0] LSB first) matching Verilog
       state bus: in[63:0]=s[0], in[127:64]=s[1], ..., in[1599:1536]=s[24] */
    printf("  flat hex (200 bytes, s[0..24] LE): ");
    for (int i = 0; i < 25; i++)
        for (int b = 0; b < 8; b++)
            printf("%02x", (uint8_t)(s[i] >> (8 * b)));
    printf("\n");
}

/*
 * test_permutation
 *
 * Verifies the Keccak-f[1600] permutation via the SHAKE128 absorb/squeeze API.
 * Chosen input: 34 zero bytes (32-byte all-zero seed + nonce bytes 0, 0),
 * matching what SHAKE128 absorbs for matrix entry A^T[0][0] with zero seed.
 *
 * Prints:
 *   - the 1600-bit sponge state BEFORE the first permutation (after absorb)
 *   - the 1600-bit sponge state AFTER  the first permutation (after squeeze)
 *   - the first 168-byte output block (SHAKE128 rate block 0)
 *
 * "Before" state  = exact 1600-bit input  to permutation.sv
 * "After"  state  = exact 1600-bit output of permutation.sv
 */
void test_permutation()
{
    printf("=== test_permutation ===\n");
    printf("Input: 34 zero bytes (seed=0x00*32, i=0, j=0)\n\n");

    uint8_t msg[KYBER_SYMBYTES + 2];
    memset(msg, 0, sizeof(msg));

    keccak_state state;
    shake128_absorb(&state, msg, sizeof(msg));

    print_keccak_state("State BEFORE first permutation  [input  to permutation.sv]", state.s);
    printf("\n");

    uint8_t out[SHAKE128_RATE];
    shake128_squeezeblocks(out, 1, &state);

    print_keccak_state("State AFTER  first permutation  [output of permutation.sv]", state.s);
    printf("\n");

    printf("Rate block 0 (%d bytes) [first %d bytes of SHAKE128 output]:\n  ",
           SHAKE128_RATE, SHAKE128_RATE);
    for (int i = 0; i < SHAKE128_RATE; i++)
        printf("%02x", out[i]);
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
