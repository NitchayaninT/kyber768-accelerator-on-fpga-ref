#include "test_hash.h"
#include <string.h>

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
