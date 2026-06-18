#include "test_hash.h"
#include "test_maincompute.h"
#include "test_mul.h"
#include "test_ntt.h"
#include <inttypes.h>

#define MONT 2285  // 2^16 mod q
#define QINV 62209 // q^-1 mod 2^16

int test_enc(){
  return 0;
}

int main(void) {
  // test_keccak_absorb();
  // poly test;
  // test_matrix_gen();
  // test_fqmul();
  // test_hash(&test);
  // test_hash(&test);

  // test_poly_basemul();
  // test_barrett();
  // test_basemul();        // verified 24-02-2026
  // test_polyvec_basemul(); // verified 
  // test_butterfly();         // verified 27-02-2026

  //test_ntt();
  test_main_compute();
  // test_inv_ntt();

  return 0;
}
