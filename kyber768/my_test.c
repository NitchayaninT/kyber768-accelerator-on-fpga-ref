#include "test_hash.h"
#include "test_mul.h"
#include "test_ntt.h"
#include <inttypes.h>

#define MONT 2285  // 2^16 mod q
#define QINV 62209 // q^-1 mod 2^16
int main(void) {
  // test_keccak_absorb();
  // poly test;
  // test_matrix_gen();
  test_ntt();
  //test_fqmul();
  // test_hash(&test);
  // test_hash(&test);

  // test_basemul();
  // test_poly_basemul();
  test_clt();
  // test_barrett();
  // test_polyvec_basemul();

  return 0;
}
