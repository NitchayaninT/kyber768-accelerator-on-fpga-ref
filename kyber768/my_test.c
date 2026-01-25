#include <stdio.h>
#include <inttypes.h>

//#include "test_hash.h"
#include "test_ntt.h"

#define MONT 2285 // 2^16 mod q
#define QINV 62209 // q^-1 mod 2^16
int main(void)
{
  //test_keccak_absorb();
  //poly test;
  //test_matrix_gen();
  //test_fqmul();
  //test_ntt(test);
  //test_hash(&test);
  //test_hash(&test);

  test_fqmul();
  //test_clt();

  return 0;
}
