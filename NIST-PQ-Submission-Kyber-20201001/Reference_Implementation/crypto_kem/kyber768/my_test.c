#include <stdio.h>
#include <inttypes.h>
#include "poly.h"

#define MONT 2285 // 2^16 mod q
#define QINV 62209 // q^-1 mod 2^16

int16_t montgomery_reduce(int32_t a)
{
  int32_t t;
  int16_t u;

  u = a * QINV;
  t = (int32_t)u * KYBER_Q;
  t = a - t;
  t >>= 16;
  return t;
}

static int16_t fqmul(int16_t a, int16_t b)
{
  return montgomery_reduce((int32_t)a * b);
}

int print_poly(poly *test)
{
  for (int i = 0; i < 256; i++) {
    printf("0x%04x\n", (uint16_t)test->coeffs[i]);
  }
  return 0;
}

void test_fqmul(void)
{
  int16_t a = 23, b = 17;
  int16_t r;

  r = fqmul(a, b);                 // Montgomery domain
  printf("Montgomery: %d\n", r);

  printf("Normal: %d\n", montgomery_reduce(r));
}

int test_ntt(poly test)
{
  for (int i = 0; i < 256; i++) {
    test.coeffs[i] = i;
  }

  poly_tomont(&test);
  poly_ntt(&test);
  print_poly(&test);

  return 0;
}

int main(void)
{
  // poly test;
  // test_ntt(test);

  test_fqmul();
  return 0;
}
