#include "test_ntt.h"
/*int16_t montgomery_reduce(int32_t a)
{
  int32_t t;
  int16_t u;

  u = a * QINV;
  t = (int32_t)u * KYBER_Q;
  t = a - t;
  t >>= 16;
  return t;
}
*/
static int16_t fqmul(int16_t a, int16_t b)
{
  return montgomery_reduce((int32_t)a * b);
}

void test_fqmul(void)
{
  int16_t a = 23, b = 17;
  int16_t r;

  r = fqmul(a, b);                 // Montgomery domain
  printf("a:%02d b:%02d\n", a, b);
  printf("Montgomery: %d\n", r);
  printf("Normal: %d\n", montgomery_reduce(r));

  a = -1044; b = 128;
  r = fqmul(a,b);
  printf("a:%02d b:%02d\n", a, b);
  printf("Montgomery: %d\n", r);
  printf("Normal: %d\n", montgomery_reduce(r));
}
void test_clt(void){
  int16_t a = 1, b = 129, zeta = -758;
  int16_t r = fqmul(zeta, b);
  printf("r = %"PRId16"\n", r);
  printf("out0 = %"PRId16", out1 = %"PRId16"\n", a+r, a-r);
}

int print_poly(poly *test)
{
  for (int i = 0; i < 256; i++) {
    printf("0x%04x\n", (uint16_t)test->coeffs[i]);
  }
  return 0;
}

int test_ntt(poly test)
{
  for (int16_t i = 0; i < 256; i++) {
    test.coeffs[i] = i;
  }

  poly_ntt(&test);
  //print_poly(&test);
  return 0;
}

