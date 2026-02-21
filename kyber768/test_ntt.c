#include "test_ntt.h"
#include <stdint.h>
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
static int16_t fqmul(int16_t a, int16_t b) {
  return montgomery_reduce((int32_t)a * b);
}

void test_fqmul(void) {
  int16_t a = 746, b = 1818;
  int16_t r;

  r = fqmul(a, b); // Montgomery domain
  printf("a:%02d b:%02d\n", a, b);
  printf("Montgomery: %d\n", r);
  printf("Normal: %d\n", montgomery_reduce(r));

  /*
  a = 17417; b = -14255;
  r = fqmul(a, b);                 // Montgomery domain
  printf("a:%02d b:%02d\n", a, b);
  printf("Montgomery: %d\n", r);
  printf("Normal: %d\n", montgomery_reduce(r));
  */
}

void test_clt(void) {
  int16_t a = 4505, b = 556;
  int16_t zeta = 2226;
  int16_t r = fqmul(zeta, b);
  printf("r = %" PRId16 "\n", r);
  printf("out0 = %" PRId16 ", out1 = %" PRId16 "\n", mod_q(a + r),
         mod_q(a - r));
}

// TODO now the compute step give correct output, next check safe
void test_ntt() {
  poly *r = malloc(sizeof(poly));
  poly *r_verilog = malloc(sizeof(poly));

  char path[256];
  get_test_result_path(path, "ntt.hex");
  read_ram_out(r_verilog, path);

  get_testcase_path(path, "ntt.mem");
  read_ram_in(r, path);
  //print_poly(r); same poly is loaded (verified)

  ntt(r->coeffs);

  compare_poly(r, r_verilog);

  free(r);
  free(r_verilog);
}
