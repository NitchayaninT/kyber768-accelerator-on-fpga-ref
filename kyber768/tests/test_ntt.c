#include "test_ntt.h"
#include "reduce.h"
#include <stdint.h>

void test_ntt() {
  poly *r = malloc(sizeof(poly));
  poly *r_verilog = malloc(sizeof(poly));

  char path[256];
  get_test_result_path(path, "ntt.hex");

  if (read_ram_out(r_verilog, path) == -1) {
    printf("Error Files not found\n");
    return;
  };

  get_testcase_path(path, "main_compute/r1_32bits.mem");
  // get_testcase_path(path, "ntt.mem");
  if (read_ram_in(r, path) == -1) {
    printf("Error Files not found\n");
    return;
  }
  // print_poly(r); same poly is loaded (verified)

  // ntt(r->coeffs); // this is wrong since poly_ntt also apply barrett reduce
  poly_ntt(r);

  compare_poly(r, r_verilog);

  free(r);
  free(r_verilog);
}

void test_inv_ntt() {
  poly *r = malloc(sizeof(poly));
  poly *r_verilog = malloc(sizeof(poly));

  char path[256];
  get_test_result_path(path, "inv_ntt.hex");

  if (read_ram_out(r_verilog, path) == -1) {
    printf("Error Files not found\n");
    return;
  };

  get_test_result_path(path, "main_compute/pvbm_at0_32bits.hex");
  // get_testcase_path(path, "ntt.mem");
  if (read_ram_in(r, path) == -1) {
    printf("Error Files not found\n");
    return;
  }
  // print_poly(r); same poly is loaded (verified)

  // ntt(r->coeffs); // this is wrong since poly_ntt also apply barrett reduce
  poly_invntt_tomont(r);

  compare_poly_modq(r, r_verilog);

  free(r);
  free(r_verilog);
}
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

void test_butterfly(void) {

  // -------- NTT (Cooley-Tukey) --------
  int16_t a = 3328, b = 556;
  int16_t zeta = 2226;

  int16_t t = fqmul(zeta, b);
  int16_t out0 = a + t;
  int16_t out1 = a - t;

  printf("NTT   out0 = %" PRId16 ", out1 = %" PRId16 "\n", mod_q(out0),
         mod_q(out1));

  // -------- INV NTT (Gentleman-Sande) --------
  a = 3328;
  b = 556;

  int16_t u = a + b;
  int16_t v = a - b;
  t = fqmul(zeta, v);

  printf("INV   out0 = %" PRId16 ", out1 = %" PRId16 "\n", mod_q(u), mod_q(t));
}
