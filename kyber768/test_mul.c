#include "test_mul.h"

void test_polyvec_basemul() {
  polyvec *a = malloc(sizeof(polyvec));
  polyvec *b = malloc(sizeof(polyvec));
  poly *r = malloc(sizeof(poly));
  poly *r_verilog = malloc(sizeof(poly));

  // get the value of polyvec a and b from files;
  char path[256];
  get_testcase_path(path, "pvbm_a0.mem");
  read_ram_in(&a->vec[0], path);
  get_testcase_path(path, "pvbm_a1.mem");
  read_ram_in(&a->vec[1], path);
  get_testcase_path(path, "pvbm_a2.mem");
  read_ram_in(&a->vec[2], path);

  get_testcase_path(path, "pvbm_b0.mem");
  read_ram_in(&b->vec[0], path);
  get_testcase_path(path, "pvbm_b1.mem");
  read_ram_in(&b->vec[1], path);
  get_testcase_path(path, "pvbm_b2.mem");
  read_ram_in(&b->vec[2], path);

  polyvec_pointwise_acc_montgomery(r, a, b);

  // get value of result from verilog code
  get_test_result_path(path, "polyvec_basemul.hex");
  read_ram_out(r_verilog, path);
  compare_poly(r, r_verilog);
  /*
  for (int i = 0; i < 256; i++) {
    if (r->coeffs[i] == r_verilog->coeffs[i])
      printf("[MATCHING] index : %d\n", i);
    else
      printf("[NOT MATCH] index : %d !!!!!!!!!!!!!!!!\n", i);
    printf("C:%d    Verilog:%d\n", r->coeffs[i], r_verilog->coeffs[i]);
  }
  */

  free(a);
  free(b);
  free(r);
  free(r_verilog);
}

void test_poly_basemul() {
  poly *a = malloc(sizeof(poly));
  poly *b = malloc(sizeof(poly));
  poly *r = malloc(sizeof(poly));
  poly *r_verilog = malloc(sizeof(poly));
  char path[256] = "/home/pakin/kyber/data/test_result/poly_basemul.hex";
  read_ram_out(r_verilog, path);
  snprintf(path, sizeof(path), "/home/pakin/kyber/data/test_case/pbm_a.mem");
  read_ram_in(a, path);
  snprintf(path, sizeof(path), "/home/pakin/kyber/data/test_case/pbm_b.mem");
  read_ram_in(b, path);
  poly_basemul_montgomery(r, a, b);

  for (int i = 0; i < 256; i++) {
    r->coeffs[i] = (((r->coeffs[i]) % 3329) + 3329) % 3329;
    if (r->coeffs[i] == r_verilog->coeffs[i])
      printf("[MATCH] Index %d, a=%d, b=%d\n", i, a->coeffs[i], b->coeffs[i]);
    else
      printf("[NOT MATCH] Index %d, a=%d, b=%d\n[NOT_MATCH] ", i, a->coeffs[i],
             b->coeffs[i]);
    printf("C:%d    Verilog:%d\n", r->coeffs[i], r_verilog->coeffs[i]);
  }

  FILE *fp;
  fopen("output.csv", "w");
  if (!fp) {
    perror("fopen");
    return;
  }

  fprintf(fp, "index,status,a,b,c,verilog\n");

  for (int i = 0; i < 256; i++) {
    r->coeffs[i] = (((r->coeffs[i]) % 3329) + 3329) % 3329;

    const char *status =
        (r->coeffs[i] == r_verilog->coeffs[i]) ? "MATCH" : "NOT_MATCH";

    fprintf(fp, "%d,%s,%d,%d,%d,%d\n", i, status, a->coeffs[i], b->coeffs[i],
            r->coeffs[i], r_verilog->coeffs[i]);
  }

  fclose(fp);
  free(a);
  free(b);
  free(r);
  free(r_verilog);
}



void test_barrett() {
  int16_t a = (int16_t)-9645;
  int16_t r;
  r = barrett_reduce(a);
  printf("%d\n", r);
  a = (int16_t)4369;
  r = barrett_reduce(a);
  printf("%d\n", r);
}
/*
// for barett reductions = 20159
 int16_t t;
 const int16_t v = ((1U << 26) + KYBER_Q / 2) / KYBER_Q;
 printf("%d", v);
*/

void test_basemul() {
  int16_t result[2];
  int16_t a[2], b[2], zeta;
  a[0] = (int16_t)1675;
  a[1] = (int16_t)1057;
  b[0] = (int16_t)3110;
  b[1] = (int16_t)1746;
  zeta = 1628;
  basemul(result, a, b, zeta);
  result[0] = ((result[0] % 3329) + 3329) % 3329;
  result[1] = ((result[1] % 3329) + 3329) % 3329;
  printf("basemul_r0 = [0]%" PRId16 "\nbasemul_r0 = [1]%" PRId16 "\n",
         result[0], result[1]);

  a[0] = (int16_t)2983;
  a[1] = (int16_t)1509;
  b[0] = (int16_t)1897;
  b[1] = (int16_t)497;
  zeta = -zeta;
  basemul(result, a, b, zeta);
  result[0] = ((result[0] % 3329) + 3329) % 3329;
  result[1] = ((result[1] % 3329) + 3329) % 3329;
  printf("basemul_r1 = [0]%" PRId16 "\nbasemul_r1 = [1]%" PRId16 "\n",
         result[0], result[1]);
}
