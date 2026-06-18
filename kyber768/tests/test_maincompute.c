#include "test_maincompute.h"
#include "poly.h"
#include "polyvec.h"
#include <stdlib.h>
#define STR_SIZE 256
void test_main_compute() {
  polyvec a_t[3];
  polyvec t_vec;
  polyvec r;
  char path[STR_SIZE], poly_name[STR_SIZE];
  int count = 0;

  // load same teste case that is used in verilog testbench
  for (int i = 0; i < 3; i++) {
    for (int j = 0; j < 3; j++) {
      sprintf(poly_name, "main_compute/at%d.mem", count++);
      get_testcase_path(path, poly_name);
      printf("count %d : ", count);
      read_ram_16bits(&a_t[i].vec[j], path);
    }
  }

  for (int i = 0; i < 3; i++) {
    sprintf(poly_name, "main_compute/tvec%d.mem", i);
    get_testcase_path(path, poly_name);
    read_ram_16bits(&t_vec.vec[i], path);
  }

  for (int i = 0; i < 3; i++) {
    sprintf(poly_name, "main_compute/r%d.mem", i);
    get_testcase_path(path, poly_name);
    read_ram_16bits(&r.vec[i], path);
  }

  printf("\nVerify ntt\n");
  // load ram result after ntt step produce by main_computation_tb
  polyvec ntt_result_verilog;
  for (int i = 0; i < 3; i++) {
    sprintf(poly_name, "main_compute/ntt%d.hex", i);
    get_test_result_path(path, poly_name);
    read_ram_out(&ntt_result_verilog.vec[i], path);
  }

  // run C reference poly_vec_ntt
  polyvec_ntt(&r);

  // compare the result get from C and from verilog
  for (int i = 0; i < 3; i++) {
    printf("ntt result %d\n", i);
    compare_poly(&r.vec[i], &ntt_result_verilog.vec[i]);
  }

  // run C reference polyvec_pointwise_acc_montgomery
  polyvec pvbm_result_at;
  poly pvbm_result_tvec;
  for (int i = 0; i < 3; i++) {
    polyvec_pointwise_acc_montgomery(&pvbm_result_at.vec[i], &a_t[i], &r);
  }
  polyvec_pointwise_acc_montgomery(&pvbm_result_tvec, &t_vec, &r);

  // load ram result after polyvec_basemul_montgomery produde by
  // main_computation_tb
  polyvec pvbm_result_at_verilog;
  poly pvbm_result_tvec_verilog;
  printf("\nVerify polyvec basemul montgomery\n");
  for (int i = 0; i < 3; i++) {
    sprintf(poly_name, "main_compute/pvbm_at%d.hex", i);
    get_test_result_path(path, poly_name);
    read_ram_out(&pvbm_result_at_verilog.vec[i], path);
    printf("Polynomial multiplication at[%d] x r\n", i);
    compare_poly(&pvbm_result_at.vec[i], &pvbm_result_at_verilog.vec[i]);
  }
  get_test_result_path(path, "main_compute/pvbm_tvec.hex");
  read_ram_out(&pvbm_result_tvec_verilog, path);
    printf("Polynomial multiplication t_vec x r\n");
    compare_poly(&pvbm_result_tvec, &pvbm_result_tvec_verilog);


  polyvec_invntt_tomont(&pvbm_result_at);
  poly_invntt_tomont(&pvbm_result_tvec);

  polyvec * inv_ntt_result_at = &pvbm_result_at;
  poly * inv_ntt_result_tvec = &pvbm_result_tvec;
  polyvec inv_ntt_result_at_verilog;
  poly  inv_ntt_result_tvec_verilog;

  printf("\nVerify inv_ntt\n");
  for (int i = 0; i < 3; i++) {
    sprintf(poly_name, "main_compute/inv_ntt_at%d.hex", i);
    get_test_result_path(path, poly_name);
    read_ram_out(&inv_ntt_result_at_verilog.vec[i], path);
    printf("Inverse NTT at[%d]\n", i);
    compare_poly(&inv_ntt_result_at->vec[i], &inv_ntt_result_at_verilog.vec[i]);
  }
  
  get_test_result_path(path, "main_compute/inv_ntt_tvec.hex");
  read_ram_out(&inv_ntt_result_tvec_verilog, path);
    printf("Inverse ntt t_vec x r\n");
    compare_poly(inv_ntt_result_tvec, &inv_ntt_result_tvec_verilog);

  polyvec u;
  poly v;
  printf("\nreg write out\n");
  for (int i = 0; i < 3; i++) {
    sprintf(poly_name, "main_compute/u%d.hex", i);
    get_test_result_path(path, poly_name);
    read_ram_out(&u.vec[i], path);
    printf("write reg u[%d]\n", i);
    compare_poly(&inv_ntt_result_at->vec[i], &u.vec[i]);
  }
  
  get_test_result_path(path, "main_compute/v.hex");
  read_ram_out(&v, path);
    printf("Inverse ntt t_vec x r\n");
    compare_poly(inv_ntt_result_tvec, &v);
}
