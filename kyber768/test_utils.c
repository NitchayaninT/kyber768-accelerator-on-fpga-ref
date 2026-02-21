#include "test_utils.h"
#include <stdint.h>

int16_t mod_q(int16_t number) { return ((number % 3329) + 3329) % 3329; }

void get_testcase_path(char *test_case_path, char *filename) {
  const char *home = getenv("HOME");
  if (home) {
    snprintf(test_case_path, 256, "%s/kyber/data/test_case/%s", home, filename);
    printf("%s\n", test_case_path);
  }
}

void get_test_result_path(char *test_case_path, char *filename) {
  const char *home = getenv("HOME");
  if (home) {
    snprintf(test_case_path, 256, "%s/kyber/data/test_result/%s", home,
             filename);
    printf("%s\n", test_case_path);
  }
}

void read_ram_in(poly *poly, const char *path) {
  FILE *fp = fopen(path, "r");
  if (!fp) {
    perror("fopen");
    return;
  }
  char buf[10];
  int16_t number;
  for (int i = 0; i < 128; i++) {
    if (fscanf(fp, "%4s", buf) != 1)
      break;
    number = (int16_t)strtol(buf, NULL, 16);
    number = mod_q(number);
    poly->coeffs[(2 * i) + 1] = number;
    if (fscanf(fp, "%4s", buf) != 1)
      break;
    number = (int16_t)strtol(buf, NULL, 16);
    number = mod_q(number);
    poly->coeffs[2 * i] = number;
    // printf("index %d : %d\nindex %d : %d\n", i*2, poly->coeffs[i*2], i*2+1,
    // poly->coeffs[i*2+1]);
  }
  fclose(fp);
}

void read_ram_out(poly *poly, const char *path) {
  FILE *fp = fopen(path, "r");
  if (!fp) {
    perror("fopen");
    return;
  }
  char buf[10];
  int16_t number;
  for (int i = 0; i < 256; i++) {
    if (fscanf(fp, "%4s", buf) != 1)
      break;
    number = (int16_t)strtol(buf, NULL, 16);
    number = mod_q(number);
    poly->coeffs[i] = number;
    // printf("index %d : %d\n", i, poly->coeffs[i]);
  }
  fclose(fp);
}

void compare_poly(poly *poly_c, poly *poly_verilog) {
  int16_t c, verilog;
  for (int i = 0; i < 256; i++) {
    c = mod_q(poly_c -> coeffs[i]);
    verilog = mod_q(poly_verilog -> coeffs[i]);
    if (c == verilog) {
      printf("index : %d [MATCHING]\n", i);
      printf("C:%d    Verilog:%d\n", c, verilog);
    } else {
      printf("index : %d [NOT MATCH]!!!!!!!!!!!!!!!!\n", i);
      printf("C:%d    Verilog:%d\n", c, verilog);
      break;
    }
  }
}

void print_poly(poly *p) {
  for (int i = 0; i < 256; i++) {
    printf("index %d: %04x\n", i, (uint16_t)p->coeffs[i]);
  }
}
