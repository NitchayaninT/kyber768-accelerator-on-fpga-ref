#include "poly.h"
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

void get_testcase_path(char *test_case_path, char *filename);
void get_test_result_path(char *test_result_path, char *filename);
int read_ram_16bits(poly *poly, const char *path);
int read_ram_in(poly *poly, const char *path);
int read_ram_out(poly *poly, const char *path);
int compare_poly(poly *poly_c, poly *poly_verilog);
int compare_poly_modq(poly *poly_c, poly *poly_verilog);
int compare_poly_verbose(poly *poly_c, poly *poly_verilog);
int16_t mod_q(int16_t number);
void print_poly(poly *p);
