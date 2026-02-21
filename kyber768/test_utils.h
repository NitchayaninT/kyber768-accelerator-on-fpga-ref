#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <inttypes.h>
#include "poly.h"

void get_testcase_path(char *test_case_path, char *filename);
void get_test_result_path(char *test_case_path, char *filename);
void read_ram_in(poly *poly, const char *path) ;
void read_ram_out(poly *poly, const char *path) ;
void compare_poly(poly *poly_c, poly *poly_verilog);
int16_t mod_q(int16_t number);
void print_poly(poly *p);
