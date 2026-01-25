#include <stdio.h>
#include <inttypes.h>
#include "ntt.h"
#include "poly.h"
#include "polyvec.h"
#include "reduce.h"

int16_t montgomery_reduce(int32_t a);
static int16_t fqmul(int16_t a, int16_t b);
void test_fqmul();
void test_clt();
int print_poly(poly * test);
int test_ntt(poly test);
