#include <stdio.h>
#include <inttypes.h>
#include "ntt.h"
#include "poly.h"
#include "polyvec.h"
#include "reduce.h"
#include "test_utils.h"

int16_t montgomery_reduce(int32_t a);
static int16_t fqmul(int16_t a, int16_t b);
void test_fqmul();
void test_butterfly();
void test_ntt();
void test_inv_ntt();
