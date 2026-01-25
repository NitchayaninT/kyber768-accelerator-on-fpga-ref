#include <stdio.h>
#include <inttypes.h>
#include "polyvec.h"
#include "params.h"
#include "cbd.h"
#include "indcpa.h"
#include "fips202.h"
#include "symmetric.h"

void test_matrix_gen();
void test_hash(poly *test);
void test_keccak_absorb();
