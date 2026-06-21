#ifndef TEST_HASH_H
#define TEST_HASH_H

#include <stdio.h>
#include <inttypes.h>
#include "params.h"
#include "fips202.h"
#include "symmetric.h"

void test_permutation();
void test_hash_controller();
void test_sponge_controller();

#endif
