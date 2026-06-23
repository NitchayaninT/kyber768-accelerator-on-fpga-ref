#ifndef TEST_ENCRYPTION_H
#define TEST_ENCRYPTION_H

#include <stdio.h>
#include <stdint.h>
#include "params.h"
#include "kem.h"
#include "indcpa.h"
#include "fips202.h"
#include "symmetric.h"
#include "rng.h"

void test_encryption_timing(void);
void test_encryption_verify(void);

#endif
