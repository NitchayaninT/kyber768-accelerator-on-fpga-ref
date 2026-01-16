#include <stdio.h>
#include <inttypes.h>
#include "poly.h"
#include "params.h"
#include "cbd.h"

#define MONT 2285 // 2^16 mod q
#define QINV 62209 // q^-1 mod 2^16

unsigned int rej_uniform(int16_t *r, unsigned int len, const uint8_t *buf, unsigned int buflen)
{
  unsigned int ctr, pos;
  uint16_t val0, val1;
// buf = buffer of bytes (672 bytes)
  ctr = pos = 0;
  while(ctr < len && pos + 3 <= buflen) {
    val0 = ((buf[pos+0] >> 0) | ((uint16_t)buf[pos+1] << 8)) & 0xFFF;
    val1 = ((buf[pos+1] >> 4) | ((uint16_t)buf[pos+2] << 4)) & 0xFFF;
    pos += 3;

    if(val0 < KYBER_Q)
      r[ctr++] = val0;
    if(ctr < len && val1 < KYBER_Q)
      r[ctr++] = val1;
  }
  return ctr;
}

uint32_t load32_littleendian(const uint8_t x[4])
{
  uint32_t r;
  r  = (uint32_t)x[0];
  r |= (uint32_t)x[1] << 8;
  r |= (uint32_t)x[2] << 16;
  r |= (uint32_t)x[3] << 24;
  return r;
}

void cbd2(poly *r, const uint8_t buf[2*KYBER_N/4])
{
  unsigned int i,j;
  uint32_t t,d;
  int16_t a,b;

  for(i=0;i<KYBER_N/8;i++) {
    t  = load32_littleendian(buf+4*i);
    d  = t & 0x55555555;
    d += (t>>1) & 0x55555555;

    for(j=0;j<8;j++) {
      a = (d >> (4*j+0)) & 0x3;
      b = (d >> (4*j+2)) & 0x3;
      r->coeffs[8*i+j] = a - b;
    }
  }
}
void cbd_eta2(poly *r, const uint8_t buf[KYBER_ETA1*KYBER_N/4])
{
#if KYBER_ETA2 != 2
#error "This implementation requires eta2 = 2"
#else
  cbd2(r, buf);
#endif
}
/*
int16_t montgomery_reduce(int32_t a)
{
  int32_t t;
  int16_t u;

  u = a * QINV;
  t = (int32_t)u * KYBER_Q;
  t = a - t;
  t >>= 16;
  return t;
}

static int16_t fqmul(int16_t a, int16_t b)
{
  return montgomery_reduce((int32_t)a * b);
}

int print_poly(poly *test)
{
  for (int i = 0; i < 256; i++) {
    printf("0x%04x\n", (uint16_t)test->coeffs[i]);
  }
  return 0;
}

void test_fqmul(void)
{
  int16_t a = 23, b = 17;
  int16_t r;

  r = fqmul(a, b);                 // Montgomery domain
  printf("Montgomery: %d\n", r);

  printf("Normal: %d\n", montgomery_reduce(r));
}

int test_ntt(poly test)
{
  for (int i = 0; i < 256; i++) {
    test.coeffs[i] = i;
  }

  poly_tomont(&test);
  poly_ntt(&test);
  print_poly(&test);

  return 0;
}*/

int main(void)
{
  poly test;
  // test_ntt(test);
  const char *seed_stream = "b17a22ce5d458ba33d6931d893324e04123b1590846653d49d019a59da9ddd1aad293fc43863b0f63c093b2e9325249a0e45cf390f8ea91fdf9450a90c34babde106958e80184c9dfcf78da5f66fd7f65feef73aced58d4d995606c2ab56d11141ec5e47c6c8baaa5fcc346f9ea76c58389af2cf4df93f38c70f542cbae644577d22fd10d46f4f5c70d72c99775bc9ed7e0c417b6af0e9e545603f42df15d09481539cfef0bdb84b3899339793c2759f4c6d3b73f07f5a2ef7927f39a6ca2b45102a5b2794449c99b04617b2bee4777e043007a9e07eb858f4a49fdb5380e1de3b739c795715f4fc11223f37896d5fce01f63ce25780c462a6f9379a8d112d026133e5b6b6df3795cc374c51785f435d2bcf64e4f6be21e38f7d8c1c447b2e73b9ca12d58a71efbc7d4cae4cb99541d8f5662dc2ad1b4083c449461b60e7ca6bd395bc878cd37eff6ebca7ec10ee6ffbe1f719eec9ebbfd31e60b174c4e4a2940d14ce9343b3c10d9ddd42d92d04c19c1ae1901cb4095fa4e00ee14949ad2f513257e1bc6295e8a0eda314c3ac3b67a0d62a4397efedd96eed0ecba9cc195276800fa0bd99a52dcdbe8d959276e5ace0fb215f3a7b01d781ef77287786653a6e7a15c187709b16854e142910976b0987ac13fd54981c47af0635eb286caeadd9c25c425088160c7965659c1e659c9a5942b330dd5f045ddf6689eac9ea06a1bd59b27768331e8b8d74f8b5c661789989160286a71e740bcd0718d5e8b84a05bdb9aa0964512c452e2feec81ad94069ce5430a05d5b806d311a9a913492a419012859b1884f94698c62a85ac0d7cf91e370d3a14a0d75d1ee3177b29cdf4aac5463b73d722603fcd1c946b71f4d60b1d0619be63b2c10464e8eed2db46d0fa6ba16beaa63a2f5f9ff6ccbe3e70953c633e81da07d3389ef6becfcfdba740b56bc";
  const char *coin_stream ="99abf40515a7387aa7a41f83840467aaba58818583cae85ec7710efbeb5dce0a5e91f3fa854b8570aaa4393e663ef90458d0d9823e682c1062947b54c496ef8a9bb38198777295bb264c790628226b8a3a3ce2172d0d0c5534d8dc67d0c1155c4a98b3559c84fa82d90e4cfc474b2fda6b38ca4f0ef964bd4efd4b5cd5be6696";
  //uint8_t buf[672]; // buffer of bytes
  uint8_t buf[128]; // buffer of bytes
  int16_t coeffs[256];

  /*for (int i = 0; i < 672; i++) {
    sscanf(&seed_stream[i * 2], "%2hhx", &buf[i]);
  }
  for (int i = 0; i < 672; i++) printf("%02x", buf[i]);
    printf("\n");

  int n = rej_uniform(coeffs, 256, buf, 672);
  printf("Generated %u coeffs\n", n);
    for (int i = 0; i < 256; i++)
        printf("%d ", coeffs[i]);
    printf("\n");*/

  for (int i = 0; i < 128; i++) {
    sscanf(&coin_stream[i * 2], "%2hhx", &buf[i]);
  }

  // 2*(256/4) = 128 bytes per poly
  cbd_eta2(&test, buf);
  printf("Generated Noise bytes\n");

  for (int i = 0; i < 256; i++)
    printf("%d ", test.coeffs[i]);

  //test_fqmul();
  return 0;
}