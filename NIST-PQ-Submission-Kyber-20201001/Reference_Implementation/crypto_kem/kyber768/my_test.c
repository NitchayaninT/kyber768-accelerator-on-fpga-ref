#include <stdio.h>
#include <inttypes.h>
#include "poly.h"
#include "polyvec.h"
#include "params.h"
#include "cbd.h"
#include "fips202.h"
#include "symmetric.h"
#include "indcpa.h"

#define MONT 2285 // 2^16 mod q
#define QINV 62209 // q^-1 mod 2^16
//#define shake128_absorb FIPS202_NAMESPACE(_shake128_absorb)
//void shake128_absorb(keccak_state *state, const uint8_t *in, size_t inlen);

/*
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
/*
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
}/*
/*************************************************
* Name:        gen_matrix
*
* Description: Deterministically generate matrix A (or the transpose of A)
*              from a seed. Entries of the matrix are polynomials that look
*              uniformly random. Performs rejection sampling on output of
*              a XOF
*
* Arguments:   - polyvec *a:          pointer to ouptput matrix A
*              - const uint8_t *seed: pointer to input seed
*              - int transposed:      boolean deciding whether A or A^T
*                                     is generated
**************************************************/
#define gen_a(A,B)  gen_matrix(A,B,0)
#define gen_at(A,B) gen_matrix(A,B,1)

#define GEN_MATRIX_NBLOCKS ((12*KYBER_N/8*(1 << 12)/KYBER_Q \
                             + XOF_BLOCKBYTES)/XOF_BLOCKBYTES)
// Not static for benchmarking
void gen_matrix(polyvec *a, const uint8_t seed[KYBER_SYMBYTES], int transposed)
{
  unsigned int ctr, i, j, k;
  unsigned int buflen, off;
  uint8_t buf[GEN_MATRIX_NBLOCKS*XOF_BLOCKBYTES+2];
  xof_state state;

  for(i=0;i<KYBER_K;i++) {
    for(j=0;j<KYBER_K;j++) {
      if(transposed)
        xof_absorb(&state, seed, i, j);
      else
        xof_absorb(&state, seed, j, i);

      xof_squeezeblocks(buf, GEN_MATRIX_NBLOCKS, &state);
      buflen = GEN_MATRIX_NBLOCKS*XOF_BLOCKBYTES;
      ctr = rej_uniform(a[i].vec[j].coeffs, KYBER_N, buf, buflen);

      while(ctr < KYBER_N) {
        off = buflen % 3;
        for(k = 0; k < off; k++)
          buf[k] = buf[buflen - off + k];
        xof_squeezeblocks(buf + off, 1, &state);
        buflen = off + XOF_BLOCKBYTES;
        ctr += rej_uniform(a[i].vec[j].coeffs + ctr, KYBER_N - ctr, buf, buflen);
      }
    }
  }
}
/*int16_t montgomery_reduce(int32_t a)
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


void test_fqmul(void)
{
  int16_t a = 23, b = 17;
  int16_t r;

  r = fqmul(a, b);                 // Montgomery domain
  printf("a:%02d b:%02d\n", a, b);
  printf("Montgomery: %d\n", r);
  printf("Normal: %d\n", montgomery_reduce(r));

  a = -1044; b = 128;
  r = fqmul(a,b);
  printf("a:%02d b:%02d\n", a, b);
  printf("Montgomery: %d\n", r);
  printf("Normal: %d\n", montgomery_reduce(r));
}
void test_clt(void){
  int16_t a = 1, b = 129, zeta = -758;
  int16_t r = fqmul(zeta, b);
  printf("r = %"PRId16"\n", r);
  printf("out0 = %"PRId16", out1 = %"PRId16"\n", a+r, a-r);
}

int print_poly(poly *test)
{
  for (int i = 0; i < 256; i++) {
    printf("0x%04x\n", (uint16_t)test->coeffs[i]);
  }
  return 0;
}

int test_ntt(poly test)
{
  for (int16_t i = 0; i < 256; i++) {
    test.coeffs[i] = i;
  }

  poly_ntt(&test);
  //print_poly(&test);
  return 0;
}*/
void test_matrix_gen(){
  polyvec a[KYBER_K];
  const char *seed = "hf8f11229044dfea54ddc214aaa439e7ea06b9b4ede8a3e3f6dfef500c9665598";
  gen_matrix(a, seed, 1);

  // print 3x3 polys (Kyber768)
  for (int i = 0; i < KYBER_K; i++) {
    for (int j = 0; j < KYBER_K; j++) {
      printf("=== A^T[%d][%d] ===\n", i, j);
      for (int k = 0; k < 256; k++) {
        printf("%d ", a[i].vec[j].coeffs[k]);
      }
      printf("\n");
    }
  }
}

void test_hash(poly *test){
  const char *seed_stream = "dbe65936fac169bd5d7888e1012ca9df90cb3392ca34000e5fbaad4c95d06f27664952e488193d313722ca38591337989f502d9188faafb9b9472b6d5c85948abb752c72483f54a2bd80378740052ddcd10e55b9499f0ec1ae2487b6931fbefd29953a7eaa0d36a614812dbb8466036a0866b98c2740b864c8a679f051599c8667b230bd85ccbd294e7f3d7c2edfc9532d47791f77e0aff4425da8199b48eb9e3a44b40d24ce21f19d9747aa41c3ca9a0f40b4a8c79e1bdaf86fb52cc226373fa523bab2af1e46e5fd046f4dfd05137d5dde7c1bcb584e717e93d03e8f9d1a4a8bf581f7455d44f4dc0d8e25913e82c417ef29bf2d26cddac2c9adb74efeeee4e6d3f13faaa12e430258e5c7a37c37584db6fab6008f8832003b15d0a5af18dcc766496b922242012a8a2a4c0511ac71476629fc9d5871939278803bdf9ec049e75f83da4956fc4e7c9b62307e6ffdf1a73387ae69ca267e8cd9844473bfc24ce6b08ab9447dca14a62a032514b71a3d69f3e532152c68d02180c170ca99951a748a17592011d946dbe3e0d14d8e4005e90c19189ff2826a94a067ac021ac76db1699ee2b6ddda083f45e29e2d537e4500032536668d5917fb1c4fe8a73f31799a3df8b130d368513b3a18a24f6623207337249b137851d67624c458ce6cef1a63257e3d92cb61cce10f9e979049a6d9b3194fcaa2f5743b976a9de7b4dcf61568e639cf61df867ba391d6f27bca44f5adac07e09e088cda63f8a5214450ce313e350c10a65d34975041a73f78c8968c6e75a0895adc506359095ccdb936cbbf2426fb53fdc53414cddeb8d6a95de8a9debd8634ebeb861ca0d3551feef5f4b39154acb90c697ec1d25101950fac0623a53fef8647ce485b07a082e9c2d7dd598b053984b21916ee66a153528fb631255541f9b4e5ae8fe837a706c2ced50679";
 // const char *coin_stream ="99abf40515a7387aa7a41f83840467aaba58818583cae85ec7710efbeb5dce0a5e91f3fa854b8570aaa4393e663ef90458d0d9823e682c1062947b54c496ef8a9bb38198777295bb264c790628226b8a3a3ce2172d0d0c5534d8dc67d0c1155c4a98b3559c84fa82d90e4cfc474b2fda6b38ca4f0ef964bd4efd4b5cd5be6696";
  //uint8_t buf[672]; // buffer of bytes
  int16_t coeffs[256];
  uint8_t buf[672];

  for (int i = 0; i < 672; i++) {
    sscanf(&seed_stream[i * 2], "%2hhx", &buf[i]);
  }
  for (int i = 0; i < 672; i++) printf("%02x", buf[i]);
  printf("\n");

  int n = rej_uniform(coeffs, 256, buf, 672);

    printf("Generated %u coeffs\n", n);
      for (int i = 0; i < 256; i++)
          printf("%d ", coeffs[i]);
      printf("\n");

  // 2*(256/4) = 128 bytes per poly
  //cbd_eta2(test, buf);
  //printf("Generated Noise bytes\n");
}

static uint64_t load64(const uint8_t x[8]) {
  unsigned int i;
  uint64_t r = 0;

  for(i=0;i<8;i++)
    r |= (uint64_t)x[i] << 8*i;

  return r;
}

/*void shake128_absorb(uint64_t s[25],
                          unsigned int r,
                          const uint8_t *m)//,
                          //size_t mlen,
                          //uint8_t p)
{
  size_t i;
  uint8_t t[200] = {0};

  Zero state 
  for(i=0;i<25;i++)
    s[i] = 0;


    // r = 168
  for(i=0;i<r/8;i++)
    s[i] ^= load64(m + 8*i);
  
  printf("state_out =");
  for(int i = 0; i < 25;i++){
    printf("%h", s[i]);
  }
  printf("\n");
    /*
  while(mlen >= r) {
  

    KeccakF1600_StatePermute(s);
    mlen -= r;
    m += r;
  }

  for(i=0;i<mlen;i++)
    t[i] = m[i];
  t[i] = p;
  t[r1] |= 128;
  for(i=0;i<r/8;i++)
    s[i] ^= load64(t + 8*i); 
}*/
void kyber_shake128_absorb(keccak_state *state,
                           const uint8_t seed[KYBER_SYMBYTES],
                           uint8_t x,
                           uint8_t y)
{
  unsigned int i;
  uint8_t extseed[KYBER_SYMBYTES+2];

  for(i=0;i<KYBER_SYMBYTES;i++)
    extseed[i] = seed[i];
  extseed[i++] = x;
  extseed[i]   = y;

  shake128_absorb(state, extseed, sizeof(extseed));
}

void test_keccak_absorb(){
  keccak_state state;
  int8_t m = "f8f11229044dfea54ddc214aaa439e7ea06b9b4ede8a3e3f6dfef500c9665598";
  unsigned int r = 168;
  kyber_shake128_absorb(&state,m,0,0);
  //f8f11229044dfea54ddc214aaa439e7ea06b9b4ede8a3e3f6dfef500c9665598
}
int main(void)
{
  test_keccak_absorb();
  //poly test;
  //test_matrix_gen();
  //test_fqmul();
  //test_ntt(test);
  //test_hash(&test);
  //test_hash(&test);

  //test_fqmul();
  //test_clt();

  return 0;
}
