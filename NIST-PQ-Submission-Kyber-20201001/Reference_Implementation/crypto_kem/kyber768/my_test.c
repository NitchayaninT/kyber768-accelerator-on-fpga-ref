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
  uint8_t m[32] = {248, 241, 18, 41, 4, 77, 254, 165, 77, 220, 33, 74, 170, 67, 158, 126, 160, 107, 155, 78, 222, 138, 62, 63, 109, 254, 245, 0, 201, 102, 85, 152};
//  const char *seed = "f8f11229044dfea54ddc214aaa439e7ea06b9b4ede8a3e3f6dfef500c9665598";
  gen_matrix(a, m, 1);

  // print 3x3 polys (Kyber768)
  /*
  for (int i = 0; i < KYBER_K; i++) {
    for (int j = 0; j < KYBER_K; j++) {
      printf("=== A^T[%d][%d] ===\n", i, j);
      for (int k = 0; k < 256; k++) {
        printf("%d ", a[i].vec[j].coeffs[k]);
      }
      printf("\n");
    } 
  }*/
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

  uint8_t buf_py[672] = {219, 230, 89, 54, 250, 193, 105, 189, 93, 120, 136, 225, 1, 44, 169, 223, 144, 203, 51, 146, 202, 52, 0, 14, 95, 186, 173, 76, 149, 208, 111, 39, 102, 73, 82, 228, 136, 25, 61, 49, 55, 34, 202, 56, 89, 19, 55, 152, 159, 80, 45, 145, 136, 250, 175, 185, 185, 71, 43, 109, 92, 133, 148, 138, 187, 117, 44, 114, 72, 63, 84, 162, 189, 128, 55, 135, 64, 5, 45, 220, 209, 14, 85, 185, 73, 159, 14, 193, 174, 36, 135, 182, 147, 31, 190, 253, 41, 149, 58, 126, 170, 13, 54, 166, 20, 129, 45, 187, 132, 102, 3, 106, 8, 102, 185, 140, 39, 64, 184, 100, 200, 166, 121, 240, 81, 89, 156, 134, 103, 178, 48, 189, 133, 204, 189, 41, 78, 127, 61, 124, 46, 223, 201, 83, 45, 71, 121, 31, 119, 224, 175, 244, 66, 93, 168, 25, 155, 72, 235, 158, 58, 68, 180, 13, 36, 206, 33, 241, 157, 151, 71, 170, 65, 195, 202, 154, 15, 64, 180, 168, 199, 158, 27, 218, 248, 111, 181, 44, 194, 38, 55, 63, 165, 35, 186, 178, 175, 30, 70, 229, 253, 4, 111, 77, 253, 5, 19, 125, 93, 222, 124, 27, 203, 88, 78, 113, 126, 147, 208, 62, 143, 157, 26, 74, 139, 245, 129, 247, 69, 93, 68, 244, 220, 13, 142, 37, 145, 62, 130, 196, 23, 239, 41, 191, 45, 38, 205, 218, 194, 201, 173, 183, 78, 254, 238, 228, 230, 211, 241, 63, 170, 161, 46, 67, 2, 88, 229, 199, 163, 124, 55, 88, 77, 182, 250, 182, 0, 143, 136, 50, 0, 59, 21, 208, 165, 175, 24, 220, 199, 102, 73, 107, 146, 34, 66, 1, 42, 138, 42, 76, 5, 17, 172, 113, 71, 102, 41, 252, 157, 88, 113, 147, 146, 120, 128, 59, 223, 158, 192, 73, 231, 95, 131, 218, 73, 86, 252, 78, 124, 155, 98, 48, 126, 111, 253, 241, 167, 51, 135, 174, 105, 202, 38, 126, 140, 217, 132, 68, 115, 191, 194, 76, 230, 176, 138, 185, 68, 125, 202, 20, 166, 42, 3, 37, 20, 183, 26, 61, 105, 243, 229, 50, 21, 44, 104, 208, 33, 128, 193, 112, 202, 153, 149, 26, 116, 138, 23, 89, 32, 17, 217, 70, 219, 227, 224, 209, 77, 142, 64, 5, 233, 12, 25, 24, 159, 242, 130, 106, 148, 160, 103, 172, 2, 26, 199, 109, 177, 105, 158, 226, 182, 221, 218, 8, 63, 69, 226, 158, 45, 83, 126, 69, 0, 3, 37, 54, 102, 141, 89, 23, 251, 28, 79, 232, 167, 63, 49, 121, 154, 61, 248, 177, 48, 211, 104, 81, 59, 58, 24, 162, 79, 102, 35, 32, 115, 55, 36, 155, 19, 120, 81, 214, 118, 36, 196, 88, 206, 108, 239, 26, 99, 37, 126, 61, 146, 203, 97, 204, 225, 15, 158, 151, 144, 73, 166, 217, 179, 25, 79, 202, 162, 245, 116, 59, 151, 106, 157, 231, 180, 220, 246, 21, 104, 230, 57, 207, 97, 223, 134, 123, 163, 145, 214, 242, 123, 202, 68, 245, 173, 172, 7, 224, 158, 8, 140, 218, 99, 248, 165, 33, 68, 80, 206, 49, 62, 53, 12, 16, 166, 93, 52, 151, 80, 65, 167, 63, 120, 200, 150, 140, 110, 117, 160, 137, 90, 220, 80, 99, 89, 9, 92, 205, 185, 54, 203, 191, 36, 38, 251, 83, 253, 197, 52, 20, 205, 222, 184, 214, 169, 93, 232, 169, 222, 189, 134, 52, 235, 235, 134, 28, 160, 211, 85, 31, 238, 245, 244, 179, 145, 84, 172, 185, 12, 105, 126, 193, 210, 81, 1, 149, 15, 172, 6, 35, 165, 63, 239, 134, 71, 206, 72, 91, 7, 160, 130, 233, 194, 215, 221, 89, 139, 5, 57, 132, 178, 25, 22, 238, 102, 161, 83, 82, 143, 182, 49, 37, 85, 65, 249, 180, 229, 174, 143, 232, 55, 167, 6, 194, 206, 213, 6, 121};
  int n = rej_uniform(coeffs, 256, buf_py, 672);

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

/*void test_keccak_absorb(){
  keccak_state state;
  int8_t m = "f8f11229044dfea54ddc214aaa439e7ea06b9b4ede8a3e3f6dfef500c9665598";
  unsigned int r = 168;
  kyber_shake128_absorb(&state,m,0,0);
  //f8f11229044dfea54ddc214aaa439e7ea06b9b4ede8a3e3f6dfef500c9665598
}*/
int main(void)
{
  //test_keccak_absorb();
  //poly test;
  test_matrix_gen();
  //test_fqmul();
  //test_ntt(test);
  //test_hash(&test);
  //test_hash(&test);

  //test_fqmul();
  //test_clt();

  return 0;
}
