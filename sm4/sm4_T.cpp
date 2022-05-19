
/* Operations */
/* Rotate Left 32-bit number */
#include <stdint.h>   
#include "sm4.h"
#include "sm4_constant.h"


static  uint32_t SM4_T(uint32_t x)
{
    return SM4_TBOX0[(uint8_t)(x >> 24)] ^
           SM4_TBOX1[(uint8_t)(x >> 16)] ^
           SM4_TBOX2[(uint8_t)(x >> 8)] ^
           SM4_TBOX3[(uint8_t)x];
}

#define SM4_ROUNDS(k0, k1, k2, k3, F)   \
  do {                                  \
    x0 ^= F(x1 ^ x2 ^ x3 ^ ks->rk[k0]); \
    x1 ^= F(x0 ^ x2 ^ x3 ^ ks->rk[k1]); \
    x2 ^= F(x0 ^ x1 ^ x3 ^ ks->rk[k2]); \
    x3 ^= F(x0 ^ x1 ^ x2 ^ ks->rk[k3]); \
  } while(0)

void sm4_T_encrypt_block(const uint8_t *in, uint8_t *out, const sm4_key_t *ks, size_t block){
    for (int i = 0; i < block; i++) {
        sm4_T_encrypt(in+ 16*i, out + 16*i, ks);
    }
}

void sm4_T_encrypt(const uint8_t *in, uint8_t *out, const sm4_key_t *ks)
//const uint32_t ks->rk[SM4_KEY_SCHEDULE], const uint8_t *in, uint8_t *out)
{
  uint32_t x0, x1, x2, x3;

  x0 = load_u32_be(in, 0);
  x1 = load_u32_be(in, 1);
  x2 = load_u32_be(in, 2);
  x3 = load_u32_be(in, 3);

  SM4_ROUNDS( 0,  1,  2,  3, SM4_T);
  SM4_ROUNDS( 4,  5,  6,  7, SM4_T);
  SM4_ROUNDS( 8,  9, 10, 11, SM4_T);
  SM4_ROUNDS(12, 13, 14, 15, SM4_T);
  SM4_ROUNDS(16, 17, 18, 19, SM4_T);
  SM4_ROUNDS(20, 21, 22, 23, SM4_T);
  SM4_ROUNDS(24, 25, 26, 27, SM4_T);
  SM4_ROUNDS(28, 29, 30, 31, SM4_T);

  store_u32_be(x3, out);
  store_u32_be(x2, out + 4);
  store_u32_be(x1, out + 8);
  store_u32_be(x0, out + 12);
}

void sm4_T_decrypt(const uint8_t *in, uint8_t *out, const sm4_key_t *ks){
  uint32_t x0, x1, x2, x3;

  x0 = load_u32_be(in, 0);
  x1 = load_u32_be(in, 1);
  x2 = load_u32_be(in, 2);
  x3 = load_u32_be(in, 3);

  SM4_ROUNDS(31, 30, 29, 28, SM4_T);
  SM4_ROUNDS(27, 26, 25, 24, SM4_T);
  SM4_ROUNDS(23, 22, 21, 20, SM4_T);
  SM4_ROUNDS(19, 18, 17, 16, SM4_T);
  SM4_ROUNDS(15, 14, 13, 12, SM4_T);
  SM4_ROUNDS(11, 10,  9,  8, SM4_T);
  SM4_ROUNDS( 7,  6,  5,  4, SM4_T);
  SM4_ROUNDS( 3,  2,  1,  0, SM4_T);

  store_u32_be(x3, out);
  store_u32_be(x2, out + 4);
  store_u32_be(x1, out + 8);
  store_u32_be(x0, out + 12);
}

