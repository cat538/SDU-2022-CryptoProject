// Vectorized implementation of SM4. Uses affine transformations and AES NI
// to implement the SM4 S-Box.

#include <x86intrin.h>
#include "SM4.h"
#include "SM4_local.h"
#include <immintrin.h>
// Encrypt 4 blocks (64 bytes) in ECB mode

#define GET_BLKS(x0, x1, x2, x3, in)                    \
    t0 = _mm_i32gather_epi32((int *)(in+4*0), vindex, 4);    \
    t1 = _mm_i32gather_epi32((int *)(in+4*1), vindex, 4);    \
    t2 = _mm_i32gather_epi32((int *)(in+4*2), vindex, 4);    \
    t3 = _mm_i32gather_epi32((int *)(in+4*3), vindex, 4);    \
    x0 = _mm_shuffle_epi8(t0, vindex_swap);            \
    x1 = _mm_shuffle_epi8(t1, vindex_swap);            \
    x2 = _mm_shuffle_epi8(t2, vindex_swap);            \
    x3 = _mm_shuffle_epi8(t3, vindex_swap)
    
# define PUT_BLKS(out, x0, x1, x2, x3)                    \
    t0 = _mm_shuffle_epi8(x0, vindex_swap);            \
    t1 = _mm_shuffle_epi8(x1, vindex_swap);            \
    t2 = _mm_shuffle_epi8(x2, vindex_swap);            \
    t3 = _mm_shuffle_epi8(x3, vindex_swap);            \
    _mm_storeu_si128((__m128i *)(out+16*0), t0);            \
    _mm_storeu_si128((__m128i *)(out+16*1), t1);            \
    _mm_storeu_si128((__m128i *)(out+16*2), t2);            \
    _mm_storeu_si128((__m128i *)(out+16*3), t3);            \
    x0 = _mm_i32gather_epi32((int *)(out+4*0), vindex_read, 4);    \
    x1 = _mm_i32gather_epi32((int *)(out+4*1), vindex_read, 4);    \
    x2 = _mm_i32gather_epi32((int *)(out+4*2), vindex_read, 4);    \
    x3 = _mm_i32gather_epi32((int *)(out+4*3), vindex_read, 4);    \
    _mm_storeu_si128((__m128i *)(out+16*0), x0);            \
    _mm_storeu_si128((__m128i *)(out+16*1), x1);            \
    _mm_storeu_si128((__m128i *)(out+16*2), x2);            \
    _mm_storeu_si128((__m128i *)(out+16*3), x3)

# define _mm_rotl_epi32(a, i)    _mm_xor_si128(            \
    _mm_slli_epi32(a, i), _mm_srli_epi32(a, 32 - i))
            

#define SM4_NI_T(x0, x1, x2, x3, x4, i){\
    t0 = _mm_set1_epi32(*(rk + i));                \
    t1 = _mm_xor_si128(x1, x2);                    \
    t2 = _mm_xor_si128(x3, t0);                    \
    x4 = _mm_xor_si128(t1, t2);                    \
    t1 = _mm_and_si128(x4, c0f);                   \
    t1 = _mm_shuffle_epi8(m1l, t1);                \
    x4 = _mm_srli_epi64(x4, 4);                    \
    x4 = _mm_and_si128(x4, c0f);                   \
    x4 = _mm_shuffle_epi8(m1h, x4);                \
    x4 = _mm_xor_si128(x4, t1);                    \
    x4 = _mm_shuffle_epi8(x4, shr);           \
    x4 = _mm_aesenclast_si128(x4, c0f);       \
    t1 = _mm_andnot_si128(x4, c0f);           \
    t1 = _mm_shuffle_epi8(m2l, t1);           \
    x4 = _mm_srli_epi64(x4, 4);               \
    x4 = _mm_and_si128(x4, c0f);              \
    x4 = _mm_shuffle_epi8(m2h, x4);           \
    x4 = _mm_xor_si128(x4,t1);                \
    t1 = _mm_shuffle_epi8(x4, r08);           \
    t2 = _mm_shuffle_epi8(x4, r16);           \
    t1 = _mm_xor_si128(t1,t2);                \
    t1 = _mm_xor_si128(t1,x4);                \
    t1 = _mm_rotl_epi32(t1,2);                \
    t2 = _mm_shuffle_epi8(x4, r24);           \
    t1 = _mm_xor_si128(t1,t2);                \
    x4 = _mm_xor_si128(x4,t1);                \
    x4 = _mm_xor_si128(x4,x0);                \
}            
      
 
# define INDEX_MASK_TBOX 0xff
#define ROUND SM4_NI_T
# define INDEX_MASK INDEX_MASK_TBOX

void sm4_ni_encrypt_block(const unsigned char *in, unsigned char *out, const sm4_key_t *key,
    size_t blocks){
     const int *rk = (int *)key->rk;
    __m128i x0, x1, x2, x3, x4;
    __m128i t0, t1, t2, t3;
    __m128i vindex = _mm_setr_epi32(0,4,8,12);
    __m128i vindex_mask = _mm_set1_epi32(INDEX_MASK);
    __m128i vindex_read = _mm_setr_epi32(0,4,8,12);//0,8,16,24);
    __m128i vindex_swap = _mm_setr_epi8(3,2,1,0,7,6,5,4,11,10,9,8,15,14,13,12);
    __m128i r08 = _mm_setr_epi8(3,0,1,2,7,4,5,6,11,8,9,10,15,12,13,14);
    __m128i r16 = _mm_setr_epi8(2,3,0,1,6,7,4,5,10,11,8,9,14,15,12,13);
    __m128i r24 = _mm_setr_epi8(1,2,3,0,5,6,7,4,9,10,11,8,13,14,15,12);
    __m128i shr = _mm_setr_epi8(0,13,10,7,4,1,14,11,8,5,2,15,12,9,6,3);
    __m128i c0f = _mm_set1_epi8(0xf);
    __m128i m1l = _mm_setr_epi32(0x74720701,0x9197E2E4,0x22245157,0xC7C1B4B2);
    __m128i m1h = _mm_setr_epi32(0xEB49A200,0xE240AB09,0xF95BB012,0xF052B91B);
    __m128i m2l = _mm_setr_epi32(0xA19D0834,0x5B67F2CE,0x172BBE82,0xEDD14478);
    __m128i m2h = _mm_setr_epi32(0x73AFDC00,0xAE7201DD,0xCC1063BF,0x11CDBE62);

    while (blocks >= 4) {
        GET_BLKS(x0, x1, x2, x3, in);
        ROUNDS(x0, x1, x2, x3, x4);
        PUT_BLKS(out, x0, x4, x3, x2);
        in += 64;
        out += 64;
        blocks -= 4;
    }
    while (blocks--) {
        sm4_T_encrypt(in, out, key);
        in += 16;
        out += 16;
    }
}


