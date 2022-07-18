//
//  SM4_enc_avx2.c
//  SM4
//
//  Created by Christine  Lin on 12/01/2022.
//  Copyright © 2022 Christine  Lin. All rights reserved.
//

#include "sm4.h"
#include "sm4_constant.h"
#include "sm4_local.h"
#include <immintrin.h>



# define _mm256_rotl_epi32(a, i)    _mm256_xor_si256(            \
    _mm256_slli_epi32(a, i), _mm256_srli_epi32(a, 32 - i))

# define INDEX_MASK_TBOX 0xff


# define AVX2NI_T(x0, x1, x2, x3, x4, i)                \
    t0 = _mm256_set1_epi32(*(rk + i));                \
    t1 = _mm256_xor_si256(x1, x2);                    \
    t2 = _mm256_xor_si256(x3, t0);                    \
    x4 = _mm256_xor_si256(t1, t2);                    \
    t0 = _mm256_and_si256(x4, vindex_mask);                \
    t0 = _mm256_i32gather_epi32((int *)SM4_TBOX3, t0, 4);        \
    x4 = _mm256_srli_epi32(x4, 8);                    \
    x0 = _mm256_xor_si256(x0, t0);                    \
    t0 = _mm256_and_si256(x4, vindex_mask);                \
    t0 = _mm256_i32gather_epi32((int *)SM4_TBOX2, t0, 4);        \
    x4 = _mm256_srli_epi32(x4, 8);                    \
    x0 = _mm256_xor_si256(x0, t0);                    \
    t0 = _mm256_and_si256(x4, vindex_mask);                \
    t0 = _mm256_i32gather_epi32((int *)SM4_TBOX1, t0, 4);        \
    x4 = _mm256_srli_epi32(x4, 8);                    \
    x0 = _mm256_xor_si256(x0, t0);                    \
    t1 = _mm256_i32gather_epi32((int *)SM4_TBOX0, x4, 4);        \
    x4 = _mm256_xor_si256(x0, t1)

# define ROUND AVX2NI_T

# define INDEX_MASK INDEX_MASK_TBOX


void sm4_avx2_encrypt_block(const uint8_t *in, uint8_t *out, const sm4_key_t *key,size_t blocks)
{
    
    const int *rk = (int *)key->rk;
    __m256i x0, x1, x2, x3, x4;
    __m256i t0, t1, t2, t3;
    __m256i vindex = _mm256_setr_epi32(0,4,8,12,16,20,24,28);
    __m256i vindex_mask = _mm256_set1_epi32(INDEX_MASK);
    __m256i vindex_read = _mm256_setr_epi32(0,8,16,24,1,9,17,25);
    __m256i vindex_swap = _mm256_setr_epi8(
        3,2,1,0,7,6,5,4,11,10,9,8,15,14,13,12,
        3,2,1,0,7,6,5,4,11,10,9,8,15,14,13,12
    );
    while (blocks >= 8) {
        GET_BLKS256(x0, x1, x2, x3, in);
        ROUNDS(x0, x1, x2, x3, x4);
        PUT_BLKS256(out, x0, x4, x3, x2);
        in += 128;
        out += 128;
        blocks -= 8;
    }
    
    while (blocks--) {
        sm4_T_encrypt(in, out, key);
        in += 16;
        out += 16;
    }
}


