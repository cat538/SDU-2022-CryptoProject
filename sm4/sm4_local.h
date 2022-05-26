//
//  SM4_local.h
//  SM4
//
//  Created by Christine  Lin on 12/01/2022.
//  Copyright © 2022 Christine  Lin. All rights reserved.
//

#ifndef SM4_local_h
#define SM4_local_h
#include "sm4.h"
extern const uint8_t SM4_S[256]; //S盒
extern const uint32_t SM4_T[256]; //T置换
extern const uint32_t SM4_D[65536];

# define _mm_rotl_epi32(a, i)    _mm_xor_si128(            \
    _mm_slli_epi32(a, i), _mm_srli_epi32(a, 32 - i))

# define _mm256_rotl_epi32(a, i)    _mm256_xor_si256(            \
    _mm256_slli_epi32(a, i), _mm256_srli_epi32(a, 32 - i))

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



#define GET_BLKS256(x0, x1, x2, x3, in)                    \
    t0 = _mm256_i32gather_epi32((int *)(in+4*0), vindex, 4);    \
    t1 = _mm256_i32gather_epi32((int *)(in+4*1), vindex, 4);    \
    t2 = _mm256_i32gather_epi32((int *)(in+4*2), vindex, 4);   \
    t3 = _mm256_i32gather_epi32((int *)(in+4*3), vindex, 4);    \
    x0 = _mm256_shuffle_epi8(t0, vindex_swap);            \
    x1 = _mm256_shuffle_epi8(t1, vindex_swap);            \
    x2 = _mm256_shuffle_epi8(t2, vindex_swap);            \
    x3 = _mm256_shuffle_epi8(t3, vindex_swap)
    

# define PUT_BLKS256(out, x0, x1, x2, x3)                    \
    t0 = _mm256_shuffle_epi8(x0, vindex_swap);            \
    t1 = _mm256_shuffle_epi8(x1, vindex_swap);            \
    t2 = _mm256_shuffle_epi8(x2, vindex_swap);            \
    t3 = _mm256_shuffle_epi8(x3, vindex_swap);            \
    _mm256_storeu_si256((__m256i *)(out+32*0), t0);            \
    _mm256_storeu_si256((__m256i *)(out+32*1), t1);            \
    _mm256_storeu_si256((__m256i *)(out+32*2), t2);            \
    _mm256_storeu_si256((__m256i *)(out+32*3), t3);            \
    x0 = _mm256_i32gather_epi32((int *)(out+8*0), vindex_read, 4);    \
    x1 = _mm256_i32gather_epi32((int *)(out+8*1), vindex_read, 4);    \
    x2 = _mm256_i32gather_epi32((int *)(out+8*2), vindex_read, 4);    \
    x3 = _mm256_i32gather_epi32((int *)(out+8*3), vindex_read, 4);    \
    _mm256_storeu_si256((__m256i *)(out+32*0), x0);            \
    _mm256_storeu_si256((__m256i *)(out+32*1), x1);            \
    _mm256_storeu_si256((__m256i *)(out+32*2), x2);            \
    _mm256_storeu_si256((__m256i *)(out+32*3), x3)

#define ROUNDS(x0, x1, x2, x3, x4)        \
    ROUND(x0, x1, x2, x3, x4, 0);        \
    ROUND(x1, x2, x3, x4, x0, 1);        \
    ROUND(x2, x3, x4, x0, x1, 2);        \
    ROUND(x3, x4, x0, x1, x2, 3);        \
    ROUND(x4, x0, x1, x2, x3, 4);        \
    ROUND(x0, x1, x2, x3, x4, 5);        \
    ROUND(x1, x2, x3, x4, x0, 6);        \
    ROUND(x2, x3, x4, x0, x1, 7);        \
    ROUND(x3, x4, x0, x1, x2, 8);        \
    ROUND(x4, x0, x1, x2, x3, 9);        \
    ROUND(x0, x1, x2, x3, x4, 10);        \
    ROUND(x1, x2, x3, x4, x0, 11);        \
    ROUND(x2, x3, x4, x0, x1, 12);        \
    ROUND(x3, x4, x0, x1, x2, 13);        \
    ROUND(x4, x0, x1, x2, x3, 14);        \
    ROUND(x0, x1, x2, x3, x4, 15);        \
    ROUND(x1, x2, x3, x4, x0, 16);        \
    ROUND(x2, x3, x4, x0, x1, 17);        \
    ROUND(x3, x4, x0, x1, x2, 18);        \
    ROUND(x4, x0, x1, x2, x3, 19);        \
    ROUND(x0, x1, x2, x3, x4, 20);        \
    ROUND(x1, x2, x3, x4, x0, 21);        \
    ROUND(x2, x3, x4, x0, x1, 22);        \
    ROUND(x3, x4, x0, x1, x2, 23);        \
    ROUND(x4, x0, x1, x2, x3, 24);        \
    ROUND(x0, x1, x2, x3, x4, 25);        \
    ROUND(x1, x2, x3, x4, x0, 26);        \
    ROUND(x2, x3, x4, x0, x1, 27);        \
    ROUND(x3, x4, x0, x1, x2, 28);        \
    ROUND(x4, x0, x1, x2, x3, 29);        \
    ROUND(x0, x1, x2, x3, x4, 30);        \
    ROUND(x1, x2, x3, x4, x0, 31)



#endif /* SM4_local_h */
