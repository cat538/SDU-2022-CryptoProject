
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
#include <stdio.h>


# define INDEX_MASK_TBOX 0xff


# define AVX2NI_T(x0, x1, x2, x3, x4, i)            \
    t0 = _mm256_set1_epi32(*(rk + i));                \
    t1 = _mm256_xor_si256(x1, x2);                    \
    t2 = _mm256_xor_si256(x3, t0);                    \
    x4 = _mm256_xor_si256(t1, t2);                    \
    t1 = _mm256_and_si256(x4, cf);           \
    t1 = _mm256_shuffle_epi8(m1l, t1);                \
    x4 = _mm256_srli_epi64(x4, 4);                    \
    x4 = _mm256_and_si256(x4, cf);           \
    x4 = _mm256_shuffle_epi8(m1h, x4);                \
    x4 = _mm256_xor_si256(x4, t1);                    \
    x4 = _mm256_shuffle_epi8(x4, shr);                \
    k0 = _mm256_extractf128_si256(x4,0);            \
    k1 = _mm256_extractf128_si256(x4,1);            \
    k0 = _mm_aesenclast_si128(k0, c0f);             \
    k1 = _mm_aesenclast_si128(k1, c0f);             \
    x4 = _mm256_loadu2_m128i(&k1,&k0);              \
    t1 = _mm256_andnot_si256(x4, cf);           \
    t1 = _mm256_shuffle_epi8(m2l, t1);           \
    x4 = _mm256_srli_epi64(x4, 4);               \
    x4 = _mm256_and_si256(x4, cf);               \
    x4 = _mm256_shuffle_epi8(m2h, x4);           \
    x4 = _mm256_xor_si256(x4,t1);                \
    t1 = _mm256_shuffle_epi8(x4, r08);           \
    t2 = _mm256_shuffle_epi8(x4, r16);           \
    t1 = _mm256_xor_si256(t1,t2);                \
    t1 = _mm256_xor_si256(t1,x4);                \
    t1 = _mm256_rotl_epi32(t1,2);                \
    t2 = _mm256_shuffle_epi8(x4, r24);           \
    t1 = _mm256_xor_si256(t1,t2);                \
    x4 = _mm256_xor_si256(x4,t1);                \
    x4 = _mm256_xor_si256(x4,x0);                \

# define ROUND AVX2NI_T

# define INDEX_MASK INDEX_MASK_TBOX


void sm4_avx2ni_encrypt_block(const uint8_t *in, uint8_t *out, const sm4_key_t *key,size_t blocks)
{
    
    const int *rk = (int *)key->rk;
    __m256i x0, x1, x2, x3, x4;
    __m256i t0, t1, t2, t3;
    __m128i k0,k1;
    __m256i vindex = _mm256_setr_epi32(0,4,8,12,16,20,24,28);
    __m256i vindex_mask = _mm256_set1_epi32(0xff);
    __m256i vindex_read = _mm256_setr_epi32(0,8,16,24,1,9,17,25);
    __m256i vindex_swap = _mm256_setr_epi8(
        3,2,1,0,7,6,5,4,11,10,9,8,15,14,13,12,
        3,2,1,0,7,6,5,4,11,10,9,8,15,14,13,12
    );
    __m256i cf =  _mm256_set1_epi8(0xf);
    __m128i c0f =  _mm_set1_epi8(0xf);
    __m256i r08 = _mm256_setr_epi8(3,0,1,2,7,4,5,6,11,8,9,10,15,12,13,14,
                                   11,8,9,10,15,12,13,14,19,16,17,18,23,20,21,22);
    __m256i r16 = _mm256_setr_epi8(2,3,0,1,6,7,4,5,10,11,8,9,14,15,12,13,
                                   10,11,8,9,14,15,12,13,18,19,16,17,22,23,20,21);
    __m256i r24 = _mm256_setr_epi8(1,2,3,0,5,6,7,4,9,10,11,8,13,14,15,12,
                                  9,10,11,8,13,14,15,12,17,18,19,16,21,22,23,20);
    __m256i shr = _mm256_setr_epi8(0,13,10,7,4,1,14,11,8,5,2,15,12,9,6,3,
                                  8,21,18,15,12,9,22,19,16,13,10,23,20,17,14,11);
    __m256i m1l = _mm256_setr_epi32(0x74720701,0x9197E2E4,0x22245157,0xC7C1B4B2,
                                    0x74720701,0x9197E2E4,0x22245157,0xC7C1B4B2);
    __m256i m1h = _mm256_setr_epi32(0xEB49A200,0xE240AB09,0xF95BB012,0xF052B91B,
                                0xEB49A200,0xE240AB09,0xF95BB012,0xF052B91B);
    __m256i m2l = _mm256_setr_epi32(0xA19D0834,0x5B67F2CE,0x172BBE82,0xEDD14478,
                                 0xA19D0834,0x5B67F2CE,0x172BBE82,0xEDD14478);
    __m256i m2h = _mm256_setr_epi32(0x73AFDC00,0xAE7201DD,0xCC1063BF,0x11CDBE62,
                                 0x73AFDC00,0xAE7201DD,0xCC1063BF,0x11CDBE62);
    while (blocks >= 8) {
        GET_BLKS256(x0, x1, x2, x3, in);
        ROUNDS(x0, x1, x2, x3, x4);
        //AVX2NI_T(x0, x1, x2, x3, x4, 0);
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

//printLineItem