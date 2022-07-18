//
//  SM4.h
//  SM4
//
//  Created by Christine  Lin on 07/01/2022.
//  Copyright © 2022 Christine  Lin. All rights reserved.
//

#ifndef SM4_h
#define SM4_h

# define SM4_KEY_LENGTH        16
# define SM4_BLOCK_SIZE        16
# define SM4_IV_LENGTH        (sm4_BLOCK_SIZE)
# define SM4_NUM_ROUNDS        32
# include <string.h>
#include <stdint.h>   
#include <stdio.h>

static uint32_t load_uint32(const uint8_t *b, uint32_t n)
{
    return ((uint32_t)b[4 * n] << 24) |
           ((uint32_t)b[4 * n + 1] << 16) |
           ((uint32_t)b[4 * n + 2] << 8) |
           ((uint32_t)b[4 * n + 3]);
}

static void store_uint32(uint32_t v, uint8_t *b)
{
    b[0] = (uint8_t)(v >> 24);
    b[1] = (uint8_t)(v >> 16);
    b[2] = (uint8_t)(v >> 8);
    b[3] = (uint8_t)(v);
}

#define rotl(x, n) (((x) << (n)) | ((x) >> (32 - (n))))

//轮函数密钥结构体
typedef struct {
    uint32_t rk[SM4_NUM_ROUNDS];
} sm4_key_t;
int sm4_set_key(const uint8_t *key, sm4_key_t *ks);
void sm4_set_encrypt_key(sm4_key_t *key, const uint8_t user_key[16]);
void sm4_set_decrypt_key(sm4_key_t *key, const uint8_t user_key[16]);



//加密方法
void sm4_basic_encrypt_block(const uint8_t* in, uint8_t* out,
    const sm4_key_t *key, size_t block);
void sm4_basic_encrypt(const uint8_t in[16], uint8_t out[16],
    const sm4_key_t *key);
void sm4_T_encrypt_block(const uint8_t* in, uint8_t* out,
    const sm4_key_t *key, size_t block);
void sm4_T_encrypt(const uint8_t in[16], uint8_t out[16],
    const sm4_key_t *key);

void sm4_avx2_encrypt_block(const uint8_t *in, uint8_t *out, const sm4_key_t *key, size_t block);
void sm4_ni_encrypt_block(const uint8_t *in, uint8_t *out, const sm4_key_t *key, size_t blocks);

void sm4_avx2ni_encrypt_block(const uint8_t *in, uint8_t *out, const sm4_key_t *key, size_t blocks);

void printLineItem(uint8_t* addr,int len,int colSize);
#endif /* SM4_h */

