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
typedef unsigned int u32;
typedef unsigned char u8;

static u32 load_u32_be(const u8 *b, u32 n)
{
    return ((u32)b[4 * n] << 24) |
           ((u32)b[4 * n + 1] << 16) |
           ((u32)b[4 * n + 2] << 8) |
           ((u32)b[4 * n + 3]);
}

static void store_u32_be(u32 v, u8 *b)
{
    b[0] = (u8)(v >> 24);
    b[1] = (u8)(v >> 16);
    b[2] = (u8)(v >> 8);
    b[3] = (u8)(v);
}

#define rotl(x, n) (((x) << (n)) | ((x) >> (32 - (n))))

# define GETU32(p)       ((u32)(p)[0]<<24|(u32)(p)[1]<<16|(u32)(p)[2]<<8|(u32)(p)[3])
# define PUTU32(p,v)     ((p)[0]=(u8)((v)>>24),(p)[1]=(u8)((v)>>16),(p)[2]=(u8)((v)>>8),(p)[3]=(u8)(v))

//轮函数密钥结构体
typedef struct {
    u32 rk[SM4_NUM_ROUNDS];
} sm4_key_t;
int sm4_set_key(const uint8_t *key, sm4_key_t *ks);
void sm4_set_encrypt_key(sm4_key_t *key, const unsigned char user_key[16]);
void sm4_set_decrypt_key(sm4_key_t *key, const unsigned char user_key[16]);



//加密方法
void sm4_basic_encrypt_block(const unsigned char* in, unsigned char* out,
    const sm4_key_t *key, size_t block);
void sm4_basic_encrypt(const unsigned char in[16], unsigned char out[16],
    const sm4_key_t *key);
void sm4_T_encrypt_block(const unsigned char* in, unsigned char* out,
    const sm4_key_t *key, size_t block);
void sm4_T_encrypt(const unsigned char in[16], unsigned char out[16],
    const sm4_key_t *key);
void sm4_avx2_encrypt(const unsigned char *in, unsigned char *out, const sm4_key_t *key);

void sm4_avx2_encrypt_block(const unsigned char *in, unsigned char *out, const sm4_key_t *key, size_t block);

// # define SM4_decrypt(in,out,key)  sm4_encrypt(in,out,key)


// void sm4_ecb_encrypt(const unsigned char *in, unsigned char *out,
//     const sm4_key_t *key, int enc);
// void sm4_cbc_encrypt(const unsigned char *in, unsigned char *out,
//     size_t len, const sm4_key_t *key, unsigned char *iv, int enc);
// void sm4_cfb128_encrypt(const unsigned char *in, unsigned char *out,
//     size_t len, const sm4_key_t *key, unsigned char *iv, int *num, int enc);

// int sm4_wrap_key(sm4_key_t *key, const unsigned char *iv,
//     unsigned char *out, const unsigned char *in, unsigned int inlen);
// int sm4_unwrap_key(sm4_key_t *key, const unsigned char *iv,
//     unsigned char *out, const unsigned char *in, unsigned int inlen);

// void sm4_ctr32_encrypt_blocks(const unsigned char *in, unsigned char *out,
//     size_t blocks, const sm4_key_t *key, const unsigned char iv[16]);



// void speedtest();
#endif /* SM4_h */
