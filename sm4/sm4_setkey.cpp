//
//  SM4_setkey.c
//  SM4
//
//  Created by Christine  Lin on 12/01/2022.
//  Copyright © 2022 Christine  Lin. All rights reserved.
//

#include "sm4_local.h"
#include "sm4.h"
#include "sm4_constant.h"
// static uint32_t FK[4] = {
//     0xa3b1bac6, 0x56aa3350, 0x677d9197, 0xb27022dc,
// };

// static uint32_t CK[32] = {
//     0x00070e15, 0x1c232a31, 0x383f464d, 0x545b6269,
//     0x70777e85, 0x8c939aa1, 0xa8afb6bd, 0xc4cbd2d9,
//     0xe0e7eef5, 0xfc030a11, 0x181f262d, 0x343b4249,
//     0x50575e65, 0x6c737a81, 0x888f969d, 0xa4abb2b9,
//     0xc0c7ced5, 0xdce3eaf1, 0xf8ff060d, 0x141b2229,
//     0x30373e45, 0x4c535a61, 0x686f767d, 0x848b9299,
//     0xa0a7aeb5, 0xbcc3cad1, 0xd8dfe6ed, 0xf4fb0209,
//     0x10171e25, 0x2c333a41, 0x484f565d, 0x646b7279,
// };

// //32字节左移n位
// //循环左移函数
// #define L32_(x)                \
//     ((x) ^                     \
//     ROL32((x), 13) ^           \
//     ROL32((x), 23))

// //加密第i轮，C = x0^x4 = x0^L(S(x1^x2^x3^rki))
// #define ENC_ROUND(x0, x1, x2, x3, x4, i)    \
//     x4 = x1 ^ x2 ^ x3 ^ *(CK + i);          \
//     x4 = S32(x4);                           \
//     x4 = x0 ^ L32_(x4);                     \
//     *(rk + i) = x4

// //解密第i轮，密钥逆使用
// #define DEC_ROUND(x0, x1, x2, x3, x4, i)    \
//     x4 = x1 ^ x2 ^ x3 ^ *(CK + i);          \
//     x4 = S32(x4);                           \
//     x4 = x0 ^ L32_(x4);                     \
//     *(rk + 31 - i) = x4

//用户密钥unsigned char数组 -> sm4_key_t结构体


int sm4_set_key(const uint8_t *key, sm4_key_t *ks)
{
    /*
     * Family Key
     */
    static const uint32_t FK[4] =
        { 0xa3b1bac6, 0x56aa3350, 0x677d9197, 0xb27022dc };

    /*
     * Constant Key
     */
    static const uint32_t CK[32] = {
        0x00070E15, 0x1C232A31, 0x383F464D, 0x545B6269,
        0x70777E85, 0x8C939AA1, 0xA8AFB6BD, 0xC4CBD2D9,
        0xE0E7EEF5, 0xFC030A11, 0x181F262D, 0x343B4249,
        0x50575E65, 0x6C737A81, 0x888F969D, 0xA4ABB2B9,
        0xC0C7CED5, 0xDCE3EAF1, 0xF8FF060D, 0x141B2229,
        0x30373E45, 0x4C535A61, 0x686F767D, 0x848B9299,
        0xA0A7AEB5, 0xBCC3CAD1, 0xD8DFE6ED, 0xF4FB0209,
        0x10171E25, 0x2C333A41, 0x484F565D, 0x646B7279
    };

    uint32_t K[4];
    int i;

    K[0] = load_u32_be(key, 0) ^ FK[0];
    K[1] = load_u32_be(key, 1) ^ FK[1];
    K[2] = load_u32_be(key, 2) ^ FK[2];
    K[3] = load_u32_be(key, 3) ^ FK[3];

    for (i = 0; i != SM4_NUM_ROUNDS; ++i) {
        uint32_t X = K[(i + 1) % 4] ^ K[(i + 2) % 4] ^ K[(i + 3) % 4] ^ CK[i];
        uint32_t t = 0;

        t |= ((uint32_t)SM4_SBOX[(uint8_t)(X >> 24)]) << 24;
        t |= ((uint32_t)SM4_SBOX[(uint8_t)(X >> 16)]) << 16;
        t |= ((uint32_t)SM4_SBOX[(uint8_t)(X >> 8)]) << 8;
        t |= SM4_SBOX[(uint8_t)X];

        t = t ^ rotl(t, 13) ^ rotl(t, 23);
        K[i % 4] ^= t;
        ks->rk[i] = K[i % 4];
    }

    return 1;
}

// void sm4_set_encrypt_key(sm4_key_t *key, const unsigned char user_key[16])
// {
//     uint32_t *rk = key->rk;
//     uint32_t x0, x1, x2, x3, x4;

//     x0 = GETU32(user_key     ) ^ FK[0];
//     x1 = GETU32(user_key  + 4) ^ FK[1];
//     x2 = GETU32(user_key  + 8) ^ FK[2];
//     x3 = GETU32(user_key + 12) ^ FK[3];
// #define ROUND ENC_ROUND
//     ROUNDS(x0, x1, x2, x3, x4);
// #undef ROUND
//     x0 = x1 = x2 = x3 = x4 = 0;
// }


// void sm4_set_decrypt_key(sm4_key_t *key, const unsigned char user_key[16])
// {
//     uint32_t *rk = key->rk;
//     uint32_t x0, x1, x2, x3, x4;

//     x0 = GETU32(user_key     ) ^ FK[0];
//     x1 = GETU32(user_key  + 4) ^ FK[1];
//     x2 = GETU32(user_key  + 8) ^ FK[2];
//     x3 = GETU32(user_key + 12) ^ FK[3];

// #define ROUND DEC_ROUND
//     ROUNDS(x0, x1, x2, x3, x4);
// #undef ROUND

//     x0 = x1 = x2 = x3 = x4 = 0;
// }
