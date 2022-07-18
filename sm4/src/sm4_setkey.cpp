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

    K[0] = load_uint32(key, 0) ^ FK[0];
    K[1] = load_uint32(key, 1) ^ FK[1];
    K[2] = load_uint32(key, 2) ^ FK[2];
    K[3] = load_uint32(key, 3) ^ FK[3];

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
