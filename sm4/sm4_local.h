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
# define ROL32(a,n)     (((a)<<(n))|(((a)&0xffffffff)>>(32-(n))))

#define S32(A)                    \
    ((SM4_S[((A) >> 24)       ] << 24) ^    \
     (SM4_S[((A) >> 16) & 0xff] << 16) ^    \
     (SM4_S[((A) >>  8) & 0xff] <<  8) ^    \
     (SM4_S[((A))       & 0xff]))

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
