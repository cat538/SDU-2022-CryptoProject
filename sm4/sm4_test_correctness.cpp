//
//  main.c
//  SM4
//
//  Created by Christine  Lin on 07/01/2022.
//  Copyright © 2022 Christine  Lin. All rights reserved.
//

#include <stdio.h>
#include <time.h>
#include "sm4.h"
//#define sm4_AVX2 1
void testsm4(int (*sm4_enc) (const uint8_t*, uint8_t*, const sm4_key_t*));
int main(int argc, const char * argv[]) {
    test_sm4(sm4_encrypt);
}


void sm4_avx2_ecb_encrypt_blocks(const unsigned char *in,
    unsigned char *out, size_t blocks, const sm4_key_t *key);
void sm4_ni_ecb_encrypt_blocks(const unsigned char *in, unsigned char *out,
    size_t blocks, const sm4_key_t *key);

void test_sm4(void (*sm4_enc) (const uint8_t*, uint8_t*, const sm4_key_t*)){
     int i;
     unsigned char user_key[16] = {
    0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
    0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10,
    };
    unsigned char plaintext[] = {
        0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
        0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10,
    };
    unsigned char buf[32*4],buf1[32*4],buf2[32*4];
    unsigned char ciphertext1[] = {
        0x68, 0x1e, 0xdf, 0x34, 0xd2, 0x06, 0x96, 0x5e,
        0x86, 0xb3, 0xe9, 0x4f, 0x53, 0x6e, 0x42, 0x46
    };
    sm4_key_t key;
     sm4_set_key(user_key,&key);
     printf("BLOCK nums:%lu\n",sizeof(plaintext)/SM4_BLOCK_SIZE);
     if (memcmp(key.rk, rk, sizeof(rk)) != 0) {
         printf("sm4 key scheduling not passed!\n");
     }else printf("sm4 key scheduling passed!\n");
     

     for (int i = 0; i < sizeof(plaintext)/SM4_BLOCK_SIZE; i++) {
        (*sm4_enc)(plaintext+ 16*i, buf + 16*i, &key);
    }
     if (memcmp(buf, ciphertext1, sizeof(ciphertext1)) != 0) {
         printf("sm4 encrypt not pass!\n");
     }else{
        printf("sm4 encrypt pass!\n");
    }
    //printLineItem(&buf,sizeof(buf),16);

    //  sm4_avx2_ecb_encrypt_blocks(plaintext, buf1, sizeof(plaintext)/SM4_BLOCK_SIZE, &key);
    //  if (memcmp(buf1, buf, sizeof(ciphertext1)) != 0) {
    //      printf("sm4 avx2 encrypt not pass!\n");
    //  }else printf("sm4 avx2 encrypt pass!\n");
     //printLineItem(&buf1,sizeof(buf1),16);


    /*sm4_avx2_ecb_encrypt_blocks(plaintext, buf2, sizeof(plaintext)/SM4_BLOCK_SIZE, &key);
     if (memcmp(buf2, buf, sizeof(ciphertext1)) != 0) {
         printf("sm4 ni encrypt not pass!\n");
         
     }else printf("sm4 ni encrypt pass!\n");*/
     //printLineItem(&buf2,sizeof(buf2),16);
     
}






