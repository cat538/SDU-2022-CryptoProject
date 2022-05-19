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
#include <benchmark/benchmark.h>

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

void speedtest(void (*sm4_enc) (const uint8_t*, uint8_t*, const sm4_key_t*)){
    (*sm4_enc)(plaintext, buf, &key);
}

static void sm4_basic_speed(benchmark::State& state) {
    sm4_set_key(user_key,&key);
    for (auto _ : state) {
        speedtest(sm4_encrypt);
    }
}

static void sm4_T_speed(benchmark::State& state) {
    sm4_set_key(user_key,&key);
    for (auto _ : state) {
        sm4_T_encrypt(plaintext, buf, &key);
        //speedtest(sm4_encrypt);
    }
}
BENCHMARK(sm4_basic_speed);
BENCHMARK(sm4_T_speed);
BENCHMARK_MAIN();
