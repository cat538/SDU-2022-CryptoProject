/*
 * Copyright (c) 2014 - 2021 The GmSSL Project.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * 3. All advertising materials mentioning features or use of this
 *    software must display the following acknowledgment:
 *    "This product includes software developed by the GmSSL Project.
 *    (http://gmssl.org/)"
 *
 * 4. The name "GmSSL Project" must not be used to endorse or promote
 *    products derived from this software without prior written
 *    permission. For written permission, please contact
 *    guanzhi1980@gmail.com.
 *
 * 5. Products derived from this software may not be called "GmSSL"
 *    nor may "GmSSL" appear in their names without prior written
 *    permission of the GmSSL Project.
 *
 * 6. Redistributions of any form whatsoever must retain the following
 *    acknowledgment:
 *    "This product includes software developed by the GmSSL Project
 *    (http://gmssl.org/)"
 *
 * THIS SOFTWARE IS PROVIDED BY THE GmSSL PROJECT ``AS IS'' AND ANY
 * EXPRESSED OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE GmSSL PROJECT OR
 * ITS CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 */
#include <iostream>
#include <cstdio>
#include <cstring>
#include <stdlib.h>
#include <gmssl/sm3.h>
#include <random>
#include <omp.h>
#include <time.h>
#include <chrono>
int main(int argc, char **argv)
{
	SM3_CTX sm3_ctx;
	std::string plain= "bithday attack for SM3 HASH";
	uint8_t buf[4096];
	ssize_t len;
	uint8_t dgst[32];
	int i;
	memcpy(buf,plain.c_str(),plain.size());
	
	sm3_init(&sm3_ctx);
	//len = fread(buf, 1, sizeof(buf), stdin);
	sm3_update(&sm3_ctx, buf, len);
	sm3_finish(&sm3_ctx, dgst);
	srand(time(NULL));
	dgst[4] &= 0xf;
	for (i = 0; i < sizeof(dgst); i++) {
		printf("%02x", dgst[i]);
	}
	printf("\n");
	auto start_time = std::chrono::steady_clock::now(); 
	uint8_t attack_array[32]={0};
	uint64_t cnt=0;
	#pragma omp parallel for(8)
	for(;;cnt++){
		int flag = memcmp(dgst,&cnt,5);
		if(flag==0 ){
			std::cout<<"attack success"<<std::endl;
			std::cout<<std::hex<<(int) cnt ;
			break;
		}
		if(cnt > (((uint64_t)1<<44)-1) )break;
 	}
	auto end_time = std::chrono::steady_clock::now(); 
    auto running_time = end_time - start_time;
	printf("\n");
    std::cout << "Bithday Attack for SM3 = " 
              << std::chrono::duration <double, std::milli> (running_time).count() << " ms" << std::endl;
	
	
	return 0;
}
