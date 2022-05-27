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
#include <string.h>
#include <stdlib.h>
#include <openssl/sm3.h>
#include <time.h>
#include <chrono>
#include <stdio.h>
#include <stdlib.h>

using namespace std;


struct item {
	unsigned char dgst[SM3_DIGEST_LENGTH]{};
};

void sm3(const unsigned char* msg, size_t msglen, unsigned char dgst[SM3_DIGEST_LENGTH]) {
	sm3_ctx_t ctx;

	sm3_init(&ctx);
	sm3_update(&ctx, msg, msglen);
	sm3_final(&ctx, dgst);

	memset(&ctx, 0, sizeof(sm3_ctx_t));
}


int main(int argc, char** argv)
{
	unsigned char msg[] = "Rho method of reduced SM3";
	size_t Rho_length = 10;
	size_t cmp_len = 2;

	item* Rho = new item[Rho_length];
	sm3(msg, strlen(msg), Rho[0].dgst);
	int i = 0;
	while (memcmp(Rho[i].dgst, Rho[(i + 1) % Rho_length].dgst, cmp_len) != 0) {
		sm3(Rho[i].dgst, SM3_DIGEST_LENGTH, Rho[(i + 1) % Rho_length].dgst);
		i = (i + 1) % Rho_length;
	}
	std::cout << "succeed!Get one Rho" << std::endl;
	i = (i + 1) % Rho_length;
	for (int j = 0; j < Rho_length; j++) {
		for (int k = 0; k < SM3_DIGEST_LENGTH; k++)
			printf("%02x", Rho[i].dgst[k]);
		printf("\n");
		i = (i + 1) % Rho_length;
	}
	return 0;
}