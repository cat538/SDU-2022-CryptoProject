#include <iostream>
#include <string.h>
#include <stdlib.h>
#include <openssl/evp.h>
#include <time.h>
#include <chrono>
#include <stdio.h>
#include <stdlib.h>

using namespace std;
#define SM3_DIGEST_LENGTH 32 

struct item {
	unsigned char dgst[SM3_DIGEST_LENGTH]{};
};

void sm3(const unsigned char* msg, size_t msglen, unsigned char dgst[SM3_DIGEST_LENGTH]) {
	uint32_t out_size = 32;
	EVP_Digest(msg,msglen,dgst,&out_size,EVP_sm3(),NULL);
}


int main(int argc, char** argv)
{
	unsigned char msg[] = "Rho method of reduced SM3";
	size_t Rho_length = 10;
	size_t cmp_len = 2;

	item* Rho = new item[Rho_length];
	sm3(msg, 26, Rho[0].dgst);
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