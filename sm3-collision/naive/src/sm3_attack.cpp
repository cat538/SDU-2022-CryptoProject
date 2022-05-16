/**
 * A basic implement of birthday attack for SM3.
 * 
 * Calculate SM3 digest with GMssl lib
 * 
 * Parallel acceleration using OpenMP and thread


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
#include <future>
/** parallel with openmp
 * 
 * 
*/
void openmp_version(uint64_t dgst[32]){
	uint8_t attack_array[32]={0};
	uint64_t cnt=0;
	#pragma omp parallel for(8)
	for(;;cnt++){
		int flag = memcmp(dgst,&cnt,5);
		if(flag==0 ){
			std::cout<<"attack success"<<std::endl;
			std::cout<<std::hex<<(int) cnt ;
			return;
		}
		if(cnt > (((uint64_t)1<<44)-1) )break;
 	}	
}


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
	dgst[4] &= 0x3f;
	for (i = 0; i < sizeof(dgst); i++) {
		printf("%02x", dgst[i]);
	}
	printf("\n");
	uint64_t cnt = (uint64_t)1<<35;
	std::future<void > threads[8]; 
	auto routine=[](uint64_t st,uint64_t ed,uint8_t goal[32],auto start_time){
		uint8_t attack_array[32]={0};
		for(;st<ed;st++){
			memcpy(attack_array,&st,5);
			int flag = memcmp(attack_array,goal,5);
			if(flag==0){
				std::cout<<"successs"<<std::endl;
				std::cout<<std::hex<<st<<std::endl;
				auto end_time = std::chrono::steady_clock::now();
				auto running_time = end_time - start_time; 
				std::cout << "Bithday Attack for SM3 = " 
              << std::chrono::duration <double, std::milli> (running_time).count() << " ms" << std::endl;
				break;
			}
		}
	};
	auto start_time = std::chrono::steady_clock::now(); 

	for(uint64_t i = 0;i<8;i++){
		threads[i]=std::async(routine,i*cnt,(i+1)*cnt,dgst,start_time);
	}
	for(int i=0;i<8;i++){
		threads[i].get();
	}
	return 0;
}
