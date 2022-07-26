#include <iostream>
#include "openssl/evp.h"
#include "openssl/rand.h"
#include <random>
#include <time.h>
#include <unordered_map>
#include <cstring>
#include <chrono>
#include <unordered_set>
// birthday attack map 
std::unordered_map<std::string,std::string> hash_map;
// std::unordered_set<std::string> hash_set;
std::unordered_set<uint64_t> hash_set;

uint8_t base[32];
const int COLLISION_LEN = 48;
const int COLLISION_BYTE = COLLISION_LEN>>3;
void printf_hex(const uint8_t str[],size_t len){
    for(int i= 0;i<len;i++){
        printf("%X",str[i]);
    }
    printf("\n");
}
void printf_hex(const char str[],size_t len){
    for(int i= 0;i<len;i++){
        printf("%X",str[i]);
    }
    printf("\n");
}

void build_table(){
    std::default_random_engine png(time(0));
    std::uniform_int_distribution<int> uniform_1byte(0, 0xff);
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    uint8_t data[32];
    uint8_t out[32];
   
    uint32_t out_size = 0;
    for(auto &x:data){
        x = (uint8_t)uniform_1byte(png);
    }
    for(auto &x:base){
        x = (uint8_t)uniform_1byte(png);
    }

    for(int i = 0;i<(1<<(COLLISION_LEN/2));i++){
        EVP_Digest(data, 32, out, &out_size, EVP_sm3(), NULL);
        // char temp[32]={0};
        uint64_t key=0;
        std::memcpy(&key,out,COLLISION_BYTE);
        //std::string key{temp, COLLISION_BYTE};
        
        *((uint64_t*)data)+=i;
       // hash_map.insert({key,std::string((char*)out)});
        hash_set.insert(key);

        // std::string temp=std::string((char*) out).substr(0,COLLISION_BYTE);
        // printf_hex(temp.c_str(),COLLISION_BYTE);

        // if(hash_map.find(temp)!=hash_map.end()){
        //     printf("success");
        // }
    }
    EVP_MD_CTX_free(ctx);
    
}

void find_collision_birthday(){
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    uint8_t out[32];
    uint32_t out_size = 0;
    for(int i = 0;i<(1<<(COLLISION_LEN/2));i++){
        EVP_Digest(base, 32, out, &out_size, EVP_sm3(), NULL);
        // char temp[32]={0};
        uint64_t key=0;
        std::memcpy(&key,out,COLLISION_BYTE);
        //std::string key{temp, COLLISION_BYTE};
        
        // auto message = hash_map.find(key);
        auto message = hash_set.find(key);

        if(message != hash_set.end()){
            printf("base :\n");
            printf_hex(base,32);
            printf("key: ");
            // std::cout<<key.size()<<std::endl;
            // printf_hex((const uint8_t*)key.c_str(),COLLISION_BYTE);
            std::cout<<std::hex<<key<<std::endl;
            printf_hex(out,32);
            // printf("hash_map key :\n");
            // printf_hex((const uint8_t*)message->first.c_str(),COLLISION_BYTE);

            // printf("hash_map value : \n");
            // printf_hex((const uint8_t*)message->second.c_str(),32);
            printf("%d\n",i);
            break;
        }
        *((uint64_t*)base)+=i;
        // printf_hex(base,32);
        // printf("\n%lld\n",base);
    }
    EVP_MD_CTX_free(ctx);
}


int main(){
    std::cout<<"attack len: "<<COLLISION_LEN<<std::endl;
    build_table();
    auto start_time = std::chrono::steady_clock::now(); 
    find_collision_birthday();
	
    auto end_time = std::chrono::steady_clock::now(); 
 	auto running_time = end_time - start_time; 
				std::cout << "Bithday Attack for SM3 = " 
              << std::chrono::duration <double, std::milli> (running_time).count() << " ms" << std::endl;
    return 0;


}