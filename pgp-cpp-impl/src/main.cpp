#include <vector>
#include <iostream>
#include <openssl/evp.h>
#include <future>
#include <thread>
#include <openssl/ec.h>
#include <openssl/ecdh.h>

using std::cout;
using std::endl;
using std::vector;
void sm2_key_exchange(EC_POINT* value,BIGNUM* sk);
uint8_t iv[8]={111,121,47,42,75,34,33,124};
EC_POINT* tmp_sender;
EC_POINT* tmp_receiver;
EC_GROUP* curve;
void Sender(uint8_t plaintext[],int plainlen,uint8_t ciphertext[],int& out){
    BN_CTX* ecctx = BN_CTX_new();
    
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    EVP_CIPHER_CTX_init(ctx);
    uint8_t key[16];
    BIGNUM* sk = BN_new();
    sm2_key_exchange(tmp_sender,sk);

    EC_POINT* session_key_point = EC_POINT_new(curve);
    EC_POINT_mul(curve,session_key_point,NULL,tmp_receiver,sk,ecctx);
    char* session_key = EC_POINT_point2hex(curve,session_key_point,POINT_CONVERSION_COMPRESSED,NULL);
    memcpy(key,session_key,16);

    int outlen = 0;
    EVP_EncryptInit(ctx,EVP_aes_128_cbc(),key,iv);
    EVP_EncryptUpdate(ctx,ciphertext,&out,plaintext,plainlen);
  //  std::cout<<outlen<<std::endl;
    EVP_EncryptFinal(ctx,ciphertext+out,&outlen);
    out+=outlen;

    EC_POINT_free(session_key_point);
    BN_free(sk);
    BN_CTX_free(ecctx);
    EVP_CIPHER_CTX_free(ctx);
}
void Receiver(BIGNUM* sk,uint8_t ctext[],int clen){
    BN_CTX* ecctx = BN_CTX_new();
    uint8_t key[16];

    EC_POINT* session_key_point = EC_POINT_new(curve);
    EC_POINT_mul(curve,session_key_point,NULL,tmp_sender,sk,ecctx);
    char* session_key = EC_POINT_point2hex(curve,session_key_point,POINT_CONVERSION_COMPRESSED,NULL);
    memcpy(key,session_key,16);


    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    EVP_CIPHER_CTX_init(ctx);
    uint8_t plaintext[32];
    int outlen;
    EVP_DecryptInit(ctx,EVP_aes_128_cbc(),key,iv);
    EVP_DecryptUpdate(ctx,plaintext,&outlen,ctext,clen);
    EVP_DecryptFinal(ctx,plaintext+outlen,&outlen);

    std::cout <<"Decrypt ans:" << plaintext<< std::endl;
    EC_POINT_free(session_key_point);
    BN_CTX_free(ecctx);
    EVP_CIPHER_CTX_free(ctx);
}


uint8_t ptext[] = {"Sender plain_text"};
int plen = 18;
int main(int argc, char*argv[]) {
    std::cout << "+++++++++++++++sm2 demo pgp++++++++++++++"<<std::endl;
    curve = EC_GROUP_new_by_curve_name(1172);
    tmp_receiver = EC_POINT_new(curve);
    tmp_sender = EC_POINT_new(curve);
    BIGNUM* sk = BN_new();
    std::cout <<"Encrypt input:" << ptext<< std::endl;
    uint8_t ciphertext[32];
    int cipherlen;
    sm2_key_exchange(tmp_receiver,sk);
    Sender(ptext,plen,ciphertext,cipherlen);
    Receiver(sk,ciphertext,cipherlen);

    BN_free(sk);
    EC_POINT_free(tmp_receiver);
    EC_POINT_free(tmp_sender);
    EC_GROUP_free(curve);
    return 0;
}

void sm2_key_exchange(EC_POINT* value,BIGNUM* sk){
    BN_CTX* ctx = BN_CTX_new();
    BN_rand(sk,80,1,1);
    EC_POINT_mul(curve,value,sk,NULL,NULL,ctx);
    BN_CTX_free(ctx);
}