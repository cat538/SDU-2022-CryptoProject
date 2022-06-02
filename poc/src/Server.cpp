#include "Server.h"

void Server::set_gen(){
    BN_CTX* ctx = BN_CTX_new();
    uint8_t hash_value[32];
    uint32_t out_size = 32;
    BIGNUM* bn = BN_new();
    
    uint16_t k = 1;
    for(auto x:data){
        EC_POINT* h = EC_POINT_new(curve);
        BN_clear(bn);
        EVP_Digest(&x,8,hash_value,&out_size,EVP_sha256(),NULL);
        BN_bin2bn(hash_value,16,bn);
        k = (((hash_value[1]<<8)|hash_value[0])&(mask));
        
        EC_POINT_mul(curve,h,bn,NULL,NULL, ctx);
        // auto str = EC_POINT_point2hex(curve,h,POINT_CONVERSION_COMPRESSED,NULL);
        // std::cout<<str<<std::endl;
        if(sets.find(k) == sets.end()){
            sets.insert({k,{h}});
        }
        else{
            sets[k].emplace_back(h);
        }
    }
    BN_free(bn);
    
    BN_CTX_free(ctx);
}

void Server::run(std::vector<std::pair<uint16_t, EC_POINT*> > &kv_pair){
    BN_CTX* ctx = BN_CTX_new();
    set_gen();
    for(auto i: kv_pair){
        if(sets.find(i.first)!=sets.end()){
            std::vector<EC_POINT*> subset_in = sets[i.first];
            size_t sets_len = subset_in.size();
            std::vector<EC_POINT*> subset_out(sets_len);

           // std::cout << sets_len << std::endl;

            std::vector<EC_POINT*> response_subset(sets_len);
            BIGNUM* b = BN_new();
            for(size_t j = 0;j<sets_len;j++){
                subset_out[j] = EC_POINT_new(curve);
                response_subset[j] = EC_POINT_new(curve);
                BN_rand(b,80,1,1);
                EC_POINT_mul(curve, subset_out[j],NULL, subset_in[j],b, ctx);
                 //std::cout << j;
                EC_POINT_mul(curve,response_subset[j],NULL,i.second,b, ctx);
                 //std::cout << "hello world\n";
                // auto str1 = EC_POINT_point2hex(curve, subset_out[j], POINT_CONVERSION_COMPRESSED, NULL);
                // std::cout << str1 << std::endl;
                // auto str2 = EC_POINT_point2hex(curve, i.second, POINT_CONVERSION_COMPRESSED, NULL);
                // std::cout << str2 << std::endl;;
              
            }
             
            h_ex_ab.emplace_back(response_subset);
            S.emplace_back(subset_out);
            flag.emplace_back(i.first);
        }

    }
    BN_CTX_free(ctx);

}