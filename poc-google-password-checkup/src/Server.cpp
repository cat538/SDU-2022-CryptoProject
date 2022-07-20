#include "Server.h"

void Server::set_gen(){
    BN_CTX* ctx = BN_CTX_new();
    uint8_t hash_value[32];
    uint32_t out_size = 32;
    BIGNUM* bn = BN_new();
    
    uint8_t salt[SALTLEN];
    memset( salt, 0x00, SALTLEN );
    uint32_t t_cost = 2;            // 2-pass computation
    uint32_t m_cost = (1<<16);      // 64 mebibytes memory usage
    uint32_t parallelism = 4;       // number of threads and lanes

    uint16_t k = 1;
    for(auto x:data){
        EC_POINT* h = EC_POINT_new(curve);
        BN_clear(bn);

        // EVP_Digest(&x,8,hash_value,&out_size,EVP_sha256(),NULL);
        argon2i_hash_raw(t_cost, m_cost, parallelism, &x, 8, salt, SALTLEN, hash_value, out_size);

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

std::vector<std::pair<uint16_t, EC_POINT*> > Server::NetIN_kvpair(){
    
    size_t client_len;
    server_port->ReceiveInteger(client_len);

    std::string in_str;
    in_str.resize(66);
    uint16_t k;
    std::vector<std::pair<uint16_t, EC_POINT*> > out;
    for(int i=0;i<client_len;i++){
        EC_POINT* v = EC_POINT_new(curve);
        server_port->ReceiveInteger(k);
        server_port->ReceiveString(in_str);
        EC_POINT_hex2point(curve,in_str.c_str(),v,NULL);
        out.emplace_back(std::make_pair(k,v));
    }

    return out;

}

void Server::NetOUT_flag_S_h(){
    size_t len = h_ex_ab.size();
    //std::cout <<"len" <<len <<std::endl;
    server_port->SendInteger(len);

    for(size_t i=0;i<len;i++){

        uint64_t send_len = h_ex_ab[i].size();
        server_port->SendInteger(send_len);
       // std::cout <<"send len" <<send_len <<std::endl;

        for(size_t j = 0; j <send_len ; j++){
            auto out_str = std::string(EC_POINT_point2hex(curve,h_ex_ab[i][j],POINT_CONVERSION_COMPRESSED,NULL));
            server_port->SendString(out_str);
        }
    }
    for(size_t i=0;i<len;i++){
        size_t send_len = S[i].size();
        server_port->SendInteger(send_len);
       //std::cout <<"send len" <<send_len <<std::endl;

        for(size_t j = 0; j <send_len ; j++){
            auto out_str = std::string(EC_POINT_point2hex(curve,S[i][j],POINT_CONVERSION_COMPRESSED,NULL));
            server_port->SendString(out_str);
        }
    }
    for(size_t i=0;i<len;i++){
        server_port->SendInteger(flag[i]);
    }


}