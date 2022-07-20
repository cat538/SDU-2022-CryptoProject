#include "Client.h"

/**
 * @brief generate h for ont item
 * 
 * @param in value
 * @return EC_POINT* h 
 */
EC_POINT* Client::h_gen(uint64_t in){
    BN_CTX* ctx = BN_CTX_new();

    EC_POINT* out = EC_POINT_new(curve);
    uint8_t hash_value[32];
    uint32_t out_size = 32;
    BIGNUM* bn = BN_new(); 
    // prepare value
    EVP_Digest(&in,8,hash_value,&out_size,EVP_sha256(),NULL);
    uint64_t temp = 1;
    temp = (hash_value[1]<<8)|hash_value[0];
    BN_set_word(bn,temp);
    // get h 
    EC_POINT_mul(curve,out,bn,NULL,NULL,NULL);
    //EC_POINT_bn2point(curve,bn,out,NULL);
    BN_free(bn);
    BN_CTX_free(ctx);
    
    return out;
}

std::vector<EC_POINT*> Client::h_gen(){
    BN_CTX* ctx = BN_CTX_new();
    std::vector<EC_POINT*> out;
    uint8_t hash_value[32];
    uint32_t out_size = 32;
    BIGNUM* bn = BN_new();
    uint8_t hash1[32];
    
    uint8_t salt[SALTLEN];
    memset( salt, 0x00, SALTLEN );
    uint32_t t_cost = 2;            // 2-pass computation
    uint32_t m_cost = (1<<16);      // 64 mebibytes memory usage
    uint32_t parallelism = 4;       // number of threads and lanes


    uint64_t temp = 1;
    for(auto x:data){
        EC_POINT* h = EC_POINT_new(curve);
        BN_clear(bn);
        // EVP_Digest(&x,8,hash_value,&out_size,EVP_sha256(),NULL);
        argon2i_hash_raw(t_cost, m_cost, parallelism, &x, 8, salt, SALTLEN, hash_value, out_size);
         //for( int i=0; i<out_size; ++i ) printf( "%02x", hash1[i] ); printf( "\n" );

        BN_bin2bn(hash_value,16,bn);
        // auto test = BN_bn2hex(bn);

        
        k.emplace_back(((hash_value[1]<<8)|hash_value[0])&(mask));
        EC_POINT_mul(curve,h,bn,NULL,NULL, ctx);
        auto str = EC_POINT_point2hex(curve,h,POINT_CONVERSION_COMPRESSED,NULL);

        out.emplace_back(h);
       //  auto g = EC_GROUP_get0_generator(curve);
        
      
        // std::cout<<str<<std::endl;

    }
    BN_free(bn);
   
    BN_CTX_free(ctx);

    return out;
}

/**
 * @brief run poc
 * 
 */
void Client::run(){
    BN_CTX* ctx = BN_CTX_new();
    std::vector<EC_POINT*> h = h_gen();
    
    for(int i = 0;i<data_len;i++){
        EC_POINT* v_t = EC_POINT_new(curve);
        a[i] = BN_new();
        BN_rand(a[i],80,1,1);
        /*auto str = BN_bn2hex(a[i]);
        std::cout<<str<<std::endl;*/
        EC_POINT_mul(curve,v_t,NULL,h[i],a[i], ctx);

    /*    auto str1 = EC_POINT_point2hex(curve, v_t, POINT_CONVERSION_COMPRESSED, NULL);
        std::cout<<str1<<std::endl;*/

        v.emplace_back(v_t);
    }
    for(int i = 0;i<data_len;i++){
        ka_pair.insert(std::make_pair(k[i],a[i]));
    }
    BN_CTX_free(ctx);
    NetOUT_kv_pair();
}

std::vector<std::pair<uint16_t, EC_POINT*> > Client::output(){
    std::vector<std::pair<uint16_t, EC_POINT*> > out;
    
    for(int i = 0;i<data_len;i++){
        out.emplace_back(std::make_pair(k[i],v[i]));
    }
    //cli_port.SendBytes((void*)k.data(),sizeof(k));
    return out;
}

void Client::NetOUT_kv_pair(){

    std::string out_str;
    cli_port->SendInteger(data_len);

    for(int i = 0;i<data_len;i++){
        cli_port->SendInteger(k[i]);

        out_str = std::string(EC_POINT_point2hex(curve,v[i],POINT_CONVERSION_COMPRESSED,NULL));
        cli_port->SendString(out_str);
    }
   
}

void Client::NetIN_flag_S_h(std::vector<uint16_t> &flag,std::vector<std::vector<EC_POINT*> > &S,std::vector<std::vector<EC_POINT*> > &h_ex_ab){
    cli_port->ReceiveInteger(data_len);

    h_ex_ab.resize(data_len);

    std::string in_str;
    in_str.resize(66);
    for(int i = 0; i <data_len;i++){
        uint64_t receive_len = 0;
        
        cli_port->ReceiveInteger(receive_len);

        for(uint64_t j = 0; j <receive_len ; j++){
            cli_port->ReceiveString(in_str);
            EC_POINT* temp = EC_POINT_new(curve);
            EC_POINT_hex2point(curve,in_str.c_str(),temp,NULL);
            h_ex_ab[i].emplace_back(temp);
        }
    }

    S.resize(data_len);
    for(int i = 0; i <data_len;i++){
        size_t receive_len = 0;
        cli_port->ReceiveInteger(receive_len);


        for(size_t j = 0; j <receive_len ; j++){

            cli_port->ReceiveString(in_str);
            EC_POINT* temp = EC_POINT_new(curve);
            EC_POINT_hex2point(curve,in_str.c_str(),temp,NULL);
            S[i].emplace_back(temp);
        }
    }

    for(int i = 0; i <data_len;i++){
        uint16_t receive_flag;
        cli_port->ReceiveInteger(receive_flag);
        flag.emplace_back(receive_flag);
    }
}

void Client::get_ins(std::vector<uint16_t> &flag,std::vector<std::vector<EC_POINT*> > S,std::vector<std::vector<EC_POINT*> > h_ex_ab){
    BN_CTX* ctx = BN_CTX_new();
    for(size_t i = 0;i<data_len;i++){
        

        auto hab_set = h_ex_ab[i];
        size_t len = h_ex_ab[i].size();
        BIGNUM*  a_val = ka_pair[flag[i]];
        EC_POINT*  hab=EC_POINT_new(curve);
        for(size_t j = 0; j < len ;j++){
            EC_POINT_mul(curve,hab,NULL,S[i][j],a_val, ctx);

           // auto str1 = EC_POINT_point2hex(curve, S[i][j], POINT_CONVERSION_COMPRESSED,NULL);
           // auto str3 = BN_bn2hex(a_val);
            //std::cout << str3 << std::endl;
            //std::cout << str1 << std::endl;

            for(size_t k = 0; k<len;k++){
              //  auto str2 = EC_POINT_point2hex(curve,hab_set[k], POINT_CONVERSION_COMPRESSED,ctx);
               
                //std::cout << str2 << std::endl;
                if(!EC_POINT_cmp(curve,hab_set[k],hab,NULL)){
                    std::cout<<std::hex<<flag[i]<<std::endl;
                    break;
                }
            }
        }   
    }
    BN_CTX_free(ctx);
}