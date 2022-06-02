

#include "Client.h"
#include "Server.h"


const int ins_size=8;
const int client_size = 16;
const int db_size = 65536;
uint64_t db[db_size];
uint64_t client[client_size];

void prepare_data(){
    std::default_random_engine png(time(0));
    std::uniform_int_distribution<uint64_t> uniform_64bit;
  
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    for(auto &x:db){
        x = uniform_64bit(png);
    }
    for(auto &x:client){
        x = uniform_64bit(png);
    }
    for(int i = 0;i<ins_size;i++){
        db[i] = client[i];
    }
}

using std::cout;

int main(){
    prepare_data();
    Client c(1172,client,client_size);
    Server s(1172,db,db_size);
    EC_GROUP* sm2 = EC_GROUP_new_by_curve_name(1172);
    
    c.run();
    auto kv_pair = c.output();
    //std::cout << "hello world\n";
   
    //auto str2 = EC_POINT_point2hex(sm2, kv_pair[0].second, POINT_CONVERSION_COMPRESSED, NULL);
    //std::cout << str2 << std::endl;;
    s.run(kv_pair);
    
    
    auto S = s.get_S();
    auto flag = s.get_flag();
    auto h_ex_ab = s.get_h_ex_ab();
   // cout << S.size();
    cout << "intersection items \n"; 
    c.get_ins(flag,S,h_ex_ab,flag.size());
    cout << "all items \n"; 
    auto k = c.get_k();
    for (auto ki : k) {
        cout << std::hex << ki << std::endl;
    }
    // auto g = EC_GROUP_get0_generator(sm2);
    // auto str = EC_POINT_point2hex(sm2, g,POINT_CONVERSION_COMPRESSED,nullptr);
    // EC_POINT* h = EC_POINT_new(sm2);
    // EC_POINT* r ;
    // BIGNUM* n = BN_new();
    // BN_set_word(n,db[0]);
    // auto strs = BN_bn2hex(n);
    // std::cout<<strs<<std::endl;
    // r = EC_POINT_bn2point(sm2,n,NULL,NULL);
    // std::cout<<"hello world";
    // BN_free(n);
    // EC_POINT_free(r);
     EC_GROUP_free(sm2);
    // std::vector<int> test1(1,1);
    // printf("%d",test1[0]);
}