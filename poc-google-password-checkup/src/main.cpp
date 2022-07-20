

#include "Client.h"
#include "Server.h"


const int ins_size=8;
const int client_size = 16;
const int db_size = 1024;
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

void Client_thread(){
    std::this_thread::sleep_for(std::chrono::milliseconds(20));

    Client c(1172,client,client_size);
    
    c.run();
    std::vector<uint16_t> flag;
    std::vector<std::vector<EC_POINT*> > S;
    std::vector<std::vector<EC_POINT*> > h_ex_ab;

    c.NetIN_flag_S_h(flag,S,h_ex_ab);
    
    c.get_ins(flag,S,h_ex_ab);
    cout << "all items \n"; 
    auto k = c.get_k();
    for (auto ki : k) {
        cout << std::hex << ki << std::endl;
    }
}
void Server_thread(){
    Server s(1172,db,db_size);

    auto kv_pair = s.NetIN_kvpair();
    s.run(kv_pair);
    s.NetOUT_flag_S_h();

}
#ifdef ARGON2TEST
    #define HASHLEN 32
    #define SALTLEN 16
    #define PWD "password"
    int test_argon2(void)
{
    uint8_t hash1[HASHLEN];
    uint8_t hash2[HASHLEN];

    uint8_t salt[SALTLEN];
    memset( salt, 0x00, SALTLEN );

    uint8_t *pwd = (uint8_t *)strdup(PWD);
    uint32_t pwdlen = strlen((char *)pwd);

    uint32_t t_cost = 2;            // 2-pass computation
    uint32_t m_cost = (1<<16);      // 64 mebibytes memory usage
    uint32_t parallelism = 1;       // number of threads and lanes

    // high-level API
    argon2i_hash_raw(t_cost, m_cost, parallelism, pwd, pwdlen, salt, SALTLEN, hash1, HASHLEN);

    // low-level API
    argon2_context context = {
        hash2,  /* output array, at least HASHLEN in size */
        HASHLEN, /* digest length */
        pwd, /* password array */
        pwdlen, /* password length */
        salt,  /* salt array */
        SALTLEN, /* salt length */
        NULL, 0, /* optional secret data */
        NULL, 0, /* optional associated data */
        t_cost, m_cost, parallelism, parallelism,
        ARGON2_VERSION_13, /* algorithm version */
        NULL, NULL, /* custom memory allocation / deallocation functions */
        /* by default only internal memory is cleared (pwd is not wiped) */
        ARGON2_DEFAULT_FLAGS
    };

    int rc = argon2i_ctx( &context );
    if(ARGON2_OK != rc) {
        printf("Error: %s\n", argon2_error_message(rc));
        exit(1);
    }
    free(pwd);

    for( int i=0; i<HASHLEN; ++i ) printf( "%02x", hash1[i] ); printf( "\n" );
    if (memcmp(hash1, hash2, HASHLEN)) {
        for( int i=0; i<HASHLEN; ++i ) {
            printf( "%02x", hash2[i] );
        }
        printf("\nfail\n");
    }
    else printf("ok\n");
    return 0;
}

#endif

int main(){
    prepare_data();
#ifdef BASIC_TEST
    EC_GROUP* sm2 = EC_GROUP_new_by_curve_name(1172);
    
   
    std::cout << "hello world\n";
   
    auto str2 = EC_POINT_point2hex(sm2, kv_pair[0].second, POINT_CONVERSION_COMPRESSED, NULL);
    std::cout << str2 << std::endl;;
    auto S = s.get_S();
    auto flag = s.get_flag();
    auto h_ex_ab = s.get_h_ex_ab();
    cout << S.size();
    cout << "intersection items \n"; 
    c.get_ins(flag,S,h_ex_ab,flag.size());
#endif
// main work
    std::future<void> thr[2];
    thr[0] = std::async(Client_thread);
    Server_thread();
    
    thr[0].get();

#ifdef ARGON2TEST
    test_argon2();
#endif
#ifdef NETIO_TEST
    auto t1 = [](){
        NetIO* port2;
        port2 = new NetIO("client","127.0.0.1",60000);
        int c;
    std::this_thread::sleep_for(std::chrono::seconds(5));

        port2->ReceiveInteger(c);
        std::string test;
        port2->ReceiveString(test);
        cout<<c<<std::endl;

    };
    NetIO* port1;
    thr[0] = std::async(t1);
    port1 = new NetIO("server","",60000);
    port1->SendInteger(16);
    std::string hello = "hello world";
    port1->SendString(hello);

    thr[0].get();
#endif
#ifdef ECGROUP_TEST
    EC_GROUP* sm2 = EC_GROUP_new_by_curve_name(1172);

    auto g = EC_GROUP_get0_generator(sm2);
    auto str = EC_POINT_point2hex(sm2, g,POINT_CONVERSION_COMPRESSED,nullptr);
    EC_POINT* h = EC_POINT_new(sm2);
    EC_POINT* r ;
    BIGNUM* n = BN_new();
    BN_set_word(n,db[0]);
    auto strs = BN_bn2hex(n);
    std::cout<<strs<<std::endl;
    r = EC_POINT_bn2point(sm2,n,NULL,NULL);
    std::cout<<"hello world";
    BN_free(n);
    EC_POINT_free(r);
    EC_GROUP_free(sm2);
    std::vector<int> test1(1,1);
    printf("%d",test1[0]);
#endif
}