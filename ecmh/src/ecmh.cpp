
#include "ecmh.hpp"
ecmh::ecmh(){
    hash = new Hash("sm3");
    x = BN_new();
    bn_ctx = BN_CTX_new();
    num = 0;
}

ecmh::~ecmh(){
    //BN_free(x);
    //BN_CTX_free(bn_ctx);
}

void ecmh::init(int nid){
    group = EC_GROUP_new_by_curve_name(nid);
    point = EC_POINT_new(group);
    assert ( EC_POINT_set_to_infinity(group,point));
}

void ecmh::init(vector<int> vec){
    init();
    num += vec.size();
    for(auto& i:vec) add(to_string(i));
}

void ecmh::init(vector<string> vec){
    init();
    num += vec.size();
    for(auto& i:vec)  add(i);
}

EC_POINT*  ecmh::hash2point(int element){
    return hash2point(to_string(element));
}
EC_POINT* ecmh::hash2point(string element){
    string val = hash -> Digest(element);
    const unsigned char* buf = (unsigned char*)val.c_str();
    EC_POINT* ret = EC_POINT_new(group);
    BN_bin2bn(buf,hash -> DigestSize(),x);
    do
    {   
        //printf("bn:%s\n", BN_bn2hex(x));
        BN_add_word(x,1);
        EC_POINT_set_compressed_coordinates(group,ret,x,0,bn_ctx);
    } while (!isOnCurve(ret) || isAtInfinity(ret));
    return ret;
}

bool ecmh::isOnCurve(EC_POINT* p){
    if(1 == EC_POINT_is_on_curve(group,p,bn_ctx)) return true;
    else return false;
}
bool ecmh::isAtInfinity(EC_POINT* p){
    return EC_POINT_is_at_infinity(group,p);
}

bool ecmh::isEqual(ecmh* b){
    if( !EC_GROUP_cmp(group, b -> group,bn_ctx) && !EC_POINT_cmp(group,point,b -> point,bn_ctx))
        return true;
    else return false;
}

void ecmh::empty(){
    num = 0;
    EC_POINT_set_to_infinity(group,point);
}
string ecmh::hashValue(){
    char *hex = NULL;
    hex = EC_POINT_point2hex(group,point,POINT_CONVERSION_COMPRESSED,bn_ctx);
    string temp(hex,hex+64);
    return temp;
}

void ecmh::add(string element){
    EC_POINT* p = hash2point(element);
    EC_POINT_add(group,point,point,p,bn_ctx);
    num ++;
}

void ecmh::erase(string element){
    if(num == 0){
        printf("Empty Set!");
        return;
    }
    EC_POINT* p = hash2point(element);
    EC_POINT_invert(group,p,bn_ctx);
    EC_POINT_add(group,point,point,p,bn_ctx);
    num --;
}

void ecmh::printHash(){
    string val = hashValue();
    printf("%s\n",val.c_str());
}


