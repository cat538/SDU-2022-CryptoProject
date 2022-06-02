
#pragma once
#include "head.h"
class Client{
    public:
        Client(int nid,uint64_t* in,size_t len){
            curve = EC_GROUP_new_by_curve_name(nid);
            data = std::vector(in,in+len);
            data_len = len;
            mask = (1<<12)-1;
            a.resize(len);
        }
        ~Client(){
            EC_GROUP_free(curve);
        }
        void run();
        std::vector<std::pair<uint16_t, EC_POINT*> > output();
        void get_ins(std::vector<uint16_t> &flag,std::vector<std::vector<EC_POINT*> > S,std::vector<std::vector<EC_POINT*> > h_ex_ab,size_t sets_len);
        std::vector<uint16_t> get_k() {
            return k;
        }
    private:
        EC_GROUP* curve;
        std::vector<uint64_t> data;
        std::size_t data_len;
        EC_POINT* h_gen(uint64_t in);
        std::vector<EC_POINT*> h_gen();
        std::vector<uint16_t > k;
        std::unordered_map<uint16_t, BIGNUM* > ka_pair;
        std::vector<EC_POINT* > v;

        std::vector<BIGNUM*> a;
        uint16_t mask;
};
