#pragma once
#include "head.h"
class Server{
    public:
        Server(int nid,uint64_t* in,size_t len){
            curve = EC_GROUP_new_by_curve_name(nid);
            data = std::vector(in,in+len);
            data_len = len;
            mask = (1<<12)-1;
            server_port = new NetIO("server","",60001);
        }
        ~Server(){
            delete server_port;
            EC_GROUP_free(curve);
        }
        void run(std::vector<std::pair<uint16_t, EC_POINT*> > &kv_pair);
        std::vector<uint16_t> get_flag(){
            return flag;
        }
        std::vector<std::vector<EC_POINT*> >& get_S(){
            return S;
        }
        std::vector<std::vector<EC_POINT*> >& get_h_ex_ab(){
            return h_ex_ab;
        }
        std::vector<std::pair<uint16_t, EC_POINT*> > NetIN_kvpair();
        void NetOUT_flag_S_h();
        

    private:
        EC_GROUP* curve;
        std::vector<uint64_t> data;
        std::size_t data_len;
        
        void set_gen();
        NetIO* server_port;
        std::unordered_map<uint16_t,std::vector<EC_POINT*> >sets;
        std::vector<EC_POINT* > v;
        std::vector<uint16_t> flag;
        uint16_t mask;
        std::vector<std::vector<EC_POINT*> > S;
        std::vector<std::vector<EC_POINT*> > h_ex_ab;
       


};
