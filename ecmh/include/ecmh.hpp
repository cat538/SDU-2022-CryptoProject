#include "hash.hpp"
using namespace std;
class ecmh{
private:
    EC_POINT* point = NULL;
    EC_GROUP* group = NULL;
    Hash* hash;
    BIGNUM *x  = NULL,*y  = NULL;
    BN_CTX *bn_ctx;
    int num; 
public:
    ecmh();
    ~ecmh();
    
    void init(int nid = NID_sm2);
    void init(vector<int> vec);
    void init(vector<string> vec);

    EC_POINT*  hash2point(int element);
    EC_POINT*  hash2point(string element);

    bool isAtInfinity(EC_POINT* p);
    bool isOnCurve(EC_POINT* p);
    bool isEqual(ecmh* b);

    void empty();
    void add(int element) {add(to_string(element));}
    void add(string element);
    void add(vector<int> vec) {num += vec.size(); for(auto& i: vec) add(i);}
    void add(vector<string> vec) {num += vec.size(); for(auto& i: vec) add(i);}

    void erase(int element) {erase(to_string(element));}
    void erase(string element);
    void erase(vector<int> vec) { num += vec.size(); for(auto& i: vec) erase(i);}
    void erase(vector<string> vec) {num += vec.size(); for(auto& i: vec) erase(i);}

    string hashValue();
    void printHash();


    void operator+=(int element) {add(element);};
    void operator+=(string element) {add(element);};
    void operator+=(vector<int> vec) {add(vec);};
    void operator+=(vector<string> vec) {add(vec);};
    void operator-=(int element) {erase(element);};
    void operator-=(string element) {erase(element);};
    void operator-=(vector<int> vec) {erase(vec);};
    void operator-=(vector<string> vec) {erase(vec);};

    bool operator==(ecmh* b){return isEqual(b);}
    bool operator==(ecmh b){return isEqual(&b);}
};