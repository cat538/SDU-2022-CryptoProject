#include "merkle_tree.h"
void print_hex(HASH_TYPE in){
    for(auto x: in){
       printf("%02x",x); 
    }
    printf("\n");

}
int main(){
    merkle_tree Merkle;
    for(uint32_t i =0; i < 1; i++){
        Merkle.add(i);
    }
    std::cout<<1<<std::endl;
    auto proof = Merkle.make_proof();
    for(auto val : proof){
        print_hex(val);
    }
}
