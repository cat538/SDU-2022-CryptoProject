#include "merkle_tree.h"
void print_hex(HASH_TYPE in){
    for(auto x: in){
       printf("%02x",x); 
    }
    printf("\n");

}
void test_inclusion(size_t tree_size,size_t idx,bool ans){
    printf("inclusion proof :\ntree size%zd \npoint idx %zd \n",tree_size,idx);

    merkle_tree inclusion_tree;
    for(size_t i = 0; i < tree_size;i++ ){
        inclusion_tree.add(i);
    }
    bool proof;
    if(ans){
        proof = inclusion_tree.inclusion_proof(idx,&merkle_leaf((uint32_t)idx));
    }else{
        proof = inclusion_tree.inclusion_proof(10,&merkle_leaf((uint32_t)10));

    }
    if(proof){
        std::cout << "inclusion proof success" <<std::endl;
    }
    else{
        std::cout << "inclusion proof failed" <<std::endl;
    }

}
void test_consistency(size_t old_tree_size,size_t new_tree_size,bool ans){
    printf("consistency proof :\nold tree size%zd\nnew tree size %zd \n",old_tree_size,new_tree_size);

    merkle_tree old_tree;
    merkle_tree new_tree;
    for(size_t i = 0 ; i < old_tree_size;i ++ ){
        old_tree.add(i);
    }
    for(size_t i = 0 ; i < new_tree_size;i ++ ){
        new_tree.add(i);
    }
    bool proof;
    if(!ans){
        old_tree.add(new_tree_size+1);
    }
    proof = new_tree.consistency_proof(&old_tree);
    if(proof){
        std::cout << "consistency proof success" <<std::endl;
    }
    else{
        std::cout << "consistency proof failed" <<std::endl;
    }
}

int main(){
    merkle_tree Merkle;
    for(uint32_t i =0; i < 7; i++){
        Merkle.add(i);
    }
    //std::cout<<1<<std::endl;
    auto proof = Merkle.make_proof();
    for(auto val : proof){
        print_hex(val);
    }
    //Merkle.print_internode();
    test_inclusion(7,4,true);
    test_consistency(3,7,true);
}
