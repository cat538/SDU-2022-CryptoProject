#include "merkle_tree.h"

merkle_leaf::merkle_leaf(uint32_t in) : value(in)
{
    temp_stmp = std::chrono::system_clock::now();
    uint32_t out_size = 32; 
    EVP_Digest(&value, 4, hash_value.data(), &out_size, EVP_sha256(), NULL);
}
// merkle_leaf::merkle_leaf(merkle_leaf &in){
//     hash_value = in.get_hash_value();
//     value = in.get_value();
//     temp_stmp = in.get_temp_stmp();
// }

merkle_leaf::~merkle_leaf()
{
}


merkle_internal_node::merkle_internal_node(/* args */)
{
    hash_value.clear();
}
// merkle_internal_node::merkle_internal_node(merkle_internal_node& in){
//     hash_value = in.hash_value;
// }
merkle_internal_node::merkle_internal_node(merkle_leaf& in){
    hash_value.clear();
    hash_value.emplace_back(in.get_hash_value());
}
merkle_internal_node::~merkle_internal_node()
{
    hash_value.clear();
}

merkle_internal_node::merkle_internal_node(merkle_internal_node& in1,merkle_internal_node& in2){
    hash_value = in1.hash_value;
    hash_value.insert(hash_value.end(),in2.hash_value.begin(),in2.hash_value.end());
}
std::vector<HASH_TYPE> merkle_internal_node::get_hash_value(){
    return hash_value;
}

/**
 * @brief 添加新元素
 * 
 * @param value 新元素
 */
void merkle_tree::add(uint32_t value){
    calculat_finish = false;
    node_cnt++;
    leaf_node.emplace_back(merkle_leaf(value));

    if(node_cnt > (1 << (level - 1))) level++;
}
/**
 * @brief 对于节点重新计算hash结果
 * 
 * @param node_idx 节点编号
 */
void merkle_tree::re_calcuate(){
    internal_node.clear();
    internal_node.resize((1<<level)-1);
    const size_t leaf_level_start = (1 << (level - 1)) - 1;
    for(size_t idx = 0; idx < leaf_node.size();idx++){
        internal_node[leaf_level_start]  = merkle_internal_node(leaf_node[idx]);
    }
    
    for(size_t idx = leaf_level_start - 1; idx > 0; idx --) {
        internal_node[idx] = merkle_internal_node(internal_node[(idx<<1)+1],internal_node[(idx<<1)+2]);
    }
    internal_node[0] = merkle_internal_node(internal_node[1],internal_node[2]);
    calculat_finish = true;

}

size_t merkle_tree::sibling_node(size_t node_idx){
    return node_idx&1?node_idx+1:node_idx-1;
}

std::vector<HASH_TYPE> merkle_tree::make_proof(){
    if(!calculat_finish)
        re_calcuate();
    
    return internal_node[0].get_hash_value();
}

merkle_tree::merkle_tree(/* args */)
{
    internal_node.clear();
    leaf_node.clear();
   
    level = 1;
    calculat_finish = false;

}

merkle_tree::~merkle_tree()
{
}
