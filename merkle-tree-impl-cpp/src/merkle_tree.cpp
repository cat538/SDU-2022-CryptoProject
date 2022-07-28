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
    leaf_nums = 0;
}
// merkle_internal_node::merkle_internal_node(merkle_internal_node& in){
//     hash_value = in.hash_value;
// }
merkle_internal_node::merkle_internal_node(merkle_leaf& in){
    hash_value.clear();
    hash_value.emplace_back(in.get_hash_value());
    leaf_nums = 1;
}
merkle_internal_node::~merkle_internal_node()
{
    hash_value.clear();
}

merkle_internal_node::merkle_internal_node(merkle_internal_node& in1,merkle_internal_node& in2){
    hash_value = in1.hash_value;
    hash_value.insert(hash_value.end(),in2.hash_value.begin(),in2.hash_value.end());
    leaf_nums = in1.leaf_nums + in2.leaf_nums;
}
std::vector<HASH_TYPE> merkle_internal_node::get_hash_value(){
    return hash_value;
}
size_t merkle_internal_node::get_leaf_nums(){
    return leaf_nums;
}

void merkle_internal_node::print_hash(){
    for(auto x : hash_value){
        for(auto i : x){
            printf("%02x",i);
        }
        printf("\n");
    }
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
   
    // std::cout << level << std::endl <<  (1 << (level - 1)) << std::endl << node_cnt <<  std::endl;
}
/**
 * @brief 对于节点重新计算hash结果
 * 
 * @param node_idx 节点编号
 */
void merkle_tree::re_calcuate(){
    internal_node.clear();
    internal_node.resize((1<<level)-1);
    leaf_level_start = (1 << (level - 1)) - 1;
    for(size_t idx = 0; idx < leaf_node.size();idx++){
        internal_node[leaf_level_start+idx]  = merkle_internal_node(leaf_node[idx]);
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
    node_cnt = 0;
    level = 1;
    calculat_finish = false;

}

merkle_tree::~merkle_tree()
{
}

void merkle_tree::print_internode(){
    if(!calculat_finish){
        std::cout<<"calculate unfinished!"<<std::endl;
    }
    std::cout<<level << std::endl;
    std::cout<< internal_node.size() << std::endl;

    for(auto nod: internal_node){
        auto print_value = nod.get_hash_value();
        std::cout<<"node size"<<print_value.size() << std::endl;
        for(auto x : print_value){
            for(auto i : x){
                printf("%02x",i);
            }
            printf("\n");
        }
    }
}

bool internode_cmp(merkle_internal_node* in1,merkle_internal_node* in2){
    auto value1 = in1->get_hash_value();
    auto value2 = in2->get_hash_value();

    if(value1.size()!= value2.size()){
        return false;
    }

    size_t len = value1.size();

    for(int i=0;i<len;i++){
        if(value1[i]!=value2[i])
            return false;
    }
    return true;
}


bool merkle_tree::inclusion_proof(size_t idx,merkle_leaf* in){
    if(!calculat_finish){
        re_calcuate();
    }

    size_t tree_idx = leaf_level_start + idx;
    merkle_internal_node vrfy_node = merkle_internal_node(*in);
    
    // vrfy_node.print_hash();
    // internal_node[tree_idx].print_hash();


    while(tree_idx!= root_idx){
        size_t pa_idx = ((tree_idx - 1 ) >> 1);
        if(tree_idx&1){
            vrfy_node = merkle_internal_node(vrfy_node,internal_node[(pa_idx<<1)+2]);
        }
        else{
            vrfy_node = merkle_internal_node(internal_node[(pa_idx<<1)+1],vrfy_node);
        }
        tree_idx =pa_idx;
    }
    return internode_cmp(&vrfy_node,&internal_node[0]);
}
size_t merkle_tree::get_node_cnt(){
    return node_cnt;
}
size_t merkle_tree::get_level_start(){
    return leaf_level_start;
}
merkle_internal_node merkle_tree::get_node(size_t idx){
    return internal_node[idx];
}

bool merkle_tree::consistency_proof(merkle_tree* old_tree){
    if(!calculat_finish) re_calcuate();
    old_tree->re_calcuate();

    size_t cnt = old_tree->get_node_cnt();
    if(cnt == 0){
        std::cout << "Always true!" <<std::endl;
        return true;
    }
    size_t logcnt = int(log2(cnt));
    merkle_internal_node con_vrfy = internal_node[leaf_level_start];
    size_t node_idx = leaf_level_start;
    for(size_t i = 0;i < logcnt ;i ++ ){
        node_idx = (node_idx - 1) >> 1;
        con_vrfy = internal_node[node_idx];
    }
    size_t leaf_num = con_vrfy.get_leaf_nums();

    while(leaf_num!=cnt){
        node_idx += 1;
        // std::cout << node_idx << std::endl;
        // std::cout <<  internal_node[node_idx].get_leaf_nums() << std::endl;
        
        if((cnt-leaf_num) == internal_node[node_idx].get_leaf_nums()){
            con_vrfy = merkle_internal_node(con_vrfy,internal_node[node_idx]);
            break;
        }
        if((cnt-leaf_num)> internal_node[node_idx].get_leaf_nums()){
            con_vrfy = merkle_internal_node(con_vrfy,internal_node[node_idx]);
            node_idx += 1;
        }else{
            // ((cnt-leaf_num)< internal_node[node_idx].get_leaf_nums())
            node_idx = (node_idx << 1) ;
        }
        leaf_num = con_vrfy.get_leaf_nums();

    }
    
    bool ans = internode_cmp(&con_vrfy,&old_tree->get_node(0));
    if(!ans){
        std::cout << "consistency_proof error: old tree error"<< std::endl;
        return false;
    }
    auto audit_node = internal_node[node_idx];
    while(node_idx!=root_idx){
       // std::cout << node_idx << std::endl;

        if(node_idx&1){
            audit_node = merkle_internal_node(audit_node,internal_node[node_idx+1]);
        }else{
            audit_node = merkle_internal_node(internal_node[node_idx - 1],audit_node);
        }
        node_idx = (node_idx - 1) >> 1;
    }
    ans = internode_cmp(&audit_node,&internal_node[root_idx]);
    if(!ans){
        std::cout << "consistency_proof error: new tree error"<< std::endl;
        return false;
    }
    return true;
}