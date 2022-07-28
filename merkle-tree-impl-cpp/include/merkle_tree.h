#pragma once
#include "head.h"


class merkle_leaf
{
private:
    /* data */
    std::chrono::time_point<std::chrono::system_clock> temp_stmp;
    HASH_TYPE hash_value;
    uint32_t value;
public:
    merkle_leaf() = default;
    merkle_leaf(uint32_t in);
    // merkle_leaf(merkle_leaf &in);
    HASH_TYPE get_hash_value(){ return hash_value; };
    uint32_t get_value() { return value ;};
    std::chrono::time_point<std::chrono::system_clock> get_temp_stmp(){ return temp_stmp;};

    ~merkle_leaf();
};




class merkle_internal_node
{
private:
    /* data */
    std::vector<HASH_TYPE> hash_value;
    size_t leaf_nums;


public:
    merkle_internal_node(/* args */);
    // merkle_internal_node(merkle_internal_node& in);
    merkle_internal_node(merkle_leaf& in);
    merkle_internal_node(merkle_internal_node& in1,merkle_internal_node& in2);
    ~merkle_internal_node();
    std::vector<HASH_TYPE> get_hash_value();
    size_t get_leaf_nums();
    void print_hash();

};

bool internode_cmp(merkle_internal_node* in1,merkle_internal_node* in2);


class merkle_tree
{
private:
    /* data */
    std::vector<merkle_internal_node> internal_node;
    std::vector<merkle_leaf> leaf_node;
    size_t node_cnt;
    size_t level;
    bool calculat_finish;
    size_t leaf_level_start;
public:
    merkle_tree(/* args */);
    ~merkle_tree();
    const size_t root_idx = 0;
    size_t sibling_node(size_t node_idx);
    void add(uint32_t value);
    void re_calcuate();
    std::vector<HASH_TYPE> make_proof();
    void print_internode();
    size_t get_level_start();
    size_t get_node_cnt();
    merkle_internal_node get_node(size_t idx);
    bool inclusion_proof(size_t idx,merkle_leaf* in);
    bool consistency_proof(merkle_tree* old_tree); 
};

