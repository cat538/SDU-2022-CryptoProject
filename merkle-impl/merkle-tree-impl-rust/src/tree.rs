use std::collections::{BTreeMap, VecDeque};
use std::collections::vec_deque::Iter;
use std::fmt::Display;
use std::rc::Rc;

use crate::element::Element;
use crate::hash_utils::*;
// use crate::proof::Proof;

#[derive(Debug)]
pub enum ProofNode {
    Left(String),
    Right(String),
}

/// MerkleTree struct represents merkle binary tree with values of type `T` and map of nodes.
#[derive(Debug)]
pub struct MerkleTree<T: AsRef<[u8]> + Clone> {
    hasher: MerkleHasher,
    root: Element<T>,
    height: usize,
    count: usize,
    storage: VecDeque<Rc<T>>,
    nodes: BTreeMap<usize, VecDeque<Element<T>>>,
}

impl<T: AsRef<[u8]> + Clone> MerkleTree<T> {
    /// Creates new, empty `MerkleTree`.
    /// # Examples
    ///
    /// ```
    /// extern crate merkle_tree;
    /// use merkle_tree::MerkleTree;
    ///
    /// let tree = MerkleTree::new();
    /// assert_eq!(0, tree.len());
    /// ```
    pub fn new() -> Self {
        MerkleTree {
            hasher: MerkleHasher::new(),
            root: Element::empty(),
            height: 0,
            count: 0,
            storage: VecDeque::new(),
            nodes: BTreeMap::new(),
        }
    }

    /// Creates `MerkleTree` from `Vec` of elements.
    ///                root
    ///         h1'             h2'
    ///         ↑               ↑
    ///     ---------       ---------
    ///     |       |       |       |        
    ///     h1      h2      h3      h4
    ///     ↑       ↑       ↑       ↑
    ///     1       2       3       4
    /// # Examples
    ///
    /// ```
    /// extern crate merkle_tree;
    /// use merkle_tree::MerkleTree;
    ///
    /// const TEST_SIZE: usize = 100000;
    /// let elements = (0..TEST_SIZE).into_iter()
    ///     .map(|x| {
    ///         let buf = [0u8;8];
    ///         unsafe{ *(buf.as_ptr() as * mut usize) = x }
    ///         buf
    ///     })
    ///     .collect::<Vec<[u8;8]>>();
    /// let mut tree = MerkleTree::from_vec(elements);
    /// println!("{}", tree.len()); 
    /// ```
    pub fn from_vec(data: Vec<T>) -> Self {
        if data.is_empty() {
            Self::new()
        } else {
            let elements = data.into_iter()
                .map(|e| Rc::new(e))
                .collect::<VecDeque<Rc<T>>>();
            let mut result = MerkleTree {
                hasher: MerkleHasher::new(),
                root: Element::empty(),
                height: 0,
                count: 0,
                storage: elements,
                nodes: BTreeMap::new(),
            };
            result.build();
            result
        }
    }

    /// Push element into the end of the tree.
    /// # Examples
    ///
    /// ```
    /// extern crate merkle_tree;
    /// use merkle_tree::MerkleTree;
    ///
    /// let mut tree = MerkleTree::new();
    /// tree.push(1);
    /// assert_eq!(1, tree.len());
    /// ```
    pub fn push(&mut self, value: T) {
        self.storage.push_back(Rc::new(value));
        self.count = self.storage.len();
        self.build();
    }

    /// Removes element from the tree and returns `true` if element was removed
    /// successfully and `false` if `index` out of bounds.
    /// # Examples
    ///
    /// ```
    /// extern crate merkle_tree;
    /// use merkle_tree::MerkleTree;
    ///
    /// let mut tree = MerkleTree::from_vec(vec![1, 2, 3]);
    /// assert!(tree.remove(1));
    /// assert_eq!(2, tree.len());
    /// assert!(!tree.remove(5));
    /// ```
    pub fn remove(&mut self, index: usize) -> bool {
        if let Some(_) = self.storage.remove(index) {
            self.count = self.storage.len();
            self.build();
            true
        } else {
            false
        }
    }

    /// Retrieves an element in the `MerkleTree` by index.
    /// # Examples
    ///
    /// ```
    /// extern crate merkle_tree;
    /// use merkle_tree::MerkleTree;
    ///
    /// let mut tree = MerkleTree::new();
    /// tree.push(1);
    /// tree.push(2);
    /// tree.push(3);
    /// assert_eq!(tree.get(1), Some(&2));
    pub fn get(&self, index: usize) -> Option<&T> {
        if let Some(v) = self.storage.get(index) {
            Some(v.as_ref())
        } else {
            None
        }
    }

    /// Retrieves copies of all elements in the `MerkleTree`.
    /// # Examples
    ///
    /// ```
    /// extern crate merkle_tree;
    /// use merkle_tree::MerkleTree;
    ///
    /// let mut tree = MerkleTree::new();
    /// tree.push(1);
    /// tree.push(2);
    /// tree.push(3);
    /// assert_eq!(tree.get_values(), Some(vec![1, 2, 3]));
    pub fn get_values(&self) -> Option<Vec<T>> {
        if self.storage.is_empty() {
            None
        } else {
            let values = self.storage
                .iter()
                .map(|v| v.as_ref().clone())
                .collect::<Vec<T>>();
            Some(values)
        }
    }

    /// Returns the number of elements in the three
    /// # Examples
    ///
    /// ```
    /// extern crate merkle_tree;
    /// use merkle_tree::MerkleTree;
    ///
    /// let mut tree = MerkleTree::new();
    /// assert_eq!(tree.len(), 0);
    /// tree.push(1);
    /// assert_eq!(tree.len(), 1);
    /// ```
    pub fn len(&self) -> usize {
        self.count
    }

    /// Returns the height of the three
    /// # Examples
    ///
    /// ```
    /// extern crate merkle_tree;
    /// use merkle_tree::MerkleTree;
    ///
    /// let mut tree = MerkleTree::new();
    /// assert_eq!(tree.height(), 0);
    /// tree.push(1);
    /// assert_eq!(tree.height(), 0);
    /// tree.push(2);
    /// assert_eq!(tree.height(), 1);
    /// tree.push(3);
    /// assert_eq!(tree.height(), 2);
    ///
    /// ```
    pub fn height(&self) -> usize {
        self.height
    }

    /// Returns `true` if the `MerkleTree` is empty.
    /// # Examples
    ///
    /// ```
    /// extern crate merkle_tree;
    /// use merkle_tree::MerkleTree;
    ///
    /// let mut tree = MerkleTree::new();
    /// assert!(tree.is_empty());
    /// tree.push(1);
    /// assert!(!tree.is_empty());
    /// ```
    pub fn is_empty(&self) -> bool {
        self.storage.is_empty()
    }


    /// Returns root hash of `MerkleTree`
    /// # Examples
    ///
    /// ```
    /// extern crate merkle_tree;
    /// use merkle_tree::MerkleTree;
    ///
    /// let mut tree = MerkleTree::new();
    /// assert_eq!(Some(&"5feceb66ffc86f38d952786c6d696c79c2dbc239dd4e91b46729d73a27fb57e9".to_string()), tree.root_hash());
    /// tree.push(1);
    /// tree.push(2);
    /// tree.push(3);
    /// tree.push(4);
    /// assert_eq!(Some(&"85df8945419d2b5038f7ac83ec1ec6b8267c40fdb3b1e56ff62f6676eb855e70".to_string()), tree.root_hash());
    /// ```
    pub fn root_hash(&self) -> Option<&String> {
        self.root.hash()
    }

    /// Returns a front-to-back iterator.
    /// # Examples
    ///
    /// ```
    /// extern crate merkle_tree;
    /// use merkle_tree::MerkleTree;
    ///
    /// let tree = MerkleTree::from_vec(vec![1, 2, 3, 4]);
    /// let vec: Vec<Rc<i32>> = tree.iter().collect();
    /// assert_eq!(4, vec.len());
    /// ```
    pub fn iter(&self) -> Iter<Rc<T>> {
        self.storage.iter()
    }

    /// Returns the proof for checking if `value` really in tree.
    /// # Examples
    ///
    /// ```
    /// extern crate merkle_tree;
    /// use merkle_tree::MerkleTree;
    ///
    /// let tree = MerkleTree::from_vec(vec![1, 2, 3, 4]);
    /// let proof = tree.get_proof(3);
    /// assert!(proof.validate(tree.root_hash().unwrap());
    /// ```
    pub fn proof_inclusion(&mut self, value: &T) -> bool{
        let path = self.get_needed_hashes_for_proof(&value);
        let mut hash = self.hasher.hash_leaf(value);
        for node in path {
            hash = match node {
                ProofNode::Left(ref proof_hash) => self.hasher.hash_node(proof_hash, &hash),
                ProofNode::Right(ref proof_hash) => self.hasher.hash_node(&hash, proof_hash),
            };
        }

        &hash == self.root_hash().unwrap()
    }

    /// Returns nth level of the MHT
    /// #Example
    /// ```
    /// extern crate merkle_tree;
    /// use merkle_tree::MerkleTree;
    ///
    /// let tree = MerkleTree::from_vec(vec![1, 2, 3, 4]);
    /// let proof = tree.print_level(2);
    /// ```
    pub fn get_level(&self, n: usize) -> Option<&VecDeque<Element<T>>>{
        self.nodes.get(&n)
    }

    fn build(&mut self) {
        self.count = self.storage.len();
        self.height = cal_height(self.count);
        self.root = Element::empty();
        self.nodes.clear();
        let mut current_level = self.height;

        if !self.storage.is_empty() {
            // 1. leaves
            let mut leaves = VecDeque::new();
            for value in &self.storage {
                let e = Element::create_leaf(value.clone());
                leaves.push_back(e);
            }
            self.nodes.insert(current_level, leaves);

            // 2. internal nodes
            while current_level > 0 {
                let above_level = current_level - 1;
                let above_row = {
                    let mut row = VecDeque::new();
                    let current_row = self.nodes.get(&current_level).unwrap();
                    for i in (0..current_row.len()).step_by(2) {
                        let left = current_row.get(i).unwrap();
                        // if odd, duplicate to maintain the balance
                        let right = current_row.get(i + 1).unwrap_or(left);
                        let node = Element::create_node(left.clone(), right.clone());
                        row.push_back(node);
                    }
                    row
                };

                self.nodes.insert(above_level, above_row);
                current_level -= 1;
            }
            // assert!(current_level == 0);
            self.root = self.nodes.get(&0).unwrap()[0].clone(); //root_node;
        }
    }

    fn get_needed_hashes_for_proof(&mut self, value: &T) -> Vec<ProofNode> {
        let mut level = self.height;
        let mut next_hash = self.hasher.hash_leaf(&value);
        let mut needed_hashes = Vec::new();

        while level > 0 {
            if let Some(index) = self.get_element_index(level, &next_hash) {
                let nodes = self.nodes.get(&level).unwrap();
                match nodes.get(index) {
                    Some(&Element::Leaf { ref hash, .. }) |
                    Some(&Element::Node { ref hash, .. }) => {
                        if index % 2 == 0 {
                            if let Some(sibling_node) = nodes.get(index + 1) {
                                needed_hashes.push(ProofNode::Right(sibling_node
                                                                        .hash()
                                                                        .unwrap()
                                                                        .clone()));
                                next_hash = self.hasher.hash_node(hash, sibling_node.hash().unwrap());
                            } else {
                                needed_hashes.push(ProofNode::Right(hash.clone()));
                                next_hash = self.hasher.hash_node(hash, hash);
                            }
                        } else {
                            if let Some(sibling_node) = nodes.get(index - 1) {
                                needed_hashes.push(ProofNode::Left(sibling_node
                                                                       .hash()
                                                                       .unwrap()
                                                                       .clone()));
                                next_hash = self.hasher.hash_node(sibling_node.hash().unwrap(), hash);
                            }
                        }
                    }
                    _ => continue,
                };
            }
            level -= 1;
        }
        needed_hashes
    }

    fn get_element_index(&self, level: usize, hash: &String) -> Option<usize> {
        let row_hashes = self.nodes
            .get(&level)
            .unwrap()
            .iter()
            .map(|e| e.hash().unwrap())
            .collect::<Vec<&String>>();
        row_hashes.iter().position(|&s| s == hash)
    }
}


pub fn cal_height(count: usize) -> usize {
    if count > 0 {
        let height = (count as f64).log2();
        if height - height.floor() > 0.0 {
            (height + 1.0) as usize
        } else {
            height as usize
        }
    } else {
        0
    }
}


#[cfg(test)]
mod tests{
    use super::*;
    #[test]
    fn test_cal_height(){
        assert_eq!(cal_height(0), 0);
        assert_eq!(cal_height(7), 3);
        assert_eq!(cal_height(1024), 10);
        assert_eq!(cal_height(1023), 10);
        assert_eq!(cal_height(1025), 11);
    }

    #[test]
    fn test_build_tree(){
        const TEST_SIZE: usize = 11;
        let elements = (0..TEST_SIZE).into_iter()
            .map(|x| {
                let buf = [0u8;8];
                unsafe{ *(buf.as_ptr() as * mut usize) = x }
                buf
            })
            .collect::<Vec<[u8;8]>>();
        
        let mut tree = MerkleTree::from_vec(elements);
        // for i in 253..263 {
        //     println!("{:?}", tree.storage[i])
        // }
        // 100000 elements 高度对应 17
        // assert_eq!(tree.height(), 17);

        let x = [10u8;8];
        let x_hash = tree.hasher.hash_leaf(&x);
        println!("{}", tree.height());
        // println!("{}", tree.nodes.get(&0).unwrap());
        let level = tree.get_level(3).unwrap();
        level.iter().for_each(|x| println!("{x}"));
        // let index = tree.get_element_index(0, &x_hash).unwrap();
        
        // println!("{index}");
    }

}