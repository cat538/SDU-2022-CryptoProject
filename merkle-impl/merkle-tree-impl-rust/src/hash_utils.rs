/// 此文件实现RFC6962描述的hash strategy:
/// 
/// **INPUT**:  a list of data entries;
/// 
/// 列表中的数据项(entries) 经过hash 作为Merkle Hash Tree的叶子节点
/// 
/// **OUTPUT**: a single 32-byte Merkle Tree Hash. 
/// 
/// Given an ordered list of n inputs, D[n] = {d(0),d(1), ..., 
/// d(n-1)}, the Merkle Tree Hash (MTH) is thus defined as follows:
/// 
/// - The hash of an empty list is the hash of an empty string:
///
///     MTH({}) = SHA-256()
/// 
/// - 叶节点hash规则:
/// 
///     MTH({d(0)}) = SHA-256(0x00 || d(0)).
///
/// - 对于n>1, k为小于n的最大的2的幂(即k<n<=2k) n元素list D[n]的MTH定义为:
///     MTH(D[n]) = SHA-256(0x01 || MTH(D[0:k]) || MTH(D[k:n])),
/// 
///   e.g.: 7 elements list: 则root hash左节点是前4个元素的hash h1,
///         右节点是后三个元素的hash h2; root_hash = H(0x01 || h1 || h2)
///   e.g.: 2 elements list: root_hash = H(0x01 || h1 || h2)
/// Note that the hash calculations for leaves and nodes differ.
/// This domain separation is required to give second preimage resistance.
/// 
/// 输入list长度没有限定是2的幂次，这可能会导致不平衡。

use sha2::{Sha256, Digest};
use base64;
use lazy_static::*;
use std::sync::Mutex;

#[derive(Debug)]
pub struct MerkleHasher{
    hasher: Sha256
}

lazy_static! {
    pub static ref HASHER: Mutex<MerkleHasher> = {
        let hasher = Mutex::new(MerkleHasher::new());
        hasher
    };
}

impl MerkleHasher{
    pub fn new() -> Self{
        MerkleHasher{
            hasher: Sha256::new()
        }
    }
    pub fn hash_empty(&mut self) -> String{
        base64::encode(self.hasher.finalize_reset())
    }
    pub fn hash_leaf(&mut self, data: &impl AsRef<[u8]>) -> String {
        // add 0x00 as prefix according to RFC6962
        let mut buff = vec![0x00u8;data.as_ref().len()+1];
        buff[1..].clone_from_slice(data.as_ref());
        self.hasher.update(buff);
        // encode with base64 according to RFC6962
        base64::encode(self.hasher.finalize_reset())
    }

    pub fn hash_node(&mut self, left: &impl AsRef<[u8]>, right: &impl AsRef<[u8]>) -> String {
        let l_len = left.as_ref().len();
        let r_len = right.as_ref().len();
        // add 0x01 as prefix according to RFC6962
        let mut buff = vec![0x01u8;l_len+r_len+1];
        buff[1..1+l_len].clone_from_slice(left.as_ref());
        buff[1+l_len..].clone_from_slice(right.as_ref());
        self.hasher.update(buff);
        // encode with base64 according to RFC6962
        base64::encode(self.hasher.finalize_reset())
    }

}