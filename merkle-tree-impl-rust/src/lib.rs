mod hash_utils;
mod element;
pub mod tree;

#[cfg(test)]
mod tests {
    use super::hash_utils::*;

    #[test]
    fn test_hash_utils(){
        let mut hasher = MerkleHasher::new();
        let empty_hash = base64::decode(hasher.hash_empty()).unwrap();
        let hex_empty = hex::encode(empty_hash);
        println!("{hex_empty}");

        let data_1 = "123456";
        let data_2 = "456789";
        let hash_1 = hasher.hash_leaf(&data_1);
        let hash_2 = hasher.hash_leaf(&data_2);
        let node_hash = hasher.hash_node(&hash_1, &hash_2);
        println!("{}\n{}\n{}", hash_1,hash_2, node_hash);
    }

    #[test]
    fn test_sha2(){
        use sha2::{Sha256, Digest};

        fn assitant (x: impl AsRef<[u8]>) ->Vec<u8>{
            let mut hasher = Sha256::new();
            hasher.update(x);
            let res = hasher.finalize_reset();
            res.to_vec()
        }

        let arr = "123456789";
        let res = assitant(arr);
        let res_str = base64::encode(res);
        println!("{:?}", res_str);
    }
}
