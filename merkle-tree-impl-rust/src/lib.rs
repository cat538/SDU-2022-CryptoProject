mod hash_utils;
mod element;
pub mod tree;

#[cfg(test)]
mod tests {
    use super::hash_utils::*;
    use super::element::*;
    use super::tree::*;
    use std::rc::Rc;

    #[test]
    fn test_build_tree(){
        const TEST_SIZE: usize = 100000;
        let elements = (0..TEST_SIZE).into_iter()
            .map(|x| {
                let buf = [0u8;8];
                unsafe{ *(buf.as_ptr() as * mut usize) = x }
                buf
            })
            .collect::<Vec<[u8;8]>>();
        
        let mut tree = MerkleTree::from_vec(elements);
        assert_eq!(tree.height(), 17);

        // let x = Rc::new([10u8;8]);
        // let x_hash = Element::create_leaf(x);
        // let level = tree.get_level(2).unwrap();
        // level.iter().for_each(|x| println!("{x}"));
    }

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
