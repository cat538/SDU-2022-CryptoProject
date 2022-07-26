mod hash_utils;
mod element;


#[cfg(test)]
mod tests {
    use std::collections::{BTreeMap, VecDeque};

    struct Element<T>{
        val: T
    }

    #[test]
    fn test_btree_map() {
        let nodes: BTreeMap<usize, VecDeque<Element<i32>>>;

    }

    #[test]
    fn test_sha2(){
        use sha2::{Sha256, Digest};
        use base64::{encode, decode};

        fn assitant (x: impl AsRef<[u8]>) ->Vec<u8>{
            let mut hasher = Sha256::new();
            hasher.update(x);
            let res = hasher.finalize_reset();
            res.to_vec()
        }

        let arr = "123456789";
        let res = assitant(arr);
        let res_str = encode(res);
        println!("{:?}", res_str);
    }
}
