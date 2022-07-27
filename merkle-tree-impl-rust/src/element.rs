use std::fmt::Display;
use std::rc::Rc;

use crate::hash_utils::*;

#[derive(Clone, Debug)]
pub enum Element<T: AsRef<[u8]>> {
    Node {
        left: Box<Element<T>>,
        right: Box<Element<T>>,
        hash: String,
    },
    Leaf { data: Rc<T>, hash: String },
    Empty { hash: String },
}

impl<T: AsRef<[u8]>> Element<T> {
    pub fn empty() -> Self {
        let mut hahser = HASHER.lock().unwrap();
        Element::Empty { hash: hahser.hash_empty() }
    }

    pub fn hash(&self) -> Option<&String> {
        match *self {
            Element::Node { ref hash, .. } |
            Element::Leaf { ref hash, .. } |
            Element::Empty { ref hash } => Some(hash),
        }
    }

    pub fn create_leaf(value: Rc<T>) -> Element<T> {
        let mut hahser = HASHER.lock().unwrap();
        let leaf_hash = hahser.hash_leaf(value.as_ref());

        Element::Leaf {
            data: value,
            hash: leaf_hash,
        }
    }

    pub fn create_node(left: Element<T>, right: Element<T>) -> Element<T> {
        let mut hahser = HASHER.lock().unwrap();
        let combined_hash = hahser.hash_node(left.hash().unwrap(), right.hash().unwrap());
        Element::Node {
            hash: combined_hash,
            left: Box::new(left),
            right: Box::new(right),
        }
    }
}

#[cfg(test)]
mod tests{
    use super::*;

    #[test]
    fn test_element(){
        let val1 = Rc::new([0u8;32]);
        let leaf1 = Element::create_leaf(val1.clone());
        println!("{}", leaf1.hash().unwrap());  
    }
}