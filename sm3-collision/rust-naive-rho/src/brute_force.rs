use crate::utils::*;
use hex;
use rand::prelude::*;
use sm3::{Digest, Sm3};
use std::time;

#[allow(unused)]
fn find_collision_brute_force(bit_len: usize) {
    let mut target = Sm3::digest(b"dmhj");
    println!("target:\t\t{}", hex::encode_upper(&target));

    let mut rng = thread_rng();
    let mut hasher = Sm3::new();
    let mut collision = [0u8; 32];
    rng.fill_bytes(&mut collision);
    let mut out;
    let mut cnt = 0;

    let t1 = time::Instant::now();
    loop {
        cnt += 1;
        unsafe {
            *(collision.as_ptr() as *mut u128) += 1;
        }
        hasher.update(collision);
        out = hasher.finalize_reset();
        if bit_cmp(&target, &out, bit_len) {
            break;
        }
    }
    let t2 = t1.elapsed();

    println!(
        "collision:\t{}\nout:\t\t{}",
        hex::encode_upper(&collision),
        hex::encode_upper(&out)
    );
    println!("Got {bit_len} bits collision");
    println!("Done At {cnt} rounds\t{:?}", t2)
}
