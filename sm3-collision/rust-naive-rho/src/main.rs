/// this file include multithread birthday attack impl
use hex;
use rand::prelude::*;
use sm3::{Digest, Sm3};
use std::sync::{mpsc::channel, Arc};
use std::{collections::HashMap, process::exit, thread, time};
pub mod find_2ndimage;
pub mod utils;
use utils::*;

const COLLISION_LEN: usize = 50;
const STORE_LEN: usize = const_ceil(COLLISION_LEN);

/// **return**
/// 1. map: HashMap<\[u8; STORE_LEN\], u64>
///     - key:    part of digest to be collided with length: STORE_LEN
///     - value:  offset from the other returned value `base`
/// 2.  base: u64
///     a random bytes array
fn build_collision_table() -> ([u8; 32], HashMap<[u8; STORE_LEN], u64>) {
    // assist function for constructing hash key
    let assist = |mut input: [u8; STORE_LEN]| {
        let remain = (COLLISION_LEN % 8) as u32;
        if remain != 0 {
            input[STORE_LEN - 1] = input[STORE_LEN - 1].wrapping_shr(8 - remain);
        }
        return input;
    };

    let mut map: HashMap<[u8; STORE_LEN], u64> = HashMap::with_capacity(1 << (COLLISION_LEN / 2));
    let mut hasher = Sm3::new();
    let mut rng = thread_rng();
    let mut key:[u8;STORE_LEN];
    let mut rand_in = [0u8; 32];
    rng.fill_bytes(&mut rand_in);
    let base = rand_in.clone();

    let mut offset = 0;
    // If the table is very large,  consider multithread here
    for _ in 0..1 << (COLLISION_LEN / 2) {
        hasher.update(rand_in);
        key = hasher.finalize_reset()[0..STORE_LEN].try_into().unwrap();
        map.insert(assist(key), offset);
        unsafe { *(rand_in.as_ptr() as *mut u64) += 1 }
        offset += 1;
    }
    println!("table size:{}", map.len());
    return (base, map);
}

#[allow(unused)]
fn find_collision_birthday(
    start_msg: &([u8; 32], HashMap<[u8; STORE_LEN], u64>),
) -> time::Duration {
    let mut rng = thread_rng();
    let mut hasher = Sm3::new();
    let mut collision = [0u8; 32];
    rng.fill_bytes(&mut collision);
    let mut k = [0u8; STORE_LEN];
    let mut cnt = 0;

    let (base, map) = start_msg;

    let t1 = time::Instant::now();
    let t2;
    loop {
        cnt += 1;
        unsafe { *(collision.as_ptr() as *mut u128) += 1 }
        hasher.update(collision);
        let out = hasher.finalize_reset();
        k.clone_from_slice(&out[0..STORE_LEN]);
        if let Some(pre) = map.get(&k) {
            t2 = t1.elapsed();
            // println!("k: {}", hex::encode_upper(k));
            unsafe { *(base.as_ptr() as *mut u64) += pre }
            hasher.update(&base);
            let pre_out = hasher.finalize_reset();
            println!(
                "input:\t\t\t{}\nhash(input):\t\t{}\n\
                collision:\t\t{}\nhash(collision):\t{}",
                hex::encode_upper(&base),
                hex::encode_upper(&pre_out),
                hex::encode_upper(&collision),
                hex::encode_upper(&out)
            );
            break;
            // return t2;
        }
    }
    println!("Got {COLLISION_LEN} bits collision");
    println!("Done At {cnt} rounds\t{:?}", t2);
    return t2;
}

#[rustfmt::skip]
/// multithread impl for birthday attack
fn find_collision_multi(start_msg: &([u8; 32], HashMap<[u8; STORE_LEN], u64>)) {
    let thread_num = 8;
    let mut rng = thread_rng();
    let mut start_values = Vec::with_capacity(thread_num);
    for _ in 0..thread_num {
        let mut tmp = [0u8; 32];
        rng.fill_bytes(&mut tmp);
        start_values.push(tmp);
    }

    let (base, map) = start_msg.clone();
    let shared_map = Arc::new(map);

    let mut threads = Vec::with_capacity(thread_num);
    let (tx, rx) = channel();

    let t1 = time::Instant::now();
    let t2;
    for i in 0..thread_num {
        let local_table = shared_map.clone();
        let local_start:[u8; 32] = start_values[i].try_into().unwrap();
        let local_tx = tx.clone();

        threads.push(thread::spawn(move || {
            let mut hasher = Sm3::new();
            let mut local_out;
            let mut k = [0u8; STORE_LEN];
            loop {
                unsafe { *(local_start.as_ptr() as *mut u128) += 1 }
                hasher.update(local_start);
                local_out = hasher.finalize_reset();
                k.clone_from_slice(&local_out[0..STORE_LEN]);
                if let Some(pre) = local_table.get(&k) {
                    unsafe { *(base.as_ptr() as *mut u64) += pre }
                    hasher.update(&base);
                    let pre_out = hasher.finalize_reset();
                    local_tx.send((
                        hex::encode_upper(&pre_out),
                        hex::encode_upper(&local_start),
                        hex::encode_upper(&local_out),
                    )).expect("Unable to send msg");
                    break;
                }
            }
        }));
    }
    // for i in threads {
    //     i.join().unwrap();
    // }
    if let Ok(msg) = rx.recv() {
        t2 = t1.elapsed();
        println!(
            "input:\t\t\t{}\nhash(input):\t\t{}\n\
            collision:\t\t{}\nhash(collision):\t{}",
            hex::encode_upper(&base), msg.0,
            msg.1, msg.2
        );
        println!("Got {COLLISION_LEN} bits collision");
        println!("Done At {:?}", t2);
        exit(0);
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let dgst_len = Sm3::output_size();
    println!("SM3 output size: {dgst_len} bytes");
    // find_2ndimage_bf(12);
    let table = build_collision_table();
    // println!(">>>Single thread :");
    // find_collision_birthday(&table);
    println!(">>>Multi  threads:");
    find_collision_multi(&table);
    Ok(())
}
