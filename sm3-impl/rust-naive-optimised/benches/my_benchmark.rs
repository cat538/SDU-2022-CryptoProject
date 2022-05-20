use criterion::{criterion_group, criterion_main, Criterion, BenchmarkId, Throughput};
use sm3::{Digest,Sm3};
use sha2::Sha256;
use sha3::Keccak256;
use rand::prelude::*;
use sm3_impl_cmp::{sm3_base::sm3_base, sm3_opt::Sm3Dm};

fn criterion_cmp(c: &mut Criterion){
    let mut group = c.benchmark_group("Hash bench");
    // let mut hasher_sha = Sha256::new();
    let mut hasher_sm3 = Sm3::new();
    let mut hasher_dm = Sm3Dm::new();
    let mut hasher_kec = Keccak256::new();
    let mut rng = thread_rng();
    let mut inputs = Vec::with_capacity(2);
    for i in 0..2{
        let mut tmp = vec![0u8;i*32];
        rng.fill(tmp.as_mut_slice());
        inputs.push(tmp);
    }

    // perform benchmarks with group
    for (index,msg) in inputs.iter().enumerate(){
        // group.bench_with_input(BenchmarkId::new("SHA",index),&msg,|b,i| b.iter(||{hasher_sha.update(i);hasher_sha.finalize_reset()}));
        group.bench_with_input(BenchmarkId::new("KEC",index),&msg,|b,i| b.iter(||{hasher_kec.update(i);hasher_kec.finalize_reset()}));
        group.bench_with_input(BenchmarkId::new("SM3_base",index),&msg,|b,i| b.iter(||{sm3_base(i)}));
        group.bench_with_input(BenchmarkId::new("SM3_lib",index),&msg,|b,i| b.iter(||{hasher_sm3.update(i);hasher_sm3.finalize_reset()}));
        group.bench_with_input(BenchmarkId::new("SM3_opt",index),&msg,|b,i| b.iter(||{hasher_dm.update(i);hasher_dm.finalize()}));
    }

    group.finish();
}

fn criterion_thrpt(c: &mut Criterion){
    let mut group = c.benchmark_group("Hash bench");
    let mut hasher_sha = Sha256::new();
    let mut hasher_sm3 = Sm3::new();
    let mut hasher_dm = Sm3Dm::new();
    let mut hasher_kec = Keccak256::new();
    let mut rng = thread_rng();
    let mut input = vec![0u8;1<<20];
    rng.fill_bytes(&mut input);
    group.throughput(Throughput::Bytes(input.len() as u64));
    group.bench_function("SHA256",|b|b.iter(|| {hasher_sha.update(&input); hasher_sha.finalize_reset()}));
    group.bench_function("keccak",|b|b.iter(|| {hasher_kec.update(&input); hasher_kec.finalize_reset()}));
    group.bench_function("sm3_base",|b|b.iter(|| sm3_base(&input)));
    group.bench_function("sm3_opt",|b|b.iter(|| {hasher_dm.update(&input); hasher_dm.finalize()}));
    group.bench_function("sm3_lib",|b|b.iter(|| {hasher_sm3.update(&input); hasher_sm3.finalize_reset()}));

    group.finish();
}

criterion_group!(benches, criterion_thrpt);
// criterion_group!(benches, criterion_cmp);
criterion_main!(benches);