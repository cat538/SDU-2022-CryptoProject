/// check `in1` `in2` in `len` bits
pub fn bit_cmp(in1: &[u8], in2: &[u8], bit_len: usize) -> bool {
    assert!(bit_len < in1.len() * 8 && bit_len < in2.len() * 8);
    let main = bit_len / 8;
    let remain = (bit_len % 8) as u32;
    if in1[0..main] != in2[0..main] {
        return false;
    }
    if remain != 0 && (in1[main].wrapping_shr(8 - remain)) != (in2[main].wrapping_shr(8 - remain)) {
        return false;
    }
    return true;
}

pub const fn const_ceil(x: usize) -> usize {
    if x % 8 == 0 {
        return x / 8;
    } else {
        return x / 8 + 1;
    }
}