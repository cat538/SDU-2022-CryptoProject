#![allow(non_snake_case, unused_assignments)]
const IV: [u32; 8] = [0x7380166f, 0x4914b2b9, 0x172442d7, 0xda8a0600, 0xa96f30bc, 0x163138aa, 0xe38dee4d, 0xb0fb0e4e];

#[inline]
fn T(j: u32) -> u32 {
    if j < 16 {
        0x79cc4519
    } else {
        0x7a879d8a
    }
}

#[inline]
fn FF(j: u32, X: u32, Y: u32, Z: u32) -> u32 {
    if j < 16 {
        X ^ Y ^ Z
    } else {
        X & Y | X & Z | Y & Z
    }
}

#[inline]
fn GG(j: u32, X: u32, Y: u32, Z: u32) -> u32 {
    if j < 16 {
        X ^ Y ^ Z
    } else {
        X & Y | !X & Z
    }
}

#[inline]
fn P0(x: u32) -> u32 {
    x ^ x.rotate_left(9) ^ x.rotate_left(17)
}

#[inline]
fn P1(x: u32) -> u32 {
    x ^ x.rotate_left(15) ^ x.rotate_left(23)
}

/// 文件描述是按bit操作，这里偷一下懒，最小操作单位为u8，以后有时间再改
fn padding(mut m: Vec<u8>) -> Vec<u8> {
    let l = m.len();
    let r = l % 64;
    if r < 56 {
        m.resize(l - r + 64, 0);
    } else {
        m.resize(l - r + 128, 0);
    }
    let new_l = m.len();
    m[l] = 0b10000000;
    m[(l + 1)..(new_l - 8)].clone_from_slice(&[0u8].repeat(new_l - 8 - l - 1));
    m[(new_l - 8)..new_l].clone_from_slice(&(8 * l as u64).to_be_bytes());
    m
}

fn iterate(m: Vec<u8>) -> [u32; 8] {
    let n = m.len() / 64;
    let B: Vec<Vec<u8>> = (0..n).map(|i| i * 64).map(|i| m[i..(i + 64)].to_vec()).collect();
    B.into_iter().fold(IV, CF)
}

/// 在Rust官方文档实现上改的
fn read_be_u32(input: &[u8]) -> u32 {
    let (int_bytes, _) = input.split_at(std::mem::size_of::<u32>());
    u32::from_be_bytes(int_bytes.try_into().unwrap())
}

fn extend(Bi: Vec<u8>) -> (Vec<u32>, Vec<u32>) {
    let n = Bi.len() / 4;
    let mut W = vec![0; 68];
    W[0..16].clone_from_slice(&(0..n).map(|i| i * 4).map(|i| read_be_u32(&Bi[i..(i + 4)])).collect::<Vec<u32>>()[..]);
    for j in 16..68 {
        W[j] = P1(W[j - 16] ^ W[j - 9] ^ W[j - 3].rotate_left(15)) ^ W[j - 13].rotate_left(7) ^ W[j - 6];
    }
    let mut W2 = vec![0; 64];
    for j in 0..64 {
        W2[j] = W[j] ^ W[j + 4];
    }
    // println!("W:{:?}\n{:?}", W.len(), W.iter().map(|&x| format!("{:08x}", x)).collect::<Vec<String>>().join(" "));
    // println!("W2:{:?}\n{:?}", W2.len(), W2.iter().map(|&x| format!("{:08x}", x)).collect::<Vec<String>>().join(" "));
    (W, W2)
}

fn CF(Vi: [u32; 8], Bi: Vec<u8>) -> [u32; 8] {
    let (W, W2) = extend(Bi);
    let [mut A, mut B, mut C, mut D, mut E, mut F, mut G, mut H] = Vi;
    let (mut SS1, mut SS2, mut TT1, mut TT2) = (0, 0, 0, 0);
    for j in 0..64 {
        SS1 = (A.rotate_left(12).wrapping_add(E).wrapping_add(T(j).rotate_left(j))).rotate_left(7);
        SS2 = SS1 ^ A.rotate_left(12);
        TT1 = FF(j, A, B, C).wrapping_add(D).wrapping_add(SS2).wrapping_add(W2[j as usize]);
        TT2 = GG(j, E, F, G).wrapping_add(H).wrapping_add(SS1).wrapping_add(W[j as usize]);
        D = C;
        C = B.rotate_left(9);
        B = A;
        A = TT1;
        H = G;
        G = F.rotate_left(19);
        F = E;
        E = P0(TT2);
        // println!("j={}, A={:?}", j, format!("{:08x}", A));
    }

    [A ^ Vi[0], B ^ Vi[1], C ^ Vi[2], D ^ Vi[3], E ^ Vi[4], F ^ Vi[5], G ^ Vi[6], H ^ Vi[7]]
}

pub fn sm3_base(m: &Vec<u8>) -> [u32;8] {
    let mut m = m.clone();
    m = padding(m);
    iterate(m)
}


#[test]
fn test() {
    let m = "abc".as_bytes().to_vec();
    let result = sm3_base(&m);
    // println!("{}", result);
    assert_eq!("66c7f0f4 62eeedd9 d1f2d46b dc10e4e2 4167c487 5cf2f7a2 297da02b 8f4ba8e0", 
        result.into_iter().map(|x| format!("{:08x}", x)).collect::<Vec<String>>().join(" "));
    let m = "abcd".repeat(16).as_bytes().to_vec();
    let result = sm3_base(&m);
    // println!("{}", result);
    assert_eq!("debe9ff9 2275b8a1 38604889 c18e5a4d 6fdb70e5 387e5765 293dcba3 9c0c5732", 
        result.into_iter().map(|x| format!("{:08x}", x)).collect::<Vec<String>>().join(" "));
}
