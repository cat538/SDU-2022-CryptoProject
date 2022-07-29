// Implementation of the prime field(SCA-256) used by SM2
// FieldCtx暴露给外部，使用montgomery reduction 优化

use crate::consts;
use crate::error::{Sm2Error, Sm2Result};
use crate::utils::*;

use byteorder::{BigEndian, ReadBytesExt, WriteBytesExt};
use num_bigint::BigUint;
use num_traits::{Num, One};
use rand::RngCore;
use std::io::Cursor;
use std::ops::Shl;

/// 域上元素类型，用4个u64表示256位大数，通常情况下使用
/// montgomery形式表示。FieldEle(a) = aR mod p, with R = 2^256.
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct FieldEle {
    is_mont: bool,
    value: [u64; 4],
}

impl FieldEle {
    pub fn new(val: [u64; 4]) -> FieldEle {
        FieldEle {
            is_mont: false,
            value: val,
        }
    }
    // pub fn from_slice(x: &[u64]) -> FieldEle {
    //     let mut arr: [u64; 4] = [0; 4];
    //     arr.copy_from_slice(&x[0..4]);
    //     FieldEle::new(arr)
    // }
    pub fn zero() -> FieldEle {
        FieldEle::new([0; 4])
    }
    #[inline]
    pub fn is_zero(&self) -> bool {
        self.value == [0; 4]
    }
    // pub fn is_even(&self) -> bool {
    //     self.0[3] & 0x01 == 0
    // }
    // pub fn div2(&self, carry: u32) -> FieldEle {
    //     let mut ret = FieldEle::zero();
    //     let mut carry = carry;

    //     let mut i = 0;
    //     while i < 8 {
    //         ret.value[i] = (carry << 31) + (self.value[i] >> 1);
    //         carry = self.value[i] & 0x01;

    //         i += 1;
    //     }
    //     ret
    // }

    // Conversions
    pub fn to_bytes(&self) -> Result<Vec<u8>, ()> {
        if self.is_mont {
            return Err(());
        }
        let mut ret: Vec<u8> = Vec::new();
        for i in 0..4 {
            ret.write_u64::<BigEndian>(self.value[i]).unwrap();
        }
        Ok(ret)
    }

    pub fn from_bytes(x: &[u8]) -> Result<FieldEle, ()> {
        // InvalidFieldLen
        if x.len() != 32 {
            return Err(());
        }
        let mut elem = FieldEle::zero();
        let mut c = Cursor::new(x);
        for i in 0..4 {
            let x = c.read_u64::<BigEndian>().unwrap();
            elem.value[i] = x;
        }
        Ok(elem)
    }

    pub fn to_biguint(&self) -> Result<BigUint, ()> {
        if self.is_mont {
            return Err(());
        }
        let v = self.to_bytes()?;
        Ok(BigUint::from_bytes_be(&v[..]))
    }

    pub fn from_biguint(bi: &BigUint) -> Result<FieldEle, ()> {
        let v = bi.to_bytes_be();
        let mut num_v = [0u8; 32];
        num_v[32 - v.len()..32].copy_from_slice(&v[..]);
        FieldEle::from_bytes(&num_v[..])
    }

    // pub fn from_num(x: u64) -> FieldEle {
    //     let mut arr: [u32; 8] = [0; 8];
    //     arr[7] = (x & 0xffff_ffff) as u32;
    //     arr[6] = (x >> 32) as u32;

    //     FieldEle::new(arr)
    // }

    // pub fn to_str(&self, radix: u32) -> String {
    //     let b = self.to_biguint();
    //     b.to_str_radix(radix)
    // }
    // pub fn get_value(&self, i: usize) -> u32 {
    //     self.value[i]
    // }
}

pub struct FieldCtx {
    /// m
    modulus: FieldEle,
    /// m' = -m^-1 mod R
    modulus_p: FieldEle,
    /// r   = 2^256 mod p
    r: FieldEle,
    /// r^2 = 2^512 mod p
    r_2: FieldEle,
}

impl FieldCtx {
    pub fn new(m: &[u64;4]) -> Result<FieldCtx, ()> {
        let mut modulus = FieldEle{is_mont:false, value: [0u64;4]};
        modulus.value.copy_from_slice(m);
        let modulus_big = modulus.to_biguint()?;
        let r = BigUint::one().shl(256) % &modulus_big;
        let r_2 = BigUint::one().shl(512) % modulus_big;
        let r = FieldEle::from_biguint(&r)?;
        let r_2 = FieldEle::from_biguint(&r_2)?;
        
        let modulus_p = FieldEle{is_mont:false, value: [0xfffffffc_00000001, 0xfffffffe_00000000, 0xffffffff_00000001, 0x00000000_00000001]};
        Ok(FieldCtx {
            modulus,
            modulus_p,
            r,
            r_2,
        })
    }

    /// to_montgomery(a) = a*R mod p, 其中R = 2^256
    #[inline]
    pub fn to_montgomery(&self, elem: &FieldEle) -> FieldEle {
        let mut res = self.mul(elem, &self.r_2).unwrap();
        res.is_mont = true;
        res    
    }

    pub fn zero(&self) -> FieldEle {
        FieldEle {
            is_mont: true,
            value: [0, 0, 0, 0],
        }
    }
    pub fn one(&self) -> FieldEle {
        FieldEle {
            is_mont: true,
            value: self.r.value,
        }
    }

    pub fn from_slice(&self, value: &[u64; 4]) -> FieldEle {
        let mut elem = FieldEle{is_mont: false, value: [0u64;4]};
        elem.value.copy_from_slice(value);
        self.to_montgomery(&elem)
    }

    pub fn from_bytes(&self, value: &[u8]) -> FieldEle {
        let mut elem = FieldEle{is_mont: false, value: [0u64;4]};
        let mut c = Cursor::new(value);
        for i in 0..4 {
            let x = c.read_u64::<BigEndian>().unwrap();
            elem.value[i] = x;
        }
        self.to_montgomery(&elem)
    }

    pub fn random(&self, mut rng: impl RngCore) -> FieldEle{
        let mut buf = [0; 32];
        rng.fill_bytes(&mut buf);
        self.from_bytes(&buf)
    }

    fn sub_inner(
        &self,
        l0: u64,
        l1: u64,
        l2: u64,
        l3: u64,
        l4: u64,
        r0: u64,
        r1: u64,
        r2: u64,
        r3: u64,
        r4: u64,
    ) -> ([u64;4], u64) {
        let (w0, borrow) = sbb(l0, r0, 0);
        let (w1, borrow) = sbb(l1, r1, borrow);
        let (w2, borrow) = sbb(l2, r2, borrow);
        let (w3, borrow) = sbb(l3, r3, borrow);
        let (_, borrow) = sbb(l4, r4, borrow);

        // 如果在上面计算过程最后一步发生underflow，则borrow = 0xfff...fff，否则borrow=0
        // 将borrow作为mask，决定是否需要加上modulus
        // 这里没有分支判断，constant-time
        let (w0, carry) = adc(w0, self.modulus.value[0] & borrow, 0);
        let (w1, carry) = adc(w1, self.modulus.value[1] & borrow, carry);
        let (w2, carry) = adc(w2, self.modulus.value[2] & borrow, carry);
        let (w3, _) = adc(w3, self.modulus.value[3] & borrow, carry);

        ([w0, w1, w2, w3], borrow)
    }



    /// Montgomery Reduction
    ///
    /// Handbook of Applied Cryptography 第600页
    ///
    /// 计算TR^-1 mod p, 其中T为512比特, R = 2^256, p' = -p^-1 mod R
    ///
    /// The general algorithm is:
    /// ```text
    /// A <- input (2n b-limbs)
    /// for i in 0..n {
    ///     u <- A[i] p' mod b
    ///     A <- A + u p b^i
    /// }
    /// A <- A / b^n
    /// if A >= p {
    ///     A <- A - p
    /// }
    /// ```
    ///
    /// 在实际视线中，以u64为单位,A = [r7,r6,r5,r4,r3,r2,r1,r0]:
    /// 
    /// A = A + (r0 * p' mod 2^64) * p
    /// A = A + (r1 * p' mod 2^64) * p
    /// A = A + (r2 * p' mod 2^64) * p
    /// A = A + (r3 * p' mod 2^64) * p
    /// 
    /// For sm2 :
    ///
    ///
    /// References:
    /// - Handbook of Applied Cryptography, Chapter 14
    ///   Algorithm 14.32
    ///   http://cacr.uwaterloo.ca/hac/about/chap14.pdf
    #[inline]
    #[allow(clippy::too_many_arguments)]
    fn montgomery_reduce(
        &self,
        r0: u64,
        r1: u64,
        r2: u64,
        r3: u64,
        r4: u64,
        r5: u64,
        r6: u64,
        r7: u64,
    ) -> FieldEle {
        let u0 = self.modulus_p.value[3].wrapping_mul(r7);
        let (_, carry) = mac(r0, u0, self.modulus.value[0], 0);
        let (r1, carry) = mac(r1, u0, self.modulus.value[1], carry);
        let (r2, carry) = mac(r2, u0, self.modulus.value[2], carry);
        let (r3, carry) = mac(r3, u0, self.modulus.value[3], carry);
        let (r4, carry2) = adc(r4, 0, carry);

        let u1 = self.modulus_p.value[3].wrapping_mul(r6);
        let (_, carry) = mac(r1, u1, self.modulus.value[0], 0);
        let (r2, carry) = mac(r2, u1, self.modulus.value[1], carry);
        let (r3, carry) = mac(r3, u1, self.modulus.value[2], carry);
        let (r4, carry) = mac(r4, u1, self.modulus.value[3], carry);
        let (r5, carry2) = adc(r5, carry2, carry);

        let u2 = self.modulus_p.value[3].wrapping_mul(r5);
        let (_, carry) = mac(r2, u2, self.modulus.value[0], 0);
        let (r3, carry) = mac(r3, u2, self.modulus.value[1], carry);
        let (r4, carry) = mac(r4, u2, self.modulus.value[2], carry);
        let (r5, carry) = mac(r5, u2, self.modulus.value[3], carry);
        let (r6, carry2) = adc(r6, carry2, carry);

        let u3 = self.modulus_p.value[3].wrapping_mul(r4);
        let (_, carry) = mac(r3, u3, self.modulus.value[0], 0);
        let (r4, carry) = mac(r4, u3, self.modulus.value[1], carry);
        let (r5, carry) = mac(r5, u3, self.modulus.value[2], carry);
        let (r6, carry) = mac(r6, u3, self.modulus.value[3], carry);
        let (r7, r8) = adc(r7, carry2, carry);

        // Result may be within MODULUS of the correct value
        let (result, _) = self.sub_inner(
            r4,
            r5,
            r6,
            r7,
            r8,
            self.modulus.value[0],
            self.modulus.value[1],
            self.modulus.value[2],
            self.modulus.value[3],
            0,
        );

        FieldEle{is_mont:true, value: result}
    }

    // return a+b mod p; 两个元素相加后减去Ctx中的modulus，保证在域上
    pub fn add(&self, a: &FieldEle, b: &FieldEle) -> Result<FieldEle, ()> {
        if a.is_mont != b.is_mont {
            return Err(())
        }
        // raw_add
        let (w0, carry) = adc(a.value[0], b.value[0], 0);
        let (w1, carry) = adc(a.value[1], b.value[1], carry);
        let (w2, carry) = adc(a.value[2], b.value[2], carry);
        let (w3, w4)    = adc(a.value[3], b.value[3], carry);

        let (result, _) = self.sub_inner(
            w0,
            w1,
            w2,
            w3,
            w4,
            self.modulus.value[0],
            self.modulus.value[1],
            self.modulus.value[2],
            self.modulus.value[3],
            0,
        );
        Ok(FieldEle{is_mont:true, value: result})
    }

    // return a-b mod p; 两个元素相减后根据borrow判断是否需要加上modulus，保证在域上
    pub fn sub(&self, a: &FieldEle, b: &FieldEle) -> Result<FieldEle, ()> {
        if a.is_mont != b.is_mont {
            return Err(())
        }
        let [l0, l1, l2, l3] = a.value;
        let [r0, r1, r2, r3] = b.value;
        let (result, _) = self.sub_inner(l0, l1, l2, l3, 0, r0, r1, r2, r3, 0);
        Ok(FieldEle{is_mont: a.is_mont, value: result})
    }

    /// return a * b * R^-1 mod p;
    pub fn mul(&self, a: &FieldEle, b: &FieldEle) -> Result<FieldEle, ()> {
        if a.is_mont != b.is_mont {
            return Err(())
        }
        // Schoolbook multiplication.
        let (w0, carry) = mac(0, a.value[0], b.value[0], 0);
        let (w1, carry) = mac(0, a.value[0], b.value[1], carry);
        let (w2, carry) = mac(0, a.value[0], b.value[2], carry);
        let (w3, w4)    = mac(0, a.value[0], b.value[3], carry);

        let (w1, carry) = mac(w1, a.value[1], b.value[0], 0);
        let (w2, carry) = mac(w2, a.value[1], b.value[1], carry);
        let (w3, carry) = mac(w3, a.value[1], b.value[2], carry);
        let (w4, w5)    = mac(w4, a.value[1], b.value[3], carry);

        let (w2, carry) = mac(w2, a.value[2], b.value[0], 0);
        let (w3, carry) = mac(w3, a.value[2], b.value[1], carry);
        let (w4, carry) = mac(w4, a.value[2], b.value[2], carry);
        let (w5, w6)    = mac(w5, a.value[2], b.value[3], carry);

        let (w3, carry) = mac(w3, a.value[3], b.value[0], 0);
        let (w4, carry) = mac(w4, a.value[3], b.value[1], carry);
        let (w5, carry) = mac(w5, a.value[3], b.value[2], carry);
        let (w6, w7)    = mac(w6, a.value[3], b.value[3], carry);

        Ok(self.montgomery_reduce(w0, w1, w2, w3, w4, w5, w6, w7))
    }


    // #[inline(always)]
    // pub fn square(&self, a: &FieldEle) -> Sm2Result<FieldEle> {
    //     self.mul(a, a)
    // }

    // #[inline(always)]
    // pub fn cubic(&self, a: &FieldEle) -> Sm2Result<FieldEle> {
    //     self.mul(a, &self.mul(a, a)?)
    // }

    // // Extended Eulidean Algorithm(EEA) to calculate x^(-1) mod p
    // // Reference:
    // // http://delta.cs.cinvestav.mx/~francisco/arith/julio.pdf
    // pub fn inv(&self, x: &FieldEle) -> Sm2Result<FieldEle> {
    //     if x.is_zero() {
    //         return Err(Sm2Error::ZeroFiled);
    //     }

    //     let mut ru = *x;
    //     let mut rv = self.modulus;
    //     let mut ra = FieldEle::from_num(1);
    //     let mut rc = FieldEle::zero();

    //     while !ru.is_zero() {
    //         if ru.is_even() {
    //             ru = ru.div2(0);
    //             if ra.is_even() {
    //                 ra = ra.div2(0);
    //             } else {
    //                 let (sum, car) = raw_add(&ra, &self.modulus);
    //                 ra = sum.div2(car);
    //             }
    //         }

    //         if rv.is_even() {
    //             rv = rv.div2(0);
    //             if rc.is_even() {
    //                 rc = rc.div2(0);
    //             } else {
    //                 let (sum, car) = raw_add(&rc, &self.modulus);
    //                 rc = sum.div2(car);
    //             }
    //         }

    //         if ru >= rv {
    //             ru = self.sub(&ru, &rv)?;
    //             ra = self.sub(&ra, &rc)?;
    //         } else {
    //             rv = self.sub(&rv, &ru)?;
    //             rc = self.sub(&rc, &ra)?;
    //         }
    //     }
    //     Ok(rc)
    // }

    // pub fn neg(&self, x: &FieldEle) -> Sm2Result<FieldEle> {
    //     self.sub(&self.modulus, x)
    // }

    // fn exp(&self, x: &FieldEle, n: &BigUint) -> Sm2Result<FieldEle> {
    //     let u = FieldEle::from_biguint(n)?;

    //     let mut q0 = FieldEle::from_num(1);
    //     let mut q1 = *x;

    //     let mut i = 0;
    //     while i < 256 {
    //         let index = i as usize / 32;
    //         let bit = 31 - i as usize % 32;

    //         let sum = self.mul(&q0, &q1)?;
    //         if (u.get_value(index) >> bit) & 0x01 == 0 {
    //             q1 = sum;
    //             q0 = self.square(&q0)?;
    //         } else {
    //             q0 = sum;
    //             q1 = self.square(&q1)?;
    //         }

    //         i += 1;
    //     }
    //     Ok(q0)
    // }

    // // Square root of a field element
    // pub fn sqrt(&self, g: &FieldEle) -> Result<FieldEle, Sm2Error> {
    //     // p = 4 * u + 3
    //     // u = u + 1
    //     let u = BigUint::from_str_radix(
    //         "28948022302589062189105086303505223191562588497981047863605298483322421248000",
    //         10,
    //     )
    //     .unwrap();

    //     let y = self.exp(g, &u)?;
    //     if self.square(&y)? == *g {
    //         Ok(y)
    //     } else {
    //         Err(Sm2Error::FieldSqrtError)
    //     }
    // }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_add() {
        let sm2_field = FieldCtx::new(&consts::P).unwrap();
        let zero = sm2_field.from_slice(&[0, 0, 0, 0]);
        let one = sm2_field.from_slice(&[0, 0, 0, 1]);
        let two = sm2_field.from_slice(&[0, 0, 0, 2]);
        println!("0: {:?}", zero);
        println!("1: {:?}", one);
        println!("2: {:?}", two);
        // println!("{:?}", sm2_field.montgomery_reduce( 0, 0, 0, 0,one.value[0], one.value[1], one.value[2], one.value[3],));
        let res1 = sm2_field.add(&zero, &one).unwrap();
        let res2 = sm2_field.add(&one, &one).unwrap();
        println!("one: {:?}", sm2_field.one());
        println!("0+1: {:?}", res1);
        println!("1+1: {:?}", res2);

        let no_mont_1 = FieldEle{is_mont:false, value:[0,0,0,1]};
        println!("{:?}", no_mont_1);
        println!("{:?}", sm2_field.to_montgomery(&no_mont_1));
        // let three = ctx.add(&one, &two).unwrap();
        // assert_eq!(three, FieldEle::new([0, 0, 0, 3]));
    }
}
