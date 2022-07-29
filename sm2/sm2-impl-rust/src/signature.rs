use crate::sm2::error::{Sm2Error, Sm2Result};
use sm3::hash::Sm3Hash;

use super::ecc::*;
use super::field::FieldEle;
use byteorder::{BigEndian, WriteBytesExt};
use num_bigint::BigUint;
use num_traits::*;
use std::fmt;
use yasna;

pub type Pubkey = Point;
pub type Seckey = BigUint;

pub struct Signature {
    r: BigUint,
    s: BigUint,
}

impl Signature {
    pub fn new(r_bytes: &[u8], s_bytes: &[u8]) -> Self {
        let r = BigUint::from_bytes_be(r_bytes);
        let s = BigUint::from_bytes_be(s_bytes);
        Signature { r, s }
    }

    pub fn der_decode(buf: &[u8]) -> Result<Signature, yasna::ASN1Error> {
        let (r, s) = yasna::parse_der(buf, |reader| {
            reader.read_sequence(|reader| {
                let r = reader.next().read_biguint()?;
                let s = reader.next().read_biguint()?;
                Ok((r, s))
            })
        })?;
        Ok(Signature { r, s })
    }

    pub fn der_decode_raw(buf: &[u8]) -> Result<Signature, Sm2Error> {
        if buf[0] != 0x02 {
            return Err(Sm2Error::InvalidDer);
        }
        let r_len: usize = buf[1] as usize;
        if buf.len() <= r_len + 4 {
            return Err(Sm2Error::InvalidDer);
        }
        let r = BigUint::from_bytes_be(&buf[2..2 + r_len]);

        let buf = &buf[2 + r_len..];
        if buf[0] != 0x02 {
            return Err(Sm2Error::InvalidDer);
        }
        let s_len: usize = buf[1] as usize;
        if buf.len() < s_len + 2 {
            return Err(Sm2Error::InvalidDer);
        }
        let s = BigUint::from_bytes_be(&buf[2..2 + s_len]);

        Ok(Signature { r, s })
    }

    pub fn der_encode(&self) -> Vec<u8> {
        yasna::construct_der(|writer| {
            writer.write_sequence(|writer| {
                writer.next().write_biguint(&self.r);
                writer.next().write_biguint(&self.s);
            })
        })
    }

    #[inline]
    pub fn get_r(&self) -> &BigUint {
        &self.r
    }

    #[inline]
    pub fn get_s(&self) -> &BigUint {
        &self.s
    }
}

impl fmt::Display for Signature {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "r = 0x{:0>64}, s = 0x{:0>64}",
            self.r.to_str_radix(16),
            self.s.to_str_radix(16)
        )
    }
}

pub struct SigCtx {
    curve: EccCtx,
}

impl SigCtx {
    pub fn new() -> SigCtx {
        SigCtx {
            curve: EccCtx::new(),
        }
    }

    pub fn hash(&self, id: &str, pk: &Point, msg: &[u8]) -> Sm2Result<[u8; 32]> {
        let curve = &self.curve;

        let mut prepend: Vec<u8> = Vec::new();
        if id.len() * 8 > 65535 {
            return Err(Sm2Error::IdTooLong);
        }
        prepend
            .write_u16::<BigEndian>((id.len() * 8) as u16)
            .unwrap();
        for c in id.bytes() {
            prepend.push(c);
        }

        let mut a = curve.get_a().to_bytes();
        let mut b = curve.get_b().to_bytes();

        prepend.append(&mut a);
        prepend.append(&mut b);

        let (x_g, y_g) = curve.to_affine(&curve.generator()?)?;
        let (mut x_g, mut y_g) = (x_g.to_bytes(), y_g.to_bytes());
        prepend.append(&mut x_g);
        prepend.append(&mut y_g);

        let (x_a, y_a) = curve.to_affine(pk)?;
        let (mut x_a, mut y_a) = (x_a.to_bytes(), y_a.to_bytes());
        prepend.append(&mut x_a);
        prepend.append(&mut y_a);

        let mut hasher = Sm3Hash::new(&prepend[..]);
        let z_a = hasher.get_hash();

        // Z_A = HASH_256(ID_LEN || ID || x_G || y_G || x_A || y_A)

        // e = HASH_256(Z_A || M)

        let mut prepended_msg: Vec<u8> = Vec::new();
        prepended_msg.extend_from_slice(&z_a[..]);
        prepended_msg.extend_from_slice(msg);

        let mut hasher = Sm3Hash::new(&prepended_msg[..]);
        Ok(hasher.get_hash())
    }

    pub fn recid_combine(&self, id: &str, pk: &Point, msg: &[u8]) -> Sm2Result<Vec<u8>> {
        let curve = &self.curve;

        let mut prepend: Vec<u8> = Vec::new();
        if id.len() * 8 > 65535 {
            return Err(Sm2Error::IdTooLong);
        }
        prepend
            .write_u16::<BigEndian>((id.len() * 8) as u16)
            .unwrap();
        for c in id.bytes() {
            prepend.push(c);
        }

        let mut a = curve.get_a().to_bytes();
        let mut b = curve.get_b().to_bytes();

        prepend.append(&mut a);
        prepend.append(&mut b);

        let (x_g, y_g) = curve.to_affine(&curve.generator()?)?;
        let (mut x_g, mut y_g) = (x_g.to_bytes(), y_g.to_bytes());
        prepend.append(&mut x_g);
        prepend.append(&mut y_g);

        let (x_a, y_a) = curve.to_affine(pk)?;
        let (mut x_a, mut y_a) = (x_a.to_bytes(), y_a.to_bytes());
        prepend.append(&mut x_a);
        prepend.append(&mut y_a);

        let mut hasher = Sm3Hash::new(&prepend[..]);
        let z_a = hasher.get_hash();

        // Z_A = HASH_256(ID_LEN || ID || x_G || y_G || x_A || y_A)

        // e = HASH_256(Z_A || M)

        let mut prepended_msg: Vec<u8> = Vec::new();
        prepended_msg.extend_from_slice(&z_a[..]);
        prepended_msg.extend_from_slice(msg);

        Ok(prepended_msg)
    }

    pub fn sign(&self, msg: &[u8], sk: &BigUint, pk: &Point) -> Sm2Result<Signature> {
        // Get the value "e", which is the hash of message and ID, EC parameters and public key
        let digest = self.hash("1234567812345678", pk, msg)?;

        self.sign_raw(&digest[..], sk)
    }

    pub fn sign_raw(&self, digest: &[u8], sk: &BigUint) -> Sm2Result<Signature> {
        let curve = &self.curve;
        // Get the value "e", which is the hash of message and ID, EC parameters and public key

        let e = BigUint::from_bytes_be(digest);

        // two while loops
        loop {
            // k = rand()
            // (x_1, y_1) = g^kg
            let k = self.curve.random_uint();

            let p_1 = curve.g_mul(&k)?;
            let (x_1, _) = curve.to_affine(&p_1)?;
            let x_1 = x_1.to_biguint();

            // r = e + x_1
            let r = (&e + x_1) % curve.get_n();
            if r == BigUint::zero() || &r + &k == *curve.get_n() {
                continue;
            }

            // s = (1 + sk)^-1 * (k - r * sk)
            let s1 = curve.inv_n(&(sk + BigUint::one()))?;

            let mut s2_1 = &r * sk;
            if s2_1 < k {
                s2_1 += curve.get_n();
            }
            let mut s2 = s2_1 - k;
            s2 %= curve.get_n();
            let s2 = curve.get_n() - s2;

            let s = (s1 * s2) % curve.get_n();

            if s != BigUint::zero() {
                // Output the signature (r, s)
                return Ok(Signature { r, s });
            }
            return Err(Sm2Error::ZeroSig);
        }
    }

    pub fn verify(&self, msg: &[u8], pk: &Point, sig: &Signature) -> Sm2Result<bool> {
        //Get hash value
        let digest = self.hash("1234567812345678", pk, msg)?;
        //println!("digest: {:?}", digest);
        self.verify_raw(&digest[..], pk, sig)
    }

    pub fn verify_raw(&self, digest: &[u8], pk: &Point, sig: &Signature) -> Sm2Result<bool> {
        if digest.len() != 32 {
            return Err(Sm2Error::InvalidDigestLen);
        }
        let e = BigUint::from_bytes_be(digest);

        let curve = &self.curve;
        // check r and s
        if *sig.get_r() == BigUint::zero() || *sig.get_s() == BigUint::zero() {
            return Ok(false);
        }
        if *sig.get_r() >= *curve.get_n() || *sig.get_s() >= *curve.get_n() {
            return Ok(false);
        }

        // calculate R
        let t = (sig.get_s() + sig.get_r()) % curve.get_n();
        if t == BigUint::zero() {
            return Ok(false);
        }

        let p_1 = curve.add(&curve.g_mul(sig.get_s())?, &curve.mul(&t, pk)?)?;
        let (x_1, _) = curve.to_affine(&p_1)?;
        let x_1 = x_1.to_biguint();

        let r_ = (e + x_1) % curve.get_n();

        // check R == r?
        Ok(r_ == *sig.get_r())
    }

    pub fn new_keypair(&self) -> Sm2Result<(Point, BigUint)> {
        let curve = &self.curve;
        let mut sk: BigUint = curve.random_uint();
        let mut pk: Point = curve.g_mul(&sk)?;

        loop {
            if !pk.is_zero() {
                break;
            }
            sk = curve.random_uint();
            pk = curve.g_mul(&sk)?;
        }

        Ok((pk, sk))
    }

    pub fn pk_from_sk(&self, sk: &BigUint) -> Sm2Result<Point> {
        let curve = &self.curve;
        if *sk >= *curve.get_n() || *sk == BigUint::zero() {
            return Err(Sm2Error::InvalidSecretKey);
        }
        curve.g_mul(sk)
    }

    pub fn load_pubkey(&self, buf: &[u8]) -> Result<Point, Sm2Error> {
        self.curve.bytes_to_point(buf)
    }

    pub fn serialize_pubkey(&self, p: &Point, compress: bool) -> Sm2Result<Vec<u8>> {
        self.curve.point_to_bytes(p, compress)
    }

    pub fn load_seckey(&self, buf: &[u8]) -> Result<BigUint, Sm2Error> {
        if buf.len() != 32 {
            return Err(Sm2Error::InvalidPrivate);
        }
        let sk = BigUint::from_bytes_be(buf);
        if sk > *self.curve.get_n() {
            Err(Sm2Error::InvalidPrivate)
        } else {
            Ok(sk)
        }
    }

    pub fn serialize_seckey(&self, x: &BigUint) -> Sm2Result<Vec<u8>> {
        if *x > *self.curve.get_n() {
            return Err(Sm2Error::InvalidSecretKey);
        }
        let x = FieldEle::from_biguint(x)?;
        Ok(x.to_bytes())
    }
}

impl Default for SigCtx {
    fn default() -> Self {
        Self::new()
    }
}

