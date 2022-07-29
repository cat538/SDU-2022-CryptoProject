package sm2

import "math/big"

//2.3.2.  Bit String to Integer
func bits2int(b []byte, qlen int) *big.Int {
	blen := len(b) * 8
	//SetBytes: b_0*2^(qlen-1) + b_1*2^(qlen-2) + ... + b_(qlen-1)*2^0
	v := new(big.Int).SetBytes(b)
	//if qlen < blen, then the qlen leftmost bits are kept, and subsequent bits are discarded;
	if qlen < blen {
		// that division is equivalent to a "right shift" by blen-qlen bits
		v = new(big.Int).Rsh(v, uint(blen-qlen))
	}
	return v
}

//2.3.3.  Integer to Octet String
func int2octets(x *big.Int, qlen int) []byte {
	rlen := 8 * ((qlen + 7) >> 3) // rlen = 8*ceil(qlen/8)
	b := x.Bytes()
	blen := len(b) * 8
	//x = x_0*2^(rlen-1) + x_1*2^(rlen-2) + ... + x_(rlen-1)
	if blen < rlen {
		// left pad with rlen - blen bits
		b = append(make([]byte, (rlen-blen)/8), b...)
	}
	if blen > rlen {
		// rlen is a multiple of 8 (the smallest multiple of 8 that is not smaller than qlen)
		b = b[:rlen/8]
	}
	return b
}

//2.3.4.  Bit String to Octet String
func bits2octets(b []byte, q *big.Int) []byte {
	z1 := bits2int(b, q.BitLen())     //1. z1 = bits2int(b)
	z2 := new(big.Int).Mod(z1, q)     //2. z2 = z1 mod q
	return int2octets(z2, q.BitLen()) // 3.  z2 is transformed into a sequence of octets by applying int2octets.
}
