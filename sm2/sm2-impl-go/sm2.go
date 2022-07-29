package sm2

import (
	"bytes"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"errors"
	"io"
	"math/big"

	"github.com/tjfoc/gmsm/sm2"
	"github.com/tjfoc/gmsm/sm3"
)

var errZeroParam = errors.New("zero parameter")
var one = new(big.Int).SetInt64(1)
var two = new(big.Int).SetInt64(2)
var (
	default_uid = []byte{0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38}
)

func msgHash(za, msg []byte) (*big.Int, error) {
	e := sm3.New()
	e.Write(za)
	e.Write(msg)
	return new(big.Int).SetBytes(e.Sum(nil)[:32]), nil
}

func RandWithPrivkey(c elliptic.Curve, priv *sm2.PrivateKey, digest []byte) (k *big.Int) {
	x := priv.D
	q := c.Params().N
	qlen := q.BitLen()
	hash := sm3.New()
	//a.  Process m through the hash function H, yielding: h1 = H(m) => digest
	//b.  Set: V = 0x01 0x01 0x01 ... 0x01, length equal to 8*ceil(hlen/8).
	V := bytes.Repeat([]byte{0x01}, hash.Size())

	//c.  Set: K = 0x00 0x00 0x00 ... 0x00, length equal to 8*ceil(hlen/8)
	K := make([]byte, hash.Size())

	//d.  Set: K = HMAC_K(V || 0x00 || int2octets(x) || bits2octets(h1))
	hm := hmac.New(sm3.New, K)
	hm.Write(V)
	hm.Write([]byte{0x00})
	hm.Write(int2octets(x, qlen))
	hm.Write(bits2octets(digest, q))
	K = hm.Sum(nil)

	//e.  Set:V = HMAC_K(V)
	vm := hmac.New(sm3.New, K)
	vm.Write(V)
	V = vm.Sum(nil)

	//f.  Set: K = HMAC_K(V || 0x01 || int2octets(x) || bits2octets(h1))
	hm = hmac.New(sm3.New, K)
	hm.Write(V)
	hm.Write([]byte{0x01})
	hm.Write(int2octets(x, qlen))
	hm.Write(bits2octets(digest, q))
	K = hm.Sum(nil)

	// g.  Set: V = HMAC_K(V)
	vm = hmac.New(sm3.New, K)
	vm.Write(V)
	V = vm.Sum(nil)

	//h.  Apply the following algorithm until a proper value is found for k
	for {
		// 1.  Set T to the empty sequence.  The length of T (in bits) is
		//     denoted tlen; thus, at that point, tlen = 0.
		T := make([]byte, 0, qlen/8)
		//  2.  While tlen < qlen, do the following:
		for len(T) < qlen/8 {
			// V = HMAC_K(V)
			vm = hmac.New(sm3.New, K)
			vm.Write(V)
			V = vm.Sum(nil)
			// T = T || V
			T = append(T, V...)
		}
		//  3.  Compute: k = bits2int(T)
		k := bits2int(T, qlen)
		one := big.NewInt(1)

		if k.Cmp(one) >= 0 && k.Cmp(q) < 0 {
			return k
		}

		// Otherwise, compute: K = HMAC_K(V || 0x00)
		km := hmac.New(sm3.New, K)
		km.Write(V)
		km.Write([]byte{0x00})
		K = km.Sum(nil)

		//    V = HMAC_K(V)
		km = hmac.New(sm3.New, K)
		km.Write(V)
		V = km.Sum(nil)
		// and loop (try to generate a new T, and so on).
	}
}

func GenerateKey(random io.Reader) (*sm2.PrivateKey, error) {
	c := sm2.P256Sm2()
	if random == nil {
		random = rand.Reader //If there is no external trusted random source,please use rand.Reader to instead of it.
	}
	params := c.Params()
	b := make([]byte, params.BitSize/8+8)
	_, err := io.ReadFull(random, b)
	if err != nil {
		return nil, err
	}

	k := new(big.Int).SetBytes(b)
	n := new(big.Int).Sub(params.N, two)
	k.Mod(k, n)
	k.Add(k, one)
	priv := new(sm2.PrivateKey)
	priv.PublicKey.Curve = c
	priv.D = k
	priv.PublicKey.X, priv.PublicKey.Y = c.ScalarBaseMult(k.Bytes())

	return priv, nil
}

//Sign_{d_A}(M,Z_A) = (r,s)
func Sm2Sign(priv *sm2.PrivateKey, msg, uid []byte) (r, s *big.Int, err error) {
	var digest []byte
	digest, err = priv.PublicKey.Sm3Digest(msg, uid) // Generate the SM3 digest, if err then return
	if err != nil {
		return nil, nil, err
	}
	// c is the curve, and N is the parameter
	c := priv.PublicKey.Curve
	N := c.Params().N
	if N.Sign() == 0 {
		return nil, nil, errZeroParam
	}

	e := new(big.Int).SetBytes(digest) // e = H_v(M)
	var k *big.Int                     // random number k

	for {
		for {
			// k, err = randFieldElement(c, random) // Get random k
			// if err != nil {
			// 	r = nil
			// 	return
			// }
			k = RandWithPrivkey(c, priv, digest)
			println(k)
			// r = (e + x1) mod n
			r, _ = priv.Curve.ScalarBaseMult(k.Bytes())
			r.Add(r, e)
			r.Mod(r, N)
			//if r = 0 or r + k = n, generate random number k again. Else break.
			if r.Sign() != 0 {
				if t := new(big.Int).Add(r, k); t.Cmp(N) != 0 {
					break
				}
			}
		}
		// s = ((1+d_A)^{-1} * (k - r*d_A)) mod n
		rD := new(big.Int).Mul(priv.D, r)       // rD = r*d_A
		s = new(big.Int).Sub(k, rD)             // s  = k - r*d_A
		d1 := new(big.Int).Add(priv.D, one)     // d1 = 1+d_A
		d1Inv := new(big.Int).ModInverse(d1, N) // d1Inv = (1+d_A)^{-1}
		s.Mul(s, d1Inv)                         // s = (1+d_A)^{-1} * (k - r*d_A)
		s.Mod(s, N)                             // s = ((1+d_A)^{-1} * (k - r*d_A)) mod n
		// if s = 0, generate random number k again
		if s.Sign() != 0 {
			break
		}
	}
	return

}

// Verify_{P_A}(M',r',s') = 0/1
func Sm2Verify(pub *sm2.PublicKey, msg, uid []byte, r, s *big.Int) bool {
	c := pub.Curve
	N := c.Params().N
	one := new(big.Int).SetInt64(1)
	// check r',s' \in [1,n-1]
	if r.Cmp(one) < 0 || s.Cmp(one) < 0 {
		return false
	}
	if r.Cmp(N) >= 0 || s.Cmp(N) >= 0 {
		return false
	}
	if len(uid) == 0 {
		uid = default_uid
	}

	// Compute ZA
	za, err := sm2.ZA(pub, uid)
	if err != nil {
		return false
	}

	// Compute e' = H_v(M')
	e, err := msgHash(za, msg)
	if err != nil {
		return false
	}

	// Compute t' = (r'+ s') mod N
	t := new(big.Int).Add(r, s)
	t.Mod(t, N)
	if t.Sign() == 0 {
		return false
	}

	// Compute (x1',y1') = s'G + tP_A
	var R *big.Int
	x1, y1 := c.ScalarBaseMult(s.Bytes())           // s'G
	x2, y2 := c.ScalarMult(pub.X, pub.Y, t.Bytes()) // tP_A
	R, _ = c.Add(x1, y1, x2, y2)                    // R = (x1',y1') = s'G + tP_A

	// Compute R = (e'+ x_1') mod n
	R.Add(R, e)
	R.Mod(R, N)
	return R.Cmp(r) == 0 // Check R == r'
}
