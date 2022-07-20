package sm2pitfall

import (
	"errors"
	"math/big"

	"github.com/tjfoc/gmsm/sm2"
)

var one = new(big.Int).SetInt64(1)
var two = new(big.Int).SetInt64(2)
var errZeroParam = errors.New("zero parameter")

func WeakSm2Sign(priv *sm2.PrivateKey, msg, uid []byte, k *big.Int) (r, s *big.Int, err error) {
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
	for {
		for {
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
