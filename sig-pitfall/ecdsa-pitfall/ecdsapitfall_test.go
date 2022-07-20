package ecdsapitfall

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"math/big"
	"testing"
)

func cmp(dA, privd *big.Int, name1 []byte, name2 []byte) {
	if name1 == nil {
		name1 = []byte("d'")
		name2 = []byte("d")
	}
	if dA.Cmp(privd) == 0 {
		fmt.Printf("Equal: %s = %s = %x\n", name1, name2, dA)
	} else {
		fmt.Printf("Unqual: %s = %x\n        %s = %x\n", name1, dA, name2, privd)
	}
}

func vry(v bool, name []byte) {
	if name == nil {
		name = []byte("(r,s)")
	}
	if v {
		fmt.Printf("%s verify pass.\n", name)
	} else {
		fmt.Printf("%s verify fail.\n", name)
	}
}
func TestLeakingk(t *testing.T) {
	c := elliptic.P256()
	privkey, err := ecdsa.GenerateKey(c, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	N := privkey.Curve.Params().N
	k, err := rand.Int(rand.Reader, N)
	msg := []byte("abcdefg")
	r, s, err := WeakEcdsaSign(privkey, c, msg, k)

	//Attack s = k^{-1}(e + dr) mod n => d = (k*s - e) * r^{-1} mod n
	sha := sha256.New()
	sha.Write(msg)
	e := sha.Sum(nil)                     // e = hash(m)
	ks := new(big.Int).Mul(k, s)          // ks = k*s
	ks.Sub(ks, HashToInt(e, c))           // ks = k*s - e
	rInv := new(big.Int).ModInverse(r, N) // rInv = r^{-1}
	d := new(big.Int).Mul(ks, rInv)       // d = (k*s - e) * r^{-1}
	d.Mod(d, N)                           // d = (k*s - e) * r^{-1} mod n

	cmp(d, privkey.D, nil, nil)
}

func TestReusingk(t *testing.T) {
	c := elliptic.P256()
	privkey, err := ecdsa.GenerateKey(c, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	N := privkey.Curve.Params().N
	k, err := rand.Int(rand.Reader, N)
	msg1 := []byte("abcdefg")
	msg2 := []byte("hyjklmn")
	r1, s1, err := WeakEcdsaSign(privkey, c, msg1, k)
	r2, s2, err := WeakEcdsaSign(privkey, c, msg2, k)
	if r1.Cmp(r2) == 0 {
		fmt.Printf("r1 = r2 = %x\n", r1)
	}

	//Attack d = [(s1 * e2) - (s2 * e1)] *  s = [(s2 - s1) * r]^{-1} mod n
	sha := sha256.New()
	sha.Write(msg1)
	e1 := sha.Sum(nil) // e1 = hash(m1)
	sha.Reset()
	sha.Write(msg2)
	e2 := sha.Sum(nil) // e2 = hash(m2)

	s1e2 := new(big.Int).Mul(s1, HashToInt(e2, c)) // s1e2 = s1 * e2
	s2e1 := new(big.Int).Mul(s2, HashToInt(e1, c)) // s2e1 = s2 * e1
	s := new(big.Int).Sub(s2, s1)                  // s = s2 - s1
	s.Mul(s, r1)                                   // s = [(s2 - s1) * r]
	s.ModInverse(s, N)                             // s = [(s2 - s1) * r]^{-1}
	d := new(big.Int).Sub(s1e2, s2e1)              //d = (s1 * e2) - (s2 * e1)
	d.Mul(d, s)                                    //d = [(s1 * e2) - (s2 * e1)] * [(s2 - s1) * r]^{-1}
	d.Mod(d, N)                                    //d = [(s1 * e2) - (s2 * e1)] * [(s2 - s1) * r]^{-1} mod n

	cmp(d, privkey.D, nil, nil)
}

func TestReusingkbyDifferentUsers(t *testing.T) {
	c := elliptic.P256()
	privkey1, err := ecdsa.GenerateKey(c, rand.Reader)
	privkey2, err := ecdsa.GenerateKey(c, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	N := privkey1.Curve.Params().N
	k, err := rand.Int(rand.Reader, N)
	msg1 := []byte("abcdefg")
	msg2 := []byte("hyjklmn")
	r1, s1, err := WeakEcdsaSign(privkey1, c, msg1, k)
	r2, s2, err := WeakEcdsaSign(privkey2, c, msg2, k)
	cmp(r1, r2, []byte("r1"), []byte("r2"))

	//Attack
	sha := sha256.New()
	sha.Write(msg1)
	e1 := sha.Sum(nil) // e1 = hash(m1)
	sha.Reset()
	sha.Write(msg2)
	e2 := sha.Sum(nil) // e2 = hash(m2)

	// dB  = (s2*e1 - s1*e2 + s2*r*d1)(s1 * r)^{-1} mod n
	fmt.Printf("User1 => ")
	s2e1 := new(big.Int).Mul(s2, HashToInt(e1, c)) // s2e1 = s2*e1
	s1e2 := new(big.Int).Mul(s1, HashToInt(e2, c)) // s1e2 = s1*e2
	srd := new(big.Int).Mul(s2, r1)                // srd = s2*r
	srd.Mul(srd, privkey1.D)                       // srd = s2*r*d1
	sr := new(big.Int).Mul(s1, r1)                 // sr = s1 * r
	sr.ModInverse(sr, N)                           // sr = (s1 * r)^{-1}
	dB := new(big.Int).Sub(s2e1, s1e2)             // dB = s2*e1 - s1*e2
	dB.Add(dB, srd)                                // dB = s2*e1 - s1*e2 + s2*r*d1
	dB.Mul(dB, sr)                                 // dB =  (s2*e1 - s1*e2 + s2*r*d1)(s1 * r)^{-1}
	dB.Mod(dB, N)                                  // dB = (s2*e1 - s1*e2 + s2*r*d1)(s1 * r)^{-1} mod n
	cmp(dB, privkey2.D, nil, nil)

	// dA = (s1*e2 - s2*e1 + s1*r*d2)(s2 * r)^{-1} mod n
	fmt.Printf("User2 => ")
	srd = new(big.Int).Mul(s1, r2)     // srd = s1*r2
	srd.Mul(srd, privkey2.D)           // srd = s2*r*d1
	sr = new(big.Int).Mul(s2, r1)      // sr = s2 * r
	sr.ModInverse(sr, N)               // sr = (s1 * r)^{-1}
	dA := new(big.Int).Sub(s1e2, s2e1) // dA = s1*e2 - s2*e1
	dA.Add(dA, srd)                    // dA = s1*e2 - s2*e1 + s1*r*d2
	dA.Mul(dA, sr)                     // dA = (s1*e2 - s2*e1 + s1*r*d2)(s2 * r)^{-1}
	dA.Mod(dA, N)                      // dA = (s1*e2 - s2*e1 + s1*r*d2)(s2 * r)^{-1} mod n
	cmp(dA, privkey1.D, nil, nil)

}

func TestInverse(t *testing.T) {
	c := elliptic.P256()
	privkey, err := ecdsa.GenerateKey(c, rand.Reader)
	pubkey := privkey.PublicKey
	if err != nil {
		t.Fatal(err)
	}
	msg := []byte("abcdefg")
	sha := sha256.New()
	sha.Write(msg)
	e := sha.Sum(nil) // e1 = hash(m1)
	r, s, err := ecdsa.Sign(rand.Reader, privkey, e)
	sNeg := new(big.Int).Neg(s)

	ok1 := WeakEcdsaVerify(&pubkey, c, e, r, s)
	ok2 := WeakEcdsaVerify(&pubkey, c, e, r, sNeg)

	vry(ok1, []byte("(r,s)"))
	vry(ok2, []byte("(r,s^{-1})"))
}

func TestUncheckm(t *testing.T) {
	c := elliptic.P256()
	privkey, err := ecdsa.GenerateKey(c, rand.Reader)
	pubkey := privkey.PublicKey
	if err != nil {
		t.Fatal(err)
	}
	N := privkey.Curve.Params().N
	msg := []byte("abcdefg")
	sha := sha256.New()
	sha.Write(msg)
	e := sha.Sum(nil) // e1 = hash(m1)
	r, s, err := ecdsa.Sign(rand.Reader, privkey, e)
	ok := ecdsa.Verify(&pubkey, e, r, s)
	vry(ok, []byte("(r,s,e)"))

	//Attack
	u, err := rand.Int(rand.Reader, N) //Random number u,v
	v, err := rand.Int(rand.Reader, N)
	var x *big.Int
	if opt, ok := c.(combinedMult); ok {
		x, _ = opt.CombinedMult(privkey.X, privkey.Y, u.Bytes(), v.Bytes())
	} else {
		x1, y1 := c.ScalarBaseMult(u.Bytes())
		x2, y2 := c.ScalarMult(privkey.X, privkey.Y, v.Bytes())
		x, _ = c.Add(x1, y1, x2, y2)
	}
	rmod := x.Mod(x, N)
	vInv := v.ModInverse(v, N)
	smod := new(big.Int).Mul(rmod, vInv)
	smod.Mod(smod, N)
	emod := new(big.Int).Mul(smod, u)
	emod.Mod(emod, N)

	ok = ecdsa.Verify(&pubkey, emod.Bytes(), rmod, smod)
	vry(ok, []byte("(r',s',e')"))

	cmp(rmod, r, []byte("r'"), []byte("r "))
	cmp(smod, s, []byte("s'"), []byte("s "))
	cmp(emod, HashToInt(e, c), []byte("e'"), []byte("e "))

}
