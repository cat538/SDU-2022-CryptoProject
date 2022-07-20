package sm2pitfall

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"math/big"
	ecdsapitfall "sig-pitfall/ecdsa-pitfall"
	"testing"

	"github.com/tjfoc/gmsm/sm2"
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
	privkey, err := sm2.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	N := privkey.Curve.Params().N
	k, err := rand.Int(rand.Reader, N)
	msg := []byte("abcdefg")
	r, s, err := WeakSm2Sign(privkey, msg, nil, k)

	//Attack
	sr := new(big.Int).Add(s, r)   // sr = s + r
	sr.ModInverse(sr, N)           // sr = (s + r)^{-1}
	ks := new(big.Int).Sub(k, s)   // ks = k - s
	dA := new(big.Int).Mul(sr, ks) // dA = (s + r)^{-1} * (k - s)
	dA.Mod(dA, N)                  // dA = (s + r)^{-1} * (k - s) mod N

	cmp(dA, privkey.D, nil, nil)
}

func TestReusingk(t *testing.T) {
	privkey, err := sm2.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	N := privkey.Curve.Params().N
	k, err := rand.Int(rand.Reader, N)
	msg1 := []byte("abcdefg")
	msg2 := []byte("hyjklmn")
	r1, s1, err := WeakSm2Sign(privkey, msg1, nil, k)
	r2, s2, err := WeakSm2Sign(privkey, msg2, nil, k)

	//Attack
	dA := new(big.Int).Sub(s2, s1) // dA = s2 - s1
	s := new(big.Int).Sub(s1, s2)  // s = s1 - s2
	r := new(big.Int).Sub(r1, r2)  // r = r1 - r2
	r.Add(r, s)                    // r = (s1 - s2 + r1 - r2)
	r.ModInverse(r, N)             // r = (s1 - s2 + r1 - r2)
	dA.Mul(dA, r)                  // dA = (s2 - s1) / (s1 - s2 + r1 - r2)
	dA.Mod(dA, N)                  // dA = (s2 - s1) / (s1 - s2 + r1 - r2) mod N

	cmp(dA, privkey.D, nil, nil)
}

func TestReusingkbyDifferentUsers(t *testing.T) {
	privkey1, err := sm2.GenerateKey(rand.Reader)
	privkey2, err := sm2.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	N := privkey1.Curve.Params().N
	k, err := rand.Int(rand.Reader, N)
	msg1 := []byte("abcdefg")
	msg2 := []byte("hyjklmn")
	r1, s1, err := WeakSm2Sign(privkey1, msg1, nil, k)
	r2, s2, err := WeakSm2Sign(privkey2, msg2, nil, k)

	//Attack
	fmt.Printf("User1 => ")
	sr := new(big.Int).Add(s2, r2) // sr = s2 + r2
	sr.ModInverse(sr, N)           // sr = (s2 + r2)^{-1}
	ks := new(big.Int).Sub(k, s2)  // ks = k - s2
	dB := new(big.Int).Mul(sr, ks) // dA = (s2 + r2)^{-1} * (k - s2)
	dB.Mod(dB, N)                  // dA = (s2 + r2)^{-1} * (k - s2) mod N
	cmp(dB, privkey2.D, []byte("dB'"), []byte("dB "))

	fmt.Printf("User2 => ")
	sr = new(big.Int).Add(s1, r1)  // sr = s1 + r1
	sr.ModInverse(sr, N)           // sr = (s1 + r1)^{-1}
	ks = new(big.Int).Sub(k, s1)   // ks = k - s1
	dA := new(big.Int).Mul(sr, ks) // dA = (s1 + r1)^{-1} * (k - s1)
	dA.Mod(dA, N)                  // dA = (s1 + r1)^{-1} * (k - s1) mod N
	cmp(dA, privkey1.D, []byte("dA'"), []byte("dA "))
}

func TestInverse(t *testing.T) {
	privkey, err := sm2.GenerateKey(rand.Reader)
	pubkey := privkey.PublicKey
	if err != nil {
		t.Fatal(err)
	}
	msg := []byte("abcdefg")
	r, s, err := sm2.Sm2Sign(privkey, msg, nil, rand.Reader)

	sNeg := new(big.Int).Neg(s)
	vry := sm2.Sm2Verify(&pubkey, msg, nil, r, s)
	if vry {
		fmt.Println("(r,s) verify pass.")
	} else {
		fmt.Println("(r,s) verify fail.")
	}
	vry = sm2.Sm2Verify(&pubkey, msg, nil, r, sNeg)
	if vry {
		fmt.Println("(r,s^{-1}) verify pass.")
	} else {
		fmt.Println("(r,s^{-1}) verify fail.")
	}

}
func TestSamedkWithEcdsa(t *testing.T) {
	privkey, err := sm2.GenerateKey(rand.Reader)
	pubkey := privkey.PublicKey
	N := pubkey.Curve.Params().N
	ecdsaprivkey := new(ecdsa.PrivateKey)
	ecdsaprivkey.PublicKey = ecdsa.PublicKey(pubkey)
	ecdsaprivkey.D = privkey.D
	k, err := rand.Int(rand.Reader, N)
	if err != nil {
		t.Fatal(err)
	}
	c := pubkey.Curve

	msg1 := []byte("abcdefg")
	msg2 := []byte("hyjklmn")
	r1, s1, err := ecdsapitfall.WeakEcdsaSign(ecdsaprivkey, c, msg1, k)
	r2, s2, err := WeakSm2Sign(privkey, msg2, nil, k)
	sha := sha256.New()
	sha.Write(msg1)
	e1 := sha.Sum(nil) // e1 = hash(m1)

	//Attack d = [(s1 * s2) - e1] * [r1 - s1 * s2 - s1 * r2] mod n
	s1s2 := new(big.Int).Mul(s1, s2)                           // s1s2 = s1 * s2
	s1r2 := new(big.Int).Mul(s1, r2)                           // s1s2 = s1 * r2
	r := new(big.Int).Sub(r1, s1s2)                            // r =  r1 - s1 * s2
	r.Sub(r, s1r2)                                             // r = r1 - s1 * s2 - s1 * r2
	r.ModInverse(r, N)                                         // r = [r1 - s1 * s2 - s1 * r2]^{-1}
	d := new(big.Int).Sub(s1s2, ecdsapitfall.HashToInt(e1, c)) // d = (s1 * s2) - e1
	d.Mul(d, r)                                                // d = [(s1 * s2) - e1] * [r1 - s1 * s2 - s1 * r2]^{-1}
	d.Mod(d, N)                                                // d = [(s1 * s2) - e1] * [r1 - s1 * s2 - s1 * r2]^{-1} mod n
	cmp(d, privkey.D, nil, nil)
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
	x1, y1 := c.ScalarBaseMult(u.Bytes())
	x2, y2 := c.ScalarMult(privkey.X, privkey.Y, v.Bytes())
	x, _ = c.Add(x1, y1, x2, y2)

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
	cmp(emod, ecdsapitfall.HashToInt(e, c), []byte("e'"), []byte("e "))

}
