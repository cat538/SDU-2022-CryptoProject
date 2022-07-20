package faketoshi

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"math/big"

	"github.com/roasbeef/btcd/btcec"
)

func faketoshi() {
	c := btcec.S256()
	pubKeyBytes, err := hex.DecodeString("04678AFDB0FE5548271967F1A67130B7105CD6A828E03909A67962E0EA1F61DEB649F6BC3F4CEF38C4F35504E51EC112DE5C384DF7BA0B8D578A4C702B6BF11D5F")
	pubKey, err := btcec.ParsePubKey(pubKeyBytes, btcec.S256())
	if err != nil {
		fmt.Println(err)
		return
	}
	N := pubKey.Params().N

	v, err := rand.Int(rand.Reader, N)
	u, err := rand.Int(rand.Reader, N) //Random number u,v

	x1, y1 := c.ScalarBaseMult(u.Bytes())
	x2, y2 := c.ScalarMult(pubKey.X, pubKey.Y, v.Bytes())
	x, _ := c.Add(x1, y1, x2, y2)
	rmod := x.Mod(x, N)
	vInv := v.ModInverse(v, N)
	smod := new(big.Int).Mul(rmod, vInv)
	smod.Mod(smod, N)
	emod := new(big.Int).Mul(smod, u)
	emod.Mod(emod, N)

	var sig btcec.Signature

	sig.R = rmod
	sig.S = smod
	fmt.Printf("u:%x\nv:%x\n", u, v)
	fmt.Printf("r:%x\ns:%x\ne:%x\n", sig.R, sig.S, emod)

	verified := sig.Verify(emod.Bytes(), pubKey)
	fmt.Println("Signature Verified?", verified)

}
