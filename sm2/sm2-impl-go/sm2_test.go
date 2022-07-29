package sm2

import (
	"crypto/rand"
	"fmt"
	"testing"
)

func TestSm2(t *testing.T) {
	privkey, err := GenerateKey(rand.Reader)

	if err != nil {
		t.Fatal(err)
	}
	fmt.Printf("Privkey in sm2 curve: %v\n", privkey.Curve.IsOnCurve(privkey.X, privkey.Y))
	pubkey := &privkey.PublicKey
	msg := []byte("123456")
	r, s, err := Sm2Sign(privkey, msg, default_uid)

	if err != nil {
		t.Fatal(err)
	} else {
		fmt.Printf("Sign success.\n")
	}

	vry := Sm2Verify(pubkey, msg, default_uid, r, s)
	if vry == false {
		println("Verify Wrong.\n")
	} else {
		println("Verify Pass.\n")
	}

}
