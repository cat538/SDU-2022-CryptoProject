package main

import (
	"crypto/rand"
	"fmt"
	"sm2-pgp/user"

	"github.com/tjfoc/gmsm/sm2"
	"github.com/tjfoc/gmsm/sm4"
)

func AliceSide(_ida, _idb chan []byte, _da, _db, _ra, _rb chan *sm2.PublicKey, _ca, _cb, _eka, _ekb chan []byte, finish chan bool) {
	Alice, _ := user.NewEntity("Alice", "", "Alice@gmail.com")
	

	fmt.Printf("Alice get Identity.\n")

	fmt.Printf("-----------------------------Key Exchange-----------------------------\n")
// SM2 key Key Exchange 
	rapriv, _ := sm2.GenerateKey(rand.Reader)
	ida := []byte(Alice.UserId.Id)
	da := &Alice.Priv.PublicKey
	ra := &rapriv.PublicKey
	_ida <- ida
	_da <- da
	_ra <- ra

	idb := <-_idb
	db := <-_db
	rb := <-_rb

	k2, S1, Sa, err := sm2.KeyExchangeA(16, ida, idb, &Alice.Priv, db, rapriv, rb)
	if err != nil {
		fmt.Print("Exchange A Side Error.\n")
	}
	fmt.Printf("k2: %x\n", k2)
	fmt.Printf("S1: %x\n", S1)
	fmt.Printf("Sa: %x\n", Sa)

	fmt.Printf("----------------------------Encrypt session key -----------------------------\n")

	msg := []byte("I'm Alice")
	enck, err := sm2.EncryptAsn1(db, k2, rand.Reader)
	cipher, err := sm4.Sm4OFB(k2, msg, true)
	_ca <- cipher
	_eka <- enck

	fmt.Print("Alice send.\n")

	fmt.Printf("----------------------------Decrypt session key-----------------------------\n")

	cb := <-_cb
	kb := <-_ekb
	sessionkey, err := sm2.DecryptAsn1(&Alice.Priv, kb)
	plaintext, err := sm4.Sm4OFB(sessionkey, cb, false)

	fmt.Printf("Alice get: %s\n", plaintext)

	finish <- true
}

func BobSide(_ida, _idb chan []byte, _da, _db, _ra, _rb chan *sm2.PublicKey, _ca, _cb, _eka, _ekb chan []byte, finish chan bool) {
	Bob, _ := user.NewEntity("Bob", "", "Bob@gmail.com")
	rbpriv, _ := sm2.GenerateKey(rand.Reader)

	fmt.Print("Bob get Identity.\n")

	idb := []byte(Bob.UserId.Id)
	db := &Bob.Priv.PublicKey
	rb := &rbpriv.PublicKey
	_idb <- idb
	_db <- db
	_rb <- rb

	ida := <-_ida
	da := <-_da
	ra := <-_ra

	k1, Sb, S2, err := sm2.KeyExchangeB(16, ida, idb, &Bob.Priv, da, rbpriv, ra)
	if err != nil {
		fmt.Print("Exchange A Side Error.\n")
	}
	fmt.Printf("k1: %x\n", k1)
	fmt.Printf("Sb: %x\n", Sb)
	fmt.Printf("S2: %x\n", S2)

	msg := []byte("I'm Bob")
	enck, err := sm2.EncryptAsn1(da, k1, rand.Reader)
	cipher, err := sm4.Sm4OFB(k1, msg, true)
	_cb <- cipher
	_ekb <- enck
	fmt.Print("Bob send.\n")

	ca := <-_ca
	ka := <-_eka
	sessionkey, err := sm2.DecryptAsn1(&Bob.Priv, ka)
	plaintext, err := sm4.Sm4OFB(sessionkey, ca, false)
	fmt.Printf("Bob get: %s\n", plaintext)
	finish <- true
}

func main() {
	_ida := make(chan []byte, 1)
	_idb := make(chan []byte, 1)
	_da := make(chan *sm2.PublicKey, 1)
	_db := make(chan *sm2.PublicKey, 1)
	_ra := make(chan *sm2.PublicKey, 1)
	_rb := make(chan *sm2.PublicKey, 1)
	finishA := make(chan bool, 1)
	finishB := make(chan bool, 1)
	_ciphera := make(chan []byte, 1)
	_cipherb := make(chan []byte, 1)
	_enckeya := make(chan []byte, 1)
	_enckeyb := make(chan []byte, 1)
	go AliceSide(_ida, _idb, _da, _db, _ra, _rb, _ciphera, _cipherb, _enckeya, _enckeyb, finishA)

	go BobSide(_ida, _idb, _da, _db, _ra, _rb, _ciphera, _cipherb, _enckeya, _enckeyb, finishB)

	<-finishA
	<-finishB

}
