package cryptanalysis

import (
	"fmt"
)

//Invertibility return the target key
func Invertibility(msg, hash []byte) (seed [SeedSize]byte) {

	seed = HashSeedInv(*(*[16]byte)(hash), msg)
	rehash := HashSeed(seed, msg)
	fmt.Printf("Msg       : %s\n", msg)
	fmt.Printf("Target    : %s\n", hash)
	fmt.Printf("Key       : %x\n", seed[:0x20])
	fmt.Printf("            %x\n", seed[0x20:0x40])
	fmt.Printf("            %x\n", seed[0x40:0x60])
	fmt.Printf("            %x\n", seed[0x60:0x80])
	fmt.Printf("Rehash    : %s\n\n", rehash)
	return
}
