package merkle

import (
	"bytes"
	"fmt"
)

func (t *merkleTree) InclusionVerify(m uint64, path Path) bool {
	//var computeRoot []byte
	Root := t.Hash()
	computeRoot := t.hasher.HashLeaf(t.Node[m])

	for _, v := range path {
		fmt.Println(m)
		if m&1 == 0 {
			computeRoot = t.hasher.HashChild(computeRoot, v)
		} else {
			computeRoot = t.hasher.HashChild(v, computeRoot)
		}
		m = log2(m)
	}
	fmt.Println(m)

	fmt.Printf("computeRoot: %x\n", computeRoot)
	fmt.Printf("Root       : %x\n", Root)
	return bytes.Equal(computeRoot, Root)
}

func (t *merkleTree) ConsistencyVerify(m uint64, path Path) bool {
	return true
}
