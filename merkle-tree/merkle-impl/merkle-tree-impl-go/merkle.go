package merkle

import (
	hasher "merkle/Hasher"
)

const (
	LeafPrefix = byte(0)
	NodePrefix = byte(1)
)

type merkleTree struct {
	Node   [][]byte
	hasher hasher.Hasher
}

func NewMerkleTree(b [][]byte) *merkleTree {
	m := merkleTree{
		Node:   b,
		hasher: *hasher.DefaultHasher,
	}
	return &m
}
func (t *merkleTree) Hash() []byte {
	return t.hash(t.Node)
}
func (t *merkleTree) hash(b [][]byte) []byte {

	n := uint64(len(b))
	//  Empty Tree
	if n == 0 {
		return t.hasher.EmptyRoot()
	}
	//  Only root
	if n == 1 {
		return t.hasher.HashLeaf(b[0])
	}

	//  Recursive hash
	k := largestPowerOf2LessThan(n)
	lh := t.hash(b[0:k])
	rh := t.hash(b[k:n])
	// fmt.Printf("Ori: %x\n", b)
	// fmt.Printf("lh: %x\n", lh)
	// fmt.Printf("rh: %x\n", rh)
	return t.hasher.HashChild(lh, rh)

}

func largestPowerOf2LessThan(n uint64) uint64 {
	if n < 2 {
		return 0
	}
	t := uint64(0)
	for i := 0; i < 64; i++ {
		c := uint64(1 << i)
		if c > n-1 {
			return t
		}
		t = c
	}
	return 0
}

func smallerPowerOf2MoreThan(n uint64) uint64 {
	if n == 0 {
		return 1
	}
	// if n != 0 && (n&(n-1)) == 0 {
	// 	return n << 1
	// }

	n--
	n |= n >> 1
	n |= n >> 2
	n |= n >> 4
	n |= n >> 8
	n |= n >> 16
	n |= n >> 32
	n++
	return n
}

func log2(x uint64) uint64 {
	if x == 0 {
		return 0
	}
	ct := uint64(0)
	for x != 0 {
		x >>= 1
		ct++
	}
	return ct - 1
}
