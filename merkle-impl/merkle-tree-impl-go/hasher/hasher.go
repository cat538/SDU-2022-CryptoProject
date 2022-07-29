package hasher

import (
	"hash"

	"github.com/tjfoc/gmsm/sm3"
)

var DefaultHasher = New(sm3.New())

const (
	LeafPrefix = 0
	NodePrefix = 1
)

type Hasher struct {
	hash.Hash
}

func New(h hash.Hash) *Hasher {
	return &Hasher{Hash: h}
}

//The hash of an empty list is the hash of an empty string:MTH({}) = SHA-256().
func (t *Hasher) EmptyRoot() []byte {
	t.Reset()
	return t.Sum(nil)
}

//The hash of a list with one entry (also known as a leaf hash) is:
//MTH({d(0)}) = SHA-256(0x00 || d(0)).
func (t *Hasher) HashLeaf(leaf []byte) []byte {
	t.Reset()
	t.Write([]byte{LeafPrefix})
	t.Write(leaf)
	return t.Sum(nil)
}

//The Merkle Tree Hash of an n-element list D[n] is then defined recursively as
//MTH(D[n]) = SHA-256(0x01 || MTH(D[0:k]) || MTH(D[k:n])),

func (t *Hasher) HashChild(l, r []byte) []byte {

	t.Reset()
	t.Write([]byte{NodePrefix})
	t.Write(l)
	t.Write(r)
	return t.Sum(nil)
}
