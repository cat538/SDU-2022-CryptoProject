package hasher

import (
	"bytes"
	"crypto"
	"encoding/hex"
	"testing"
)

func TestRFC6962Hasher(t *testing.T) {
	Hasher := New(crypto.SHA256.New())

	leafHash := Hasher.HashLeaf([]byte("L123456"))
	emptyLeafHash := Hasher.HashLeaf([]byte{})

	for _, tc := range []struct {
		desc string
		got  []byte
		want string
	}{
		// echo -n | sha256sum
		{
			desc: "RFC6962 Empty",
			want: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
			got:  Hasher.EmptyRoot(),
		},
		// Check that the empty hash is not the same as the hash of an empty leaf.
		// echo -n 00 | xxd -r -p | sha256sum
		{
			desc: "RFC6962 Empty Leaf",
			want: "6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d",
			got:  emptyLeafHash,
		},
		// echo -n 004C313233343536 | xxd -r -p | sha256sum
		{
			desc: "RFC6962 Leaf",
			want: "395aa064aa4c29f7010acfe3f25db9485bbd4b91897b6ad7ad547639252b4d56",
			got:  leafHash,
		},
		// echo -n 014E3132334E343536 | xxd -r -p | sha256sum
		{
			desc: "RFC6962 Node",
			want: "aa217fe888e47007fa15edab33c2b492a722cb106c64667fc2b044444de66bbb",
			got:  Hasher.HashChild([]byte("N123"), []byte("N456")),
		},
	} {
		t.Run(tc.desc, func(t *testing.T) {
			wantBytes, err := hex.DecodeString(tc.want)
			if err != nil {
				t.Fatalf("hex.DecodeString(%x): %v", tc.want, err)
			}
			if got, want := tc.got, wantBytes; !bytes.Equal(got, want) {
				t.Errorf("got %x, want %x", got, want)
			}
		})
	}
}

// TODO(pavelkalinnikov): Apply this test to all LogHasher implementations.
func TestRFC6962HasherCollisions(t *testing.T) {
	Hasher := New(crypto.SHA256.New())

	// Check that different leaves have different hashes.
	leaf1, leaf2 := []byte("Hello"), []byte("World")
	hash1 := Hasher.HashLeaf(leaf1)
	hash2 := Hasher.HashLeaf(leaf2)
	if bytes.Equal(hash1, hash2) {
		t.Errorf("Leaf hashes should differ, but both are %x", hash1)
	}

	// Compute an intermediate subtree hash.
	subHash1 := Hasher.HashChild(hash1, hash2)
	// Check that this is not the same as a leaf hash of their concatenation.
	preimage := append(hash1, hash2...)
	forgedHash := Hasher.HashLeaf(preimage)
	if bytes.Equal(subHash1, forgedHash) {
		t.Errorf("Hasher is not second-preimage resistant")
	}

	// Swap the order of nodes and check that the hash is different.
	subHash2 := Hasher.HashChild(hash2, hash1)
	if bytes.Equal(subHash1, subHash2) {
		t.Errorf("Subtree hash does not depend on the order of leaves")
	}
}

func BenchmarkHashChildren(b *testing.B) {
	h := New(crypto.SHA256.New())
	l := h.HashLeaf([]byte("one"))
	r := h.HashLeaf([]byte("or other"))
	for i := 0; i < b.N; i++ {
		_ = h.HashChild(l, r)
	}
}
