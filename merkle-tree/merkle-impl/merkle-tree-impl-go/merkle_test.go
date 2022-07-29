package merkle

import (
	"fmt"
	"strconv"
	"testing"
)

func TestMerkle(t *testing.T) {
	//msg := []byte("gogogog")

}

/*
   The binary Merkle Tree with 7 leaves:

               hash
              /    \
             /      \
            /        \
           /          \
          /            \
         k              l
        / \            / \
       /   \          /   \
      /     \        /     \
     g       h      i      j
    / \     / \    / \     |
    a b     c d    e f     d6
    | |     | |    | |
   d0 d1   d2 d3  d4 d5

   The audit path for d0 is [b, h, l].

   The audit path for d3 is [c, g, l].

   The audit path for d4 is [f, j, k].

   The audit path for d6 is [i, k].

*/

func TestInclusionProof(t *testing.T) {
	var D [][]byte

	for i := 0; i < 7; i++ {
		v := "d" + strconv.FormatInt(int64(i), 10)
		D = append(D, []byte(v))
	}
	tree := NewMerkleTree(D)
	fmt.Printf("All: %x\n", tree.Node)
	fmt.Printf("Hash: %x\n", tree.Hash())

	path := tree.InclusionProof(0)
	fmt.Printf("\n0: %x\n", path)

	path = tree.InclusionProof(1)
	fmt.Printf("\n1: %x\n", path)

	path = tree.InclusionProof(3)
	fmt.Printf("\n3: %x\n", path)

	path = tree.InclusionProof(4)
	fmt.Printf("\n4: %x\n", path)

	path = tree.InclusionProof(6)
	fmt.Printf("\n6: %x\n", path)
}

/*
   The same tree, built incrementally in four steps:

       hash0          hash1=k
       / \              /  \
      /   \            /    \
     /     \          /      \
     g      c         g       h
    / \     |        / \     / \
    a b     d2       a b     c d
    | |              | |     | |
   d0 d1            d0 d1   d2 d3

             hash2                    hash
             /  \                    /    \
            /    \                  /      \
           /      \                /        \
          /        \              /          \
         /          \            /            \
        k            i          k              l
       / \          / \        / \            / \
      /   \         e f       /   \          /   \
     /     \        | |      /     \        /     \
    g       h      d4 d5    g       h      i      j
   / \     / \             / \     / \    / \     |
   a b     c d             a b     c d    e f     d6
   | |     | |             | |     | |    | |
   d0 d1   d2 d3           d0 d1   d2 d3  d4 d5

   The consistency proof between hash0 and hash is PROOF(3, D[7]) = [c,
   d, g, l].  c, g are used to verify hash0, and d, l are additionally
   used to show hash is consistent with hash0.

   The consistency proof between hash1 and hash is PROOF(4, D[7]) = [l].
   hash can be verified using hash1=k and l.

   The consistency proof between hash2 and hash is PROOF(6, D[7]) = [i,
   j, k].  k, i are used to verify hash2, and j is additionally used to
   show hash is consistent with hash2.

*/
func TestConsistencyProof(t *testing.T) {
	var D [][]byte

	for i := 0; i < 7; i++ {
		v := "d" + strconv.FormatInt(int64(i), 10)
		D = append(D, []byte(v))
	}
	tree := NewMerkleTree(D)

	path := tree.ConsistencyProof(3)
	fmt.Printf("3: %x\n", path)

	path = tree.ConsistencyProof(4)
	fmt.Printf("4: %x\n", path)
	path = tree.ConsistencyProof(6)
	fmt.Printf("6: %x\n", path)
}

func Test100000(t *testing.T) {
	var D [][]byte

	for i := 0; i < 100000; i++ {
		v := "d" + strconv.FormatInt(int64(i), 10)
		D = append(D, []byte(v))
	}
	tree := NewMerkleTree(D)

	path := tree.InclusionProof(0)
	fmt.Printf("InclusionProof Len: %d\n", len(path))

	path = tree.ConsistencyProof(3)
	fmt.Printf("ConsistencyProof Len: %d\n", len(path))

}
