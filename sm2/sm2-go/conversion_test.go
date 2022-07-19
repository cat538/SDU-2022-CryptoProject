package sm2

import (
	"bytes"
	"math/big"
	"testing"
)

func TestBits2int(t *testing.T) {
	for _, tc := range []struct {
		b    []byte
		qlen int
		want *big.Int
	}{
		{b: []byte{0x01}, qlen: 1, want: big.NewInt(0)},
		{b: []byte{0x80}, qlen: 1, want: big.NewInt(1)}, // 1 leftmost bit is kept.
		{b: []byte{0x01}, qlen: 8, want: big.NewInt(1)},
		{b: []byte{0x01, 0x00}, qlen: 8, want: big.NewInt(1)}, // 8 leftmost bits are kept.
		{b: []byte{0x01, 0x00}, qlen: 16, want: big.NewInt(256)},
	} {
		if got := bits2int(tc.b, tc.qlen); got.Cmp(tc.want) != 0 {
			t.Errorf("bits2int(0x%x, %v): %v, want %v", tc.b, tc.qlen, got, tc.want)
		}
	}
}

func TestInt2octets(t *testing.T) {
	for _, tc := range []struct {
		x    *big.Int
		qlen int
		want []byte
	}{
		{x: big.NewInt(1), qlen: 0, want: []byte{}},
		{x: big.NewInt(1), qlen: 8, want: []byte{0x01}},
		{x: big.NewInt(1), qlen: 16, want: []byte{0x00, 0x01}},
	} {
		if got := int2octets(tc.x, tc.qlen); !bytes.Equal(got, tc.want) {
			t.Errorf("int2octets(%v, %d):0x%x, want 0x%x", tc.x, tc.qlen, got, tc.want)
		}
	}
}
