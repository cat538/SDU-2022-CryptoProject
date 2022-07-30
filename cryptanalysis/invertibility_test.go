package cryptanalysis

import "testing"

func TestInvertibility(t *testing.T) {
	msg1 := []byte("Xie Zhongxuan 201800180063")
	msg2 := []byte("Duanmu Haojie 201900460051")
	msg3 := []byte("Liu qi 201900460038")
	hash := []byte("sdu_cst_20220610")
	Invertibility(msg1, hash)
	Invertibility(msg2, hash)
	Invertibility(msg3, hash)
}
