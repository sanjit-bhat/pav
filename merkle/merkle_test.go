package merkle

import (
	"bytes"
	"github.com/mit-pdos/pav/cryptoffi"
	"testing"
)

func PutCheck(t *testing.T, tr *Tree, label []byte, val []byte) {
	dig, proof, err := tr.Put(label, val)
	if err {
		t.Fatal()
	}
	err = CheckProof(MembProofTy, proof, label, val, dig)
	if err {
		t.Fatal()
	}
}

// GetMembCheck returns the treeVal.
func GetMembCheck(t *testing.T, tr *Tree, label []byte) []byte {
	val, dig, proofTy, proof, err0 := tr.Get(label)
	if err0 {
		t.Fatal()
	}
	if proofTy != MembProofTy {
		t.Fatal()
	}
	err1 := CheckProof(MembProofTy, proof, label, val, dig)
	if err1 {
		t.Fatal()
	}
	return val
}

func GetNonmembCheck(t *testing.T, tr *Tree, label []byte) {
	_, dig, proofTy, proof, err0 := tr.Get(label)
	if err0 {
		t.Fatal()
	}
	if proofTy != NonmembProofTy {
		t.Fatal()
	}
	err := CheckProof(NonmembProofTy, proof, label, nil, dig)
	if err {
		t.Fatal()
	}
}

func TestOnePut(t *testing.T) {
	label0 := make([]byte, cryptoffi.HashLen)
	val0 := make([]byte, 1)

	tr := NewTree()
	PutCheck(t, tr, label0, val0)
	val1 := GetMembCheck(t, tr, label0)
	if !bytes.Equal(val0, val1) {
		t.Fatal()
	}
}

func TestTwoPut(t *testing.T) {
	label0 := cryptoffi.Hash([]byte("label0"))
	val0 := []byte("val0")
	label1 := cryptoffi.Hash([]byte("label1"))
	val1 := []byte("val1")

	tr := NewTree()
	PutCheck(t, tr, label0, val0)
	PutCheck(t, tr, label1, val1)
	val2 := GetMembCheck(t, tr, label0)
	val3 := GetMembCheck(t, tr, label1)
	if !bytes.Equal(val0, val2) {
		t.Fatal()
	}
	if !bytes.Equal(val1, val3) {
		t.Fatal()
	}
}

func TestOverwrite(t *testing.T) {
	label0 := cryptoffi.Hash([]byte("label0"))
	val0 := []byte("val0")
	val1 := []byte("val1")

	tr := NewTree()
	PutCheck(t, tr, label0, val0)
	PutCheck(t, tr, label0, val1)
	val2 := GetMembCheck(t, tr, label0)
	if !bytes.Equal(val1, val2) {
		t.Fatal()
	}
}

func TestGetNil(t *testing.T) {
	label0 := make([]byte, cryptoffi.HashLen)
	val0 := []byte("val0")
	label1 := make([]byte, cryptoffi.HashLen)
	label1[0] = 1

	tr := NewTree()
	PutCheck(t, tr, label0, val0)
	GetNonmembCheck(t, tr, label1)
}

func TestGetNilEmpty(t *testing.T) {
	label0 := make([]byte, cryptoffi.HashLen)
	tr := NewTree()
	GetNonmembCheck(t, tr, label0)
}

func TestGetNilBottom(t *testing.T) {
	label0 := make([]byte, cryptoffi.HashLen)
	val0 := []byte("val0")
	label1 := make([]byte, cryptoffi.HashLen)
	label1[cryptoffi.HashLen-1] = 1

	tr := NewTree()
	PutCheck(t, tr, label0, val0)
	GetNonmembCheck(t, tr, label1)
}

// We had a bug where Hash(nil val) = Hash(empty node).
// This attack exploits the bug to prove membership of a nil
// value at some empty node in the tree.
func TestAttackPutNilEmptyNode(t *testing.T) {
	label0 := make([]byte, cryptoffi.HashLen)
	label1 := make([]byte, cryptoffi.HashLen)
	// It's important that the change be at the end since that's where
	// membership proofs will still be valid.
	label1[cryptoffi.HashLen-1] = 1

	tr := NewTree()
	dig0, proof0, err := tr.Put(label0, nil)
	if err {
		t.Fatal()
	}
	err = CheckProof(MembProofTy, proof0, label0, nil, dig0)
	if err {
		t.Fatal()
	}

	err = CheckProof(MembProofTy, proof0, label1, nil, dig0)
	if !err {
		t.Fatal()
	}
}

// had a bug where a 255 label would overflow the proof fetching code.
// check for underflow as well.
func TestLabelOverflow(t *testing.T) {
	label := []byte{}
	for i := 0; i < int(cryptoffi.HashLen/2); i++ {
		label = append(label, 0)
	}
	for i := 0; i < int(cryptoffi.HashLen/2); i++ {
		label = append(label, 255)
	}
	val := []byte{1}

	tr := NewTree()
	dig, proof, err := tr.Put(label, val)
	if err {
		t.Fatal()
	}
	if CheckProof(true, proof, label, val, dig) {
		t.Fatal()
	}
}
