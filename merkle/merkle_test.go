package merkle

import (
	"bytes"
	"github.com/mit-pdos/pav/cryptoffi"
	"testing"
)

func PutCheck(t *testing.T, tr *Tree, label []byte, val []byte) {
	digest, proof, err := tr.Put(label, val)
	if err {
		t.Fatal()
	}
	err = CheckProof(MembProofTy, proof, label, val, digest)
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
	id0 := make([]byte, cryptoffi.HashLen)
	val0 := make([]byte, 1)

	tr := NewTree()
	PutCheck(t, tr, id0, val0)
	val1 := GetMembCheck(t, tr, id0)
	if !bytes.Equal(val0, val1) {
		t.Fatal()
	}
}

func TestTwoPut(t *testing.T) {
	id0 := cryptoffi.Hash([]byte("id0"))
	val0 := []byte("val0")
	id1 := cryptoffi.Hash([]byte("id1"))
	val1 := []byte("val1")

	tr := NewTree()
	PutCheck(t, tr, id0, val0)
	PutCheck(t, tr, id1, val1)
	val2 := GetMembCheck(t, tr, id0)
	val3 := GetMembCheck(t, tr, id1)
	if !bytes.Equal(val0, val2) {
		t.Fatal()
	}
	if !bytes.Equal(val1, val3) {
		t.Fatal()
	}
}

func TestOverwrite(t *testing.T) {
	id0 := cryptoffi.Hash([]byte("id0"))
	val0 := []byte("val0")
	val1 := []byte("val1")

	tr := NewTree()
	PutCheck(t, tr, id0, val0)
	PutCheck(t, tr, id0, val1)
	val2 := GetMembCheck(t, tr, id0)
	if !bytes.Equal(val1, val2) {
		t.Fatal()
	}
}

func TestGetNil(t *testing.T) {
	id0 := make([]byte, cryptoffi.HashLen)
	val0 := []byte("val0")
	id1 := make([]byte, cryptoffi.HashLen)
	id1[0] = 1

	tr := NewTree()
	PutCheck(t, tr, id0, val0)
	GetNonmembCheck(t, tr, id1)
}

func TestGetNilEmpty(t *testing.T) {
	id0 := make([]byte, cryptoffi.HashLen)
	tr := NewTree()
	GetNonmembCheck(t, tr, id0)
}

func TestGetNilBottom(t *testing.T) {
	id0 := make([]byte, cryptoffi.HashLen)
	val0 := []byte("val0")
	id1 := make([]byte, cryptoffi.HashLen)
	id1[cryptoffi.HashLen-1] = 1

	tr := NewTree()
	PutCheck(t, tr, id0, val0)
	GetNonmembCheck(t, tr, id1)
}

// Don't want proof(id, val, digest) and proof(id, val', digest)
// to exist at the same time.
// This could happen if, e.g., nil children weren't factored into their
// parent's hash.
func TestAttackChildEmptyHashing(t *testing.T) {
	id0 := make([]byte, cryptoffi.HashLen)
	val0 := []byte("val0")

	tr := NewTree()
	digest0, proof0, err := tr.Put(id0, val0)
	if err {
		t.Fatal()
	}
	err = CheckProof(MembProofTy, proof0, id0, val0, digest0)
	if err {
		t.Fatal()
	}

	// Construct non-membership proof for that same path,
	// by swapping actual child ([0][0]) with a nil child ([0][1]).
	proof1 := proof0[:1]
	tmp := proof1[0][0]
	proof1[0][0] = proof1[0][1]
	proof1[0][1] = tmp
	err = CheckProof(NonmembProofTy, proof1, id0, nil, digest0)
	if !err {
		t.Fatal()
	}
}

// We had a bug where Hash(nil val) = Hash(empty node).
// This attack exploits the bug to prove membership of a nil
// value at some empty node in the tree.
func TestAttackPutNilEmptyNode(t *testing.T) {
	id0 := make([]byte, cryptoffi.HashLen)
	id1 := make([]byte, cryptoffi.HashLen)
	// It's important that the change be at the end since that's where
	// membership proofs will still be valid.
	id1[cryptoffi.HashLen-1] = 1

	tr := NewTree()
	digest0, proof0, err := tr.Put(id0, nil)
	if err {
		t.Fatal()
	}
	err = CheckProof(MembProofTy, proof0, id0, nil, digest0)
	if err {
		t.Fatal()
	}

	err = CheckProof(MembProofTy, proof0, id1, nil, digest0)
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
