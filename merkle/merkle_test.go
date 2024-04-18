package merkle

import (
	"bytes"
	"github.com/mit-pdos/secure-chat/crypto/ffi"
	"testing"
)

func TestTreeDeepCopy(t *testing.T) {
	child := NewGenericNode()
	child.Val = []byte{1}
	child.hash = []byte{1}
	root := NewGenericNode()
	root.Val = []byte{1}
	root.hash = []byte{1}
	root.Children[0] = child
	tr := &Tree{Root: root}

	tr2 := tr.DeepCopy()
	root2 := tr2.Root
	root2.Val[0] = 2
	root2.hash[0] = 2
	child2 := root2.Children[0]
	child2.Val[0] = 2
	child2.hash[0] = 2

	if !bytes.Equal(root.Val, []byte{1}) {
		t.Fatal()
	}
	if !bytes.Equal(root.hash, []byte{1}) {
		t.Fatal()
	}
	if !bytes.Equal(child.Val, []byte{1}) {
		t.Fatal()
	}
	if !bytes.Equal(child.hash, []byte{1}) {
		t.Fatal()
	}
}

func PutCheck(t *testing.T, tr *Tree, id Id, val Val) {
	digest, proof, err := tr.Put(id, val)
	if err != ErrNone {
		t.Fatal()
	}
	err = MembProofCheck(proof, id, val, digest)
	if err != ErrNone {
		t.Fatal()
	}
}

func GetCheck(t *testing.T, tr *Tree, id Id) Val {
	val, digest, proof, err := tr.Get(id)
	if err != ErrNone {
		t.Fatal()
	}
	err = MembProofCheck(proof, id, val, digest)
	if err != ErrNone {
		t.Fatal()
	}
	return val
}

func GetNilCheck(t *testing.T, tr *Tree, id Id) {
	digest, proof, err := tr.GetNil(id)
	if err != ErrNone {
		t.Fatal()
	}
	err = NonmembProofCheck(proof, id, digest)
	if err != ErrNone {
		t.Fatal()
	}
}

func TestOnePut(t *testing.T) {
	id0 := make([]byte, ffi.HashLen)
	val0 := make([]byte, 1)

	tr := &Tree{}
	PutCheck(t, tr, id0, val0)
	val1 := GetCheck(t, tr, id0)
	if !bytes.Equal(val0, val1) {
		t.Fatal()
	}
}

func TestTwoPut(t *testing.T) {
	id0 := ffi.Hash([]byte("id0"))
	val0 := []byte("val0")
	id1 := ffi.Hash([]byte("id1"))
	val1 := []byte("val1")

	tr := &Tree{}
	PutCheck(t, tr, id0, val0)
	PutCheck(t, tr, id1, val1)
	val2 := GetCheck(t, tr, id0)
	val3 := GetCheck(t, tr, id1)
	if !bytes.Equal(val0, val2) {
		t.Fatal()
	}
	if !bytes.Equal(val1, val3) {
		t.Fatal()
	}
}

func TestOverwrite(t *testing.T) {
	id0 := ffi.Hash([]byte("id0"))
	val0 := []byte("val0")
	val1 := []byte("val1")

	tr := &Tree{}
	PutCheck(t, tr, id0, val0)
	PutCheck(t, tr, id0, val1)
	val2 := GetCheck(t, tr, id0)
	if !bytes.Equal(val1, val2) {
		t.Fatal()
	}
}

func TestGetNil(t *testing.T) {
	id0 := make([]byte, ffi.HashLen)
	val0 := []byte("val0")
	id1 := make([]byte, ffi.HashLen)
	id1[0] = 1

	tr := &Tree{}
	PutCheck(t, tr, id0, val0)
	_, _, _, err := tr.Get(id1)
	if err == ErrNone {
		t.Fatal()
	}
	GetNilCheck(t, tr, id1)
}

func TestGetNilEmpty(t *testing.T) {
	id0 := make([]byte, ffi.HashLen)
	tr := &Tree{}
	_, _, _, err := tr.Get(id0)
	if err == ErrNone {
		t.Fatal()
	}
	GetNilCheck(t, tr, id0)
}

func TestGetNilBottom(t *testing.T) {
	id0 := make([]byte, ffi.HashLen)
	val0 := []byte("val0")
	id1 := make([]byte, ffi.HashLen)
	id1[ffi.HashLen-1] = 1

	tr := &Tree{}
	PutCheck(t, tr, id0, val0)
	_, _, _, err := tr.Get(id1)
	if err == ErrNone {
		t.Fatal()
	}
	GetNilCheck(t, tr, id1)
}

// Don't want proof(id, val, digest) and proof(id, val', digest)
// to exist at the same time.
// This could happen if, e.g., nil children weren't factored into their
// parent's hash.
func TestAttackChildEmptyHashing(t *testing.T) {
	id0 := make([]byte, ffi.HashLen)
	val0 := []byte("val0")

	tr := &Tree{}
	digest0, proof0, err := tr.Put(id0, val0)
	if err != ErrNone {
		t.Fatal()
	}
	err = MembProofCheck(proof0, id0, val0, digest0)
	if err != ErrNone {
		t.Fatal()
	}

	// Construct non-membership proof for that same path,
	// by swapping actual child ([0][0]) with a nil child ([0][1]).
	proof1 := proof0[:1]
	tmp := proof1[0][0]
	proof1[0][0] = proof1[0][1]
	proof1[0][1] = tmp
	err = NonmembProofCheck(proof1, id0, digest0)
	if err != ErrPathProof {
		t.Fatal()
	}
}

// We had a bug where Hash(nil val) = Hash(empty node).
// This attack exploits the bug to prove membership of a nil
// value at some empty node in the tree.
func TestAttackPutNilEmptyNode(t *testing.T) {
	id0 := make([]byte, ffi.HashLen)
	id1 := make([]byte, ffi.HashLen)
	// It's important that the change be at the end since that's where
	// membership proofs will still be valid.
	id1[ffi.HashLen-1] = 1

	tr := &Tree{}
	digest0, proof0, err := tr.Put(id0, nil)
	if err != ErrNone {
		t.Fatal()
	}
	err = MembProofCheck(proof0, id0, nil, digest0)
	if err != ErrNone {
		t.Fatal()
	}

	err = MembProofCheck(proof0, id1, nil, digest0)
	if err != ErrPathProof {
		t.Fatal()
	}
}
