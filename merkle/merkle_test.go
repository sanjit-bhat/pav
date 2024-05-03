package merkle

import (
	"bytes"
	"github.com/mit-pdos/secure-chat/cryptoFFI"
	"testing"
)

func TestTreeDeepCopy(t *testing.T) {
	child := newGenericNode()
	child.val = []byte{1}
	child.hash = []byte{1}
	root := newGenericNode()
	root.val = []byte{1}
	root.hash = []byte{1}
	root.children[0] = child
	tr := &Tree{root: root}

	tr2 := tr.DeepCopy()
	root2 := tr2.root
	root2.val[0] = 2
	root2.hash[0] = 2
	child2 := root2.children[0]
	child2.val[0] = 2
	child2.hash[0] = 2

	if !bytes.Equal(root.val, []byte{1}) {
		t.Fatal()
	}
	if !bytes.Equal(root.hash, []byte{1}) {
		t.Fatal()
	}
	if !bytes.Equal(child.val, []byte{1}) {
		t.Fatal()
	}
	if !bytes.Equal(child.hash, []byte{1}) {
		t.Fatal()
	}
}

func PutCheck(t *testing.T, tr *Tree, id Id, val Val) {
	digest, proof, err := tr.Put(id, val)
	if err != errNone {
		t.Fatal()
	}
	err = CheckProof(MembProofTy, proof, id, val, digest)
	if err != errNone {
		t.Fatal()
	}
}

func GetMembCheck(t *testing.T, tr *Tree, id Id) Val {
	reply := tr.Get(id)
	if reply.Error != errNone {
		t.Fatal()
	}
	if reply.ProofTy != MembProofTy {
		t.Fatal()
	}
	err := CheckProof(MembProofTy, reply.Proof, id, reply.Val, reply.Digest)
	if err != errNone {
		t.Fatal()
	}
	return reply.Val
}

func GetNonmembCheck(t *testing.T, tr *Tree, id Id) {
	reply := tr.Get(id)
	if reply.Error != errNone {
		t.Fatal()
	}
	if reply.ProofTy != NonmembProofTy {
		t.Fatal()
	}
	err := CheckProof(NonmembProofTy, reply.Proof, id, nil, reply.Digest)
	if err != errNone {
		t.Fatal()
	}
}

func TestOnePut(t *testing.T) {
	id0 := make([]byte, cryptoFFI.HashLen)
	val0 := make([]byte, 1)

	tr := &Tree{}
	PutCheck(t, tr, id0, val0)
	val1 := GetMembCheck(t, tr, id0)
	if !bytes.Equal(val0, val1) {
		t.Fatal()
	}
}

func TestTwoPut(t *testing.T) {
	id0 := cryptoFFI.Hash([]byte("id0"))
	val0 := []byte("val0")
	id1 := cryptoFFI.Hash([]byte("id1"))
	val1 := []byte("val1")

	tr := &Tree{}
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
	id0 := cryptoFFI.Hash([]byte("id0"))
	val0 := []byte("val0")
	val1 := []byte("val1")

	tr := &Tree{}
	PutCheck(t, tr, id0, val0)
	PutCheck(t, tr, id0, val1)
	val2 := GetMembCheck(t, tr, id0)
	if !bytes.Equal(val1, val2) {
		t.Fatal()
	}
}

func TestGetNil(t *testing.T) {
	id0 := make([]byte, cryptoFFI.HashLen)
	val0 := []byte("val0")
	id1 := make([]byte, cryptoFFI.HashLen)
	id1[0] = 1

	tr := &Tree{}
	PutCheck(t, tr, id0, val0)
	GetNonmembCheck(t, tr, id1)
}

func TestGetNilEmpty(t *testing.T) {
	id0 := make([]byte, cryptoFFI.HashLen)
	tr := &Tree{}
	GetNonmembCheck(t, tr, id0)
}

func TestGetNilBottom(t *testing.T) {
	id0 := make([]byte, cryptoFFI.HashLen)
	val0 := []byte("val0")
	id1 := make([]byte, cryptoFFI.HashLen)
	id1[cryptoFFI.HashLen-1] = 1

	tr := &Tree{}
	PutCheck(t, tr, id0, val0)
	GetNonmembCheck(t, tr, id1)
}

// Don't want proof(id, val, digest) and proof(id, val', digest)
// to exist at the same time.
// This could happen if, e.g., nil children weren't factored into their
// parent's hash.
func TestAttackChildEmptyHashing(t *testing.T) {
	id0 := make([]byte, cryptoFFI.HashLen)
	val0 := []byte("val0")

	tr := &Tree{}
	digest0, proof0, err := tr.Put(id0, val0)
	if err != errNone {
		t.Fatal()
	}
	err = CheckProof(MembProofTy, proof0, id0, val0, digest0)
	if err != errNone {
		t.Fatal()
	}

	// Construct non-membership proof for that same path,
	// by swapping actual child ([0][0]) with a nil child ([0][1]).
	proof1 := proof0[:1]
	tmp := proof1[0][0]
	proof1[0][0] = proof1[0][1]
	proof1[0][1] = tmp
	err = CheckProof(NonmembProofTy, proof1, id0, nil, digest0)
	if err != errSome {
		t.Fatal()
	}
}

// We had a bug where Hash(nil val) = Hash(empty node).
// This attack exploits the bug to prove membership of a nil
// value at some empty node in the tree.
func TestAttackPutNilEmptyNode(t *testing.T) {
	id0 := make([]byte, cryptoFFI.HashLen)
	id1 := make([]byte, cryptoFFI.HashLen)
	// It's important that the change be at the end since that's where
	// membership proofs will still be valid.
	id1[cryptoFFI.HashLen-1] = 1

	tr := &Tree{}
	digest0, proof0, err := tr.Put(id0, nil)
	if err != errNone {
		t.Fatal()
	}
	err = CheckProof(MembProofTy, proof0, id0, nil, digest0)
	if err != errNone {
		t.Fatal()
	}

	err = CheckProof(MembProofTy, proof0, id1, nil, digest0)
	if err != errSome {
		t.Fatal()
	}
}
