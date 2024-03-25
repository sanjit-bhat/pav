package merkle

import (
	"bytes"
	"github.com/mit-pdos/secure-chat/merkle/merkle_ffi"
	"github.com/tchajed/goose/machine"
	"testing"
)

func TestHasher(t *testing.T) {
	str := []byte("hello")
	var hr1 Hasher
	HasherWrite(&hr1, str)
	hash1 := HasherSum(hr1, nil)
	var hr2 Hasher
	hash2 := HasherSum(hr2, nil)
	hash3 := merkle_ffi.Hash(str)
	hash4 := merkle_ffi.Hash(nil)

	machine.Assert(bytes.Equal(hash1, hash3))
	machine.Assert(bytes.Equal(hash2, hash4))
	machine.Assert(!bytes.Equal(hash1, hash2))
	machine.Assert(uint64(len(hash2)) == HashLen)
}

func PutCheck(tr *Tree, id Id, val Val) {
	digest, proof, err := tr.Put(id, val)
	machine.Assert(err == ErrNone)
	err = MembProofCheck(proof, id, val, digest)
	machine.Assert(err == ErrNone)
}

func GetCheck(tr *Tree, id Id) Val {
	val, digest, proof, err := tr.Get(id)
	machine.Assert(err == ErrNone)
	err = MembProofCheck(proof, id, val, digest)
	machine.Assert(err == ErrNone)
	return val
}

func GetNilCheck(tr *Tree, id Id) {
	digest, proof, err := tr.GetNil(id)
	machine.Assert(err == ErrNone)
	err = NonmembProofCheck(proof, id, digest)
	machine.Assert(err == ErrNone)
}

func TestOnePut(t *testing.T) {
	id0 := make([]byte, HashLen)
	val0 := make([]byte, 1)

	tr := &Tree{}
	PutCheck(tr, id0, val0)
	val1 := GetCheck(tr, id0)
	machine.Assert(bytes.Equal(val0, val1))
}

func TestTwoPut(t *testing.T) {
	id0 := merkle_ffi.Hash([]byte("id0"))
	val0 := []byte("val0")
	id1 := merkle_ffi.Hash([]byte("id1"))
	val1 := []byte("val1")

	tr := &Tree{}
	PutCheck(tr, id0, val0)
	PutCheck(tr, id1, val1)
	val2 := GetCheck(tr, id0)
	val3 := GetCheck(tr, id1)
	machine.Assert(bytes.Equal(val0, val2))
	machine.Assert(bytes.Equal(val1, val3))
}

func TestOverwrite(t *testing.T) {
	id0 := merkle_ffi.Hash([]byte("id0"))
	val0 := []byte("val0")
	val1 := []byte("val1")

	tr := &Tree{}
	PutCheck(tr, id0, val0)
	PutCheck(tr, id0, val1)
	val2 := GetCheck(tr, id0)
	machine.Assert(bytes.Equal(val1, val2))
}

func TestGetNil(t *testing.T) {
	id0 := make([]byte, HashLen)
	val0 := []byte("val0")
	id1 := make([]byte, HashLen)
	id1[0] = 1

	tr := &Tree{}
	PutCheck(tr, id0, val0)
	_, _, _, err := tr.Get(id1)
	machine.Assert(err != ErrNone)
	GetNilCheck(tr, id1)
}

func TestGetNilEmpty(t *testing.T) {
	id0 := make([]byte, HashLen)
	tr := &Tree{}
	_, _, _, err := tr.Get(id0)
	machine.Assert(err != ErrNone)
	GetNilCheck(tr, id0)
}

func TestGetNilBottom(t *testing.T) {
	id0 := make([]byte, HashLen)
	val0 := []byte("val0")
	id1 := make([]byte, HashLen)
	id1[HashLen-1] = 1

	tr := &Tree{}
	PutCheck(tr, id0, val0)
	_, _, _, err := tr.Get(id1)
	machine.Assert(err != ErrNone)
	GetNilCheck(tr, id1)
}

// Don't want proof(id, val, digest) and proof(id, val', digest)
// to exist at the same time.
// This could happen if, e.g., nil children weren't factored into their
// parent's hash.
func TestAttackChildEmptyHashing(t *testing.T) {
	id0 := make([]byte, HashLen)
	val0 := []byte("val0")

	tr := &Tree{}
	digest0, proof0, err := tr.Put(id0, val0)
	machine.Assert(err == ErrNone)
	err = MembProofCheck(proof0, id0, val0, digest0)
	machine.Assert(err == ErrNone)

	// Construct non-membership proof for that same path,
	// by swapping actual child ([0][0]) with a nil child ([0][1]).
	proof1 := proof0[:1]
	tmp := proof1[0][0]
	proof1[0][0] = proof1[0][1]
	proof1[0][1] = tmp
	err = NonmembProofCheck(proof1, id0, digest0)
	machine.Assert(err == ErrPathProof)
}

// We had a bug where Hash(nil val) = Hash(empty node).
// This attack exploits the bug to prove membership of a nil
// value at some empty node in the tree.
func TestAttackPutNilEmptyNode(t *testing.T) {
	id0 := make([]byte, HashLen)
	id1 := make([]byte, HashLen)
	// It's important that the change be at the end since that's where
	// membership proofs will still be valid.
	id1[HashLen-1] = 1

	tr := &Tree{}
	digest0, proof0, err := tr.Put(id0, nil)
	machine.Assert(err == ErrNone)
	err = MembProofCheck(proof0, id0, nil, digest0)
	machine.Assert(err == ErrNone)

	err = MembProofCheck(proof0, id1, nil, digest0)
	machine.Assert(err == ErrPathProof)
}
