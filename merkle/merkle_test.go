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
	hr1.Write(str)
	hash1 := hr1.Sum(nil)
	var hr2 Hasher
	hash2 := hr2.Sum(nil)
	hash3 := merkle_ffi.Hash(str)
	hash4 := merkle_ffi.Hash(nil)

	machine.Assert(bytes.Equal(hash1, hash3))
	machine.Assert(bytes.Equal(hash2, hash4))
	machine.Assert(!bytes.Equal(hash1, hash2))
	machine.Assert(uint64(len(hash2)) == HashLen)
}

func TestOnePut(t *testing.T) {
	tr := &Tree{}

	id0 := make([]byte, HashLen)
	id0[0] = 1
	val0 := make([]byte, 4)
	val0[2] = 1
	digest0, proof0, err0 := tr.Put(id0, val0)
	machine.Assert(err0 == ErrNone)
	err1 := proof0.Check(id0, val0, digest0)
	machine.Assert(err1 == ErrNone)

	val1, digest1, proof1, err2 := tr.Get(id0)
	machine.Assert(err2 == ErrNone)
	err3 := proof1.Check(id0, val1, digest1)
	machine.Assert(err3 == ErrNone)
	machine.Assert(bytes.Equal(val0, val1))
}

func TestTwoPut(t *testing.T) {
	tr := &Tree{}

	id0 := merkle_ffi.Hash([]byte("id0"))
	val0 := []byte("val0")
	digest0, proof0, err0 := tr.Put(id0, val0)
	machine.Assert(err0 == ErrNone)
	err1 := proof0.Check(id0, val0, digest0)
	machine.Assert(err1 == ErrNone)

	id1 := merkle_ffi.Hash([]byte("id1"))
	val1 := []byte("val1")
	digest1, proof1, err2 := tr.Put(id1, val1)
	machine.Assert(err2 == ErrNone)
	err3 := proof1.Check(id1, val1, digest1)
	machine.Assert(err3 == ErrNone)

	val2, digest2, proof2, err4 := tr.Get(id0)
	machine.Assert(err4 == ErrNone)
	err5 := proof2.Check(id0, val2, digest2)
	machine.Assert(err5 == ErrNone)
	val3, digest3, proof3, err6 := tr.Get(id1)
	machine.Assert(err6 == ErrNone)
	err7 := proof3.Check(id1, val3, digest3)
	machine.Assert(err7 == ErrNone)

	machine.Assert(bytes.Equal(val0, val2))
	machine.Assert(bytes.Equal(val1, val3))
}

func TestOverwrite(t *testing.T) {
	tr := &Tree{}

	id0 := merkle_ffi.Hash([]byte("id0"))
	val0 := []byte("val0")
	digest0, proof0, err0 := tr.Put(id0, val0)
	machine.Assert(err0 == ErrNone)
	err1 := proof0.Check(id0, val0, digest0)
	machine.Assert(err1 == ErrNone)

	val1 := []byte("val1")
	digest1, proof1, err2 := tr.Put(id0, val1)
	machine.Assert(err2 == ErrNone)
	err3 := proof1.Check(id0, val1, digest1)
	machine.Assert(err3 == ErrNone)

	val2, digest2, proof2, err4 := tr.Get(id0)
	machine.Assert(err4 == ErrNone)
	err5 := proof2.Check(id0, val2, digest2)
	machine.Assert(err5 == ErrNone)
	machine.Assert(bytes.Equal(val1, val2))
}

func TestGetNotFound(t *testing.T) {
	tr := &Tree{}

	id0 := make([]byte, HashLen)
	id0[0] = 1
	id0[1] = 1
	val0 := []byte("val0")
	digest0, proof0, err0 := tr.Put(id0, val0)
	machine.Assert(err0 == ErrNone)
	err1 := proof0.Check(id0, val0, digest0)
	machine.Assert(err1 == ErrNone)

	id1 := make([]byte, HashLen)
	id1[0] = 1
	id1[1] = 2
	id1[2] = 1
	_, _, _, err2 := tr.Get(id1)
	machine.Assert(err2 != ErrNone)
}

func TestNonmembership(t *testing.T) {
	tr := &Tree{}

	id0 := make([]byte, HashLen)
	id0[0] = 1
	id0[1] = 1
	val0 := []byte("val0")
	digest0, proof0, err0 := tr.Put(id0, val0)
	machine.Assert(err0 == ErrNone)
	err1 := proof0.Check(id0, val0, digest0)
	machine.Assert(err1 == ErrNone)

	id1 := make([]byte, HashLen)
	id1[0] = 1
	id1[1] = 2
	id1[2] = 1
	digest1, proof1, err2 := tr.GetNil(id1)
	machine.Assert(err2 == ErrNone)
	err3 := proof1.Check(id1, digest1)
	machine.Assert(err3 == ErrNone)
}

func TestNonmembershipEmpty(t *testing.T) {
	tr := &Tree{}

	id0 := make([]byte, HashLen)
	digest0, proof0, err0 := tr.GetNil(id0)
	machine.Assert(err0 == ErrNone)
	err1 := proof0.Check(id0, digest0)
	machine.Assert(err1 == ErrNone)
}

func TestNonmembershipBottom(t *testing.T) {
	tr := &Tree{}

	id0 := make([]byte, HashLen)
	val0 := []byte("val0")
	digest0, proof0, err0 := tr.Put(id0, val0)
	machine.Assert(err0 == ErrNone)
	err1 := proof0.Check(id0, val0, digest0)
	machine.Assert(err1 == ErrNone)

	id1 := make([]byte, HashLen)
	id1[HashLen-1] = 1
	digest1, proof1, err2 := tr.GetNil(id1)
	machine.Assert(err2 == ErrNone)
	err3 := proof1.Check(id1, digest1)
	machine.Assert(err3 == ErrNone)
}

// Don't want proof(id, val, digest) and proof(id, val', digest)
// to exist at the same time.
// This could happen if, e.g., nil children weren't factored into their
// parent's hash.
func TestAttackChildEmptyHashing(t *testing.T) {
	tr := &Tree{}

	id0 := make([]byte, HashLen)
	id0[0] = 1
	val0 := []byte("val0")
	digest0, proof0, err0 := tr.Put(id0, val0)
	machine.Assert(err0 == ErrNone)

	err1 := proof0.Check(id0, val0, digest0)
	machine.Assert(err1 == ErrNone)

	// Construct non-membership proof for that same path,
	// by swapping actual child ([0][1]) with a nil child ([0][0]).
	proof1 := NonmembProof(proof0[:1])
	tmp := proof1[0][1]
	proof1[0][1] = proof1[0][0]
	proof1[0][0] = tmp
	err2 := proof1.Check(id0, digest0)
	machine.Assert(err2 == ErrPathProof)
}

// We had a bug where Hash(nil val) = Hash(empty node).
// This attack exploits the bug to prove membership of a nil
// value at some empty node in the tree.
func TestAttackPutNilEmptyNode(t *testing.T) {
	tr := &Tree{}

	id0 := merkle_ffi.Hash([]byte("id0"))
	digest0, proof0, err0 := tr.Put(id0, nil)
	machine.Assert(err0 == ErrNone)

	err1 := proof0.Check(id0, nil, digest0)
	machine.Assert(err1 == ErrNone)

	id1 := CopySlice(id0)
	// Create some different id.
	id1[HashLen-1] ^= 255

	err2 := proof0.Check(id1, nil, digest0)
	machine.Assert(err2 == ErrPathProof)
}
