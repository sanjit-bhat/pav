package merkle

import (
	"bytes"
	"github.com/tchajed/goose/machine"
	"testing"
)

func TestOnePut(t *testing.T) {
	tr := NewTree()

	path0 := make([]byte, DigestLen)
	path0[0] = 1
	id0 := &Id{B: path0}
	data0 := make([]byte, 4)
	data0[2] = 1
	val0 := &Val{B: data0}
	root0, proof0, err0 := tr.Put(id0, val0)
	machine.Assert(err0 == ErrNone)
	err1 := proof0.Check(id0, val0, root0)
	machine.Assert(err1 == ErrNone)

	val1, root1, proof1, err2 := tr.Get(id0)
	machine.Assert(err2 == ErrNone)
	err3 := proof1.Check(id0, val1, root1)
	machine.Assert(err3 == ErrNone)
	machine.Assert(bytes.Equal(val0.B, val1.B))
}

func TestTwoPut(t *testing.T) {
	tr := NewTree()

	path0 := HashOne([]byte("path0"))
	id0 := &Id{B: path0}
	data0 := []byte("data0")
	val0 := &Val{B: data0}
	root0, proof0, err0 := tr.Put(id0, val0)
	machine.Assert(err0 == ErrNone)
	err1 := proof0.Check(id0, val0, root0)
	machine.Assert(err1 == ErrNone)

	path1 := HashOne([]byte("path1"))
	id1 := &Id{B: path1}
	data1 := []byte("data1")
	val1 := &Val{B: data1}
	root1, proof1, err2 := tr.Put(id1, val1)
	machine.Assert(err2 == ErrNone)
	err3 := proof1.Check(id1, val1, root1)
	machine.Assert(err3 == ErrNone)

	val2, root2, proof2, err4 := tr.Get(id0)
	machine.Assert(err4 == ErrNone)
	err5 := proof2.Check(id0, val2, root2)
	machine.Assert(err5 == ErrNone)
	val3, root3, proof3, err6 := tr.Get(id1)
	machine.Assert(err6 == ErrNone)
	err7 := proof3.Check(id1, val3, root3)
	machine.Assert(err7 == ErrNone)

	machine.Assert(bytes.Equal(val0.B, val2.B))
	machine.Assert(bytes.Equal(val1.B, val3.B))
}

func TestOverwrite(t *testing.T) {
	tr := NewTree()

	path0 := HashOne([]byte("path0"))
	id0 := &Id{B: path0}
	data0 := []byte("data0")
	val0 := &Val{B: data0}
	root0, proof0, err0 := tr.Put(id0, val0)
	machine.Assert(err0 == ErrNone)
	err1 := proof0.Check(id0, val0, root0)
	machine.Assert(err1 == ErrNone)

	data1 := []byte("data1")
	val1 := &Val{B: data1}
	root1, proof1, err2 := tr.Put(id0, val1)
	machine.Assert(err2 == ErrNone)
	err3 := proof1.Check(id0, val1, root1)
	machine.Assert(err3 == ErrNone)

	val2, root2, proof2, err4 := tr.Get(id0)
	machine.Assert(err4 == ErrNone)
	err5 := proof2.Check(id0, val2, root2)
	machine.Assert(err5 == ErrNone)
	machine.Assert(bytes.Equal(val1.B, val2.B))
}

func TestGetNotFound(t *testing.T) {
	tr := NewTree()

	path0 := make([]byte, DigestLen)
	path0[0] = 1
	path0[1] = 1
	id0 := &Id{B: path0}
	data0 := []byte("data0")
	val0 := &Val{B: data0}
	root0, proof0, err0 := tr.Put(id0, val0)
	machine.Assert(err0 == ErrNone)
	err1 := proof0.Check(id0, val0, root0)
	machine.Assert(err1 == ErrNone)

	path1 := make([]byte, DigestLen)
	path1[0] = 1
	path1[1] = 2
	path1[2] = 1
	id1 := &Id{B: path1}
	_, _, _, err2 := tr.Get(id1)
	machine.Assert(err2 != ErrNone)
}

func TestNonmembership(t *testing.T) {
	tr := NewTree()

	path0 := make([]byte, DigestLen)
	path0[0] = 1
	path0[1] = 1
	id0 := &Id{B: path0}
	data0 := []byte("data0")
	val0 := &Val{B: data0}
	root0, proof0, err0 := tr.Put(id0, val0)
	machine.Assert(err0 == ErrNone)
	err1 := proof0.Check(id0, val0, root0)
	machine.Assert(err1 == ErrNone)

	path1 := make([]byte, DigestLen)
	path1[0] = 1
	path1[1] = 2
	path1[2] = 1
	id1 := &Id{B: path1}
	root1, proof1, err2 := tr.GetNil(id1)
	machine.Assert(err2 == ErrNone)
	err3 := proof1.Check(id1, root1)
	machine.Assert(err3 == ErrNone)
}

// Don't want proof(id, val, root) and proof(id, val', root)
// to exist at the same time.
// This could happen if, e.g., nil children weren't factored into their
// parent's hash.
func TestAttackNilConfusion(t *testing.T) {
	tr := NewTree()

	path0 := make([]byte, DigestLen)
	path0[0] = 1
	id0 := &Id{B: path0}
	data0 := []byte("data0")
	val0 := &Val{B: data0}
	root0, proof0, err0 := tr.Put(id0, val0)
	machine.Assert(err0 == ErrNone)

	// Original proof0 checks out.
	err1 := proof0.Check(id0, val0, root0)
	machine.Assert(err1 == ErrNone)

	// Construct non-membership proof for that same path.
	childDigests := proof0.ChildDigests[:1]
	tmp := childDigests[0][1]
	childDigests[0][1] = childDigests[0][0]
	childDigests[0][0] = tmp
	proof1 := &NonmembProof{
		ChildDigests: childDigests,
	}
	err2 := proof1.Check(id0, root0)
	machine.Assert(err2 == ErrPathProof)
}
