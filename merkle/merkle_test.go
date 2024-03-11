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
	id0 := &Id{Path: path0}
	data0 := make([]byte, 4)
	data0[2] = 1
	val0 := &Val{Data: data0}
	proof0, err0 := tr.Put(id0, val0)
	machine.Assert(err0 == ErrNone)
	err1 := proof0.Check()
	machine.Assert(err1 == ErrNone)

	proof1, err2 := tr.Get(id0)
	machine.Assert(err2 == ErrNone)
	err3 := proof1.Check()
	machine.Assert(err3 == ErrNone)
	machine.Assert(bytes.Equal(val0.Data, proof1.Val.Data))
}

func TestTwoPut(t *testing.T) {
	tr := NewTree()

	path0 := HashOne([]byte("path0"))
	id0 := &Id{Path: path0}
	data0 := []byte("data0")
	val0 := &Val{Data: data0}
	proof0, err0 := tr.Put(id0, val0)
	machine.Assert(err0 == ErrNone)
	err1 := proof0.Check()
	machine.Assert(err1 == ErrNone)

	path1 := HashOne([]byte("path1"))
	id1 := &Id{Path: path1}
	data1 := []byte("data1")
	val1 := &Val{Data: data1}
	proof1, err2 := tr.Put(id1, val1)
	machine.Assert(err2 == ErrNone)
	err3 := proof1.Check()
	machine.Assert(err3 == ErrNone)

	proof2, err4 := tr.Get(id0)
	machine.Assert(err4 == ErrNone)
	err5 := proof2.Check()
	machine.Assert(err5 == ErrNone)
	proof3, err6 := tr.Get(id1)
	machine.Assert(err6 == ErrNone)
	err7 := proof3.Check()
	machine.Assert(err7 == ErrNone)

	machine.Assert(bytes.Equal(val0.Data, proof2.Val.Data))
	machine.Assert(bytes.Equal(val1.Data, proof3.Val.Data))
}

func TestOverwrite(t *testing.T) {
	tr := NewTree()

	path0 := HashOne([]byte("path0"))
	id0 := &Id{Path: path0}
	data0 := []byte("data0")
	val0 := &Val{Data: data0}
	proof0, err0 := tr.Put(id0, val0)
	machine.Assert(err0 == ErrNone)
	err1 := proof0.Check()
	machine.Assert(err1 == ErrNone)

	data1 := []byte("data1")
	val1 := &Val{Data: data1}
	proof1, err2 := tr.Put(id0, val1)
	machine.Assert(err2 == ErrNone)
	err3 := proof1.Check()
	machine.Assert(err3 == ErrNone)

	proof2, err4 := tr.Get(id0)
	machine.Assert(err4 == ErrNone)
	err5 := proof2.Check()
	machine.Assert(err5 == ErrNone)
	machine.Assert(bytes.Equal(val1.Data, proof2.Val.Data))
}

func TestGetNotFound(t *testing.T) {
	tr := NewTree()

	path0 := make([]byte, DigestLen)
	path0[0] = 1
	path0[1] = 1
	id0 := &Id{Path: path0}
	data0 := []byte("data0")
	val0 := &Val{Data: data0}
	proof0, err0 := tr.Put(id0, val0)
	machine.Assert(err0 == ErrNone)
	err1 := proof0.Check()
	machine.Assert(err1 == ErrNone)

	path1 := make([]byte, DigestLen)
	path1[0] = 1
	path1[1] = 2
	path1[2] = 1
	id1 := &Id{Path: path1}
	_, err2 := tr.Get(id1)
	machine.Assert(err2 != ErrNone)
}

func TestNonmembership(t *testing.T) {
	tr := NewTree()

	path0 := make([]byte, DigestLen)
	path0[0] = 1
	path0[1] = 1
	id0 := &Id{Path: path0}
	data0 := []byte("data0")
	val0 := &Val{Data: data0}
	proof0, err0 := tr.Put(id0, val0)
	machine.Assert(err0 == ErrNone)
	err1 := proof0.Check()
	machine.Assert(err1 == ErrNone)

	path1 := make([]byte, DigestLen)
	path1[0] = 1
	path1[1] = 2
	path1[2] = 1
	id1 := &Id{Path: path1}
	proof1, err2 := tr.GetNil(id1)
	machine.Assert(err2 == ErrNone)
	err3 := proof1.Check()
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
	id0 := &Id{Path: path0}
	data0 := []byte("data0")
	val0 := &Val{Data: data0}
	proof0, err0 := tr.Put(id0, val0)
	machine.Assert(err0 == ErrNone)

	// Original proof0 checks out.
	err1 := proof0.Check()
	machine.Assert(err1 == ErrNone)

	// Construct non-membership proof for that same path.
	childDigests := proof0.ChildDigests[:1]
	tmp := childDigests[0][1]
	childDigests[0][1] = childDigests[0][0]
	childDigests[0][0] = tmp
	proof1 := &NonmembProof{
		Path:         path0[:1],
		RootDigest:   proof0.RootDigest,
		ChildDigests: childDigests,
	}
	err2 := proof1.Check()
	machine.Assert(err2 == ErrPathProof)
}
