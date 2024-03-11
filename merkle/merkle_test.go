package merkle

import (
	"bytes"
	"github.com/tchajed/goose/machine"
	"testing"
)

func TestOne(t *testing.T) {
	tr := NewTree()

	path0 := make([]byte, DigestLen)
	path0[0] = 1
	id0 := &Id{Path: path0}
	data0 := make([]byte, 4)
	data0[2] = 1
	val0 := &Val{Data: data0}
	proof0, err0 := tr.Put(id0, val0)
	machine.Assume(err0 == ErrNone)
	err1 := proof0.Check()
	machine.Assume(err1 == ErrNone)

	proof1, err2 := tr.Get(id0)
	machine.Assume(err2 == ErrNone)
	err3 := proof1.Check()
	machine.Assume(err3 == ErrNone)
	machine.Assert(bytes.Equal(val0.Data, proof1.Val.Data))
}

func TestTwo(t *testing.T) {
	tr := NewTree()

	path0 := HashOne([]byte("path0"))
	id0 := &Id{Path: path0}
	data0 := []byte("data0")
	val0 := &Val{Data: data0}
	proof0, err0 := tr.Put(id0, val0)
	machine.Assume(err0 == ErrNone)
	err1 := proof0.Check()
	machine.Assume(err1 == ErrNone)

	path1 := HashOne([]byte("path1"))
	id1 := &Id{Path: path1}
	data1 := []byte("data1")
	val1 := &Val{Data: data1}
	proof1, err2 := tr.Put(id1, val1)
	machine.Assume(err2 == ErrNone)
	err3 := proof1.Check()
	machine.Assume(err3 == ErrNone)

	proof2, err4 := tr.Get(id0)
	machine.Assume(err4 == ErrNone)
	err5 := proof2.Check()
	machine.Assume(err5 == ErrNone)
	proof3, err6 := tr.Get(id1)
	machine.Assume(err6 == ErrNone)
	err7 := proof3.Check()
	machine.Assume(err7 == ErrNone)

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
	machine.Assume(err0 == ErrNone)
	err1 := proof0.Check()
	machine.Assume(err1 == ErrNone)

	data1 := []byte("data1")
	val1 := &Val{Data: data1}
	proof1, err2 := tr.Put(id0, val1)
	machine.Assume(err2 == ErrNone)
	err3 := proof1.Check()
	machine.Assume(err3 == ErrNone)

	proof2, err4 := tr.Get(id0)
	machine.Assume(err4 == ErrNone)
	err5 := proof2.Check()
	machine.Assume(err5 == ErrNone)
	machine.Assert(bytes.Equal(val1.Data, proof2.Val.Data))
}

/*
// Don't want proof(id, val, root) and proof(id, val', root)
// to exist at the same time.
// This could happen if, e.g., nil children weren't factored into their
// parent's hash.
func TestBadNilProof(t *testing.T) {
	tr := NewTree()

	path0 := make([]byte, DigestLen)
	path0[0] = 1
	id0 := &Id{Path: path0}
	data0 := []byte("data0")
	val0 := &Val{Data: data0}
	proof0, err0 := tr.Put(id0, val0)
	machine.Assume(err0 == ErrNone)

    // Original proof0 checks out.
	err1 := proof0.Check()
	machine.Assume(err1 == ErrNone)

    // Construct non-membership proof foir that same Path.
    proof1 := &NonmembershipProof {
        Path: 
    }
    tmp := proof0.ChildDigests[0][1]
    proof0.ChildDigests[0][1] = proof0.ChildDigests[0][2]
    proof0.ChildDigests[0][2] = tmp
    proof0.Val = 

    // Modified 

	proof1, err2 := tr.Get(id0)
	machine.Assume(err2 == ErrNone)
	err3 := proof1.Check()
	machine.Assume(err3 == ErrNone)
	machine.Assert(val0.Equals(proof1.Val))
}
*/

// TODO: Test non-membership.
