package merkle

import (
	"github.com/tchajed/goose/machine"
	"testing"
	//"github.com/zeebo/blake3"
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
	machine.Assert(val0.Equals(proof1.Val))
}

func TestTwo(t *testing.T) {
	tr := NewTree()

	path0 := make([]byte, DigestLen)
	path0[5] = 1
	id0 := &Id{Path: path0}
	data0 := make([]byte, 4)
	data0[2] = 1
	val0 := &Val{Data: data0}
	proof0, err0 := tr.Put(id0, val0)
	machine.Assume(err0 == ErrNone)
	err1 := proof0.Check()
	machine.Assume(err1 == ErrNone)

	path1 := make([]byte, DigestLen)
	path1[5] = 2
	id1 := &Id{Path: path1}
	data1 := make([]byte, 4)
	data1[2] = 2
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

	machine.Assert(val0.Equals(proof2.Val))
	machine.Assert(val1.Equals(proof3.Val))
}
