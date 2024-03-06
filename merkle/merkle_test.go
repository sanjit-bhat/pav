package merkle

import (
	"github.com/tchajed/goose/machine"
	"testing"
)

func TestOne(t *testing.T) {
	tr := NewTree()

	path0 := make([]byte, DigestLen)
	path0[5] = 1
	id0 := &Id{Path: path0}
	data0 := make([]byte, 4)
	data0[2] = 1
	val0 := &Val{Data: data0}
	err0 := tr.Put(id0, val0)
	machine.Assume(err0 == ErrNone)

	val1, err1 := tr.Get(id0)
	machine.Assume(err1 == ErrNone)
	machine.Assert(val0.Equals(val1))
}

func TestTwo(t *testing.T) {
	tr := NewTree()

	path0 := make([]byte, DigestLen)
	path0[5] = 1
	id0 := &Id{Path: path0}
	data0 := make([]byte, 4)
	data0[2] = 1
	val0 := &Val{Data: data0}
	err0 := tr.Put(id0, val0)
	machine.Assume(err0 == ErrNone)

	path1 := make([]byte, DigestLen)
	path1[5] = 2
	id1 := &Id{Path: path1}
	data1 := make([]byte, 4)
	data1[2] = 2
	val1 := &Val{Data: data1}
	err1 := tr.Put(id1, val1)
	machine.Assume(err1 == ErrNone)

	val2, err2 := tr.Get(id0)
	machine.Assume(err2 == ErrNone)
	val3, err3 := tr.Get(id1)
	machine.Assume(err3 == ErrNone)
	machine.Assert(val0.Equals(val2))
	machine.Assert(val1.Equals(val3))
}
