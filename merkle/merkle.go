package merkle

/*
Requirements:
What should the paths down the tree be?
A byte array, for the most general thing.
Max len can be 32 bytes, the output size of the blake hash func,
used by AKD.
Could also specialize to a uname or something,
which might be a u64 (8 bytes).
But then when add in epoch, gets more complicated.
It's easiest to just do a hash value.

Make value at node be another byte arr.
Ops:
1) Put
2) Get
Get proofs of membership and non-membership for specific keys.
*/

import (
	"bytes"
)

const (
	ErrNone         uint64 = 0
	ErrGet_NotFound uint64 = 1
	ErrPut_BadLen   uint64 = 2
	ErrGet_BadLen   uint64 = 3
)

type Id struct {
	Path []byte
}

const DigestLen = 32

func NewId() *Id {
	return &Id{Path: make([]byte, DigestLen)}
}

type Val struct {
	Data []byte
}

func (v1 *Val) Equals(v2 *Val) bool {
	return bytes.Equal(v1.Data, v2.Data)
}

type Node struct {
	Val      *Val
	Children []*Node
}

const ByteSlots = 64

func NewNode() *Node {
	return &Node{Val: nil, Children: make([]*Node, ByteSlots)}
}

type Tree struct {
	Root *Node
}

func NewTree() *Tree {
	return &Tree{Root: NewNode()}
}

func (t *Tree) Put(id *Id, v *Val) uint64 {
	if len(id.Path) != DigestLen {
		return ErrPut_BadLen
	}
	currNode := t.Root
	for pathIdx := 0; pathIdx < DigestLen; pathIdx++ {
		pos := id.Path[pathIdx]
		if currNode.Children[pos] == nil {
			currNode.Children[pos] = NewNode()
		}
		currNode = currNode.Children[pos]
	}
	currNode.Val = v
	return ErrNone
}

func (t *Tree) Get(id *Id) (*Val, uint64) {
	if len(id.Path) != DigestLen {
		return nil, ErrGet_BadLen
	}
	currNode := t.Root
	found := true
	for pathIdx := 0; pathIdx < DigestLen; pathIdx++ {
		pos := id.Path[pathIdx]
		currNode = currNode.Children[pos]
		if currNode == nil {
			found = false
			break
		}
	}
	if !found {
		return nil, ErrGet_NotFound
	}
	return currNode.Val, ErrNone
}

