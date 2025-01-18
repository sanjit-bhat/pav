package merkle

import (
	"github.com/mit-pdos/pav/cryptoffi"
)

const (
	emptyNodeTag    byte = 0
	interiorNodeTag byte = 1
	leafNodeTag     byte = 2
)

type Tree struct {
	cache *cache
	root  *node
}

// node contains the union of different node types:
//  1. empty node. nil node.
//  2. interior node. have child0 or child1; and hash.
//  3. leaf node. have the full label and val; and hash.
type node struct {
	child0 *node
	child1 *node
	hash   []byte
	label  []byte
	val    []byte
}

type cache struct {
	emptyHash []byte
}

// Put adds (label, val) to the tree.
func (t *Tree) Put(label []byte, val []byte) {
}

// TODO: fixup nextBit.
func put(n *node, c *cache, nextBit bool, label []byte, val []byte) *node {
	// n is empty node. replace with leaf node.
	if n == nil {
		n0 := &node{label: label, val: val}
		setLeafHash(n0)
		return n0
	}

	// TODO: inefficient to always set pointer? most of time,
	// not actually changing that thing. only when adding new node.
	// n is interior node. go down branch.
	if n.child0 != nil {
		n.child0 = put(n.child0, c, nextBit, label, val)
		setInteriorHash(n, c)
		return n
	}
	if n.child1 != nil {
		n.child1 = put(n.child1, c, nextBit, label, val)
		setInteriorHash(n, c)
		return n
	}

	// n is leaf node. replace it.
	n.label = label
	n.val = val
	setLeafHash(n)
	return n
}

func put0(n *node, c *cache, nextBit bool, label []byte, val []byte) {
	if !nextBit {
		if n.child0 == nil {
			n.child0 = newLeafNode(label, val)
		} else {
			put0(n.child0, c, nextBit, label, val)
		}
		setInteriorHash(n, c)
	} else {
		if n.child1 == nil {
			n.child1 = newLeafNode(label, val)
		} else {
			put0(n.child1, c, nextBit, label, val)
		}
		setInteriorHash(n, c)
	}
}

func compEmptyHash() []byte {
	b := []byte{emptyNodeTag}
	return cryptoffi.Hash(b)
}

func setLeafHash(n *node) {
	var b = make([]byte, 0, len(n.val)+1)
	b = append(b, n.val...)
	b = append(b, leafNodeTag)
	n.hash = cryptoffi.Hash(b)
}

func newLeafNode(label []byte, val []byte) *node {
	n := &node{label: label, val: val}
	setLeafHash(n)
	return n
}

func setInteriorHash(n *node, c *cache) {
	var b = make([]byte, 0, 2*cryptoffi.HashLen+1)
	b = append(b, getNodeHash(n.child0, c)...)
	b = append(b, getNodeHash(n.child1, c)...)
	n.hash = cryptoffi.Hash(b)
}

func getNodeHash(n *node, c *cache) []byte {
	if n == nil {
		return c.emptyHash
	}
	return n.hash
}
