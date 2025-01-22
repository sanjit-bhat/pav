package merkle

import (
	"github.com/goose-lang/primitive"
	"github.com/goose-lang/std"
	"github.com/mit-pdos/pav/cryptoffi"
	"github.com/tchajed/marshal"
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

// node contains the union of different node types, which distinguish as:
//  1. empty node. if node ptr is nil.
//  2. interior node. if either child0 or child1 not nil. has hash.
//  3. leaf node. else. has hash, full label, and val.
type node struct {
	hash []byte
	// only for interior node.
	child0 *node
	// only for interior node.
	child1 *node
	// only for leaf node.
	label []byte
	// only for leaf node.
	val []byte
}

type cache struct {
	emptyHash []byte
}

// Put adds (label, val) to the tree and errors if label isn't a hash.
func (t *Tree) Put(label []byte, val []byte) bool {
	if uint64(len(label)) != cryptoffi.HashLen {
		return true
	}
	put(&t.root, 0, label, val, t.cache)
	return false
}

// Get returns if label is in the tree and, if so, the val.
// it errors if label isn't a hash.
func (t *Tree) Get(label []byte) (bool, []byte, bool) {
	if uint64(len(label)) != cryptoffi.HashLen {
		return false, nil, true
	}
	var n = t.root
	var depth uint64
	for ; depth < cryptoffi.HashLen*8; depth++ {
		// break on nil or leaf node.
		if n == nil || (n.child0 == nil && n.child1 == nil) {
			break
		}
		n = *getChild(n, label, depth)
	}
	// empty node.
	if n == nil {
		return false, nil, false
	}
	// not interior node. can't go depth 256 down and still have interior.
	primitive.Assert(n.child0 == nil && n.child1 == nil)
	// leaf node.
	if !std.BytesEqual(n.label, label) {
		return false, nil, false
	}
	return true, n.val, false
}

func put(n0 **node, depth uint64, label, val []byte, cache *cache) {
	n := *n0
	// empty node.
	if n == nil {
		// replace with leaf node.
		leaf := &node{label: label, val: val}
		*n0 = leaf
		setLeafHash(leaf)
		return
	}

	// leaf node.
	if n.child0 == nil && n.child1 == nil {
		// on exact label match, replace val.
		if std.BytesEqual(n.label, label) {
			n.val = val
			setLeafHash(n)
			return
		}

		// otherwise, replace with interior node and recurse.
		inter := &node{}
		*n0 = inter
		*getChild(inter, n.label, depth) = n
		put(getChild(inter, label, depth), depth+1, label, val, cache)
		setInteriorHash(inter, cache)
		return
	}

	// interior node. recurse.
	put(getChild(n, label, depth), depth+1, label, val, cache)
	setInteriorHash(n, cache)
}

func getNodeHash(n *node, c *cache) []byte {
	if n == nil {
		return c.emptyHash
	}
	return n.hash
}

func compEmptyHash() []byte {
	b := []byte{emptyNodeTag}
	return cryptoffi.Hash(b)
}

func setLeafHash(n *node) {
	valLen := uint64(len(n.val))
	// TODO: need depth here?
	var b = make([]byte, 0, cryptoffi.HashLen+8+valLen+1)
	b = append(b, n.label...)
	b = marshal.WriteInt(b, valLen)
	b = append(b, n.val...)
	b = append(b, leafNodeTag)
	n.hash = cryptoffi.Hash(b)
}

func setInteriorHash(n *node, c *cache) {
	// TODO: need depth here?
	var b = make([]byte, 0, 2*cryptoffi.HashLen+1)
	b = append(b, getNodeHash(n.child0, c)...)
	b = append(b, getNodeHash(n.child1, c)...)
	b = append(b, interiorNodeTag)
	n.hash = cryptoffi.Hash(b)
}

func getChild(n *node, b []byte, depth uint64) **node {
	if !getBit(b, depth) {
		return &n.child0
	} else {
		return &n.child1
	}
}

func getBit(b []byte, n uint64) bool {
	slot := n / 8
	off := n % 8
	x := b[slot]
	return x&(1<<off) != 0
}
