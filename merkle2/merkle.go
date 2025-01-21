package merkle

import (
	"github.com/mit-pdos/pav/cryptoffi"
	"github.com/tchajed/marshal"
)

const (
	emptyNodeTag    byte = 0
	interiorNodeTag byte = 1
	leafNodeTag     byte = 2
)

type bits []bool

func newBitsFromBytes(b []byte) bits {
	var bs = make([]bool, 0, 8*len(b))
	for _, x := range b {
		for i := 0; i < 8; i++ {
			bs = append(bs, x&(1<<i) != 0)
		}
	}
	return bs
}

func boolToByte(b bool) byte {
	if b {
		return 1
	} else {
		return 0
	}
}

func (b bits) encode() []byte {
	var bs []byte
	var i int
	var byt byte
	// TODO: encode and decode might not be inverses.
	// but maybe that's not important.
	for _, x := range b {
		byt |= boolToByte(x) << i
		i += 1
		if i == 8 {
			bs = append(bs, byt)
			i = 0
			byt = 0
		}
	}
	return bs
}

type Tree struct {
	cache *cache
	root  *node
}

// node contains the union of different node types, which distinguish as:
//  1. empty node. if has nil node ptr.
//  2. interior node. if has child0 and child1. has prefix and hash.
//  3. leaf node. else. has prefix, hash, and val.
type node struct {
	prefix bits
	hash   []byte
	// only for interior node.
	child0 *node
	// only for interior node.
	child1 *node
	// only for leaf node.
	val []byte
}

type cache struct {
	emptyHash []byte
}

type updEntry struct {
	label bits
	val   []byte
}

// updSet has across all entries, labels being same len.
type updSet []*updEntry

// splitSelf gets the longest prefix and splits entries into 0 and 1 post-bits.
// the updated entries will have the prefix bits removed.
func (u updSet) splitSelf() (bits, updSet, updSet) {
	// TODO
	return nil, nil, nil
}

// splitOther uses prefix to split entries into 0 and 1 post-bits.
// the updated entries will have the prefix bits removed.
func (u updSet) splitOther(prefix bits) (updSet, updSet) {
	// TODO
	_ = prefix
	return nil, nil
}

// Put adds (label, val) to the tree.
func (t *Tree) Put(label []byte, val []byte) {
}

func mkNode(upd updSet, cache *cache) *node {
	if len(upd) == 0 {
		// empty node.
		return nil
	}
	if len(upd) == 1 {
		// leaf node.
		u := upd[0]
		n := &node{prefix: u.label, val: u.val}
		setLeafHash(n)
		return n
	}
	// interior node.
	prefix, zero, one := upd.splitSelf()
	child0 := mkNode(zero, cache)
	child1 := mkNode(one, cache)
	n := &node{prefix: prefix, child0: child0, child1: child1}
	setInteriorHash(n, cache)
	return n
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
	pref := n.prefix.encode()
	var b = make([]byte, 0, 8+len(pref)+8+len(n.val)+1)
	b = marshal.WriteInt(b, uint64(len(pref)))
	b = append(b, pref...)
	b = marshal.WriteInt(b, uint64(len(n.val)))
	b = append(b, n.val...)
	b = append(b, leafNodeTag)
	n.hash = cryptoffi.Hash(b)
}

func setInteriorHash(n *node, c *cache) {
	pref := n.prefix.encode()
	var b = make([]byte, 0, 8+uint64(len(pref))+2*cryptoffi.HashLen+1)
	b = marshal.WriteInt(b, uint64(len(pref)))
	b = append(b, pref...)
	b = append(b, getNodeHash(n.child0, c)...)
	b = append(b, getNodeHash(n.child1, c)...)
	b = append(b, interiorNodeTag)
	n.hash = cryptoffi.Hash(b)
}
