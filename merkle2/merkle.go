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

// Proof has non-nil leaf data for non-membership proofs
// that terminate in a different leaf.
type Proof struct {
	siblings  []byte
	leafLabel []byte
	leafVal   []byte
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
	inTree, val, _, _, err := t.get(label, false)
	return inTree, val, err
}

// Prove returns (1) if label is in the tree and, if so, (2) the val.
// it gives a (3) cryptographic proof of this, against (4) the tree digest.
// it (5) errors if label isn't a hash.
func (t *Tree) Prove(label []byte) (bool, []byte, *Proof, []byte, bool) {
	return t.get(label, true)
}

// VerifyProof verifies proof against the tree rooted at dig
// and returns an error upon failure.
// there are two types of inputs.
// if inTree, (label, val) should be in the tree.
// if !inTree, label should not be in the tree.
func VerifyProof(inTree bool, label, val []byte, proof *Proof, dig []byte) bool {
	if uint64(len(label)) != cryptoffi.HashLen {
		return true
	}
	sibsLen := uint64(len(proof.siblings))
	if sibsLen%cryptoffi.HashLen != 0 {
		return true
	}
	maxDepth := sibsLen / cryptoffi.HashLen
	if maxDepth > cryptoffi.HashLen*8 {
		return true
	}

	// compute leaf hash.
	var currHash []byte
	if inTree {
		currHash = compLeafHash(label, val)
	} else {
		if proof.leafLabel != nil {
			currHash = compLeafHash(proof.leafLabel, proof.leafVal)
		} else {
			currHash = compEmptyHash()
		}
	}

	// compute hash up the tree.
	var depth = maxDepth
	// depth offset by one to prevent underflow.
	for depth >= 1 {
		begin := (depth - 1) * cryptoffi.HashLen
		end := depth * cryptoffi.HashLen
		sib := proof.siblings[begin:end]
		if !getBit(label, depth-1) {
			// TODO: could reuse and reset hasher state across these calls,
			// along with in put calls.
			currHash = compInteriorHash(currHash, sib)
		} else {
			currHash = compInteriorHash(sib, currHash)
		}
		depth--
	}

	// check against supplied dig.
	return !std.BytesEqual(currHash, dig)
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
			n.hash = compLeafHash(n.label, n.val)
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

func (t *Tree) get(label []byte, prove bool) (bool, []byte, *Proof, []byte, bool) {
	if uint64(len(label)) != cryptoffi.HashLen {
		return false, nil, nil, nil, true
	}
	var n = t.root
	// TODO: could pre-size this if store # elems in tree.
	var sibs []byte
	var depth uint64
	for {
		// break if at max depth, empty node, or leaf node.
		if depth < cryptoffi.HashLen*8 {
			break
		}
		if n == nil {
			break
		}
		if n.child0 == nil && n.child1 == nil {
			break
		}
		if prove {
			// proof will have hashes of all interior nodes.
			sibs = append(sibs, getNodeHash(n, t.cache)...)
		}
		n = *getChild(n, label, depth)
		depth++
	}

	dig := getNodeHash(t.root, t.cache)
	proof := &Proof{siblings: sibs}
	// empty node.
	if n == nil {
		return false, nil, proof, dig, false
	}
	// not interior node. can't go full depth down and still have interior.
	primitive.Assert(n.child0 == nil && n.child1 == nil)
	// leaf node with different label.
	if !std.BytesEqual(n.label, label) {
		proof.leafLabel = n.label
		proof.leafVal = n.val
		return false, nil, proof, dig, false
	}
	// leaf node with same label.
	return true, n.val, proof, dig, false
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
	n.hash = compLeafHash(n.label, n.val)
}

func compLeafHash(label, val []byte) []byte {
	valLen := uint64(len(val))
	var b = make([]byte, 0, cryptoffi.HashLen+8+valLen+1)
	b = append(b, label...)
	b = marshal.WriteInt(b, valLen)
	b = append(b, val...)
	b = append(b, leafNodeTag)
	return cryptoffi.Hash(b)
}

func setInteriorHash(n *node, c *cache) {
	child0 := getNodeHash(n.child0, c)
	child1 := getNodeHash(n.child1, c)
	n.hash = compInteriorHash(child0, child1)
}

func compInteriorHash(child0, child1 []byte) []byte {
	var b = make([]byte, 0, 2*cryptoffi.HashLen+1)
	b = append(b, child0...)
	b = append(b, child1...)
	b = append(b, interiorNodeTag)
	return cryptoffi.Hash(b)
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
