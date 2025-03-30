package merkle

import (
	"github.com/goose-lang/primitive"
	"github.com/goose-lang/std"
	"github.com/mit-pdos/pav/cryptoffi"
	"github.com/mit-pdos/pav/cryptoutil"
	"github.com/tchajed/marshal"
)

const (
	emptyNodeTag byte = 0
	leafNodeTag  byte = 1
	innerNodeTag byte = 2
	// pre-size for roughly 2^30 (1.07B) entries.
	// proof = SibsLen ++ Sibs ++ LeafLabelLen ++ LeafLabel ++ LeafValLen ++ LeafVal (ed25519 pk).
	avgProofLen uint64 = 8 + 30*cryptoffi.HashLen + 8 + cryptoffi.HashLen + 8 + 32
)

type Tree struct {
	ctx  *context
	root *node
}

// node contains the union of different node types, which distinguish as:
//  1. empty node. if node ptr is nil.
//  2. leaf node. if child0 and child1 nil. has hash, label, and val.
//  3. inner node. else. has hash.
type node struct {
	hash []byte
	// only for inner node.
	child0 *node
	// only for inner node.
	child1 *node
	// only for leaf node.
	label []byte
	// only for leaf node.
	val []byte
}

type context struct {
	emptyHash []byte
}

// Put adds (label, val) to the tree and errors if label isn't a hash.
// it consumes both label and val.
func (t *Tree) Put(label []byte, val []byte) bool {
	if uint64(len(label)) != cryptoffi.HashLen {
		return true
	}
	put(&t.root, 0, label, val, t.ctx)
	return false
}

func put(n0 **node, depth uint64, label, val []byte, ctx *context) {
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

		// otherwise, replace with inner node that links
		// to existing leaf, and recurse.
		inner := &node{}
		*n0 = inner
		leafChild, _ := getChild(inner, n.label, depth)
		*leafChild = n
		recurChild, _ := getChild(inner, label, depth)
		put(recurChild, depth+1, label, val, ctx)
		setInnerHash(inner, ctx)
		return
	}

	// inner node. recurse.
	c, _ := getChild(n, label, depth)
	put(c, depth+1, label, val, ctx)
	setInnerHash(n, ctx)
}

// Get returns if label is in the tree and, if so, the val.
// it errors if label isn't a hash.
func (t *Tree) Get(label []byte) (bool, []byte, bool) {
	inTree, val, _, err := t.prove(label, false)
	return inTree, val, err
}

// Prove returns (1) if label is in the tree and, if so, (2) the val.
// it gives a (3) cryptographic proof of this.
// it (4) errors if label isn't a hash.
func (t *Tree) Prove(label []byte) (bool, []byte, []byte, bool) {
	return t.prove(label, true)
}

func (t *Tree) prove(label []byte, prove bool) (bool, []byte, []byte, bool) {
	if uint64(len(label)) != cryptoffi.HashLen {
		return false, nil, nil, true
	}
	proof0, last := proveSiblings(label, prove, t.ctx, t.root, 0)
	var proof = proof0
	if prove {
		primitive.UInt64Put(proof, uint64(len(proof))-8) // SibsLen
	}

	// empty node.
	if last == nil {
		if prove {
			proof = marshal.WriteInt(proof, 0) // empty LeafLabelLen
			proof = marshal.WriteInt(proof, 0) // empty LeafValLen
		}
		return false, nil, proof, false
	}
	// leaf node with different label.
	if !std.BytesEqual(last.label, label) {
		if prove {
			proof = marshal.WriteInt(proof, uint64(len(last.label)))
			proof = marshal.WriteBytes(proof, last.label)
			proof = marshal.WriteInt(proof, uint64(len(last.val)))
			proof = marshal.WriteBytes(proof, last.val)
		}
		return false, nil, proof, false
	}
	// leaf node with same label.
	if prove {
		proof = marshal.WriteInt(proof, 0) // empty LeafLabelLen
		proof = marshal.WriteInt(proof, 0) // empty LeafValLen
	}
	return true, last.val, proof, false
}

func proveSiblings(label []byte, prove bool, ctx *context, n *node, depth uint64) ([]byte, *node) {
	// break if empty node or leaf node.
	if n == nil {
		if prove {
			return make([]byte, 8, avgProofLen), n
		}
		return nil, n
	}
	if n.child0 == nil && n.child1 == nil {
		if prove {
			return make([]byte, 8, avgProofLen), n
		}
		return nil, n
	}

	child, sib := getChild(n, label, depth)
	proof0, last := proveSiblings(label, prove, ctx, *child, depth+1)
	var proof = proof0
	if prove {
		// proof will have sibling hash for each inner node.
		proof = append(proof, getNodeHash(sib, ctx)...)
	}
	return proof, last
}

// Verify verifies proof against the tree rooted at dig
// and returns an error upon failure.
// there are two types of inputs.
// if inTree, (label, val) should be in the tree.
// if !inTree, label should not be in the tree.
func Verify(inTree bool, label, val, proof, dig []byte) bool {
	if uint64(len(label)) != cryptoffi.HashLen {
		return true
	}
	proofDec, _, err0 := MerkleProofDecode(proof)
	if err0 {
		return true
	}
	if std.BytesEqual(label, proofDec.LeafLabel) {
		return true
	}

	// hash last node.
	var lastHash []byte
	if inTree {
		lastHash = compLeafHash(label, val)
	} else {
		if uint64(len(proofDec.LeafLabel)) == cryptoffi.HashLen {
			lastHash = compLeafHash(proofDec.LeafLabel, proofDec.LeafVal)
		} else {
			lastHash = compEmptyHash()
		}
	}
	return verifySiblings(label, lastHash, proofDec.Siblings, dig)
}

func verifySiblings(label, lastHash, siblings, dig []byte) bool {
	sibsLen := uint64(len(siblings))
	if sibsLen%cryptoffi.HashLen != 0 {
		return true
	}

	// hash up the tree.
	var currHash = lastHash
	var hashOut = make([]byte, 0, cryptoffi.HashLen)
	maxDepth := sibsLen / cryptoffi.HashLen
	var depthInv uint64
	for ; depthInv < maxDepth; depthInv++ {
		begin := depthInv * cryptoffi.HashLen
		end := (depthInv + 1) * cryptoffi.HashLen
		sib := siblings[begin:end]

		depth := maxDepth - depthInv - 1
		if !getBit(label, depth) {
			hashOut = compInnerHash(currHash, sib, hashOut)
		} else {
			hashOut = compInnerHash(sib, currHash, hashOut)
		}
		currHash = append(currHash[:0], hashOut...)
		hashOut = hashOut[:0]
	}

	// check against supplied dig.
	return !std.BytesEqual(currHash, dig)
}

func (t *Tree) Digest() []byte {
	return getNodeHash(t.root, t.ctx)
}

func NewTree() *Tree {
	c := &context{emptyHash: compEmptyHash()}
	return &Tree{ctx: c}
}

func getNodeHash(n *node, c *context) []byte {
	if n == nil {
		return c.emptyHash
	}
	return n.hash
}

func compEmptyHash() []byte {
	return cryptoutil.Hash([]byte{emptyNodeTag})
}

func setLeafHash(n *node) {
	n.hash = compLeafHash(n.label, n.val)
}

func compLeafHash(label, val []byte) []byte {
	valLen := uint64(len(val))
	hr := cryptoffi.NewHasher()
	hr.Write([]byte{leafNodeTag})
	hr.Write(label)
	hr.Write(marshal.WriteInt(nil, valLen))
	hr.Write(val)
	return hr.Sum(nil)
}

func setInnerHash(n *node, c *context) {
	child0 := getNodeHash(n.child0, c)
	child1 := getNodeHash(n.child1, c)
	n.hash = compInnerHash(child0, child1, nil)
}

func compInnerHash(child0, child1, h []byte) []byte {
	hr := cryptoffi.NewHasher()
	hr.Write([]byte{innerNodeTag})
	hr.Write(child0)
	hr.Write(child1)
	return hr.Sum(h)
}

// getChild returns a child and its sibling child,
// relative to the bit referenced by label and depth.
func getChild(n *node, label []byte, depth uint64) (**node, *node) {
	if !getBit(label, depth) {
		return &n.child0, n.child1
	} else {
		return &n.child1, n.child0
	}
}

// getBit returns false if the nth bit of b is 0.
// if n exceeds b, it returns false.
// this is fine as long as it's used consistently across the code.
func getBit(b []byte, n uint64) bool {
	slot := n / 8
	if slot < uint64(len(b)) {
		off := n % 8
		x := b[slot]
		return x&(1<<off) != 0
	} else {
		return false
	}
}
