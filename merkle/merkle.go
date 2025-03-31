package merkle

import (
	"github.com/goose-lang/std"
	"github.com/mit-pdos/pav/cryptoffi"
	"github.com/mit-pdos/pav/cryptoutil"
	"github.com/tchajed/marshal"
)

const (
	emptyNodeTag byte = 0
	leafNodeTag  byte = 1
	innerNodeTag byte = 2
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
	if uint64(len(label)) != cryptoffi.HashLen {
		return false, nil, true
	}
	inTree, val, _ := prove(label, false, t.ctx, t.root, 0)
	return inTree, val, false
}

// Prove returns (1) if label is in the tree and, if so, (2) the val.
// it gives a (3) cryptographic proof of this.
// it (4) errors if label isn't a hash.
func (t *Tree) Prove(label []byte) (bool, []byte, []byte, bool) {
	if uint64(len(label)) != cryptoffi.HashLen {
		return false, nil, nil, true
	}
	inTree, val, proof := prove(label, true, t.ctx, t.root, 0)
	return inTree, val, proof, false
}

func prove(label []byte, getProof bool, ctx *context, n *node, depth uint64) (bool, []byte, []byte) {
	// break on empty node.
	if n == nil {
		if getProof {
			var proof = make([]byte, 0, getProofLen(depth))
			proof = marshal.WriteInt(proof, 0) // empty LeafLabelLen
			proof = marshal.WriteInt(proof, 0) // empty LeafValLen
			proof = marshal.WriteInt(proof, depth*cryptoffi.HashLen)
			return false, nil, proof
		}
		return false, nil, nil
	}
	// break on leaf node.
	if n.child0 == nil && n.child1 == nil {
		// different label.
		if !std.BytesEqual(n.label, label) {
			if getProof {
				var proof = make([]byte, 0, getProofLen(depth))
				proof = marshal.WriteInt(proof, uint64(len(n.label)))
				proof = marshal.WriteBytes(proof, n.label)
				proof = marshal.WriteInt(proof, uint64(len(n.val)))
				proof = marshal.WriteBytes(proof, n.val)
				proof = marshal.WriteInt(proof, depth*cryptoffi.HashLen)
				return false, nil, proof
			}
			return false, nil, nil
		}

		// same label.
		if getProof {
			var proof = make([]byte, 0, getProofLen(depth))
			proof = marshal.WriteInt(proof, 0) // empty LeafLabelLen
			proof = marshal.WriteInt(proof, 0) // empty LeafValLen
			proof = marshal.WriteInt(proof, depth*cryptoffi.HashLen)
			return true, n.val, proof
		}
		return true, n.val, nil
	}

	child, sib := getChild(n, label, depth)
	inTree, val, proof0 := prove(label, getProof, ctx, *child, depth+1)
	var proof = proof0
	if getProof {
		// proof will have sibling hash for each inner node.
		proof = append(proof, getNodeHash(sib, ctx)...)
	}
	return inTree, val, proof
}

func getProofLen(depth uint64) uint64 {
	// proof = LeafLabelLen ++ LeafLabel ++ LeafValLen ++ LeafVal (ed25519 pk) ++ SibsLen ++ Sibs.
	return 8 + cryptoffi.HashLen + 8 + 32 + 8 + depth*cryptoffi.HashLen
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
