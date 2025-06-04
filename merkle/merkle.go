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

// Put adds (label, val) to the tree, storing immutable references to both.
// for liveness (not safety) reasons, it returns an error
// if the label does not have a fixed length.
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

// Get returns if label is in the tree and if so, the val.
func (t *Tree) Get(label []byte) (bool, []byte) {
	in, val, _ := t.prove(label, false)
	return in, val
}

// Prove returns if label is in tree (and if so, the val) and
// a cryptographic proof of this.
func (t *Tree) Prove(label []byte) (bool, []byte, []byte) {
	return t.prove(label, true)
}

func (t *Tree) prove(label []byte, getProof bool) (bool, []byte, []byte) {
	found, foundLabel, foundVal, proof0 := find(label, getProof, t.ctx, t.root, 0)
	var proof = proof0
	if getProof {
		primitive.UInt64Put(proof, uint64(len(proof))-8) // SibsLen
	}

	if !found {
		if getProof {
			proof = marshal.WriteBool(proof, false) // FoundOtherLeaf
			proof = marshal.WriteInt(proof, 0)      // empty LeafLabelLen
			proof = marshal.WriteInt(proof, 0)      // empty LeafValLen
		}
		return false, nil, proof
	}
	if !std.BytesEqual(foundLabel, label) {
		if getProof {
			proof = marshal.WriteBool(proof, true) // FoundOtherLeaf
			proof = marshal.WriteInt(proof, uint64(len(foundLabel)))
			proof = marshal.WriteBytes(proof, foundLabel)
			proof = marshal.WriteInt(proof, uint64(len(foundVal)))
			proof = marshal.WriteBytes(proof, foundVal)
		}
		return false, nil, proof
	}
	if getProof {
		proof = marshal.WriteBool(proof, false) // FoundOtherLeaf
		proof = marshal.WriteInt(proof, 0)      // empty LeafLabelLen
		proof = marshal.WriteInt(proof, 0)      // empty LeafValLen
	}
	return true, foundVal, proof
}

// find returns whether label path was found (and if so, the found label and val)
// and the sibling proof.
func find(label []byte, getProof bool, ctx *context, n *node, depth uint64) (bool, []byte, []byte, []byte) {
	// break on empty node.
	if n == nil {
		var proof []byte
		if getProof {
			proof = make([]byte, 8, getProofLen(depth))
		}
		return false, nil, nil, proof
	}
	// break on leaf node.
	if n.child0 == nil && n.child1 == nil {
		var proof []byte
		if getProof {
			proof = make([]byte, 8, getProofLen(depth))
		}
		return true, n.label, n.val, proof
	}

	child, sib := getChild(n, label, depth)
	f, fl, fv, proof0 := find(label, getProof, ctx, *child, depth+1)
	var proof = proof0
	if getProof {
		// proof will have sibling hash for each inner node.
		proof = append(proof, getNodeHash(sib, ctx)...)
	}
	return f, fl, fv, proof
}

func getProofLen(depth uint64) uint64 {
	// proof = SibsLen ++ Sibs ++ FoundOtherLeaf ++
	// LeafLabelLen ++ LeafLabel ++ LeafValLen ++ LeafVal (ed25519 pk).
	return 8 + depth*cryptoffi.HashLen + 1 + 8 + cryptoffi.HashLen + 8 + 32
}

// Verify verifies proof against the tree rooted at dig
// and returns an error upon failure.
// there are two types of inputs:
// if inTree, (label, val) should be in the tree.
// if !inTree, label should not be in the tree.
func Verify(inTree bool, label, val, proof, dig []byte) bool {
	proofDec, _, err0 := MerkleProofDecode(proof)
	if err0 {
		return true
	}

	// hash last node.
	var lastHash []byte
	var err1 bool
	if inTree {
		lastHash = compLeafHash(label, val)
	} else {
		if proofDec.FoundOtherLeaf {
			lastHash = compLeafHash(proofDec.LeafLabel, proofDec.LeafVal)
			if std.BytesEqual(label, proofDec.LeafLabel) {
				err1 = true
			}
		} else {
			lastHash = compEmptyHash()
		}
	}
	if err1 {
		return true
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

// VerifyMono checks label not in oldDig and
// newDig is oldDig with (label, val) inserted.
// it returns an error.
func VerifyMono(label, val, oldProof, oldDig, newDig []byte) bool {
	// label not in oldDig.
	if Verify(false, label, nil, oldProof, oldDig) {
		return true
	}

	// make new proof by inserting new entry into last node of old proof.
	// everything else in tree (the old sibling hashes) is constant.

	proofDec, _, err0 := MerkleProofDecode(oldProof)
	std.Assert(!err0)
	last := NewTree()
	if proofDec.FoundOtherLeaf {
		last.root = &node{label: proofDec.LeafLabel, val: proofDec.LeafVal}
		setLeafHash(last.root)
	}

	depth := uint64(len(proofDec.Siblings)) / cryptoffi.HashLen
	// for liveness, not safety.
	if uint64(len(label)) != cryptoffi.HashLen {
		return true
	}
	put(&last.root, depth, label, val, last.ctx)
	found, foundLabel, foundVal, newProof0 := find(label, true, last.ctx, last.root, depth)
	var newProof = newProof0
	std.Assert(found)
	std.Assert(std.BytesEqual(label, foundLabel))
	std.Assert(std.BytesEqual(val, foundVal))

	// unfort, this causes slice re-allocs.
	newProof = append(newProof, proofDec.Siblings...)
	primitive.UInt64Put(newProof, uint64(len(newProof))-8) // SibsLen
	newProof = marshal.WriteBool(newProof, false)          // FoundOtherLeaf
	newProof = marshal.WriteInt(newProof, 0)               // empty LeafLabelLen
	newProof = marshal.WriteInt(newProof, 0)               // empty LeafValLen

	// check new proof against newDig.
	if Verify(true, label, val, newProof, newDig) {
		return true
	}
	return false
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
	hr := cryptoffi.NewHasher()
	hr.Write([]byte{leafNodeTag})
	hr.Write(marshal.WriteInt(nil, uint64(len(label))))
	hr.Write(label)
	hr.Write(marshal.WriteInt(nil, uint64(len(val))))
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
// this is fine as long as the code consistently treats labels as
// having variable length.
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
