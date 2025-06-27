package merkle

import (
	"github.com/goose-lang/primitive"
	"github.com/goose-lang/std"
	"github.com/sanjit-bhat/pav/cryptoffi"
	"github.com/sanjit-bhat/pav/cryptoutil"
	"github.com/tchajed/marshal"
)

const (
	// tags used as hash domain separation prefixes.
	// cut nodes don't have a tag.
	// their hashes could represent anything, even invalid sub-trees.
	emptyNodeTag byte = 1
	leafNodeTag  byte = 2
	innerNodeTag byte = 3

	cutNodeTy   byte = 1
	leafNodeTy  byte = 2
	innerNodeTy byte = 3
)

type Tree struct {
	ctx  *context
	root *node
}

// node contains union of different nodeTy's.
// empty node is nil node ptr.
type node struct {
	nodeTy byte
	hash   []byte
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

// Put adds the leaf (label, val), storing immutable references to both.
// for liveness (not safety) reasons, it returns an error
// if the label does not have a fixed length.
func (t *Tree) Put(label []byte, val []byte) bool {
	if uint64(len(label)) != cryptoffi.HashLen {
		return true
	}
	put(&t.root, 0, label, val, t.ctx)
	return false
}

// put inserts leaf node (label, val) into the n0 sub-tree.
// it never drops the update.
func put(n0 **node, depth uint64, label, val []byte, ctx *context) {
	n := *n0
	// empty or cut node.
	if n == nil || n.nodeTy == cutNodeTy {
		// replace with leaf.
		leaf := &node{nodeTy: leafNodeTy, label: label, val: val}
		*n0 = leaf
		setLeafHash(leaf)
		return
	}

	if n.nodeTy == leafNodeTy {
		// on exact label match, replace val.
		if std.BytesEqual(n.label, label) {
			n.val = val
			setLeafHash(n)
			return
		}

		// otherwise, replace with inner node that links
		// to existing leaf, and recurse.
		inner := &node{nodeTy: innerNodeTy}
		*n0 = inner
		leafChild, _ := getChild(inner, n.label, depth)
		*leafChild = n
		recurChild, _ := getChild(inner, label, depth)
		put(recurChild, depth+1, label, val, ctx)
		setInnerHash(inner, ctx)
		return
	}

	std.Assert(n.nodeTy == innerNodeTy)
	c, _ := getChild(n, label, depth)
	put(c, depth+1, label, val, ctx)
	// recurse.
	setInnerHash(n, ctx)
}

// Get returns if label is in the tree (and if so, the val).
// it should only be called on complete trees (no cuts).
func (t *Tree) Get(label []byte) (bool, []byte) {
	in, val, _, err0 := t.prove(label, false)
	std.Assert(!err0)
	return in, val
}

// Prove returns if label is in tree (and if so, the val) and
// a cryptographic proof of this.
// it should only be called on complete trees (no cuts).
func (t *Tree) Prove(label []byte) (bool, []byte, []byte) {
	in, val, proof, err0 := t.prove(label, true)
	std.Assert(!err0)
	return in, val, proof
}

// prove returns whether label is in the tree (and if so, the val) and
// a cryptographic proof of this.
// it errors if search lands on a cut node.
func (t *Tree) prove(label []byte, getProof bool) (bool, []byte, []byte, bool) {
	found, foundLabel, foundVal, proof0, err0 := find(label, getProof, t.ctx, t.root, 0)
	var proof = proof0
	if err0 {
		return false, nil, nil, true
	}
	if getProof {
		primitive.UInt64Put(proof, uint64(len(proof))-8) // SibsLen
	}

	if !found {
		if getProof {
			proof = marshal.WriteBool(proof, false) // IsOtherLeaf
			proof = marshal.WriteInt(proof, 0)      // empty LeafLabelLen
			proof = marshal.WriteInt(proof, 0)      // empty LeafValLen
		}
		return false, nil, proof, false
	}
	if !std.BytesEqual(foundLabel, label) {
		if getProof {
			proof = marshal.WriteBool(proof, true) // IsOtherLeaf
			proof = marshal.WriteInt(proof, uint64(len(foundLabel)))
			proof = marshal.WriteBytes(proof, foundLabel)
			proof = marshal.WriteInt(proof, uint64(len(foundVal)))
			proof = marshal.WriteBytes(proof, foundVal)
		}
		return false, nil, proof, false
	}
	if getProof {
		proof = marshal.WriteBool(proof, false) // IsOtherLeaf
		proof = marshal.WriteInt(proof, 0)      // empty LeafLabelLen
		proof = marshal.WriteInt(proof, 0)      // empty LeafValLen
	}
	return true, foundVal, proof, false
}

// find searches the tree for label, returning whether a leaf was found
// (and if so, the leaf label and val) and the sibling proof.
// it errors if search lands on a cut node.
func find(label []byte, getProof bool, ctx *context, n *node, depth uint64) (bool, []byte, []byte, []byte, bool) {
	// if empty, not found.
	if n == nil {
		var proof []byte
		if getProof {
			proof = make([]byte, 8, getProofLen(depth))
		}
		return false, nil, nil, proof, false
	}
	// cut hides the sub-tree, so don't know if there. error.
	if n.nodeTy == cutNodeTy {
		return false, nil, nil, nil, true
	}
	// if leaf, found!
	if n.nodeTy == leafNodeTy {
		var proof []byte
		if getProof {
			proof = make([]byte, 8, getProofLen(depth))
		}
		return true, n.label, n.val, proof, false
	}

	// recurse down inner.
	std.Assert(n.nodeTy == innerNodeTy)
	child, sib := getChild(n, label, depth)
	f, fl, fv, proof0, err0 := find(label, getProof, ctx, *child, depth+1)
	var proof = proof0
	if err0 {
		return false, nil, nil, nil, true
	}
	if getProof {
		// proof will have sibling hash for each inner node.
		proof = append(proof, getNodeHash(*sib, ctx)...)
	}
	return f, fl, fv, proof, false
}

func getProofLen(depth uint64) uint64 {
	// proof = SibsLen ++ Sibs ++ IsOtherLeaf ++
	// LeafLabelLen ++ LeafLabel ++ LeafValLen ++ LeafVal (ed25519 pk).
	return 8 + depth*cryptoffi.HashLen + 1 + 8 + cryptoffi.HashLen + 8 + 32
}

// VerifyMemb checks that (label, val) in tree described by proof,
// returning the tree dig and an error on failure.
func VerifyMemb(label, val, proof []byte) ([]byte, bool) {
	tr, err0 := proofToTree(label, proof)
	if err0 {
		return nil, true
	}
	tr.Put(label, val)
	return tr.Digest(), false
}

// VerifyNonMemb checks that label not in tree described by proof,
// returning the tree dig and an error on failure.
func VerifyNonMemb(label, proof []byte) ([]byte, bool) {
	tr, err0 := proofToTree(label, proof)
	if err0 {
		return nil, true
	}
	found, _, _, err1 := tr.prove(label, false)
	if err1 {
		return nil, true
	}
	if found {
		return nil, true
	}
	return tr.Digest(), false
}

// VerifyUpdate returns the dig for an old tree without label and
// the dig after inserting (label, val).
// it errors on failure.
func VerifyUpdate(label, val, proof []byte) ([]byte, []byte, bool) {
	tr, err0 := proofToTree(label, proof)
	if err0 {
		return nil, nil, true
	}
	oldDig := tr.Digest()
	// label doesn't exist.
	found, _, _, err1 := tr.prove(label, false)
	if err1 {
		return nil, nil, true
	}
	if found {
		return nil, nil, true
	}
	// insert (label, val).
	if tr.Put(label, val) {
		return nil, nil, true
	}
	newDig := tr.Digest()
	return oldDig, newDig, false
}

func (t *Tree) Digest() []byte {
	return getNodeHash(t.root, t.ctx)
}

func New() *Tree {
	c := &context{emptyHash: compEmptyHash()}
	return &Tree{ctx: c}
}

// newShell makes a tree shell from sibs,
// guaranteeing that down label is empty.
func newShell(label []byte, ctx *context, depth uint64, sibs []byte) *node {
	sibsLen := uint64(len(sibs))
	if sibsLen == 0 {
		return nil
	}
	split := sibsLen - cryptoffi.HashLen
	sibs0 := sibs[:split]
	hash := sibs[split:]
	cut := &node{nodeTy: cutNodeTy, hash: hash}
	inner := &node{nodeTy: innerNodeTy}
	child, sib := getChild(inner, label, depth)
	*sib = cut
	*child = newShell(label, ctx, depth+1, sibs0)
	setInnerHash(inner, ctx)
	return inner
}

// proofToTree errors on failure.
func proofToTree(label, proof []byte) (*Tree, bool) {
	proof0, _, err0 := MerkleProofDecode(proof)
	if err0 {
		return nil, true
	}
	if uint64(len(proof0.Siblings))%cryptoffi.HashLen != 0 {
		return nil, true
	}
	ctx := &context{emptyHash: compEmptyHash()}
	root := newShell(label, ctx, 0, proof0.Siblings)
	tr := &Tree{ctx: ctx, root: root}
	if proof0.IsOtherLeaf {
		tr.Put(proof0.LeafLabel, proof0.LeafVal)
	}
	return tr, false
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
func getChild(n *node, label []byte, depth uint64) (**node, **node) {
	if !getBit(label, depth) {
		return &n.child0, &n.child1
	} else {
		return &n.child1, &n.child0
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
