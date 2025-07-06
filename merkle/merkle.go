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

var (
	// emptyHash pre-computed. frequently used.
	emptyHash = compEmptyHash()
)

type Tree struct {
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

// Put adds the leaf (label, val), storing immutable references to both.
// for liveness (not safety) reasons, it returns an error
// if the label does not have a fixed length.
func (t *Tree) Put(label []byte, val []byte) (err bool) {
	if uint64(len(label)) != cryptoffi.HashLen {
		return true
	}
	put(&t.root, 0, label, val)
	return
}

// put inserts leaf node (label, val) into the n0 sub-tree.
// it never drops the update.
func put(n0 **node, depth uint64, label, val []byte) {
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
		put(recurChild, depth+1, label, val)
		setInnerHash(inner)
		return
	}

	std.Assert(n.nodeTy == innerNodeTy)
	c, _ := getChild(n, label, depth)
	put(c, depth+1, label, val)
	// recurse.
	setInnerHash(n)
}

// Get should only be called on complete trees (no cuts).
func (t *Tree) Get(label []byte) (inTree bool, val []byte) {
	inTree, val, _, errb := t.prove(label, false)
	std.Assert(!errb)
	return
}

// Prove should only be called on complete trees (no cuts).
func (t *Tree) Prove(label []byte) (inTree bool, val, proof []byte) {
	inTree, val, proof, errb := t.prove(label, true)
	std.Assert(!errb)
	return
}

// prove errors if search lands on a cut node.
func (t *Tree) prove(label []byte, getProof bool) (inTree bool, val, proof []byte, err bool) {
	found, foundLabel, val, proof, err := find(label, getProof, t.root, 0)
	if err {
		return
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
		return
	}
	if !std.BytesEqual(foundLabel, label) {
		if getProof {
			proof = marshal.WriteBool(proof, true) // IsOtherLeaf
			proof = marshal.WriteInt(proof, uint64(len(foundLabel)))
			proof = marshal.WriteBytes(proof, foundLabel)
			proof = marshal.WriteInt(proof, uint64(len(val)))
			proof = marshal.WriteBytes(proof, val)
		}
		return
	}
	if getProof {
		proof = marshal.WriteBool(proof, false) // IsOtherLeaf
		proof = marshal.WriteInt(proof, 0)      // empty LeafLabelLen
		proof = marshal.WriteInt(proof, 0)      // empty LeafValLen
	}
	inTree = true
	return
}

// find searches the tree for a leaf node down path label.
// it errors if search lands on a cut node.
func find(label []byte, getProof bool, n *node, depth uint64) (found bool, foundLabel, foundVal, proof []byte, err bool) {
	// if empty, not found.
	if n == nil {
		if getProof {
			proof = make([]byte, 8, getProofLen(depth))
		}
		return
	}
	// cut hides the sub-tree, so don't know if there. error.
	if n.nodeTy == cutNodeTy {
		err = true
		return
	}
	// if leaf, found!
	if n.nodeTy == leafNodeTy {
		if getProof {
			proof = make([]byte, 8, getProofLen(depth))
		}
		found = true
		foundLabel = n.label
		foundVal = n.val
		return
	}

	// recurse down inner.
	std.Assert(n.nodeTy == innerNodeTy)
	child, sib := getChild(n, label, depth)
	found, foundLabel, foundVal, proof, err = find(label, getProof, *child, depth+1)
	if err {
		return
	}
	if getProof {
		// proof will have sibling hash for each inner node.
		proof = append(proof, getNodeHash(*sib)...)
	}
	return
}

func getProofLen(depth uint64) uint64 {
	// proof = SibsLen ++ Sibs ++ IsOtherLeaf ++
	// LeafLabelLen ++ LeafLabel ++ LeafValLen ++ LeafVal (ed25519 pk).
	return 8 + depth*cryptoffi.HashLen + 1 + 8 + cryptoffi.HashLen + 8 + 32
}

// VerifyMemb checks that (label, val) in tree described by proof.
func VerifyMemb(label, val, proof []byte) (dig []byte, err bool) {
	tr, err := proofToTree(label, proof)
	if err {
		return
	}
	tr.Put(label, val)
	dig = tr.Digest()
	return
}

// VerifyNonMemb checks that label not in tree described by proof.
func VerifyNonMemb(label, proof []byte) (dig []byte, err bool) {
	tr, err := proofToTree(label, proof)
	if err {
		return
	}
	found, _, _, err := tr.prove(label, false)
	if err {
		return
	}
	if found {
		err = true
		return
	}
	dig = tr.Digest()
	return
}

// VerifyUpdate returns the dig for an old tree without label and
// the dig after inserting (label, val).
func VerifyUpdate(label, val, proof []byte) (oldDig, newDig []byte, err bool) {
	tr, err := proofToTree(label, proof)
	if err {
		return
	}
	oldDig = tr.Digest()
	// label doesn't exist.
	found, _, _, err := tr.prove(label, false)
	if err {
		return
	}
	if found {
		err = true
		return
	}
	// insert (label, val).
	if err = tr.Put(label, val); err {
		return
	}
	newDig = tr.Digest()
	return
}

func (t *Tree) Digest() []byte {
	return getNodeHash(t.root)
}

// newShell makes a tree shell from sibs, guaranteeing that down label is empty.
func newShell(label []byte, depth uint64, sibs []byte) (n *node) {
	sibsLen := uint64(len(sibs))
	if sibsLen == 0 {
		return
	}
	split := sibsLen - cryptoffi.HashLen
	sibs0 := sibs[:split]
	hash := sibs[split:]
	cut := &node{nodeTy: cutNodeTy, hash: hash}
	inner := &node{nodeTy: innerNodeTy}
	child, sib := getChild(inner, label, depth)
	*sib = cut
	*child = newShell(label, depth+1, sibs0)
	setInnerHash(inner)
	return inner
}

func proofToTree(label, proof []byte) (tr *Tree, err bool) {
	p, _, err := MerkleProofDecode(proof)
	if err {
		return
	}
	if uint64(len(p.Siblings))%cryptoffi.HashLen != 0 {
		err = true
		return
	}
	root := newShell(label, 0, p.Siblings)
	tr = &Tree{root: root}
	if p.IsOtherLeaf {
		tr.Put(p.LeafLabel, p.LeafVal)
	}
	return
}

func getNodeHash(n *node) []byte {
	if n == nil {
		return emptyHash
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

func setInnerHash(n *node) {
	child0 := getNodeHash(n.child0)
	child1 := getNodeHash(n.child1)
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
