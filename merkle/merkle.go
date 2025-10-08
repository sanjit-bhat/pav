package merkle

import (
	"bytes"

	"github.com/goose-lang/primitive"
	"github.com/goose-lang/std"
	"github.com/sanjit-bhat/pav/cryptoffi"
	"github.com/sanjit-bhat/pav/cryptoutil"
	"github.com/tchajed/marshal"
)

// tags used as hash domain separation prefixes.
// cut nodes don't have a tag.
// their hashes could represent anything, even invalid sub-trees.
const (
	emptyNodeTag byte = iota
	leafNodeTag
	innerNodeTag
)

// nodeTy used to distinguish in-memory nodes.
// empty node is nil node ptr.
const (
	cutNodeTy byte = iota
	leafNodeTy
	innerNodeTy
)

const maxDepth = cryptoffi.HashLen * 8

var (
	// emptyHash pre-computed. frequently used.
	emptyHash = compEmptyHash()
)

type Map struct {
	root *node
}

// node contains union of different nodeTy's.
// NOTE: it may be cleaner to use diff structs for the diff node types.
// their interface includes compHash and getHash.
// compHash has a unique impl, but getHash is the same.
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
// for liveness and safety reasons, it expects the label to have fixed length.
func (m *Map) Put(label []byte, val []byte) (updProof []byte) {
	std.Assert(uint64(len(label)) == cryptoffi.HashLen)
	inMap, _, updProof := m.Prove(label)
	// for now, [VerifyUpdate] only works for monotonic update.
	std.Assert(!inMap)
	std.Assert(!put(&m.root, 0, label, val))
	return
}

// put inserts leaf node (label, val) into the n0 sub-tree.
// it errors iff there's an insert into a cut node, since that almost always
// leaves the tree in an unintended state.
func put(n0 **node, depth uint64, label, val []byte) (err bool) {
	std.Assert(depth <= maxDepth)
	n := *n0

	// empty.
	if n == nil {
		// replace with leaf.
		leaf := &node{nodeTy: leafNodeTy, label: label, val: val}
		*n0 = leaf
		leaf.hash = compLeafHash(label, val)
		return
	}

	if n.nodeTy == leafNodeTy {
		// on exact label match, replace val.
		if bytes.Equal(n.label, label) {
			n.val = val
			n.hash = compLeafHash(label, val)
			return
		}

		// otherwise, replace with inner node that links
		// to existing leaf, and recurse.
		inner := &node{nodeTy: innerNodeTy}
		*n0 = inner
		oldChild, _ := inner.getChild(n.label, depth)
		*oldChild = n
		newChild, _ := inner.getChild(label, depth)
		std.Assert(!put(newChild, depth+1, label, val))
		inner.hash = compInnerHash(inner.child0.getHash(), inner.child1.getHash())
		return
	}

	if n.nodeTy == innerNodeTy {
		c, _ := n.getChild(label, depth)
		// recurse.
		if err = put(c, depth+1, label, val); err {
			return
		}
		n.hash = compInnerHash(n.child0.getHash(), n.child1.getHash())
		return
	}
	std.Assert(n.nodeTy == cutNodeTy)
	return true
}

// Prove the membership of label.
func (m *Map) Prove(label []byte) (inMap bool, val, entryProof []byte) {
	// Prove is part of the external API, which does not expose cut trees.
	// therefore, we meet the precond.
	return m.root.prove(label, true)
}

// prove expects no cut nodes along label.
func (n *node) prove(label []byte, getProof bool) (inTree bool, val, proof []byte) {
	found, foundLabel, val, proof := n.find(0, label, getProof)
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
	if !bytes.Equal(foundLabel, label) {
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
// it expects no cut nodes along label.
func (n *node) find(depth uint64, label []byte, getProof bool) (found bool, foundLabel, foundVal, sibs []byte) {
	// if empty, not found.
	if n == nil {
		if getProof {
			// leave space for SibsLen (8).
			sibs = make([]byte, 8, getProofCap(depth))
		}
		return
	}

	// if leaf, found!
	if n.nodeTy == leafNodeTy {
		found = true
		foundLabel = n.label
		foundVal = n.val
		if getProof {
			sibs = make([]byte, 8, getProofCap(depth))
		}
		return
	}

	// recurse down inner.
	if n.nodeTy == innerNodeTy {
		child, sib := n.getChild(label, depth)
		found, foundLabel, foundVal, sibs = (*child).find(depth+1, label, getProof)
		if getProof {
			// proof will have sibling hash for each inner node.
			sibs = append(sibs, (*sib).getHash()...)
		}
		return
	}
	// cut hides the sub-tree, so don't know if there.
	panic("merkle: find into cut node")
}

func getProofCap(depth uint64) uint64 {
	// proof = SibsLen ++ Sibs ++
	//         IsOtherLeaf ++ LeafLabelLen ++ LeafLabel ++
	//         LeafValLen ++ LeafVal (ed25519 pk).
	return 8 + depth*cryptoffi.HashLen + 1 + 8 + cryptoffi.HashLen + 8 + 32
}

// VerifyMemb checks that (label, val) in tree described by proof.
// to save on bandwidth, some callers get hash from Verify.
// callers that expect some hash should check that they got the right one.
func VerifyMemb(label, val, entryProof []byte) (hash []byte, err bool) {
	tr, err := proofToTree(label, entryProof)
	if err {
		return
	}
	std.Assert(!put(&tr, 0, label, val))
	hash = tr.getHash()
	return
}

// VerifyNonMemb checks that label not in tree described by proof.
func VerifyNonMemb(label, entryProof []byte) (hash []byte, err bool) {
	tr, err := proofToTree(label, entryProof)
	if err {
		return
	}
	hash = tr.getHash()
	return
}

// VerifyUpdate returns the hash for an old tree without label and
// the hash after inserting (label, val).
func VerifyUpdate(label, val, updProof []byte) (hashOld, hashNew []byte, err bool) {
	tr, err := proofToTree(label, updProof)
	if err {
		return
	}
	hashOld = tr.getHash()
	std.Assert(!put(&tr, 0, label, val))
	hashNew = tr.getHash()
	return
}

func (m *Map) Hash() []byte {
	return m.root.getHash()
}

// proofToTree guarantees that label not in tree and that label has fixed len.
func proofToTree(label, proof []byte) (tr *node, err bool) {
	if uint64(len(label)) != cryptoffi.HashLen {
		err = true
		return
	}
	p, _, err := MerkleProofDecode(proof)
	if err {
		return
	}
	if uint64(len(p.Siblings))%cryptoffi.HashLen != 0 {
		err = true
		return
	}
	sibsDepth := uint64(len(p.Siblings)) / cryptoffi.HashLen
	if sibsDepth > maxDepth {
		err = true
		return
	}
	tr = newShell(0, label, p.Siblings)
	if p.IsOtherLeaf {
		if uint64(len(p.LeafLabel)) != cryptoffi.HashLen {
			err = true
			return
		}
		if bytes.Equal(label, p.LeafLabel) {
			err = true
			return
		}
		if err = put(&tr, 0, p.LeafLabel, p.LeafVal); err {
			return
		}
	}
	return
}

func newShell(depth uint64, label []byte, sibs []byte) (n *node) {
	sibsLen := uint64(len(sibs))
	if sibsLen == 0 {
		return
	}
	split := sibsLen - cryptoffi.HashLen
	sibs0 := sibs[:split]
	hash := sibs[split:]
	cut := &node{nodeTy: cutNodeTy, hash: hash}
	inner := &node{nodeTy: innerNodeTy}
	child, sib := inner.getChild(label, depth)
	*sib = cut
	*child = newShell(depth+1, label, sibs0)
	inner.hash = compInnerHash(inner.child0.getHash(), inner.child1.getHash())
	return inner
}

func (n *node) getHash() []byte {
	if n == nil {
		return emptyHash
	}
	return n.hash
}

func compEmptyHash() []byte {
	return cryptoutil.Hash([]byte{emptyNodeTag})
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

func compInnerHash(child0, child1 []byte) []byte {
	hr := cryptoffi.NewHasher()
	hr.Write([]byte{innerNodeTag})
	hr.Write(child0)
	hr.Write(child1)
	return hr.Sum(nil)
}

// getChild returns a child and its sibling child,
// relative to the bit referenced by label and depth.
func (n *node) getChild(label []byte, depth uint64) (**node, **node) {
	if getBit(label, depth) {
		return &n.child1, &n.child0
	} else {
		return &n.child0, &n.child1
	}
}

// getBit returns false if the nth bit of b is 0.
// if n exceeds b, it returns true.
func getBit(b []byte, n uint64) bool {
	slot := n / 8
	if slot < uint64(len(b)) {
		off := n % 8
		x := b[slot]
		return x&(1<<off) != 0
	} else {
		return true
	}
}
