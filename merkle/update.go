package merkle

import (
	"github.com/goose-lang/std"
	"github.com/sanjit-bhat/pav/cryptoffi"
	"github.com/sanjit-bhat/pav/safemarshal"
	"github.com/tchajed/marshal"
)

// an update proof is a tape: the DFS pre-order (child0 first) serialization of
// the smallest sub-tree that covers every inserted label, with everything off
// that sub-tree replaced by an opaque cut.
// the verifier rebuilds the tape into a tree, hashes it for the old digest,
// [put]'s the batch into it, and hashes again for the new digest. the prover
// runs the mirror of that: [serialize], then the same [putAll].
// so the tape's meaning is "the part of the old tree an insert can reach",
// and everything else about the update is decided by [put], which both sides
// run.
const (
	// tapeSplit descends into child0, then child1.
	tapeSplit byte = iota
	// tapeEmpty terminates in an empty sub-tree.
	tapeEmpty
	// tapeCut terminates in an unchanged sub-tree with the following hash.
	tapeCut
	// tapeLeaf terminates in the following leaf, which an insert may push down.
	tapeLeaf
)

// Update inserts the batch of (labels[i], vals[i]) leaves and returns a proof
// that the new map is the old map plus exactly those leaves.
// it errors iff some label is already in the map or repeats within the batch,
// or the batch reaches an unloaded sub-tree.
// it stores immutable references to the labels and vals, and it leaves both
// slices in the caller's order.
// on error, the map may already hold a prefix of the batch, so callers discard
// it rather than reusing it.
func (m *Map) Update(labels, vals [][]byte) (updProof []byte, err bool) {
	std.Assert(uint64(len(labels)) == uint64(len(vals)))
	// [serialize] partitions the labels into trie order, so it gets its own
	// copy of the slice headers.
	ownLabels := make([][]byte, 0, uint64(len(labels)))
	for _, l := range labels {
		std.Assert(uint64(len(l)) == cryptoffi.HashLen)
		ownLabels = append(ownLabels, l)
	}

	// the same two passes the verifier runs, in the same order: say what the
	// old tree looked like where the batch can reach, then [put] the batch in.
	tape, err := serialize(m.root, 0, ownLabels, nil)
	if err {
		return nil, true
	}
	if putAll(&m.root, labels, vals) {
		return nil, true
	}
	return tape, false
}

// serialize appends to tape the sub-tree n, which sits at depth and covers
// every label in the batch. it is the inverse of [tapeToTree].
// it errors iff the batch reaches a cut, which hides where the leaves land.
func serialize(n *node, depth uint64, labels [][]byte, tape []byte) (tapeOut []byte, err bool) {
	std.Assert(depth <= maxDepth)

	// nothing inserted here, so the sub-tree is unchanged.
	if uint64(len(labels)) == 0 {
		if n == nil {
			return append(tape, tapeEmpty), false
		}
		tape = append(tape, tapeCut)
		return marshal.WriteBytes(tape, n.hash), false
	}

	// the batch reaches the bottom of the old tree.
	// [put] takes it from here, and the tape says what it started from.
	if n == nil {
		return append(tape, tapeEmpty), false
	}
	if n.nodeTy == leafNodeTy {
		tape = append(tape, tapeLeaf)
		tape = marshal.WriteBytes(tape, n.label)
		return safemarshal.WriteSlice1D(tape, n.val), false
	}

	if n.nodeTy == innerNodeTy {
		tape = append(tape, tapeSplit)
		mid := partition(labels, depth)
		tape, err = serialize(n.child0, depth+1, labels[:mid], tape)
		if err {
			return tape, true
		}
		return serialize(n.child1, depth+1, labels[mid:], tape)
	}

	std.Assert(n.nodeTy == cutNodeTy)
	return tape, true
}

func putAll(n0 **node, labels, vals [][]byte) (err bool) {
	for i := uint64(0); i < uint64(len(labels)); i++ {
		if put(n0, 0, labels[i], vals[i]) {
			return true
		}
	}
	return false
}

// partition reorders labels so that the ones with a 0 bit at depth come
// first, and returns how many there are.
func partition(labels [][]byte, depth uint64) (mid uint64) {
	for j := uint64(0); j < uint64(len(labels)); j++ {
		if !getBit(labels[j], depth) {
			l := labels[mid]
			labels[mid] = labels[j]
			labels[j] = l
			mid++
		}
	}
	return
}

// VerifyUpdate returns the hash of an old map without any of the labels and
// the hash after inserting the batch into it.
func VerifyUpdate(labels, vals [][]byte, updProof []byte) (hashOld, hashNew []byte, err bool) {
	m, hashOld, err := ApplyUpdate(labels, vals, updProof)
	if err {
		return nil, nil, true
	}
	return hashOld, m.Hash(), false
}

// ApplyUpdate is VerifyUpdate, keeping the map it built. every node the epoch
// changed is in it and everything else is a cut, so a party holding only the
// epoch's proof ends up holding the new tree's top, checked against hashOld.
func ApplyUpdate(labels, vals [][]byte, updProof []byte) (m *Map, hashOld []byte, err bool) {
	if uint64(len(labels)) != uint64(len(vals)) {
		return nil, nil, true
	}
	for _, l := range labels {
		if uint64(len(l)) != cryptoffi.HashLen {
			return nil, nil, true
		}
	}
	tr, rem, err := tapeToTree(updProof, 0)
	if err {
		return nil, nil, true
	}
	if uint64(len(rem)) != 0 {
		return nil, nil, true
	}
	hashOld = tr.getHash()
	if putAll(&tr, labels, vals) {
		return nil, nil, true
	}
	return &Map{root: tr}, hashOld, false
}

// tapeToTree parses one sub-tree, sitting at depth, off the front of tape.
func tapeToTree(tape []byte, depth uint64) (n *node, rem []byte, err bool) {
	if depth > maxDepth {
		return nil, nil, true
	}
	op, rem, err := safemarshal.ReadByte(tape)
	if err {
		return nil, nil, true
	}

	if op == tapeEmpty {
		return nil, rem, false
	}

	if op == tapeCut {
		h, rem, err := safemarshal.ReadBytes(rem, cryptoffi.HashLen)
		if err {
			return nil, nil, true
		}
		// a cut standing for the empty sub-tree is the empty sub-tree, so
		// tapeCut(emptyHash) and tapeEmpty mean the same thing.
		return mkCut(h), rem, false
	}

	if op == tapeLeaf {
		label, rem, err := safemarshal.ReadBytes(rem, cryptoffi.HashLen)
		if err {
			return nil, nil, true
		}
		val, rem, err := safemarshal.ReadSlice1D(rem)
		if err {
			return nil, nil, true
		}
		leaf := &node{nodeTy: leafNodeTy, label: label, val: val}
		leaf.hash = compLeafHash(label, val)
		return leaf, rem, false
	}

	if op == tapeSplit {
		c0, rem, err := tapeToTree(rem, depth+1)
		if err {
			return nil, nil, true
		}
		c1, rem, err := tapeToTree(rem, depth+1)
		if err {
			return nil, nil, true
		}
		inner := &node{nodeTy: innerNodeTy, child0: c0, child1: c1}
		inner.hash = compInnerHash(c0.getHash(), c1.getHash())
		return inner, rem, false
	}

	return nil, nil, true
}
