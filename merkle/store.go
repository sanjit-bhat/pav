package merkle

import (
	"bytes"

	"github.com/goose-lang/std"
	"github.com/sanjit-bhat/pav/cryptoffi"
	"github.com/sanjit-bhat/pav/safemarshal"
	"github.com/tchajed/marshal"
)

// out-of-core maps.
//
// a node's storage key is its position in the trie: the label prefix it covers
// with the deeper bits zeroed, then the depth. two things follow, and they are
// the whole design.
//
// every node on label's path is a prefix of label, so all of a path's keys are
// computable before any I/O, and one batch read fetches a whole path.
//
// the key is value-major, so the *deep* keys cluster: the key at depth d shares
// label's first d/8 bytes, so every key below depth D lies in a range of
// relative width 2^-8*(D/8). the shallow keys do not cluster -- depth 0 is all
// zeros -- but those are the top of the tree, which a warm map holds anyway
// (see Evict, ApplyUpdate). so on a sorted engine the probes that actually go
// to storage come off a handful of blocks.
//
// an inner node's record holds its two children's hashes. so the path's
// records already contain every sibling hash a proof needs, and the record at
// the deepest existing prefix is the blocking leaf when there is one. one
// batch read therefore answers membership and non-membership alike, with the
// proof, and never needs a second hop.
//
// unloaded sub-trees are cut nodes, which the tree already had. a record's
// hash is checked against the cut it replaces, so the store is trusted for
// liveness only.
//
// the caller picks how deep to probe. a leaf sits at depth log2(N) + Geom(1/2),
// so a bound of log2(N) + slack leaves a 2^-slack tail to a second read, and
// the two callers want different slack: an epoch's retry is one much smaller
// batch read, so a writer minimizes probes at slack 1-2, while a lookup's
// retry is a whole extra round trip, so a reader minimizes at 3.

// StoreKeyLen is the length of every storage key: a label, then a depth.
const StoreKeyLen = cryptoffi.HashLen + 2

// StoreKey returns the storage key of the node covering label's depth-length
// prefix.
func StoreKey(label []byte, depth uint64) []byte {
	std.Assert(depth <= maxDepth)
	k := make([]byte, 0, StoreKeyLen)
	full := depth / 8
	k = marshal.WriteBytes(k, label[:full])
	if full < cryptoffi.HashLen {
		// getBit reads bits low to high within a byte, so the prefix keeps
		// the low depth%8 bits.
		k = append(k, label[full]&(byte(1)<<(depth%8)-1))
		k = marshal.WriteBytes(k, make([]byte, cryptoffi.HashLen-full-1))
	}
	k = append(k, byte(depth))
	return append(k, byte(depth>>8))
}

// PathKeys returns the storage keys of every node on label's path, for depths
// minD through maxD, in that order.
func PathKeys(label []byte, minD, maxD uint64) (keys [][]byte) {
	std.Assert(uint64(len(label)) == cryptoffi.HashLen)
	std.Assert(maxD <= maxDepth)
	keys = make([][]byte, 0, maxD-minD+1)
	for d := minD; d <= maxD; d++ {
		keys = append(keys, StoreKey(label, d))
	}
	return
}

// PathNeeds returns the depth of the first cut on label's path, and the keys
// from there through maxD. everything above it the map already holds, so this
// is the read a LoadPath actually needs. needed is false if the path is
// already complete.
func (m *Map) PathNeeds(label []byte, maxD uint64) (minD uint64, keys [][]byte, needed bool) {
	std.Assert(uint64(len(label)) == cryptoffi.HashLen)
	minD, needed = firstCut(m.root, 0, label)
	if !needed {
		return 0, nil, false
	}
	if minD > maxD {
		maxD = minD
	}
	return minD, PathKeys(label, minD, maxD), true
}

func firstCut(n *node, depth uint64, label []byte) (minD uint64, found bool) {
	if n == nil {
		return 0, false
	}
	if n.nodeTy == cutNodeTy {
		return depth, true
	}
	if n.nodeTy == leafNodeTy {
		return 0, false
	}
	std.Assert(n.nodeTy == innerNodeTy)
	if depth == maxDepth {
		return 0, false
	}
	c, _ := n.getChild(label, depth)
	return firstCut(*c, depth+1, label)
}

// Evict replaces every node at or below depth with a cut, bounding what the
// map holds. an evicted sub-tree is reloadable from the store.
func (m *Map) Evict(depth uint64) {
	evict(&m.root, 0, depth)
}

// EvictPath is Evict along one label, which is what undoes one LoadPath.
// walking the whole map to shed one path costs more than the lookup did.
func (m *Map) EvictPath(label []byte, depth uint64) {
	std.Assert(uint64(len(label)) == cryptoffi.HashLen)
	evictPath(&m.root, 0, label, depth)
}

func evictPath(n0 **node, depth uint64, label []byte, maxD uint64) {
	n := *n0
	if n == nil {
		return
	}
	if n.nodeTy == cutNodeTy {
		return
	}
	if depth >= maxD {
		*n0 = &node{nodeTy: cutNodeTy, hash: n.hash}
		return
	}
	if n.nodeTy == innerNodeTy {
		c, _ := n.getChild(label, depth)
		evictPath(c, depth+1, label, maxD)
	}
}

func evict(n0 **node, depth, maxD uint64) {
	n := *n0
	if n == nil {
		return
	}
	if n.nodeTy == cutNodeTy {
		return
	}
	if depth >= maxD {
		*n0 = &node{nodeTy: cutNodeTy, hash: n.hash}
		return
	}
	if n.nodeTy == innerNodeTy {
		evict(&n.child0, depth+1, maxD)
		evict(&n.child1, depth+1, maxD)
	}
}

// NewCut returns a map that is entirely unloaded, standing for the map with
// the given hash.
func NewCut(hash []byte) *Map {
	std.Assert(uint64(len(hash)) == cryptoffi.HashLen)
	return &Map{root: mkCut(hash)}
}

// mkCut returns the unloaded stand-in for a sub-tree with the given hash,
// which for an empty sub-tree is the empty node itself.
func mkCut(hash []byte) *node {
	if bytes.Equal(hash, emptyHash) {
		return nil
	}
	return &node{nodeTy: cutNodeTy, hash: hash}
}

// LoadPath stores immutable references into recs: a grafted node's label,
// value, and hashes are sub-slices of the record it came from.
//
// LoadPath grafts label's path into the map, where recs[i] is the record
// stored under PathKeys(label, minD, maxD)[i], or nil if the store has none.
// complete reports that the path reached a leaf or an empty sub-tree; if it is
// false and there is no error, the path runs past maxD and the caller must
// probe deeper.
func (m *Map) LoadPath(label []byte, minD uint64, recs [][]byte) (complete, err bool) {
	std.Assert(uint64(len(label)) == cryptoffi.HashLen)
	return loadPath(&m.root, 0, label, minD, recs)
}

func loadPath(n0 **node, depth uint64, label []byte, minD uint64, recs [][]byte) (complete, err bool) {
	n := *n0
	// empty and leaf both terminate the path.
	if n == nil {
		return true, false
	}
	if n.nodeTy == leafNodeTy {
		return true, false
	}
	if n.nodeTy == innerNodeTy {
		if depth == maxDepth {
			return false, true
		}
		c, _ := n.getChild(label, depth)
		return loadPath(c, depth+1, label, minD, recs)
	}

	std.Assert(n.nodeTy == cutNodeTy)
	if depth < minD || depth-minD >= uint64(len(recs)) {
		// the path is outside what the caller probed.
		return false, false
	}
	// a cut is never the empty sub-tree, so the store owes us a record.
	loaded, err := decodeNode(recs[depth-minD])
	if err {
		return false, true
	}
	if !bytes.Equal(loaded.getHash(), n.hash) {
		return false, true
	}
	*n0 = loaded
	return loadPath(n0, depth, label, minD, recs)
}

// Records returns the storage key and record of every node the map holds,
// which after a LoadPath and an Update is exactly the set the update changed,
// since every node loaded for a batch is an ancestor of one of its new leaves.
// a writer that instead kept its map warm across epochs would need to track
// which nodes are dirty; it would trade ~28% of its read probes for that
// bookkeeping.
func (m *Map) Records() (keys, recs [][]byte) {
	return records(m.root, 0, make([]byte, cryptoffi.HashLen), nil, nil)
}

func records(n *node, depth uint64, prefix []byte, keys, recs [][]byte) ([][]byte, [][]byte) {
	if n == nil {
		return keys, recs
	}
	if n.nodeTy == cutNodeTy {
		return keys, recs
	}
	keys = append(keys, StoreKey(prefix, depth))
	recs = append(recs, encodeNode(n))
	if n.nodeTy == innerNodeTy {
		slot := depth / 8
		bit := byte(1) << (depth % 8)
		keys, recs = records(n.child0, depth+1, prefix, keys, recs)
		prefix[slot] |= bit
		keys, recs = records(n.child1, depth+1, prefix, keys, recs)
		prefix[slot] &^= bit
	}
	return keys, recs
}

// a record is an inner node's two child hashes, or a leaf's label and value.
func encodeNode(n *node) []byte {
	if n.nodeTy == innerNodeTy {
		b := make([]byte, 0, 1+2*cryptoffi.HashLen)
		b = append(b, innerNodeTag)
		b = marshal.WriteBytes(b, n.child0.getHash())
		return marshal.WriteBytes(b, n.child1.getHash())
	}
	std.Assert(n.nodeTy == leafNodeTy)
	b := make([]byte, 0, 1+cryptoffi.HashLen+uint64(len(n.val)))
	b = append(b, leafNodeTag)
	b = marshal.WriteBytes(b, n.label)
	return marshal.WriteBytes(b, n.val)
}

func decodeNode(rec []byte) (n *node, err bool) {
	tag, rem, err := safemarshal.ReadByte(rec)
	if err {
		return nil, true
	}

	if tag == innerNodeTag {
		h0, rem, err := safemarshal.ReadBytes(rem, cryptoffi.HashLen)
		if err {
			return nil, true
		}
		h1, rem, err := safemarshal.ReadBytes(rem, cryptoffi.HashLen)
		if err {
			return nil, true
		}
		if uint64(len(rem)) != 0 {
			return nil, true
		}
		inner := &node{nodeTy: innerNodeTy, child0: mkCut(h0), child1: mkCut(h1)}
		inner.hash = compInnerHash(h0, h1)
		return inner, false
	}

	if tag == leafNodeTag {
		label, val, err := safemarshal.ReadBytes(rem, cryptoffi.HashLen)
		if err {
			return nil, true
		}
		leaf := &node{nodeTy: leafNodeTy, label: label, val: val}
		leaf.hash = compLeafHash(label, val)
		return leaf, false
	}

	return nil, true
}
