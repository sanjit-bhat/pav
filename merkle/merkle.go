package merkle

import (
	"github.com/goose-lang/std"
	"github.com/mit-pdos/pav/cryptoffi"
	"github.com/mit-pdos/pav/cryptoutil"
)

const (
	// Branch on a byte. 2 ** 8 (bits in byte) = 256.
	numChildren     uint64 = 256
	emptyNodeTag    byte   = 0
	leafNodeTag     byte   = 1
	interiorNodeTag byte   = 2
	NonmembProofTy  bool   = false
	MembProofTy     bool   = true
)

type Tree struct {
	ctx  *context
	root *node
}

type node struct {
	mapVal   []byte
	hash     []byte
	children []*node
}

// context is a result of:
// 1) for performance reasons, wanting to pre-compute the empty hash.
// 2) requiring that all hashes come from program steps.
// 3) goose not having init() support.
type context struct {
	emptyHash []byte
}

func (t *Tree) Digest() []byte {
	return t.ctx.getHash(t.root)
}

// Put returns the digest, proof, and error.
func (t *Tree) Put(label []byte, mapVal []byte) ([]byte, [][][]byte, bool) {
	if uint64(len(label)) != cryptoffi.HashLen {
		return nil, nil, true
	}

	nodePath := t.getPathAddNodes(label)
	nodePath[cryptoffi.HashLen].mapVal = mapVal
	nodePath[cryptoffi.HashLen].hash = getLeafNodeHash(mapVal)
	// +1/-1 offsets for Goosable uint64 loop var.
	for pathIdx := cryptoffi.HashLen; pathIdx >= 1; pathIdx-- {
		t.ctx.updateInteriorHash(nodePath[pathIdx-1])
	}

	digest := t.ctx.getHash(nodePath[0])
	proof := t.ctx.getChildHashes(nodePath, label)
	return digest, proof, false
}

// Get returns the mapVal, digest, proofTy, proof, and error.
// return ProofTy vs. having sep funcs bc regardless, would want a proof.
func (t *Tree) Get(label []byte) ([]byte, []byte, bool, [][][]byte, bool) {
	if uint64(len(label)) != cryptoffi.HashLen {
		return nil, nil, false, nil, true
	}
	nodePath := t.getPath(label)
	lastNode := nodePath[uint64(len(nodePath))-1]

	digest := t.ctx.getHash(nodePath[0])
	proof := t.ctx.getChildHashes(nodePath, label)
	if lastNode == nil {
		return nil, digest, NonmembProofTy, proof, false
	} else {
		val := lastNode.mapVal
		return val, digest, MembProofTy, proof, false
	}
}

func NewTree() *Tree {
	return &Tree{ctx: newCtx()}
}

func CheckProof(proofTy bool, proof [][][]byte, label []byte, mapVal []byte, digest []byte) bool {
	proofLen := uint64(len(proof))
	if proofLen > cryptoffi.HashLen {
		return true
	}
	if uint64(len(label)) < proofLen {
		return true
	}
	// For NonmembProof, have original label, so slice it down
	// to same sz as path.
	labelPref := label[:len(proof)]
	var nodeHash []byte
	if proofTy {
		nodeHash = getLeafNodeHash(mapVal)
	} else {
		nodeHash = getEmptyNodeHash()
	}

	var loopErr = false
	var loopCurrHash []byte = nodeHash
	var loopIdx = uint64(0)
	for ; loopIdx < proofLen; loopIdx++ {
		pathIdx := proofLen - 1 - loopIdx
		children := proof[pathIdx]
		if uint64(len(children)) != numChildren-1 {
			loopErr = true
			continue
		}
		if !isValidHashSl(children) {
			loopErr = true
			continue
		}
		pos := uint64(labelPref[pathIdx])
		before := children[:pos]
		after := children[pos:]

		var hr cryptoutil.Hasher
		cryptoutil.HasherWriteSl(&hr, before)
		cryptoutil.HasherWrite(&hr, loopCurrHash)
		cryptoutil.HasherWriteSl(&hr, after)
		cryptoutil.HasherWrite(&hr, []byte{interiorNodeTag})
		loopCurrHash = cryptoutil.HasherSum(hr, nil)
	}

	if loopErr {
		return true
	}
	if !std.BytesEqual(loopCurrHash, digest) {
		return true
	}
	return false
}

func getEmptyNodeHash() []byte {
	return cryptoffi.Hash([]byte{emptyNodeTag})
}

func getLeafNodeHash(mapVal []byte) []byte {
	var hr cryptoutil.Hasher
	cryptoutil.HasherWrite(&hr, mapVal)
	cryptoutil.HasherWrite(&hr, []byte{leafNodeTag})
	return cryptoutil.HasherSum(hr, nil)
}

func newCtx() *context {
	return &context{emptyHash: getEmptyNodeHash()}
}

// getHash getter to support hashes of empty (nil) nodes.
func (ctx *context) getHash(n *node) []byte {
	if n == nil {
		return ctx.emptyHash
	}
	return n.hash
}

// Assumes recursive child hashes are already up-to-date.
func (ctx *context) updateInteriorHash(n *node) {
	var h cryptoutil.Hasher
	for _, child := range n.children {
		cryptoutil.HasherWrite(&h, ctx.getHash(child))
	}
	cryptoutil.HasherWrite(&h, []byte{interiorNodeTag})
	n.hash = cryptoutil.HasherSum(h, nil)
}

// Get the maximal path corresponding to label.
// If the full path to a leaf node doesn't exist,
// return the partial path that ends in an empty node.
func (t *Tree) getPath(label []byte) []*node {
	var nodePath []*node
	nodePath = append(nodePath, t.root)
	if t.root == nil {
		return nodePath
	}
	var stop = false
	for pathIdx := uint64(0); pathIdx < cryptoffi.HashLen && !stop; pathIdx++ {
		currNode := nodePath[pathIdx]
		pos := label[pathIdx]
		nextNode := currNode.children[pos]
		nodePath = append(nodePath, nextNode)
		if nextNode == nil {
			stop = true
		}
	}
	return nodePath
}

// This node doesn't satisfy the invariant for any logical node.
// It'll be specialized after adding it to the tree.
func newGenericNode() *node {
	c := make([]*node, numChildren)
	return &node{children: c}
}

func (t *Tree) getPathAddNodes(label []byte) []*node {
	if t.root == nil {
		t.root = newGenericNode()
	}
	var nodePath []*node
	nodePath = append(nodePath, t.root)
	for pathIdx := uint64(0); pathIdx < cryptoffi.HashLen; pathIdx++ {
		currNode := nodePath[pathIdx]
		pos := uint64(label[pathIdx])
		if currNode.children[pos] == nil {
			currNode.children[pos] = newGenericNode()
		}
		nodePath = append(nodePath, currNode.children[pos])
	}
	return nodePath
}

func (ctx *context) getChildHashes(nodePath []*node, label []byte) [][][]byte {
	childHashes := make([][][]byte, 0, len(nodePath)-1)
	for pathIdx := uint64(0); pathIdx < uint64(len(nodePath))-1; pathIdx++ {
		children := nodePath[pathIdx].children
		// had a bug where w/o uint64, pos+1 would overflow byte.
		pos := uint64(label[pathIdx])
		proofChildren := make([][]byte, 0, numChildren-1)
		ctx.appendNode2D(&proofChildren, children[:pos])
		ctx.appendNode2D(&proofChildren, children[pos+1:])
		childHashes = append(childHashes, proofChildren)
	}
	return childHashes
}

func (ctx *context) appendNode2D(dst *[][]byte, src []*node) {
	for _, n := range src {
		*dst = append(*dst, ctx.getHash(n))
	}
}

func isValidHashSl(data [][]byte) bool {
	var ok = true
	for _, hash := range data {
		if uint64(len(hash)) != cryptoffi.HashLen {
			ok = false
		}
	}
	return ok
}
