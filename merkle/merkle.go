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

	// make all interior nodes.
	var interiors = make([]*node, 0, cryptoffi.HashLen)
	if t.root == nil {
		t.root = newInteriorNode()
	}
	interiors = append(interiors, t.root)
	for pathIdx := uint64(0); pathIdx < cryptoffi.HashLen-1; pathIdx++ {
		currNode := interiors[pathIdx]
		pos := uint64(label[pathIdx])
		if currNode.children[pos] == nil {
			currNode.children[pos] = newInteriorNode()
		}
		interiors = append(interiors, currNode.children[pos])
	}

	// make leaf node with correct hash.
	lastInterior := interiors[cryptoffi.HashLen-1]
	lastPos := label[cryptoffi.HashLen-1]
	lastInterior.children[lastPos] = &node{mapVal: mapVal, hash: compLeafNodeHash(mapVal)}

	// correct hashes of interior nodes, bubbling up.
	// +1/-1 offsets for Goosable uint64 loop var.
	for pathIdx := cryptoffi.HashLen; pathIdx >= 1; pathIdx-- {
		t.ctx.updInteriorHash(interiors[pathIdx-1])
	}

	dig := t.ctx.getHash(t.root)
	proof := t.ctx.getChildHashes(interiors, label)
	return dig, proof, false
}

// Get returns the mapVal, digest, proofTy, proof, and error.
// return ProofTy vs. having sep funcs bc regardless, would want a proof.
func (t *Tree) Get(label []byte) ([]byte, []byte, bool, [][][]byte, bool) {
	if uint64(len(label)) != cryptoffi.HashLen {
		return nil, nil, false, nil, true
	}
	nodePath := getPath(t.root, label)
	lastIdx := uint64(len(nodePath)) - 1
	lastNode := nodePath[lastIdx]
	dig := t.ctx.getHash(t.root)
	proof := t.ctx.getChildHashes(nodePath[:lastIdx], label)
	if lastNode == nil {
		return nil, dig, NonmembProofTy, proof, false
	} else {
		val := lastNode.mapVal
		return val, dig, MembProofTy, proof, false
	}
}

func NewTree() *Tree {
	return &Tree{ctx: newCtx()}
}

func CheckProof(proofTy bool, proof [][][]byte, label []byte, mapVal []byte, dig []byte) bool {
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
		nodeHash = compLeafNodeHash(mapVal)
	} else {
		nodeHash = compEmptyNodeHash()
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
	if !std.BytesEqual(loopCurrHash, dig) {
		return true
	}
	return false
}

func compEmptyNodeHash() []byte {
	return cryptoffi.Hash([]byte{emptyNodeTag})
}

func compLeafNodeHash(mapVal []byte) []byte {
	var hr cryptoutil.Hasher
	cryptoutil.HasherWrite(&hr, mapVal)
	cryptoutil.HasherWrite(&hr, []byte{leafNodeTag})
	return cryptoutil.HasherSum(hr, nil)
}

func newCtx() *context {
	return &context{emptyHash: compEmptyNodeHash()}
}

// getHash getter to support hashes of empty (nil) nodes.
func (ctx *context) getHash(n *node) []byte {
	if n == nil {
		return ctx.emptyHash
	}
	return n.hash
}

// Assumes recursive child hashes are already up-to-date.
func (ctx *context) updInteriorHash(n *node) {
	var h cryptoutil.Hasher
	for _, child := range n.children {
		cryptoutil.HasherWrite(&h, ctx.getHash(child))
	}
	cryptoutil.HasherWrite(&h, []byte{interiorNodeTag})
	n.hash = cryptoutil.HasherSum(h, nil)
}

// getPath fetches the maximal path to label, including the leaf node.
// if the path doesn't exist, it terminates in an empty node.
func getPath(root *node, label []byte) []*node {
	var nodePath []*node
	nodePath = append(nodePath, root)
	if root == nil {
		return nodePath
	}
	var isEmpty = false
	for pathIdx := uint64(0); pathIdx < cryptoffi.HashLen && !isEmpty; pathIdx++ {
		currNode := nodePath[pathIdx]
		pos := label[pathIdx]
		nextNode := currNode.children[pos]
		nodePath = append(nodePath, nextNode)
		if nextNode == nil {
			isEmpty = true
		}
	}
	return nodePath
}

func newInteriorNode() *node {
	c := make([]*node, numChildren)
	return &node{children: c}
}

func (ctx *context) getChildHashes(interiors []*node, label []byte) [][][]byte {
	var childHashes = make([][][]byte, 0, len(interiors))
	for pathIdx := uint64(0); pathIdx < uint64(len(interiors)); pathIdx++ {
		children := interiors[pathIdx].children
		// had a bug where w/o uint64, pos+1 would overflow byte.
		pos := uint64(label[pathIdx])
		var proofChildren = make([][]byte, 0, numChildren-1)
		ctx.appNode2D(&proofChildren, children[:pos])
		ctx.appNode2D(&proofChildren, children[pos+1:])
		childHashes = append(childHashes, proofChildren)
	}
	return childHashes
}

func (ctx *context) appNode2D(dst *[][]byte, src []*node) {
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
