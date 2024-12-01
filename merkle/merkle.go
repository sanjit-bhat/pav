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

type node struct {
	mapVal   []byte
	hash     []byte
	children []*node
}

// getHash getter to support hashes of empty (nil) nodes.
func (n *node) getHash() []byte {
	if n == nil {
		// Empty node.
		return cryptoffi.Hash([]byte{emptyNodeTag})
	}
	return n.hash
}

func (n *node) updateLeafHash() {
	var h cryptoutil.Hasher
	// TODO: tag needs to go before val?
	cryptoutil.HasherWrite(&h, n.mapVal)
	cryptoutil.HasherWrite(&h, []byte{leafNodeTag})
	n.hash = cryptoutil.HasherSum(h, nil)
}

// Assumes recursive child hashes are already up-to-date.
func (n *node) updateInteriorHash() {
	var h cryptoutil.Hasher
	for _, n := range n.children {
		cryptoutil.HasherWrite(&h, n.getHash())
	}
	cryptoutil.HasherWrite(&h, []byte{interiorNodeTag})
	n.hash = cryptoutil.HasherSum(h, nil)
}

// This node doesn't satisfy the invariant for any logical node.
// It'll be specialized after adding it to the tree.
func newGenericNode() *node {
	c := make([]*node, numChildren)
	return &node{children: c}
}

// General proof object.
// Binds a label down the tree to a particular node hash.
type pathProof struct {
	label       []byte
	nodeHash    []byte
	digest      []byte
	childHashes [][][]byte
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

func (p *pathProof) check() bool {
	var err = false
	var currHash []byte = p.nodeHash
	proofLen := uint64(len(p.childHashes))
	// Goose doesn't support general loops, so re-write this way.
	// TODO: try writing with general loop syntax.
	var loopIdx = uint64(0)
	for ; loopIdx < proofLen; loopIdx++ {
		pathIdx := proofLen - 1 - loopIdx
		children := p.childHashes[pathIdx]
		if uint64(len(children)) != numChildren-1 {
			err = true
			continue
		}
		if !isValidHashSl(children) {
			err = true
			continue
		}
		pos := uint64(p.label[pathIdx])
		before := children[:pos]
		after := children[pos:]

		var hr cryptoutil.Hasher
		cryptoutil.HasherWriteSl(&hr, before)
		cryptoutil.HasherWrite(&hr, currHash)
		cryptoutil.HasherWriteSl(&hr, after)
		cryptoutil.HasherWrite(&hr, []byte{interiorNodeTag})
		currHash = cryptoutil.HasherSum(hr, nil)
	}

	if err {
		return true
	}
	if !std.BytesEqual(currHash, p.digest) {
		return true
	}
	return false
}

func getLeafNodeHash(mapVal []byte) []byte {
	var hr cryptoutil.Hasher
	cryptoutil.HasherWrite(&hr, mapVal)
	cryptoutil.HasherWrite(&hr, []byte{leafNodeTag})
	return cryptoutil.HasherSum(hr, nil)
}

func getEmptyNodeHash() []byte {
	return cryptoffi.Hash([]byte{emptyNodeTag})
}

func CheckProof(proofTy bool, proof [][][]byte, label []byte, mapVal []byte, digest []byte) bool {
	if uint64(len(proof)) > cryptoffi.HashLen {
		return true
	}
	if len(label) < len(proof) {
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

	pathProof := &pathProof{
		label:       labelPref,
		nodeHash:    nodeHash,
		digest:      digest,
		childHashes: proof,
	}
	return pathProof.check()
}

// Having a separate Tree type makes the API more clear compared to if it
// was just a Node.
type Tree struct {
	root *node
}

func (t *Tree) Digest() []byte {
	return t.root.getHash()
}

func appendNode2D(dst *[][]byte, src []*node) {
	for _, sl := range src {
		*dst = append(*dst, std.BytesClone(sl.getHash()))
	}
}

func getChildHashes(nodePath []*node, label []byte) [][][]byte {
	childHashes := make([][][]byte, len(nodePath)-1)
	for pathIdx := uint64(0); pathIdx < uint64(len(nodePath))-1; pathIdx++ {
		children := nodePath[pathIdx].children
		// had a bug where w/o uint64, pos+1 would overflow byte.
		pos := uint64(label[pathIdx])
		var proofChildren [][]byte
		appendNode2D(&proofChildren, children[:pos])
		appendNode2D(&proofChildren, children[pos+1:])
		childHashes[pathIdx] = proofChildren
	}
	return childHashes
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

// Put returns the digest, proof, and error.
func (t *Tree) Put(label []byte, mapVal []byte) ([]byte, [][][]byte, bool) {
	if uint64(len(label)) != cryptoffi.HashLen {
		return nil, nil, true
	}

	nodePath := t.getPathAddNodes(label)
	nodePath[cryptoffi.HashLen].mapVal = mapVal
	nodePath[cryptoffi.HashLen].updateLeafHash()
	// +1/-1 offsets for Goosable uint64 loop var.
	for pathIdx := cryptoffi.HashLen; pathIdx >= 1; pathIdx-- {
		nodePath[pathIdx-1].updateInteriorHash()
	}

	digest := std.BytesClone(nodePath[0].getHash())
	proof := getChildHashes(nodePath, label)
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

	digest := std.BytesClone(nodePath[0].getHash())
	proof := getChildHashes(nodePath, label)
	if lastNode == nil {
		return nil, digest, NonmembProofTy, proof, false
	} else {
		val := std.BytesClone(lastNode.mapVal)
		return val, digest, MembProofTy, proof, false
	}
}
