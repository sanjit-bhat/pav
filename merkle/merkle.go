package merkle

import (
	"github.com/goose-lang/std"
	"github.com/mit-pdos/pav/cryptoffi"
	"github.com/tchajed/marshal"
)

const (
	// Branch on a byte. 2 ** 8 (bits in byte) = 256.
	numChildren         uint64 = 256
	hashesPerProofDepth uint64 = (numChildren - 1) * cryptoffi.HashLen
	emptyNodeTag        byte   = 0
	leafNodeTag         byte   = 1
	interiorNodeTag     byte   = 2
	NonmembProofTy      bool   = false
	MembProofTy         bool   = true
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
func (t *Tree) Put(label []byte, mapVal []byte) ([]byte, []byte, bool) {
	if uint64(len(label)) != cryptoffi.HashLen {
		return nil, nil, true
	}

	// make all interior nodes.
	var interiors = make([]*node, 0, cryptoffi.HashLen)
	if t.root == nil {
		t.root = newInteriorNode()
	}
	interiors = append(interiors, t.root)
	n := cryptoffi.HashLen - 1
	for depth := uint64(0); depth < n; depth++ {
		currNode := interiors[depth]

		// XXX: Converting to `uint64` for Goose, since it does not handle the
		// implicit conversion from uint8 to int when using `pos` as a slice
		// index.
		pos := uint64(label[depth])

		if currNode.children[pos] == nil {
			currNode.children[pos] = newInteriorNode()
		}
		interiors = append(interiors, currNode.children[pos])
	}

	// make leaf node with correct hash.
	lastInterior := interiors[cryptoffi.HashLen-1]
	// XXX: To deal with goose failing to handle the implicit conversion to int
	// when using as a slice index
	lastPos := uint64(label[cryptoffi.HashLen-1])
	lastInterior.children[lastPos] = &node{mapVal: mapVal, hash: compLeafNodeHash(mapVal)}

	// correct hashes of interior nodes, bubbling up.
	// +1/-1 offsets for Goosable uint64 loop var.
	var loopBuf = make([]byte, 0, numChildren*cryptoffi.HashLen+1)
	for depth := cryptoffi.HashLen; depth >= 1; depth-- {
		loopBuf = t.ctx.updInteriorHash(loopBuf, interiors[depth-1])
		loopBuf = loopBuf[:0]
	}

	dig := t.ctx.getHash(t.root)
	proof := t.ctx.getProof(interiors, label)
	return dig, proof, false
}

// Get returns the mapVal, digest, proofTy, proof, and error.
// return ProofTy vs. having sep funcs bc regardless, would want a proof.
func (t *Tree) Get(label []byte) ([]byte, []byte, bool, []byte, bool) {
	if uint64(len(label)) != cryptoffi.HashLen {
		return nil, nil, false, nil, true
	}
	nodePath := getPath(t.root, label)
	lastIdx := uint64(len(nodePath)) - 1
	lastNode := nodePath[lastIdx]
	dig := t.ctx.getHash(t.root)
	proof := t.ctx.getProof(nodePath[:lastIdx], label)
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

// CheckProof returns an error if the proof is invalid.
func CheckProof(proofTy bool, proof []byte, label []byte, mapVal []byte, dig []byte) bool {
	proofLen := uint64(len(proof))
	if proofLen%hashesPerProofDepth != 0 {
		return true
	}
	proofDepth := proofLen / hashesPerProofDepth
	if proofDepth > cryptoffi.HashLen {
		return true
	}
	if uint64(len(label)) != cryptoffi.HashLen {
		return true
	}
	// NonmembProof has original label. slice it down to match proof.
	labelPref := label[:proofDepth]
	var nodeHash []byte
	if proofTy {
		nodeHash = compLeafNodeHash(mapVal)
	} else {
		nodeHash = compEmptyNodeHash()
	}

	var loopErr = false
	var loopCurrHash []byte = nodeHash
	var loopBuf = make([]byte, 0, numChildren*cryptoffi.HashLen+1)
	var loopIdx = uint64(0)
	for ; loopIdx < proofDepth; loopIdx++ {
		depth := proofDepth - 1 - loopIdx
		begin := depth * hashesPerProofDepth
		middle := begin + uint64(labelPref[depth])*cryptoffi.HashLen
		end := (depth + 1) * hashesPerProofDepth

		loopBuf = marshal.WriteBytes(loopBuf, proof[begin:middle])
		loopBuf = marshal.WriteBytes(loopBuf, loopCurrHash)
		loopBuf = marshal.WriteBytes(loopBuf, proof[middle:end])
		loopBuf = append(loopBuf, interiorNodeTag)
		loopCurrHash = cryptoffi.Hash(loopBuf)
		loopBuf = loopBuf[:0]
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
	var b = make([]byte, 0, len(mapVal)+1)
	b = marshal.WriteBytes(b, mapVal)
	b = append(b, leafNodeTag)
	return cryptoffi.Hash(b)
}

// getHash getter to support hashes of empty (nil) nodes.
func (ctx *context) getHash(n *node) []byte {
	if n == nil {
		return ctx.emptyHash
	}
	return n.hash
}

// Assumes recursive child hashes are already up-to-date.
// uses and returns hash buf, to allow for its re-use.
func (ctx *context) updInteriorHash(b []byte, n *node) []byte {
	var b0 = b
	for _, child := range n.children {
		b0 = marshal.WriteBytes(b0, ctx.getHash(child))
	}
	b0 = append(b0, interiorNodeTag)
	n.hash = cryptoffi.Hash(b0)
	return b0
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
	for depth := uint64(0); depth < cryptoffi.HashLen && !isEmpty; depth++ {
		currNode := nodePath[depth]
		pos := label[depth]
		nextNode := currNode.children[pos]
		nodePath = append(nodePath, nextNode)
		if nextNode == nil {
			isEmpty = true
		}
	}
	return nodePath
}

func (ctx *context) getProof(interiors []*node, label []byte) []byte {
	interiorsLen := uint64(len(interiors))
	var proof = make([]byte, 0, interiorsLen*hashesPerProofDepth)
	for depth := uint64(0); depth < interiorsLen; depth++ {
		children := interiors[depth].children
		// convert to uint64 bc otherwise pos+1 might overflow.
		pos := uint64(label[depth])
		for _, n := range children[:pos] {
			proof = marshal.WriteBytes(proof, ctx.getHash(n))
		}
		for _, n := range children[pos+1:] {
			proof = marshal.WriteBytes(proof, ctx.getHash(n))
		}
	}
	return proof
}

func newInteriorNode() *node {
	c := make([]*node, numChildren)
	return &node{children: c}
}

func newCtx() *context {
	return &context{emptyHash: compEmptyNodeHash()}
}
