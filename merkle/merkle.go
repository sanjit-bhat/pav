package merkle

import (
	"github.com/goose-lang/std"
	"github.com/mit-pdos/pav/cryptoffi"
	"github.com/mit-pdos/pav/cryptoutil"
)

type errorTy = bool
type ProofTy = bool

const (
	errNone errorTy = false
	errSome errorTy = true
	// Branch on a byte. 2 ** 8 (bits in byte) = 256.
	numChildren     uint64  = 256
	emptyNodeTag    byte    = 0
	leafNodeTag     byte    = 1
	interiorNodeTag byte    = 2
	NonmembProofTy  ProofTy = false
	MembProofTy     ProofTy = true
)

// "keys" of the tree.
// We use term "Id" to differentiate this from the public keys that could be
// stored in the tree.
type Id = []byte

// "values" of the tree.
type Val = []byte

type node struct {
	val      Val
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

func (n *node) deepCopy() *node {
	if n == nil {
		return nil
	}
	var n2 = &node{}
	n2.val = std.BytesClone(n.val)
	n2.hash = std.BytesClone(n.hash)
	children := make([]*node, len(n.children))
	for i, c := range n.children {
		children[i] = c.deepCopy()
	}
	n2.children = children
	return n2
}

func (n *node) updateLeafHash() {
	var h cryptoutil.Hasher
	// TODO: tag needs to go before val?
	cryptoutil.HasherWrite(&h, n.val)
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

type Digest = []byte

// General proof object.
// Binds an id down the tree to a particular node hash.
type pathProof struct {
	id          Id
	nodeHash    []byte
	digest      Digest
	childHashes [][][]byte
}

type Proof = [][][]byte

func isValidHashSl(data [][]byte) bool {
	var ok = true
	for _, hash := range data {
		if uint64(len(hash)) != cryptoffi.HashLen {
			ok = false
		}
	}
	return ok
}

func (p *pathProof) check() errorTy {
	var err = errNone
	var currHash []byte = p.nodeHash
	proofLen := uint64(len(p.childHashes))
	// Goose doesn't support general loops, so re-write this way.
	// TODO: try writing with general loop syntax.
	var loopIdx = uint64(0)
	for ; loopIdx < proofLen; loopIdx++ {
		pathIdx := proofLen - 1 - loopIdx
		children := p.childHashes[pathIdx]
		if uint64(len(children)) != numChildren-1 {
			err = errSome
			continue
		}
		if !isValidHashSl(children) {
			err = errSome
			continue
		}
		pos := uint64(p.id[pathIdx])
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
		return errSome
	}
	if !std.BytesEqual(currHash, p.digest) {
		return errSome
	}
	return errNone
}

func getLeafNodeHash(val Val) []byte {
	var hr cryptoutil.Hasher
	cryptoutil.HasherWrite(&hr, val)
	cryptoutil.HasherWrite(&hr, []byte{leafNodeTag})
	return cryptoutil.HasherSum(hr, nil)
}

func getEmptyNodeHash() []byte {
	return cryptoffi.Hash([]byte{emptyNodeTag})
}

func CheckProof(proofTy ProofTy, proof Proof, id Id, val Val, digest Digest) errorTy {
	if uint64(len(proof)) > cryptoffi.HashLen {
		return errSome
	}
	if len(id) < len(proof) {
		return errSome
	}
	// For NonmembProof, have original id, so slice it down
	// to same sz as path.
	idPref := id[:len(proof)]
	var nodeHash []byte
	if proofTy {
		nodeHash = getLeafNodeHash(val)
	} else {
		nodeHash = getEmptyNodeHash()
	}

	pathProof := &pathProof{
		id:          idPref,
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

func (t *Tree) DeepCopy() *Tree {
	return &Tree{root: t.root.deepCopy()}
}

func (t *Tree) Digest() Digest {
	return t.root.getHash()
}

func appendNode2D(dst *[][]byte, src []*node) {
	for _, sl := range src {
		*dst = append(*dst, std.BytesClone(sl.getHash()))
	}
}

func getChildHashes(nodePath []*node, id Id) [][][]byte {
	childHashes := make([][][]byte, len(nodePath)-1)
	for pathIdx := uint64(0); pathIdx < uint64(len(nodePath))-1; pathIdx++ {
		children := nodePath[pathIdx].children
		// had a bug where w/o uint64, pos+1 would overflow byte.
		pos := uint64(id[pathIdx])
		var proofChildren [][]byte
		appendNode2D(&proofChildren, children[:pos])
		appendNode2D(&proofChildren, children[pos+1:])
		childHashes[pathIdx] = proofChildren
	}
	return childHashes
}

// Get the maximal path corresponding to Id.
// If the full path to a leaf node doesn't exist,
// return the partial path that ends in an empty node.
func (t *Tree) getPath(id Id) []*node {
	var nodePath []*node
	nodePath = append(nodePath, t.root)
	if t.root == nil {
		return nodePath
	}
	var stop = false
	for pathIdx := uint64(0); pathIdx < cryptoffi.HashLen && !stop; pathIdx++ {
		currNode := nodePath[pathIdx]
		pos := id[pathIdx]
		nextNode := currNode.children[pos]
		nodePath = append(nodePath, nextNode)
		if nextNode == nil {
			stop = true
		}
	}
	return nodePath
}

func (t *Tree) getPathAddNodes(id Id) []*node {
	if t.root == nil {
		t.root = newGenericNode()
	}
	var nodePath []*node
	nodePath = append(nodePath, t.root)
	for pathIdx := uint64(0); pathIdx < cryptoffi.HashLen; pathIdx++ {
		currNode := nodePath[pathIdx]
		pos := id[pathIdx]
		if currNode.children[pos] == nil {
			currNode.children[pos] = newGenericNode()
		}
		nodePath = append(nodePath, currNode.children[pos])
	}
	return nodePath
}

func (t *Tree) Put(id Id, val Val) (Digest, Proof, errorTy) {
	if uint64(len(id)) != cryptoffi.HashLen {
		return nil, nil, errSome
	}

	nodePath := t.getPathAddNodes(id)
	nodePath[cryptoffi.HashLen].val = val
	nodePath[cryptoffi.HashLen].updateLeafHash()
	// +1/-1 offsets for Goosable uint64 loop var.
	for pathIdx := cryptoffi.HashLen; pathIdx >= 1; pathIdx-- {
		nodePath[pathIdx-1].updateInteriorHash()
	}

	digest := std.BytesClone(nodePath[0].getHash())
	proof := getChildHashes(nodePath, id)
	return digest, proof, errNone
}

// Goose doesn't support returning more than 4 vars.
type GetReply struct {
	Val     Val
	Digest  Digest
	ProofTy ProofTy
	Proof   Proof
	Error   errorTy
}

// Return ProofTy vs. having sep funcs bc regardless, would want a proof.
func (t *Tree) Get(id Id) *GetReply {
	errReply := &GetReply{}
	if uint64(len(id)) != cryptoffi.HashLen {
		errReply.Error = errSome
		return errReply
	}
	nodePath := t.getPath(id)
	lastNode := nodePath[uint64(len(nodePath))-1]

	digest := std.BytesClone(nodePath[0].getHash())
	proof := getChildHashes(nodePath, id)
	if lastNode == nil {
		return &GetReply{Digest: digest, ProofTy: NonmembProofTy,
			Proof: proof, Error: errNone}
	} else {
		val := std.BytesClone(lastNode.val)
		return &GetReply{Val: val, Digest: digest, ProofTy: MembProofTy,
			Proof: proof, Error: errNone}
	}
}
