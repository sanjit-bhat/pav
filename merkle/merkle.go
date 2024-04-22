package merkle

import (
	"github.com/goose-lang/std"
	"github.com/mit-pdos/secure-chat/cryptoHelpers"
	"github.com/mit-pdos/secure-chat/cryptoShim"
)

type Error = uint64
type ProofTy = bool

const (
	ErrNone      Error = 0
	ErrFound     Error = 1
	ErrNotFound  Error = 2
	ErrBadInput  Error = 3
	ErrPathProof Error = 4
	// Branch on a byte. 2 ** 8 (bits in byte) = 256.
	NumChildren    uint64 = 256
	EmptyNodeId    byte   = 0
	LeafNodeId     byte   = 1
	InteriorNodeId byte   = 2
	NonmembProofTy        = false
	MembProofTy           = true
)

func CopySlice(b1 []byte) []byte {
	b2 := make([]byte, len(b1))
	copy(b2, b1)
	return b2
}

// "keys" of the tree.
// We use term "Id" to differentiate this from the public keys that could be
// stored in the tree.
type Id = []byte

// "values" of the tree.
type Val = []byte

type Node struct {
	Val      Val
	hash     []byte
	Children []*Node
}

// Hash getter to support hashes of empty (nil) nodes.
func (n *Node) Hash() []byte {
	if n == nil {
		// Empty node.
		return cryptoShim.Hash([]byte{EmptyNodeId})
	}
	return n.hash
}

func (n *Node) DeepCopy() *Node {
	if n == nil {
		return nil
	}
	var n2 = &Node{}
	n2.Val = CopySlice(n.Val)
	n2.hash = CopySlice(n.hash)
	children := make([]*Node, len(n.Children))
	for i, c := range n.Children {
		children[i] = c.DeepCopy()
	}
	n2.Children = children
	return n2
}

func (n *Node) UpdateLeafHash() {
	var h cryptoHelpers.Hasher
	cryptoHelpers.HasherWrite(&h, n.Val)
	cryptoHelpers.HasherWrite(&h, []byte{LeafNodeId})
	n.hash = cryptoHelpers.HasherSum(h, nil)
}

// Assumes recursive child hashes are already up-to-date.
func (n *Node) UpdateInteriorHash() {
	var h cryptoHelpers.Hasher
	for _, n := range n.Children {
		cryptoHelpers.HasherWrite(&h, n.Hash())
	}
	cryptoHelpers.HasherWrite(&h, []byte{InteriorNodeId})
	n.hash = cryptoHelpers.HasherSum(h, nil)
}

// This node doesn't satisfy the invariant for any logical node.
// It'll be specialized after adding it to the tree.
func NewGenericNode() *Node {
	c := make([]*Node, NumChildren)
	return &Node{Val: nil, hash: nil, Children: c}
}

type Digest = []byte

// General proof object.
// Binds an id down the tree to a particular node hash.
type PathProof struct {
	Id          Id
	NodeHash    []byte
	Digest      Digest
	ChildHashes [][][]byte
}

type Proof = [][][]byte

func IsValidHashSl(data [][]byte) bool {
	var ok = true
	for _, hash := range data {
		if uint64(len(hash)) != cryptoShim.HashLen {
			ok = false
		}
	}
	return ok
}

func (p *PathProof) Check() Error {
	var err = ErrNone
	var currHash []byte = p.NodeHash
	proofLen := uint64(len(p.ChildHashes))
	// Goose doesn't support general loops, so re-write this way.
	// TODO: try writing with general loop syntax.
	var loopIdx = uint64(0)
	for ; loopIdx < proofLen; loopIdx++ {
		pathIdx := proofLen - 1 - loopIdx
		children := p.ChildHashes[pathIdx]
		if uint64(len(children)) != NumChildren-1 {
			err = ErrPathProof
			continue
		}
		if !IsValidHashSl(children) {
			err = ErrPathProof
			continue
		}
		pos := uint64(p.Id[pathIdx])
		before := children[:pos]
		after := children[pos:]

		var hr cryptoHelpers.Hasher
		cryptoHelpers.HasherWriteSl(&hr, before)
		cryptoHelpers.HasherWrite(&hr, currHash)
		cryptoHelpers.HasherWriteSl(&hr, after)
		cryptoHelpers.HasherWrite(&hr, []byte{InteriorNodeId})
		currHash = cryptoHelpers.HasherSum(hr, nil)
	}

	if err != ErrNone {
		return ErrPathProof
	}
	if !std.BytesEqual(currHash, p.Digest) {
		return ErrPathProof
	}
	return ErrNone
}

func getLeafNodeHash(val Val) []byte {
	var hr cryptoHelpers.Hasher
	cryptoHelpers.HasherWrite(&hr, val)
	cryptoHelpers.HasherWrite(&hr, []byte{LeafNodeId})
	return cryptoHelpers.HasherSum(hr, nil)
}

func getEmptyNodeHash() []byte {
	return cryptoShim.Hash([]byte{EmptyNodeId})
}

func CheckProof(proofTy ProofTy, proof Proof, id Id, val Val, digest Digest) Error {
	if uint64(len(proof)) > cryptoShim.HashLen {
		return ErrBadInput
	}
	if len(id) < len(proof) {
		return ErrBadInput
	}
	// For NonmembProof, have original id, so slice it down
	// to same sz as path.
	idPref := id[:len(proof)]
	var nodeHash []byte
	if proofTy == MembProofTy {
		nodeHash = getLeafNodeHash(val)
	} else {
		nodeHash = getEmptyNodeHash()
	}

	pathProof := &PathProof{
		Id:          idPref,
		NodeHash:    nodeHash,
		Digest:      digest,
		ChildHashes: proof,
	}
	return pathProof.Check()
}

// Having a separate Tree type makes the API more clear compared to if it
// was just a Node.
type Tree struct {
	Root *Node
}

func (t *Tree) DeepCopy() *Tree {
	return &Tree{Root: t.Root.DeepCopy()}
}

func (t *Tree) Digest() Digest {
	return t.Root.Hash()
}

func AppendNode2D(dst *[][]byte, src []*Node) {
	for _, sl := range src {
		*dst = append(*dst, CopySlice(sl.Hash()))
	}
}

func GetChildHashes(nodePath []*Node, id Id) [][][]byte {
	childHashes := make([][][]byte, len(nodePath)-1)
	for pathIdx := uint64(0); pathIdx < uint64(len(nodePath))-1; pathIdx++ {
		children := nodePath[pathIdx].Children
		pos := id[pathIdx]
		var proofChildren [][]byte
		AppendNode2D(&proofChildren, children[:pos])
		AppendNode2D(&proofChildren, children[pos+1:])
		childHashes[pathIdx] = proofChildren
	}
	return childHashes
}

// Get the maximal path corresponding to Id.
// If the full path to a leaf node doesn't exist,
// return the partial path that ends in an empty node.
func (t *Tree) GetPath(id Id) []*Node {
	var nodePath []*Node
	nodePath = append(nodePath, t.Root)
	if t.Root == nil {
		return nodePath
	}
	var stop = false
	for pathIdx := uint64(0); pathIdx < cryptoShim.HashLen && !stop; pathIdx++ {
		currNode := nodePath[pathIdx]
		pos := id[pathIdx]
		nextNode := currNode.Children[pos]
		nodePath = append(nodePath, nextNode)
		if nextNode == nil {
			stop = true
		}
	}
	return nodePath
}

func (t *Tree) GetPathAddNodes(id Id) []*Node {
	if t.Root == nil {
		t.Root = NewGenericNode()
	}
	var nodePath []*Node
	nodePath = append(nodePath, t.Root)
	for pathIdx := uint64(0); pathIdx < cryptoShim.HashLen; pathIdx++ {
		currNode := nodePath[pathIdx]
		pos := id[pathIdx]
		if currNode.Children[pos] == nil {
			currNode.Children[pos] = NewGenericNode()
		}
		nodePath = append(nodePath, currNode.Children[pos])
	}
	return nodePath
}

func (t *Tree) Put(id Id, val Val) (Digest, Proof, Error) {
	if uint64(len(id)) != cryptoShim.HashLen {
		return nil, nil, ErrBadInput
	}

	nodePath := t.GetPathAddNodes(id)
	nodePath[cryptoShim.HashLen].Val = val
	nodePath[cryptoShim.HashLen].UpdateLeafHash()
	// +1/-1 offsets for Goosable uint64 loop var.
	for pathIdx := cryptoShim.HashLen; pathIdx >= 1; pathIdx-- {
		nodePath[pathIdx-1].UpdateInteriorHash()
	}

	digest := CopySlice(nodePath[0].Hash())
	proof := GetChildHashes(nodePath, id)
	return digest, proof, ErrNone
}

// Return ProofTy vs. having sep funcs bc regardless, would want a proof.
func (t *Tree) Get(id Id) (Val, Digest, ProofTy, Proof, Error) {
	if uint64(len(id)) != cryptoShim.HashLen {
		return nil, nil, false, nil, ErrBadInput
	}
	nodePath := t.GetPath(id)
	lastNode := nodePath[uint64(len(nodePath))-1]

	digest := CopySlice(nodePath[0].Hash())
	proof := GetChildHashes(nodePath, id)
	if lastNode == nil {
		return nil, digest, NonmembProofTy, proof, ErrNone
	} else {
		val := CopySlice(lastNode.Val)
		return val, digest, MembProofTy, proof, ErrNone
	}
}
