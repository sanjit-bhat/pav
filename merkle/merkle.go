package merkle

import (
	"github.com/mit-pdos/secure-chat/merkle/merkle_shim"
	"log"
)

const (
	ErrNone      uint64 = 0
	ErrFound     uint64 = 1
	ErrNotFound  uint64 = 2
	ErrBadInput  uint64 = 3
	ErrPathProof uint64 = 4
	HashLen      uint64 = 32
	// Branch on a byte. 2 ** 8 (bits in byte) = 256.
	NumChildren    uint64 = 256
	EmptyNodeId    byte   = 0
	LeafNodeId     byte   = 1
	InteriorNodeId byte   = 2
)

type Hasher []byte

func (h *Hasher) Write(b []byte) {
	for _, b := range b {
		*h = append(*h, b)
	}
}

func (h Hasher) Sum(b []byte) []byte {
	var b1 = b
	hash := merkle_shim.Hash(h)
	for _, byt := range hash {
		b1 = append(b1, byt)
	}
	return b1
}

func HashSlice2D(b [][]byte) []byte {
	var h Hasher
	for _, b1 := range b {
		h.Write(b1)
	}
	return h.Sum(nil)
}

func CopySlice(b1 []byte) []byte {
	b2 := make([]byte, len(b1))
	copy(b2, b1)
	return b2
}

func BytesEqual(b1, b2 []byte) bool {
	if len(b1) != len(b2) {
		return false
	}
	var isEq = true
	for i := uint64(0); i < uint64(len(b1)) && isEq; i++ {
		if b1[i] != b2[i] {
			isEq = false
		}
	}
	return isEq
}

// "keys" of the tree.
// We use term "Id" to differentiate this from the public keys that could be
// stored in the tree.
type Id []byte

// "values" of the tree.
type Val []byte

type Node struct {
	Val      Val
	hash     []byte
	Children []*Node
}

func (n *Node) Hash() []byte {
	if n == nil {
		// Empty node.
		return merkle_shim.Hash([]byte{EmptyNodeId})
	}
	return n.hash
}

func (n *Node) UpdateLeafHash() {
	var h Hasher
	h.Write(n.Val)
	h.Write([]byte{LeafNodeId})
	n.hash = h.Sum(nil)
}

// Assumes recursive child hashes are already up-to-date.
func (n *Node) UpdateInteriorHash() {
	var h Hasher
	for _, n := range n.Children {
		h.Write(n.Hash())
	}
	h.Write([]byte{InteriorNodeId})
	n.hash = h.Sum(nil)
}

// These nodes are neither interior nodes nor leaf nodes.
// They'll be specialized after adding them to the tree.
func NewGenericNode() *Node {
	var v Val
	c := make([]*Node, NumChildren)
	return &Node{Val: v, hash: nil, Children: c}
}

type Digest []byte

// General proof object.
// Binds an id down the tree to a particular node hash.
type PathProof struct {
	Id          Id
	NodeHash    []byte
	Digest      Digest
	ChildHashes [][][]byte
}

type MembProof [][][]byte

type NonmembProof [][][]byte

// TODO: rename to something better.
// TODO: not sure whether this re-use of the interior hash methods
// will actually help me.
func ProofInteriorHash(childHashes [][]byte) []byte {
	n := NewGenericNode()
	for i := uint64(0); i < NumChildren; i++ {
		child := &Node{}
		child.hash = childHashes[i]
		n.Children[i] = child
	}
	n.UpdateInteriorHash()
	return n.Hash()
}

func (p *PathProof) Check() uint64 {
	proofLen := uint64(len(p.Id))
	if proofLen == 0 {
		// Tree was empty node.
		if BytesEqual(p.NodeHash, p.Digest) {
			return ErrNone
		} else {
			return ErrPathProof
		}
	}

	// Check tree bottom.
	posBott := p.Id[proofLen-1]
	if !BytesEqual(p.NodeHash, p.ChildHashes[proofLen-1][posBott]) {
		return ErrPathProof
	}

	// Check tree interior.
	var err = ErrNone
	for pathIdx := proofLen - 1; pathIdx >= 1; pathIdx-- {
		interiorHash := ProofInteriorHash(p.ChildHashes[pathIdx])
		prevIdx := pathIdx - 1
		pos := p.Id[prevIdx]
		if !BytesEqual(interiorHash, p.ChildHashes[prevIdx][pos]) {
			err = ErrPathProof
		}
	}
	if err != ErrNone {
		return err
	}

	// Check tree top.
	digest := ProofInteriorHash(p.ChildHashes[0])
	if !BytesEqual(digest, p.Digest) {
		return ErrPathProof
	}
	return ErrNone
}

func (p MembProof) Check(id Id, val Val, digest Digest) uint64 {
	if uint64(len(id)) != HashLen {
		return ErrBadInput
	}
	if uint64(len(p)) != HashLen {
		return ErrBadInput
	}
	leaf := &Node{Val: val}
	leaf.UpdateLeafHash()
	pathProof := &PathProof{
		Id:          id,
		NodeHash:    leaf.Hash(),
		Digest:      digest,
		ChildHashes: p,
	}
	return pathProof.Check()
}

func (p NonmembProof) Check(id Id, digest Digest) uint64 {
	// An empty node can appear at any depth down the tree.
	if HashLen < uint64(len(p)) {
		return ErrBadInput
	}
	// After slicing, id will have same len as p.ChildHashes.
	// It now corresponds to the prefix path down the tree that contains
	// the empty node.
	if len(id) < len(p) {
		return ErrBadInput
	}
	idPref := CopySlice(id)[:len(p)]
	var empty *Node = nil
	pathProof := &PathProof{
		Id:          idPref,
		NodeHash:    empty.Hash(),
		Digest:      digest,
		ChildHashes: p,
	}
	return pathProof.Check()
}

// Having a separate Tree type makes the API more clear compared to if it
// was just a Node.
type Tree struct {
	Root *Node
}

func (t *Tree) Print() {
	var qCurr []*Node
	var qNext []*Node
	qCurr = append(qCurr, t.Root)
	for len(qCurr) > 0 {
		for len(qCurr) > 0 {
			top := qCurr[0]
			qCurr = qCurr[1:]

			if top == nil {
				log.Print("nil | ")
			} else {
				if top.Val != nil {
					log.Print(top.Hash(), top.Val, " | ")
				} else {
					log.Print(top.Hash(), " | ")
				}

				for _, child := range top.Children {
					qNext = append(qNext, child)
				}
			}
		}
		qCurr = qNext
		qNext = nil
		log.Println()
	}
}

func GetChildHashes(nodePath []*Node) [][][]byte {
	childHashes := make([][][]byte, len(nodePath))
	for pathIdx := uint64(0); pathIdx < uint64(len(nodePath)); pathIdx++ {
		treeChildren := nodePath[pathIdx].Children
		proofChildren := make([][]byte, NumChildren)
		childHashes[pathIdx] = proofChildren

		for childIdx := uint64(0); childIdx < NumChildren; childIdx++ {
			proofChildren[childIdx] = CopySlice(treeChildren[childIdx].Hash())
		}
	}
	return childHashes
}

// Get the maximal path corresponding to Id.
// If the full path to a leaf node doesn't exist,
// return the partial path that ends in an empty node,
// and set found to true.
func (t *Tree) GetPath(id Id) ([]*Node, bool) {
	var nodePath []*Node
	nodePath = append(nodePath, t.Root)
	if t.Root == nil {
		return nodePath, false
	}
	var found = true
	for pathIdx := uint64(0); pathIdx < HashLen && found; pathIdx++ {
		currNode := nodePath[pathIdx]
		pos := id[pathIdx]
		nextNode := currNode.Children[pos]
		nodePath = append(nodePath, nextNode)
		if nextNode == nil {
			found = false
		}
	}
	return nodePath, found
}

func (t *Tree) GetPathAddNodes(id Id) []*Node {
	if t.Root == nil {
		t.Root = NewGenericNode()
	}
	var nodePath []*Node
	nodePath = append(nodePath, t.Root)
	for pathIdx := uint64(0); pathIdx < HashLen; pathIdx++ {
		currNode := nodePath[pathIdx]
		pos := id[pathIdx]
		if currNode.Children[pos] == nil {
			currNode.Children[pos] = NewGenericNode()
		}
		nodePath = append(nodePath, currNode.Children[pos])
	}
	return nodePath
}

func (t *Tree) Put(id Id, v Val) (Digest, MembProof, uint64) {
	if uint64(len(id)) != HashLen {
		return nil, nil, ErrBadInput
	}

	nodePath := t.GetPathAddNodes(id)
	nodePath[HashLen].Val = v
	nodePath[HashLen].UpdateLeafHash()
	// +1/-1 offsets for Goosable uint64 loop var.
	for pathIdx := HashLen; pathIdx >= 1; pathIdx-- {
		nodePath[pathIdx-1].UpdateInteriorHash()
	}

	digest := CopySlice(nodePath[0].Hash())
	proof := GetChildHashes(nodePath[:HashLen])
	return digest, proof, ErrNone
}

func (t *Tree) Get(id Id) (Val, Digest, MembProof, uint64) {
	if uint64(len(id)) != HashLen {
		return nil, nil, nil, ErrBadInput
	}

	nodePath, found := t.GetPath(id)
	if !found {
		return nil, nil, nil, ErrNotFound
	}

	val := CopySlice(nodePath[HashLen].Val)
	digest := CopySlice(nodePath[0].Hash())
	proof := GetChildHashes(nodePath[:HashLen])
	return val, digest, proof, ErrNone
}

func (t *Tree) GetNil(id Id) (Digest, NonmembProof, uint64) {
	if uint64(len(id)) != HashLen {
		return nil, nil, ErrBadInput
	}

	nodePath, found := t.GetPath(id)
	if found {
		return nil, nil, ErrFound
	}

	digest := CopySlice(nodePath[0].Hash())
	// For incomplete paths, nodePath ends in nil.
	proof := GetChildHashes(nodePath[:len(nodePath)-1])
	return digest, proof, ErrNone
}
