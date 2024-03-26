package merkle

import (
	"github.com/goose-lang/std"
	"github.com/mit-pdos/secure-chat/merkle/merkle_ffi"
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

type Hasher = []byte

// Goose doesn't support non-struct types that well, so until that exists,
// use type aliases and non-method funcs.
func HasherWrite(h *Hasher, b []byte) {
	for _, b := range b {
		*h = append(*h, b)
	}
}

func HasherSum(h Hasher, b []byte) []byte {
	var b1 = b
	hash := merkle_ffi.Hash(h)
	for _, byt := range hash {
		b1 = append(b1, byt)
	}
	return b1
}

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

func (n *Node) Hash() []byte {
	if n == nil {
		// Empty node.
		return merkle_ffi.Hash([]byte{EmptyNodeId})
	}
	return n.hash
}

func (n *Node) UpdateLeafHash() {
	var h Hasher
	HasherWrite(&h, n.Val)
	HasherWrite(&h, []byte{LeafNodeId})
	n.hash = HasherSum(h, nil)
}

// Assumes recursive child hashes are already up-to-date.
func (n *Node) UpdateInteriorHash() {
	var h Hasher
	for _, n := range n.Children {
		HasherWrite(&h, n.Hash())
	}
	HasherWrite(&h, []byte{InteriorNodeId})
	n.hash = HasherSum(h, nil)
}

// These nodes are neither interior nodes nor leaf nodes.
// They'll be specialized after adding them to the tree.
func NewGenericNode() *Node {
	var v Val
	c := make([]*Node, NumChildren)
	return &Node{Val: v, hash: nil, Children: c}
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

type MembProof = [][][]byte

type NonmembProof = [][][]byte

func (p *PathProof) Check() uint64 {
	var currHash []byte = p.NodeHash
	proofLen := len(p.ChildHashes)
	var err = ErrNone

	for _, children := range p.ChildHashes {
		if uint64(len(children)) != NumChildren-1 {
			err = ErrPathProof
		}
	}
	if err != ErrNone {
		return err
	}

	// +1/-1 offsets for Goosable uint64 loop var.
	for pathIdx := uint64(proofLen); pathIdx >= 1; pathIdx-- {
		pos := uint64(p.Id[pathIdx-1])
		children := p.ChildHashes[pathIdx-1]
		var hr Hasher

		for beforeIdx := uint64(0); beforeIdx < pos; beforeIdx++ {
			HasherWrite(&hr, children[beforeIdx])
		}
		HasherWrite(&hr, currHash)
		for afterIdx := pos; afterIdx < NumChildren-1; afterIdx++ {
			HasherWrite(&hr, children[afterIdx])
		}
		HasherWrite(&hr, []byte{InteriorNodeId})

		currHash = HasherSum(hr, nil)
	}

	if !std.BytesEqual(currHash, p.Digest) {
		return ErrPathProof
	}
	return ErrNone
}

func MembProofCheck(proof MembProof, id Id, val Val, digest Digest) uint64 {
	if uint64(len(id)) != HashLen {
		return ErrBadInput
	}
	if uint64(len(proof)) != HashLen {
		return ErrBadInput
	}
	var hr Hasher
	HasherWrite(&hr, val)
	HasherWrite(&hr, []byte{LeafNodeId})
	pathProof := &PathProof{
		Id:          id,
		NodeHash:    HasherSum(hr, nil),
		Digest:      digest,
		ChildHashes: proof,
	}
	return pathProof.Check()
}

func NonmembProofCheck(proof NonmembProof, id Id, digest Digest) uint64 {
	// An empty node can appear at any depth down the tree.
	if HashLen < uint64(len(proof)) {
		return ErrBadInput
	}
	// After slicing, id will have same len as p.ChildHashes.
	// It now corresponds to the prefix path down the tree that contains
	// the empty node.
	if len(id) < len(proof) {
		return ErrBadInput
	}
	idPref := CopySlice(id)[:len(proof)]
	var hr Hasher
	HasherWrite(&hr, []byte{EmptyNodeId})
	pathProof := &PathProof{
		Id:          idPref,
		NodeHash:    HasherSum(hr, nil),
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

func GetChildHashes(nodePath []*Node, id Id) [][][]byte {
	childHashes := make([][][]byte, len(nodePath)-1)
	for pathIdx := uint64(0); pathIdx < uint64(len(nodePath))-1; pathIdx++ {
		children := nodePath[pathIdx].Children
		pos := id[pathIdx]
		proofChildren := make([][]byte, NumChildren-1)
		childHashes[pathIdx] = proofChildren

		for beforeIdx := uint64(0); beforeIdx < uint64(pos); beforeIdx++ {
			proofChildren[beforeIdx] = CopySlice(children[beforeIdx].Hash())
		}
		for afterIdx := uint64(pos) + 1; afterIdx < NumChildren; afterIdx++ {
			proofChildren[afterIdx-1] = CopySlice(children[afterIdx].Hash())
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
	proof := GetChildHashes(nodePath, id)
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
	proof := GetChildHashes(nodePath, id)
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
	proof := GetChildHashes(nodePath, id)
	return digest, proof, ErrNone
}
