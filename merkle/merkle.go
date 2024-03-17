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
	NumChildren uint64 = 256
)

type Hasher struct {
	B []byte
}

func NewHasher() *Hasher {
	return &Hasher{}
}

func (h *Hasher) Write(b []byte) {
	for _, b := range b {
		h.B = append(h.B, b)
	}
}

func (h *Hasher) Sum(b []byte) []byte {
	var b1 = b
	hash := merkle_shim.Hash(h.B)
	for _, byt := range hash {
		b1 = append(b, byt)
	}
	return b1
}

func HashSlice2D(b [][]byte) []byte {
	h := NewHasher()
	for _, b1 := range b {
		h.Write(b1)
	}
	return h.Sum(nil)
}

func HashNodes(nodeSl []*Node) []byte {
	h := NewHasher()
	for _, n := range nodeSl {
		h.Write(n.Hash())
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
	for i, b := range b1 {
		if b != b2[i] {
			isEq = false
		}
	}
	return isEq
}

// "keys" of the tree.
// We use "Id" to differentiate this from the public keys that could be stored
// in the tree.
type Id struct {
	B []byte
}

// "vals" of the tree.
type Val struct {
	B []byte
}

type Node struct {
	Val      *Val
	hash     []byte
	Children []*Node
}

func (n *Node) Hash() []byte {
	if n == nil {
		return merkle_shim.Hash(nil)
	}
	return n.hash
}

func NewGenericNode() *Node {
	var v *Val
	c := make([]*Node, NumChildren)
	return &Node{Val: v, hash: nil, Children: c}
}

type Digest struct {
	B []byte
}

// General proof object.
// Binds an id down the tree to a particular node hash.
type PathProof struct {
	Id          *Id
	NodeHash    []byte
	Digest      *Digest
	ChildHashes [][][]byte
}

type MembProof struct {
	ChildHashes [][][]byte
}

type NonmembProof struct {
	ChildHashes [][][]byte
}

func (p *PathProof) Check() uint64 {
	proofLen := uint64(len(p.Id.B))
	posBott := p.Id.B[proofLen-1]
	if !BytesEqual(p.NodeHash, p.ChildHashes[proofLen-1][posBott]) {
		return ErrPathProof
	}

	var err = ErrNone
	for pathIdx := proofLen - 1; pathIdx >= 1; pathIdx-- {
		hChildren := HashSlice2D(p.ChildHashes[pathIdx])
		prevIdx := pathIdx - 1
		pos := p.Id.B[prevIdx]
		if !BytesEqual(hChildren, p.ChildHashes[prevIdx][pos]) {
			err = ErrPathProof
		}
	}
	if err != ErrNone {
		return err
	}

	digest := HashSlice2D(p.ChildHashes[0])
	if !BytesEqual(digest, p.Digest.B) {
		return ErrPathProof
	}
	return ErrNone
}

func (p *MembProof) Check(id *Id, val *Val, digest *Digest) uint64 {
	if uint64(len(id.B)) != HashLen {
		return ErrBadInput
	}
	if uint64(len(p.ChildHashes)) != HashLen {
		return ErrBadInput
	}
	pathProof := &PathProof{
		Id:          id,
		NodeHash:    merkle_shim.Hash(val.B),
		Digest:      digest,
		ChildHashes: p.ChildHashes,
	}
	return pathProof.Check()
}

func (p *NonmembProof) Check(id *Id, digest *Digest) uint64 {
	if HashLen <= uint64(len(p.ChildHashes)) {
		return ErrBadInput
	}
	// After slicing (which panics if id is too small),
	// id will have the same len as p.ChildHashes.
	// It now corresponds to the prefix path down the tree that contains
	// the nil value.
	idPref := &Id{B: CopySlice(id.B)[:len(p.ChildHashes)]}
	pathProof := &PathProof{
		Id:          idPref,
		NodeHash:    merkle_shim.Hash(nil),
		Digest:      digest,
		ChildHashes: p.ChildHashes,
	}
	return pathProof.Check()
}

// Assumes recursive child hashes are already up-to-date.
func (n *Node) UpdateHash(depth uint64) {
	if depth == HashLen {
		// Leaf node.
		n.hash = merkle_shim.Hash(n.Val.B)
	} else {
		// Interior node.
		n.hash = HashNodes(n.Children)
	}
}

type Tree struct {
	Root *Node
}

func NewTree() *Tree {
	n := &Node{}
	n.Children = make([]*Node, NumChildren)
	n.UpdateHash(0)
	return &Tree{Root: n}
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
					log.Print(top.Hash(), top.Val.B, " | ")
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

func (t *Tree) WalkTree(id *Id) ([]*Node, bool) {
	var nodePath []*Node
	nodePath = append(nodePath, t.Root)
	var found = true
	for pathIdx := uint64(0); pathIdx < HashLen && found; pathIdx++ {
		currNode := nodePath[pathIdx]
		pos := id.B[pathIdx]
		if currNode.Children[pos] == nil {
			found = false
		} else {
			nodePath = append(nodePath, currNode.Children[pos])
		}
	}
	return nodePath, found
}

func (t *Tree) WalkTreeAddLinks(id *Id) []*Node {
	var nodePath []*Node
	nodePath = append(nodePath, t.Root)
	for pathIdx := uint64(0); pathIdx < HashLen; pathIdx++ {
		currNode := nodePath[pathIdx]
		pos := id.B[pathIdx]
		if currNode.Children[pos] == nil {
			currNode.Children[pos] = NewGenericNode()
		}
		nodePath = append(nodePath, currNode.Children[pos])
	}
	return nodePath
}

func (t *Tree) Put(id *Id, v *Val) (*Digest, *MembProof, uint64) {
	if uint64(len(id.B)) != HashLen {
		return nil, nil, ErrBadInput
	}

	nodePath := t.WalkTreeAddLinks(id)
	nodePath[HashLen].Val = v
	// +1/-1 offsets for Goosable uint64 loop var.
	for pathIdx := HashLen + 1; pathIdx >= 1; pathIdx-- {
		nodePath[pathIdx-1].UpdateHash(pathIdx - 1)
	}

	digest := &Digest{B: CopySlice(nodePath[0].Hash())}
	proof := &MembProof{ChildHashes: GetChildHashes(nodePath[:HashLen])}
	return digest, proof, ErrNone
}

func (t *Tree) Get(id *Id) (*Val, *Digest, *MembProof, uint64) {
	if uint64(len(id.B)) != HashLen {
		return nil, nil, nil, ErrBadInput
	}

	nodePath, found := t.WalkTree(id)
	if !found {
		return nil, nil, nil, ErrNotFound
	}

	val := &Val{B: CopySlice(nodePath[HashLen].Val.B)}
	digest := &Digest{B: CopySlice(nodePath[0].Hash())}
	proof := &MembProof{ChildHashes: GetChildHashes(nodePath[:HashLen])}
	return val, digest, proof, ErrNone
}

func (t *Tree) GetNil(id *Id) (*Digest, *NonmembProof, uint64) {
	if uint64(len(id.B)) != HashLen {
		return nil, nil, ErrBadInput
	}

	nodePath, found := t.WalkTree(id)
	if found {
		return nil, nil, ErrFound
	}

	digest := &Digest{B: CopySlice(nodePath[0].Hash())}
	proof := &NonmembProof{ChildHashes: GetChildHashes(nodePath)}
	return digest, proof, ErrNone
}
