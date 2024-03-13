package merkle

import (
	"bytes"
	"fmt"
	"github.com/zeebo/blake3"
)

const (
	ErrNone      uint64 = 0
	ErrFound     uint64 = 1
	ErrNotFound  uint64 = 2
	ErrBadInput  uint64 = 3
	ErrPathProof uint64 = 4
	// The output length of our hash function.
	DigestLen = 32
	// Each node's number of children.
	// Branch on a byte, and 2 ** 8 (bits in byte) = 256.
	ChildLen = 256
)

func HashOne(d []byte) []byte {
	hasher := blake3.New()
	hasher.Write(d)
	return hasher.Sum(nil)[:DigestLen]
}

func HashSum(h *blake3.Hasher) []byte {
	return h.Sum(nil)[:DigestLen]
}

func HashSlice2D(b [][]byte) []byte {
	h := blake3.New()
	for _, bSub := range b {
		h.Write(bSub)
	}
	return HashSum(h)
}

func HashNodes(nodeSl []*Node) []byte {
	h := blake3.New()
	for _, n := range nodeSl {
		h.Write(n.Digest())
	}
	return HashSum(h)
}

func CopySlice(b1 []byte) []byte {
	b2 := make([]byte, len(b1))
	copy(b2, b1)
	return b2
}

// "keys" of the tree.
// We use Id to differentiate this from the public keys that could be stored
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
	digest   []byte
	Children []*Node
}

func NewNode() *Node {
	d := HashOne(nil)
	c := make([]*Node, ChildLen)
	return &Node{Val: nil, digest: d, Children: c}
}

func (n *Node) Digest() []byte {
	if n == nil {
		return HashOne(nil)
	}
	return n.digest
}

type RootDigest struct {
	B []byte
}

// General proof object.
// Binds an id down the tree to a digest.
type PathProof struct {
	Id           *Id
	ValDigest    []byte
	Root         *RootDigest
	ChildDigests [][][]byte
}

type MembProof struct {
	ChildDigests [][][]byte
}

type NonmembProof struct {
	ChildDigests [][][]byte
}

func (p *PathProof) Check() uint64 {
	proofLen := len(p.Id.B)
	posBott := p.Id.B[proofLen-1]
	if !bytes.Equal(p.ValDigest, p.ChildDigests[proofLen-1][posBott]) {
		return ErrPathProof
	}

	err := ErrNone
	for pathIdx := proofLen - 1; pathIdx >= 1; pathIdx-- {
		hChildren := HashSlice2D(p.ChildDigests[pathIdx])
		prevIdx := pathIdx - 1
		pos := p.Id.B[prevIdx]
		if !bytes.Equal(hChildren, p.ChildDigests[prevIdx][pos]) {
			err = ErrPathProof
		}
	}
	if err != ErrNone {
		return err
	}

	hRoot := HashSlice2D(p.ChildDigests[0])
	if !bytes.Equal(hRoot, p.Root.B) {
		return ErrPathProof
	}
	return ErrNone
}

func (p *MembProof) Check(id *Id, val *Val, root *RootDigest) uint64 {
	if len(id.B) != DigestLen {
		return ErrBadInput
	}
	if len(p.ChildDigests) != DigestLen {
		return ErrBadInput
	}
	pathProof := &PathProof{
		Id:           id,
		ValDigest:    HashOne(val.B),
		Root:         root,
		ChildDigests: p.ChildDigests,
	}
	return pathProof.Check()
}

func (p *NonmembProof) Check(id *Id, root *RootDigest) uint64 {
	if DigestLen <= len(p.ChildDigests) {
		return ErrBadInput
	}
	id.B = id.B[:len(p.ChildDigests)]
	pathProof := &PathProof{
		Id:           id,
		ValDigest:    HashOne(nil),
		Root:         root,
		ChildDigests: p.ChildDigests,
	}
	return pathProof.Check()
}

// Assumes recursive child hashes are already up-to-date.
func (n *Node) UpdateHash() {
	if n.Val != nil {
		n.digest = HashOne(n.Val.B)
	} else {
		n.digest = HashNodes(n.Children)
	}
}

type Tree struct {
	Root *Node
}

func NewTree() *Tree {
	return &Tree{Root: NewNode()}
}

func (t *Tree) Print() {
	qCurr := make([]*Node, 0)
	qCurr = append(qCurr, t.Root)
	qNext := make([]*Node, 0)
	for len(qCurr) > 0 {
		for len(qCurr) > 0 {
			top := qCurr[0]
			qCurr = qCurr[1:]

			if top == nil {
				fmt.Print("nil | ")
				continue
			} else if top.Val != nil {
				fmt.Print(top.Digest(), top.Val.B, " | ")
			} else {
				fmt.Print(top.Digest(), " | ")
			}

			for _, child := range top.Children {
				qNext = append(qNext, child)
			}
		}
		qCurr = qNext
		qNext = nil
		fmt.Println()
	}
}

func GetChildDigests(nodePath []*Node) [][][]byte {
	childDigests := make([][][]byte, len(nodePath))
	for pathIdx := 0; pathIdx < len(nodePath); pathIdx++ {
		treeChildren := nodePath[pathIdx].Children
		proofChildren := make([][]byte, ChildLen)
		childDigests[pathIdx] = proofChildren

		for childIdx := 0; childIdx < ChildLen; childIdx++ {
			proofChildren[childIdx] = CopySlice(treeChildren[childIdx].Digest())
		}
	}
	return childDigests
}

func (t *Tree) WalkTree(id *Id) ([]*Node, bool) {
	var nodePath []*Node
	nodePath = append(nodePath, t.Root)
	found := true
	for pathIdx := 0; pathIdx < DigestLen && found; pathIdx++ {
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
	for pathIdx := 0; pathIdx < DigestLen; pathIdx++ {
		currNode := nodePath[pathIdx]
		pos := id.B[pathIdx]
		if currNode.Children[pos] == nil {
			currNode.Children[pos] = NewNode()
		}
		nodePath = append(nodePath, currNode.Children[pos])
	}
	return nodePath
}

func (t *Tree) Put(id *Id, v *Val) (*RootDigest, *MembProof, uint64) {
	if len(id.B) != DigestLen {
		return nil, nil, ErrBadInput
	}

	nodePath := t.WalkTreeAddLinks(id)
	nodePath[DigestLen].Val = v
	for pathIdx := DigestLen; pathIdx >= 0; pathIdx-- {
		nodePath[pathIdx].UpdateHash()
	}

	root := &RootDigest{B: CopySlice(nodePath[0].Digest())}
	proof := &MembProof{ChildDigests: GetChildDigests(nodePath[:DigestLen])}
	return root, proof, ErrNone
}

func (t *Tree) Get(id *Id) (*Val, *RootDigest, *MembProof, uint64) {
	if len(id.B) != DigestLen {
		return nil, nil, nil, ErrBadInput
	}

	nodePath, found := t.WalkTree(id)
	if !found {
		return nil, nil, nil, ErrNotFound
	}

	val := &Val{B: CopySlice(nodePath[DigestLen].Val.B)}
	root := &RootDigest{B: CopySlice(nodePath[0].Digest())}
	proof := &MembProof{ChildDigests: GetChildDigests(nodePath[:DigestLen])}
	return val, root, proof, ErrNone
}

func (t *Tree) GetNil(id *Id) (*RootDigest, *NonmembProof, uint64) {
	if len(id.B) != DigestLen {
		return nil, nil, ErrBadInput
	}

	nodePath, found := t.WalkTree(id)
	if found {
		return nil, nil, ErrFound
	}

	root := &RootDigest{B: CopySlice(nodePath[0].Digest())}
	proof := &NonmembProof{ChildDigests: GetChildDigests(nodePath)}
	return root, proof, ErrNone
}
