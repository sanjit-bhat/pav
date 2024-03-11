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

func CopyByteSlice(b1 []byte) []byte {
	b2 := make([]byte, len(b1))
	copy(b2, b1)
	return b2
}

type Id struct {
	Path []byte
}

type Val struct {
	Data []byte
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

// General proof object.
// Binds a path down the tree to a digest.
type PathProof struct {
	Path         []byte
	ValDigest    []byte
	RootDigest   []byte
	ChildDigests [][][]byte
}

type MembProof struct {
	Path         []byte
	Val          *Val
	RootDigest   []byte
	ChildDigests [][][]byte
}

// User checks that proof.Path is prefix of their desired Path.
type NonmembProof struct {
	Path         []byte
	RootDigest   []byte
	ChildDigests [][][]byte
}

func (p *PathProof) Check() uint64 {
	if len(p.Path) != len(p.ChildDigests) {
		return ErrPathProof
	}
	proofLen := len(p.Path)

	posBott := p.Path[proofLen-1]
	if !bytes.Equal(p.ValDigest, p.ChildDigests[proofLen-1][posBott]) {
		return ErrPathProof
	}

	err := ErrNone
	for pathIdx := proofLen - 1; pathIdx >= 1; pathIdx-- {
		h := blake3.New()
		for _, childHash := range p.ChildDigests[pathIdx] {
			h.Write(childHash)
		}
		prevIdx := pathIdx - 1
		pos := p.Path[prevIdx]
		if !bytes.Equal(HashSum(h), p.ChildDigests[prevIdx][pos]) {
			err = ErrPathProof
		}
	}
	if err != ErrNone {
		return err
	}

	hTop := blake3.New()
	for _, childHash := range p.ChildDigests[0] {
		hTop.Write(childHash)
	}
	if !bytes.Equal(HashSum(hTop), p.RootDigest) {
		return ErrPathProof
	}
	return ErrNone
}

func (p *MembProof) Check() uint64 {
	if p.Val.Data == nil {
		return ErrPathProof
	}
	pathProof := &PathProof{
		Path:         p.Path,
		ValDigest:    HashOne(p.Val.Data),
		RootDigest:   p.RootDigest,
		ChildDigests: p.ChildDigests,
	}
	return pathProof.Check()
}

func (p *NonmembProof) Check() uint64 {
	pathProof := &PathProof{
		Path:         p.Path,
		ValDigest:    HashOne(nil),
		RootDigest:   p.RootDigest,
		ChildDigests: p.ChildDigests,
	}
	return pathProof.Check()
}

// Assumes recursive child hashes are already up-to-date.
func (n *Node) UpdateHash() {
	h := blake3.New()
	if n.Val != nil {
		h.Write(n.Val.Data)
	} else {
		for _, child := range n.Children {
			h.Write(child.Digest())
		}
	}
	n.digest = HashSum(h)
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
				fmt.Print(top.Digest(), top.Val.Data, " | ")
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

func CopyChildDigests(nodePath []*Node, copyLen int) [][][]byte {
	childDigests := make([][][]byte, copyLen)
	for pathIdx := 0; pathIdx < copyLen; pathIdx++ {
		treeChildren := nodePath[pathIdx].Children
		proofChildren := make([][]byte, ChildLen)
		childDigests[pathIdx] = proofChildren

		for childIdx := 0; childIdx < ChildLen; childIdx++ {
			proofChildren[childIdx] = CopyByteSlice(treeChildren[childIdx].Digest())
		}
	}
	return childDigests
}

func GetMembProof(nodePath []*Node, id *Id) *MembProof {
	proof := &MembProof{}
	proof.Path = CopyByteSlice(id.Path)
	proof.Val = &Val{}
	proof.Val.Data = CopyByteSlice(nodePath[DigestLen].Val.Data)
	proof.RootDigest = CopyByteSlice(nodePath[0].Digest())
	proof.ChildDigests = CopyChildDigests(nodePath, DigestLen)
	return proof
}

func GetNonmembProof(nodePath []*Node, id *Id) *NonmembProof {
	proof := &NonmembProof{}
	prefixLen := len(nodePath)
	proof.Path = CopyByteSlice(id.Path[:prefixLen])
	proof.RootDigest = CopyByteSlice(nodePath[0].Digest())
	proof.ChildDigests = CopyChildDigests(nodePath, prefixLen)
	return proof
}

func (t *Tree) WalkTree(id *Id) ([]*Node, bool) {
	var nodePath []*Node
	nodePath = append(nodePath, t.Root)
	found := true
	for pathIdx := 0; pathIdx < DigestLen && found; pathIdx++ {
		currNode := nodePath[pathIdx]
		pos := id.Path[pathIdx]
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
		pos := id.Path[pathIdx]
		if currNode.Children[pos] == nil {
			currNode.Children[pos] = NewNode()
		}
		nodePath = append(nodePath, currNode.Children[pos])
	}
	return nodePath
}

func (t *Tree) Put(id *Id, v *Val) (*MembProof, uint64) {
	if len(id.Path) != DigestLen {
		return nil, ErrBadInput
	}
	if v.Data == nil {
		return nil, ErrBadInput
	}

	nodePath := t.WalkTreeAddLinks(id)
	nodePath[DigestLen].Val = v
	for pathIdx := DigestLen; pathIdx >= 0; pathIdx-- {
		nodePath[pathIdx].UpdateHash()
	}
	return GetMembProof(nodePath, id), ErrNone
}

func (t *Tree) Get(id *Id) (*MembProof, uint64) {
	if len(id.Path) != DigestLen {
		return nil, ErrBadInput
	}

	nodePath, found := t.WalkTree(id)
	if !found {
		return nil, ErrNotFound
	}
	return GetMembProof(nodePath, id), ErrNone
}

func (t *Tree) GetNil(id *Id) (*NonmembProof, uint64) {
	if len(id.Path) != DigestLen {
		return nil, ErrBadInput
	}

	nodePath, found := t.WalkTree(id)
	if found {
		return nil, ErrFound
	}
	return GetNonmembProof(nodePath, id), ErrNone
}
