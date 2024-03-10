package merkle

/*
Requirements:
What should the paths down the tree be?
A byte array, for the most general thing.
Max len can be 32 bytes, the output size of the blake hash func,
used by AKD.
Could also specialize to a uname or something,
which might be a u64 (8 bytes).
But then when add in epoch, gets more complicated.
It's easiest to just do a hash value.

Make value at node be another byte arr.
Ops:
1) Put
2) Get
Get proofs of membership and non-membership for specific keys.
*/

import (
	"bytes"
	"fmt"
	//"github.com/tchajed/goose/machine"
	"github.com/zeebo/blake3"
)

const (
	ErrNone          uint64 = 0
	ErrGet_NotFound  uint64 = 1
	ErrPut_BadLen    uint64 = 2
	ErrGet_BadLen    uint64 = 3
	ErrMembProof_Bad uint64 = 4
	DigestLen               = 2
)

type Id struct {
	Path []byte
}

type Val struct {
	Data []byte
}

func (v1 *Val) Equals(v2 *Val) bool {
	return bytes.Equal(v1.Data, v2.Data)
}

type Node struct {
	Val      *Val
	Digest   []byte
	Children []*Node
}

const ByteSlots = 2

func NewNode() *Node {
	// TODO: init digest?
    d := HashOne(nil)
	c := make([]*Node, ByteSlots)
	return &Node{Val: nil, Digest: d, Children: c}
}

type MembershipProof struct {
	Path         []byte
	Val          *Val
	RootDigest   []byte
	ChildDigests [][][]byte
}

func HashOne(d []byte) []byte {
	hasher := blake3.New()
	hasher.Write(d)
	return hasher.Sum(nil)[:DigestLen]
}

func HashSlice(h *blake3.Hasher) []byte {
	return h.Sum(nil)[:DigestLen]
}

func (p *MembershipProof) Check() uint64 {
	hBott := HashOne(p.Val.Data)
	posBott := p.Path[DigestLen-1]
	if !bytes.Equal(hBott, p.ChildDigests[DigestLen-1][posBott]) {
		return ErrMembProof_Bad
	}

	err := ErrNone
	for pathIdx := DigestLen - 1; pathIdx >= 1; pathIdx-- {
		h := blake3.New()
		for _, childHash := range p.ChildDigests[pathIdx] {
			h.Write(childHash)
		}
		prevIdx := pathIdx - 1
		pos := p.Path[prevIdx]
		if !bytes.Equal(HashSlice(h), p.ChildDigests[prevIdx][pos]) {
			err = ErrMembProof_Bad
		}
	}
	if err != ErrNone {
		return err
	}

	hTop := blake3.New()
	for _, childHash := range p.ChildDigests[0] {
		hTop.Write(childHash)
	}
	if !bytes.Equal(HashSlice(hTop), p.RootDigest) {
		return ErrMembProof_Bad
	}
	return ErrNone
}

// Assumes child hashes are already up-to-date.
func (n *Node) UpdateHash() {
	h := blake3.New()
	// TODO: need to deal with nil vals in more principled way.
	if n.Val != nil {
		h.Write(n.Val.Data)
	}
	for _, child := range n.Children {
		if child != nil {
			h.Write(child.Digest)
		}
	}
	n.Digest = HashSlice(h)
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
                fmt.Print(top.Digest, top.Val.Data, " | ")
            } else {
                fmt.Print(top.Digest, " | ")
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

func GetMembProof(nodePath []*Node, id *Id) *MembershipProof {
	proof := &MembershipProof{}
	proof.Path = id.Path
	proof.Val = nodePath[DigestLen].Val
	proof.RootDigest = nodePath[0].Digest
	proof.ChildDigests = make([][][]byte, DigestLen)
	for pathIdx := 0; pathIdx < DigestLen; pathIdx++ {
		proofChildren := make([][]byte, ByteSlots)
		treeChildren := nodePath[pathIdx].Children
		proof.ChildDigests[pathIdx] = proofChildren
		for childIdx := 0; childIdx < ByteSlots; childIdx++ {
			if treeChildren[childIdx] != nil {
				proofChildren[childIdx] = treeChildren[childIdx].Digest
			}
		}
	}
	return proof
}

func (t *Tree) Put(id *Id, v *Val) (*MembershipProof, uint64) {
	if len(id.Path) != DigestLen {
		return nil, ErrPut_BadLen
	}

	nodePath := make([]*Node, DigestLen+1)
	nodePath[0] = t.Root
	for pathIdx := 0; pathIdx < DigestLen; pathIdx++ {
		currNode := nodePath[pathIdx]
		pos := id.Path[pathIdx]
		if currNode.Children[pos] == nil {
			currNode.Children[pos] = NewNode()
		}
		nodePath[pathIdx+1] = currNode.Children[pos]
	}

	nodePath[DigestLen].Val = v

	for pathIdx := DigestLen; pathIdx >= 0; pathIdx-- {
		nodePath[pathIdx].UpdateHash()
	}

    t.Print()
	return GetMembProof(nodePath, id), ErrNone
}

func (t *Tree) Get(id *Id) (*MembershipProof, uint64) {
	if len(id.Path) != DigestLen {
		return nil, ErrGet_BadLen
	}

	nodePath := make([]*Node, DigestLen+1)
	nodePath[0] = t.Root
	found := true
	for pathIdx := 0; pathIdx < DigestLen; pathIdx++ {
		currNode := nodePath[pathIdx]
		pos := id.Path[pathIdx]
		if currNode.Children[pos] == nil {
			found = false
			break
		}
		nodePath[pathIdx+1] = currNode.Children[pos]
	}

	if !found {
		return nil, ErrGet_NotFound
	}

	return GetMembProof(nodePath, id), ErrNone
}
