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

const (
    ErrNone uint64 = 0
    ErrGet_NotFound uint64 = 1
)

type Val struct {
	Data []byte
}

type Node struct {
	Val      *Val
	Children []*Node
}
const BYTE_POS = 64

func NewNode() *Node {
	return &Node{Val: nil, Children: make([]*Node, BYTE_POS)}
}

type Tree struct {
	Root *Node
}

func NewMTree() *Tree {
	return &Tree{Root: NewNode()}
}

type Id struct {
	Path []byte
}
const DIGEST_LEN = 32

func NewId() *Id {
	return &Id{Path: make([]byte, DIGEST_LEN)}
}

func (t *Tree) Put(id *Id, v *Val) {
	currNode := t.Root
    for pathIdx := 0; pathIdx < DIGEST_LEN; pathIdx++ {
        pos := id.Path[pathIdx]
        child := currNode.Children[pos]
        if child == nil {
            child := NewNode()
            currNode.Children[pos] = child
        }
        currNode = child
	}
    currNode.Val = v
}

func (t *Tree) Get(id *Id) (*Val, uint64) {
    currNode := t.Root
    found := true
    for pathIdx := 0; pathIdx < DIGEST_LEN; pathIdx++ {
        pos := id.Path[pathIdx]
        currNode = currNode.Children[pos]
        if currNode == nil {
            found = false
            break
        }
	}
    if !found {
        return nil, ErrGet_NotFound
    }
    return currNode.Val, ErrNone
}
