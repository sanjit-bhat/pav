package merkle

import (
	"github.com/goose-lang/std"
	"github.com/mit-pdos/secure-chat/crypto/helpers"
	"github.com/mit-pdos/secure-chat/crypto/shim"
	"log"
)

type ErrorT = uint64
type ProofT = bool

const (
	ErrNone      ErrorT = 0
	ErrFound     ErrorT = 1
	ErrNotFound  ErrorT = 2
	ErrBadInput  ErrorT = 3
	ErrPathProof ErrorT = 4
	// Branch on a byte. 2 ** 8 (bits in byte) = 256.
	NumChildren    uint64 = 256
	EmptyNodeId    byte   = 0
	LeafNodeId     byte   = 1
	InteriorNodeId byte   = 2
	NonmembProofT         = false
	MembProofT            = true
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
		return shim.Hash([]byte{EmptyNodeId})
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
	var h helpers.Hasher
	helpers.HasherWrite(&h, n.Val)
	helpers.HasherWrite(&h, []byte{LeafNodeId})
	n.hash = helpers.HasherSum(h, nil)
}

// Assumes recursive child hashes are already up-to-date.
func (n *Node) UpdateInteriorHash() {
	var h helpers.Hasher
	for _, n := range n.Children {
		helpers.HasherWrite(&h, n.Hash())
	}
	helpers.HasherWrite(&h, []byte{InteriorNodeId})
	n.hash = helpers.HasherSum(h, nil)
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

type MembProof = [][][]byte

type NonmembProof = [][][]byte

type GenProof = [][][]byte

func IsValidHashSl(data [][]byte) bool {
	var ok = true
	for _, hash := range data {
		if uint64(len(hash)) != shim.HashLen {
			ok = false
		}
	}
	return ok
}

func (p *PathProof) Check() ErrorT {
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

		var hr helpers.Hasher
		helpers.HasherWriteSl(&hr, before)
		helpers.HasherWrite(&hr, currHash)
		helpers.HasherWriteSl(&hr, after)
		helpers.HasherWrite(&hr, []byte{InteriorNodeId})
		currHash = helpers.HasherSum(hr, nil)
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
	var hr helpers.Hasher
	helpers.HasherWrite(&hr, val)
	helpers.HasherWrite(&hr, []byte{LeafNodeId})
	return helpers.HasherSum(hr, nil)
}

func getEmptyNodeHash() []byte {
	return shim.Hash([]byte{EmptyNodeId})
}

func CheckProofTotal(proofT ProofT, proof GenProof, id Id, val Val, digest Digest) ErrorT {
	if uint64(len(proof)) > shim.HashLen {
		return ErrBadInput
	}
	if len(id) < len(proof) {
		return ErrBadInput
	}
	// For NonmembProof, have original id, so slice it down
	// to same sz as path.
	idPref := id[:len(proof)]
	var nodeHash []byte
	if proofT == MembProofT {
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

func MembProofCheck(proof MembProof, id Id, val Val, digest Digest) ErrorT {
	// TODO: are these checks necessary?
	if uint64(len(id)) != shim.HashLen {
		return ErrBadInput
	}
	if uint64(len(proof)) != shim.HashLen {
		return ErrBadInput
	}
	var hr helpers.Hasher
	helpers.HasherWrite(&hr, val)
	helpers.HasherWrite(&hr, []byte{LeafNodeId})
	pathProof := &PathProof{
		Id:          id,
		NodeHash:    helpers.HasherSum(hr, nil),
		Digest:      digest,
		ChildHashes: proof,
	}
	return pathProof.Check()
}

func NonmembProofCheck(proof NonmembProof, id Id, digest Digest) ErrorT {
	// An empty node can appear at any depth down the tree.
	if shim.HashLen < uint64(len(proof)) {
		return ErrBadInput
	}
	// After slicing, id will have same len as p.ChildHashes.
	// It now corresponds to the prefix path down the tree that contains
	// the empty node.
	if len(id) < len(proof) {
		return ErrBadInput
	}
	idPref := CopySlice(id)[:len(proof)]
	var hr helpers.Hasher
	helpers.HasherWrite(&hr, []byte{EmptyNodeId})
	pathProof := &PathProof{
		Id:          idPref,
		NodeHash:    helpers.HasherSum(hr, nil),
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

func (t *Tree) Digest() Digest {
	return t.Root.Hash()
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
	for pathIdx := uint64(0); pathIdx < shim.HashLen && found; pathIdx++ {
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
	for pathIdx := uint64(0); pathIdx < shim.HashLen; pathIdx++ {
		currNode := nodePath[pathIdx]
		pos := id[pathIdx]
		if currNode.Children[pos] == nil {
			currNode.Children[pos] = NewGenericNode()
		}
		nodePath = append(nodePath, currNode.Children[pos])
	}
	return nodePath
}

func (t *Tree) Put(id Id, val Val) (Digest, MembProof, ErrorT) {
	if uint64(len(id)) != shim.HashLen {
		return nil, nil, ErrBadInput
	}

	nodePath := t.GetPathAddNodes(id)
	nodePath[shim.HashLen].Val = val
	nodePath[shim.HashLen].UpdateLeafHash()
	// +1/-1 offsets for Goosable uint64 loop var.
	for pathIdx := shim.HashLen; pathIdx >= 1; pathIdx-- {
		nodePath[pathIdx-1].UpdateInteriorHash()
	}

	digest := CopySlice(nodePath[0].Hash())
	proof := GetChildHashes(nodePath, id)
	return digest, proof, ErrNone
}

func (t *Tree) GetTotal(id Id) (Val, Digest, ProofT, GenProof, ErrorT) {
	if uint64(len(id)) != shim.HashLen {
		return nil, nil, false, nil, ErrBadInput
	}
	nodePath, found := t.GetPath(id)
	if !found {
		return nil, nil, false, nil, ErrNotFound
	}

	digest := CopySlice(nodePath[0].Hash())
	proof := GetChildHashes(nodePath, id)
	if nodePath[uint64(len(nodePath))-1] == nil {
		return nil, digest, NonmembProofT, proof, ErrNone
	}
	val := CopySlice(nodePath[shim.HashLen].Val)
	return val, digest, MembProofT, proof, ErrNone
}

func (t *Tree) Get(id Id) (Val, Digest, MembProof, ErrorT) {
	if uint64(len(id)) != shim.HashLen {
		return nil, nil, nil, ErrBadInput
	}

	nodePath, found := t.GetPath(id)
	if !found {
		return nil, nil, nil, ErrNotFound
	}

	val := CopySlice(nodePath[shim.HashLen].Val)
	digest := CopySlice(nodePath[0].Hash())
	proof := GetChildHashes(nodePath, id)
	return val, digest, proof, ErrNone
}

func (t *Tree) GetNil(id Id) (Digest, NonmembProof, ErrorT) {
	if uint64(len(id)) != shim.HashLen {
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
