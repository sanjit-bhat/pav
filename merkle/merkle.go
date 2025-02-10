package merkle

import (
	"github.com/goose-lang/primitive"
	"github.com/goose-lang/std"
	"github.com/mit-pdos/pav/cryptoffi"
	"github.com/mit-pdos/pav/cryptoutil"
	"github.com/tchajed/marshal"
)

const (
	emptyNodeTag byte = 0
	innerNodeTag byte = 1
	leafNodeTag  byte = 2
)

type Tree struct {
	cache *cache
	root  *node
}

// node contains the union of different node types, which distinguish as:
//  1. empty node. if node ptr is nil.
//  2. inner node. if either child0 or child1 not nil. has hash.
//  3. leaf node. else. has hash, full label, and val.
type node struct {
	hash []byte
	// only for inner node.
	child0 *node
	// only for inner node.
	child1 *node
	// only for leaf node.
	label []byte
	// only for leaf node.
	val []byte
}

type cache struct {
	emptyHash []byte
}

// Put adds (label, val) to the tree and errors if label isn't a hash.
// it consumes both label and val.
func (t *Tree) Put(label []byte, val []byte) bool {
	if uint64(len(label)) != cryptoffi.HashLen {
		return true
	}
	put(&t.root, 0, label, val, t.cache)
	return false
}

func put(n0 **node, depth uint64, label, val []byte, cache *cache) {
	n := *n0
	// empty node.
	if n == nil {
		// replace with leaf node.
		leaf := &node{label: label, val: val}
		*n0 = leaf
		setLeafHash(leaf)
		return
	}

	// leaf node.
	if n.child0 == nil && n.child1 == nil {
		// on exact label match, replace val.
		if std.BytesEqual(n.label, label) {
			n.val = val
			setLeafHash(n)
			return
		}

		// otherwise, replace with inner node that links
		// to existing leaf, and recurse.
		inter := &node{}
		*n0 = inter
		leafChild, _ := getChild(inter, n.label, depth)
		*leafChild = n
		recurChild, _ := getChild(inter, label, depth)
		put(recurChild, depth+1, label, val, cache)
		setInnerHash(inter, cache)
		return
	}

	// inner node. recurse.
	c, _ := getChild(n, label, depth)
	put(c, depth+1, label, val, cache)
	setInnerHash(n, cache)
}

// Get returns if label is in the tree and, if so, the val.
// it errors if label isn't a hash.
func (t *Tree) Get(label []byte) (bool, []byte, bool) {
	inTree, val, _, err := t.get(label, false)
	return inTree, val, err
}

// Prove returns (1) if label is in the tree and, if so, (2) the val.
// it gives a (3) cryptographic proof of this.
// it (4) errors if label isn't a hash.
func (t *Tree) Prove(label []byte) (bool, []byte, []byte, bool) {
	inTree, val, p, err := t.get(label, true)
	proof := MerkleProofEncode(make([]byte, 0, 8+len(p.Siblings)+8+len(p.LeafLabel)+8+len(p.LeafVal)), p)
	return inTree, val, proof, err
}

func (t *Tree) get(label []byte, prove bool) (bool, []byte, *MerkleProof, bool) {
	if uint64(len(label)) != cryptoffi.HashLen {
		return false, nil, nil, true
	}
	var n = t.root
	var sibs []byte
	if prove {
		// pre-size for roughly 2^30 (1.07B) entries.
		sibs = make([]byte, 0, 30*cryptoffi.HashLen)
	}
	var depth uint64
	for ; depth < cryptoffi.HashLen*8; depth++ {
		// break if empty node or leaf node.
		if n == nil {
			break
		}
		if n.child0 == nil && n.child1 == nil {
			break
		}
		child, sib := getChild(n, label, depth)
		if prove {
			// proof will have sibling hash for each inner node.
			sibs = append(sibs, getNodeHash(sib, t.cache)...)
		}
		n = *child
	}

	proof := &MerkleProof{Siblings: sibs}
	// empty node.
	if n == nil {
		return false, nil, proof, false
	}
	// not inner node. can't go full depth down and still have inner.
	primitive.Assert(n.child0 == nil && n.child1 == nil)
	// leaf node with different label.
	if !std.BytesEqual(n.label, label) {
		proof.LeafLabel = n.label
		proof.LeafVal = n.val
		return false, nil, proof, false
	}
	// leaf node with same label.
	return true, n.val, proof, false
}

// VerifyProof verifies proof against the tree rooted at dig
// and returns an error upon failure.
// there are two types of inputs.
// if inTree, (label, val) should be in the tree.
// if !inTree, label should not be in the tree.
func VerifyProof(inTree bool, label, val []byte, proof []byte, dig []byte) bool {
	if uint64(len(label)) != cryptoffi.HashLen {
		return true
	}
	proofDec, _, err0 := MerkleProofDecode(proof)
	if err0 {
		return true
	}
	sibsLen := uint64(len(proofDec.Siblings))
	if sibsLen%cryptoffi.HashLen != 0 {
		return true
	}
	maxDepth := sibsLen / cryptoffi.HashLen
	if maxDepth > cryptoffi.HashLen*8 {
		return true
	}

	// compute leaf hash.
	var currHash []byte
	if inTree {
		currHash = compLeafHash(label, val)
	} else {
		if proofDec.LeafLabel != nil {
			currHash = compLeafHash(proofDec.LeafLabel, proofDec.LeafVal)
		} else {
			currHash = compEmptyHash()
		}
	}

	// compute hash up the tree.
	var depth = maxDepth
	var hashBuf = make([]byte, 0, 2*cryptoffi.HashLen+1)
	// depth offset by one to prevent underflow.
	for depth >= 1 {
		begin := (depth - 1) * cryptoffi.HashLen
		end := depth * cryptoffi.HashLen
		sib := proofDec.Siblings[begin:end]

		if !getBit(label, depth-1) {
			hashBuf = setInnerHashBuf(hashBuf, currHash, sib)
		} else {
			hashBuf = setInnerHashBuf(hashBuf, sib, currHash)
		}
		hr := cryptoffi.NewHasher()
		hr.Write(hashBuf)
		hashBuf = hashBuf[:0]
		currHash = hr.Sum(currHash)
		depth--
	}

	// check against supplied dig.
	return !std.BytesEqual(currHash, dig)
}

func (t *Tree) Digest() []byte {
	return getNodeHash(t.root, t.cache)
}

func NewTree() *Tree {
	c := &cache{emptyHash: compEmptyHash()}
	return &Tree{cache: c}
}

func getNodeHash(n *node, c *cache) []byte {
	if n == nil {
		return c.emptyHash
	}
	return n.hash
}

func compEmptyHash() []byte {
	b := []byte{emptyNodeTag}
	return cryptoutil.Hash(b)
}

func setLeafHash(n *node) {
	n.hash = compLeafHash(n.label, n.val)
}

func compLeafHash(label, val []byte) []byte {
	valLen := uint64(len(val))
	var b = make([]byte, 0, cryptoffi.HashLen+8+valLen+1)
	b = append(b, label...)
	b = marshal.WriteInt(b, valLen)
	b = append(b, val...)
	b = append(b, leafNodeTag)
	return cryptoutil.Hash(b)
}

func setInnerHash(n *node, c *cache) {
	child0 := getNodeHash(n.child0, c)
	child1 := getNodeHash(n.child1, c)
	var b = make([]byte, 0, 2*cryptoffi.HashLen+1)
	b = setInnerHashBuf(b, child0, child1)
	n.hash = cryptoutil.Hash(b)
}

func setInnerHashBuf(b []byte, child0, child1 []byte) []byte {
	b = append(b, child0...)
	b = append(b, child1...)
	b = append(b, innerNodeTag)
	return b
}

// getChild returns a child and its sibling child,
// relative to the bit referenced by label and depth.
func getChild(n *node, label []byte, depth uint64) (**node, *node) {
	if !getBit(label, depth) {
		return &n.child0, n.child1
	} else {
		return &n.child1, n.child0
	}
}

func getBit(b []byte, n uint64) bool {
	slot := n / 8
	off := n % 8
	x := b[slot]
	return x&(1<<off) != 0
}
