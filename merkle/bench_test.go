package merkle

import (
	"github.com/mit-pdos/pav/cryptoffi"
	"math/rand/v2"
	"testing"
)

var val = []byte("val")

func BenchmarkPutNoProof(b *testing.B) {
	tr, rnd, label := newSeededTree(b, 1000)
	b.ResetTimer()
	for range b.N {
		_, err := rnd.Read(label)
		if err != nil {
			b.Fatal(err)
		}
		_, errb := tr.putNoProof(label, val)
		if errb {
			b.Fatal()
		}
	}
}

func BenchmarkPutWithProof(b *testing.B) {
	tr, rnd, label := newSeededTree(b, 1000)
	b.ResetTimer()
	for range b.N {
		_, err := rnd.Read(label)
		if err != nil {
			b.Fatal(err)
		}
		_, _, errb := tr.Put(label, val)
		if errb {
			b.Fatal()
		}
	}
}

func BenchmarkGetMemb(b *testing.B) {
	tr, _, label := newSeededTree(b, 1000)
	b.ResetTimer()
	for range b.N {
		_, _, _, _, errb := tr.Get(label)
		if errb {
			b.Fatal()
		}
	}
}

func BenchmarkGetNonMemb(b *testing.B) {
	tr, rnd, label := newSeededTree(b, 1000)
	b.ResetTimer()
	for range b.N {
		_, err := rnd.Read(label)
		if err != nil {
			b.Fatal(err)
		}
		_, _, _, _, errb := tr.Get(label)
		if errb {
			b.Fatal()
		}
	}
}

func newSeededTree(b *testing.B, sz int) (tr *Tree, rnd *rand.ChaCha8, label []byte) {
	tr = NewTree()
	var seed [32]byte
	rnd = rand.NewChaCha8(seed)
	label = make([]byte, cryptoffi.HashLen)

	for i := 0; i < sz; i++ {
		_, err := rnd.Read(label)
		if err != nil {
			b.Fatal(err)
		}
		_, errb := tr.putNoProof(label, val)
		if errb {
			b.Fatal()
		}
	}
	return
}

// putNoProof returns the digest and error.
func (t *Tree) putNoProof(label []byte, mapVal []byte) ([]byte, bool) {
	if uint64(len(label)) != cryptoffi.HashLen {
		return nil, true
	}

	// make all interior nodes.
	var interiors = make([]*node, 0, cryptoffi.HashLen)
	if t.root == nil {
		t.root = newInteriorNode()
	}
	interiors = append(interiors, t.root)
	n := cryptoffi.HashLen - 1
	for depth := uint64(0); depth < n; depth++ {
		currNode := interiors[depth]

		// XXX: Converting to `uint64` for Goose, since it does not handle the
		// implicit conversion from uint8 to int when using `pos` as a slice
		// index.
		pos := uint64(label[depth])

		if currNode.children[pos] == nil {
			currNode.children[pos] = newInteriorNode()
		}
		interiors = append(interiors, currNode.children[pos])
	}

	// make leaf node with correct hash.
	lastInterior := interiors[cryptoffi.HashLen-1]
	// XXX: To deal with goose failing to handle the implicit conversion to int
	// when using as a slice index
	lastPos := uint64(label[cryptoffi.HashLen-1])
	lastInterior.children[lastPos] = &node{mapVal: mapVal, hash: compLeafNodeHash(mapVal)}

	// correct hashes of interior nodes, bubbling up.
	// +1/-1 offsets for Goosable uint64 loop var.
	var loopBuf = make([]byte, 0, numChildren*cryptoffi.HashLen+1)
	var depth = cryptoffi.HashLen
	for depth >= 1 {
		loopBuf = t.ctx.updInteriorHash(loopBuf, interiors[depth-1])
		loopBuf = loopBuf[:0]
		depth--
	}

	dig := t.ctx.getHash(t.root)
	return dig, false
}
