package merkle

import (
	"github.com/mit-pdos/pav/cryptoffi"
	"math/rand/v2"
	"testing"
)

func BenchmarkPut(b *testing.B) {
	tr := NewTree()
	val := []byte("val")
	var seed [32]byte
	rnd := rand.NewChaCha8(seed)
	label := make([]byte, cryptoffi.HashLen)

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
	tr := NewTree()
	val := []byte("val")
	var seed [32]byte
	rnd := rand.NewChaCha8(seed)
	label := make([]byte, cryptoffi.HashLen)

	for range b.N {
		_, err := rnd.Read(label)
		if err != nil {
			b.Fatal(err)
		}
		b.StopTimer()
		_, _, errb := tr.Put(label, val)
		if errb {
			b.Fatal()
		}
		b.StartTimer()

		_, _, _, _, errb = tr.Get(label)
		if errb {
			b.Fatal()
		}
	}
}

var mapVal []byte
var proof []byte

func BenchmarkGetNonMembNone(b *testing.B) {
	tr := NewTree()
	var seed [32]byte
	rnd := rand.NewChaCha8(seed)
	label := make([]byte, cryptoffi.HashLen)
	nonEmpt := 0

	tr2 := NewTree()
	val := []byte("val")
	for i := 0; i < 500; i++ {
		_, err := rnd.Read(label)
		if err != nil {
			b.Fatal(err)
		}
		_, _, errb := tr2.Put(label, val)
		if errb {
			b.Fatal()
		}
	}

	b.ResetTimer()
	for range b.N {
		_, err := rnd.Read(label)
		if err != nil {
			b.Fatal(err)
		}

		mapVal0, _, _, proof0, errb := tr.Get(label)
		mapVal = mapVal0
		proof = proof0
		if errb {
			b.Fatal()
		}
		depth := uint64(len(proof0)) / hashesPerProofDepth
		if depth != 0 {
			nonEmpt++
		}
	}

	b.Log(nonEmpt)
}

func BenchmarkGetNonMembSome(b *testing.B) {
	tr := NewTree()
	val := []byte("val")
	var seed [32]byte
	rnd := rand.NewChaCha8(seed)
	label := make([]byte, cryptoffi.HashLen)
	totalDep := 0
	total := 0

	for i := 0; i < 500; i++ {
		_, err := rnd.Read(label)
		if err != nil {
			b.Fatal(err)
		}
		_, _, errb := tr.Put(label, val)
		if errb {
			b.Fatal()
		}
	}

	b.ResetTimer()
	for range b.N {
		_, err := rnd.Read(label)
		if err != nil {
			b.Fatal(err)
		}

		mapVal0, _, _, proof0, errb := tr.Get(label)
		mapVal = mapVal0
		proof = proof0
		if errb {
			b.Fatal()
		}
		depth := len(proof0) / int(hashesPerProofDepth)
		totalDep += depth
		total++
	}

	b.Log("avg dep", float32(totalDep)/float32(total), "total", total)
}

func BenchmarkGetProofNone(b *testing.B) {
	tr := NewTree()
	label := make([]byte, cryptoffi.HashLen)

	b.ResetTimer()
	for range b.N {
		proof = tr.ctx.getProof(tr.root, label)
	}
}

func BenchmarkGetProofSome(b *testing.B) {
	tr := NewTree()
	root := newInteriorNode()
	child0 := newInteriorNode()
	tr.root = root
	root.children[0] = child0
	label := make([]byte, cryptoffi.HashLen)

	b.ResetTimer()
	for range b.N {
		proof = tr.ctx.getProof(tr.root, label)
	}
}

func BenchmarkMallocUnstable(b *testing.B) {
	proofs := make([][]byte, 0, 1_000_000)
	for range b.N {
		proof := make([]byte, 0, cryptoffi.HashLen*hashesPerProofDepth)
		proofs = append(proofs, proof)
	}
}

func BenchmarkMallocWarmup(b *testing.B) {
	var proof []byte
	for range b.N {
		proof = make([]byte, 0, cryptoffi.HashLen*hashesPerProofDepth)
		proof = append(proof, 1)
	}
}
