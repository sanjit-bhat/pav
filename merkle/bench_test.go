package merkle

import (
	"github.com/mit-pdos/pav/cryptoffi"
	"math/rand/v2"
	"testing"
)

func BenchmarkPut(b *testing.B) {
	tree := NewTree()
	val := []byte("val")
	var seed [32]byte
	rnd := rand.NewChaCha8(seed)
	label := make([]byte, cryptoffi.HashLen)

	for range b.N {
		_, err := rnd.Read(label)
		if err != nil {
			b.Fatal(err)
		}
		_, _, errb := tree.Put(label, val)
		if errb {
			b.Fatal()
		}
	}
}

func BenchmarkGetMemb(b *testing.B) {
	tree := NewTree()
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
		_, _, errb := tree.Put(label, val)
		if errb {
			b.Fatal()
		}
		b.StartTimer()

		_, _, _, _, errb = tree.Get(label)
		if errb {
			b.Fatal()
		}
	}
}

func BenchmarkGetNonMembWithPuts(b *testing.B) {
	tree := NewTree()
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
		_, _, errb := tree.Put(label, val)
		if errb {
			b.Fatal()
		}
	}

	b.Log("starting new loop")
	b.ResetTimer()
	for range b.N {
		_, err := rnd.Read(label)
		if err != nil {
			b.Fatal(err)
		}

		_, _, _, proof, errb := tree.Get(label)
		if errb {
			b.Fatal()
		}
		depth := uint64(len(proof)) / hashesPerProofDepth
		totalDep += int(depth)
		total++
	}

	b.Log("avg dep", float32(totalDep) / float32(total), "total", total)
}

func BenchmarkGetNonMemb(b *testing.B) {
	tree := NewTree()
	var seed [32]byte
	rnd := rand.NewChaCha8(seed)
	label := make([]byte, cryptoffi.HashLen)
	nonEmpt := 0

	b.ResetTimer()
	for range b.N {
		_, err := rnd.Read(label)
		if err != nil {
			b.Fatal(err)
		}

		_, _, _, proof, errb := tree.Get(label)
		if errb {
			b.Fatal()
		}
		depth := uint64(len(proof)) / hashesPerProofDepth
		if depth != 0 {
			nonEmpt++
		}
	}

	b.Log(nonEmpt)
}
