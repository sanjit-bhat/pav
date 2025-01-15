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

func BenchmarkGetNonMembExisting(b *testing.B) {
	tree := NewTree()
	val := []byte("val")
	var seed [32]byte
	rnd := rand.NewChaCha8(seed)
	label := make([]byte, cryptoffi.HashLen)

	b.StopTimer()
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
	b.StartTimer()

	for range b.N {
		_, err := rnd.Read(label)
		if err != nil {
			b.Fatal(err)
		}

		_, _, _, _, errb := tree.Get(label)
		if errb {
			b.Fatal()
		}
	}
}

func BenchmarkGetNonMemb(b *testing.B) {
	tree := NewTree()
	var seed [32]byte
	rnd := rand.NewChaCha8(seed)
	label := make([]byte, cryptoffi.HashLen)

	for range b.N {
		_, err := rnd.Read(label)
		if err != nil {
			b.Fatal(err)
		}

		_, _, _, _, errb := tree.Get(label)
		if errb {
			b.Fatal()
		}
	}
}
