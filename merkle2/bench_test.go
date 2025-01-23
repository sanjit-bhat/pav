package merkle

import (
	"github.com/mit-pdos/pav/cryptoffi"
	"math/rand/v2"
	"testing"
)

var val = []byte("val")

/*
func BenchmarkPut(b *testing.B) {
	for range b.N {
		b.StopTimer()
		tr, rnd, label := newSeededTree(b, 1000)
		b.StartTimer()

		for i := 0; i < 1000; i++ {
			// TODO: this is affecting measurement.
			b.StopTimer()
			_, err := rnd.Read(label)
			if err != nil {
				b.Fatal(err)
			}
			b.StartTimer()

			errb := tr.Put(label, val)
			if errb {
				b.Fatal()
			}
		}
	}
}
*/

func BenchmarkGetMemb(b *testing.B) {
	for range b.N {
		b.StopTimer()
		tr, _, label := newSeededTree(b, 1000)
		b.StartTimer()

		for i := 0; i < 1000; i++ {
			_, _, errb := tr.Get(label)
			if errb {
				b.Fatal()
			}
		}
	}
}

func BenchmarkGetNonMemb(b *testing.B) {
	for range b.N {
		b.StopTimer()
		tr, rnd, label := newSeededTree(b, 1000)
		_, err := rnd.Read(label)
		if err != nil {
			b.Fatal(err)
		}
		b.StartTimer()

		for i := 0; i < 1000; i++ {
			// TODO: inTree isn't correct. fix later.
			_, _, errb := tr.Get(label)
			if errb {
				b.Fatal()
			}
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
		errb := tr.Put(label, val)
		if errb {
			b.Fatal()
		}
	}
	return
}
