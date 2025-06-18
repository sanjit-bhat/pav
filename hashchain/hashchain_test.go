package hashchain

import (
	"bytes"
	"math/rand/v2"
	"testing"

	"github.com/mit-pdos/pav/cryptoffi"
)

func TestHashChain(t *testing.T) {
	var seed [32]byte
	rndSrc := rand.NewChaCha8(seed)
	rnd := rand.New(rndSrc)
	chain := New()
	links := [][]byte{GetEmptyLink()}

	{
		// empty chain.
		p := chain.Prove(0)
		newLen, newVal, newLink, err := Verify(links[0], p)
		if err {
			t.Fatal()
		}
		if newLen != 0 {
			t.Fatal()
		}
		if newVal != nil {
			t.Fatal()
		}
		if !bytes.Equal(links[0], newLink) {
			t.Fatal()
		}
	}

	for newLen := uint64(1); newLen < 1_000; newLen++ {
		newVal := make([]byte, cryptoffi.HashLen)
		rndSrc.Read(newVal)
		newLink := chain.Append(newVal)
		links = append(links, newLink)

		prevLen := rnd.Uint64N(newLen + 1)
		proof0 := chain.Prove(prevLen)
		extLen0, newVal0, newLink0, err := Verify(links[prevLen], proof0)
		if err {
			t.Fatal()
		}
		if extLen0 != newLen-prevLen {
			t.Fatal()
		}
		if extLen0 == 0 && newVal0 != nil {
			t.Fatal()
		}
		if extLen0 != 0 && !bytes.Equal(newVal, newVal0) {
			t.Fatal()
		}
		if !bytes.Equal(newLink, newLink0) {
			t.Fatal()
		}

		startLink, startVal := chain.ProveLast()
		extLen1, newVal1, newLink1, err := Verify(startLink, startVal)
		if err {
			t.Fatal()
		}
		if extLen1 != 1 {
			t.Fatal()
		}
		if !bytes.Equal(newVal, newVal1) {
			t.Fatal()
		}
		if !bytes.Equal(newLink, newLink1) {
			t.Fatal()
		}
	}
}
