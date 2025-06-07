package hashchain

import (
	"bytes"
	"math/rand/v2"
	"testing"

	"github.com/mit-pdos/pav/cryptoffi"
	"github.com/mit-pdos/pav/cryptoutil"
)

func TestHashChain(t *testing.T) {
	c := New()
	links := [][]byte{cryptoutil.Hash(nil)}

	for i := uint64(0); i < 1_000; i++ {
		v := make([]byte, cryptoffi.HashLen)
		newLink, err := c.Append(v)
		if err {
			t.Fatal()
		}
		links = append(links, newLink)

		prevLen := rand.Uint64N(i + 1)
		proof, v0, err := c.Prove(prevLen)
		if err {
			t.Fatal()
		}
		if !bytes.Equal(v, v0) {
			t.Fatal()
		}

		newLen, newLink0, err := Verify(prevLen, links[prevLen], proof, v)
		if err {
			t.Fatal()
		}
		if newLen != i+1 {
			t.Fatal()
		}
		if !bytes.Equal(newLink, newLink0) {
			t.Fatal()
		}
	}
}
