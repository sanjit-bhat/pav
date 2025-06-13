// Package hashchain commits to a list of values.
package hashchain

import (
	"github.com/goose-lang/std"
	"github.com/mit-pdos/pav/cryptoffi"
	"github.com/mit-pdos/pav/cryptoutil"
)

type HashChain struct {
	lastLink []byte
	// vals is pre-flattened to quickly convert it to a proof.
	vals []byte
}

// Append adds a val and returns the new link.
// it expects val to be of constant len, which lets us encode smaller proofs.
func (c *HashChain) Append(val []byte) []byte {
	std.Assert(uint64(len(val)) == cryptoffi.HashLen)
	c.lastLink = getNextLink(c.lastLink, val)
	c.vals = append(c.vals, val...)
	return c.lastLink
}

// Prove transitions from knowing a prevLen prefix to knowing the latest list.
// it expects prevLen <= curr len.
func (c *HashChain) Prove(prevLen uint64) []byte {
	start := prevLen * cryptoffi.HashLen
	return std.BytesClone(c.vals[start:])
}

// Verify updates prevLink with proof, returning the extended length,
// new val, and new link.
// if length extension is 0, new val is nil.
// it errors on failure.
func Verify(prevLink, proof []byte) (uint64, []byte, []byte, bool) {
	proofLen := uint64(len(proof))
	if proofLen%cryptoffi.HashLen != 0 {
		return 0, nil, nil, true
	}
	lenVals := proofLen / cryptoffi.HashLen

	var newVal []byte
	var newLink = prevLink
	for i := uint64(0); i < lenVals; i++ {
		start := i * cryptoffi.HashLen
		end := (i + 1) * cryptoffi.HashLen
		newVal = proof[start:end]
		newLink = getNextLink(newLink, newVal)
	}
	return lenVals, newVal, newLink, false
}

func New() *HashChain {
	return &HashChain{lastLink: getEmptyLink()}
}

func getEmptyLink() []byte {
	return cryptoutil.Hash(nil)
}

func getNextLink(prevLink, nextVal []byte) []byte {
	hr := cryptoffi.NewHasher()
	hr.Write(prevLink)
	hr.Write(nextVal)
	return hr.Sum(nil)
}
