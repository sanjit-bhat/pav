// Package hashchain commits to a list of values.
package hashchain

import (
	"github.com/goose-lang/std"
	"github.com/sanjit-bhat/pav/cryptoffi"
	"github.com/sanjit-bhat/pav/cryptoutil"
)

type HashChain struct {
	predLastLink []byte
	lastLink     []byte
	// vals is pre-flattened to quickly convert it to a proof.
	vals []byte
}

// Append adds a val.
// it expects val to be of constant len, which lets us encode smaller proofs.
func (c *HashChain) Append(val []byte) (newLink []byte) {
	std.Assert(uint64(len(val)) == cryptoffi.HashLen)
	c.predLastLink = c.lastLink
	c.lastLink = GetNextLink(c.lastLink, val)
	c.vals = append(c.vals, val...)
	return c.lastLink
}

// Prove transitions from knowing a prevLen prefix to knowing the latest list.
// it expects prevLen <= curr len.
func (c *HashChain) Prove(prevLen uint64) (proof []byte) {
	start := prevLen * cryptoffi.HashLen
	return std.BytesClone(c.vals[start:])
}

// Bootstrap hashchain verifiers with the last value.
// it expects non-empty values.
func (c *HashChain) Bootstrap() (lastVal []byte, proof []byte) {
	start := uint64(len(c.vals)) - cryptoffi.HashLen
	return c.predLastLink, std.BytesClone(c.vals[start:])
}

// Verify updates prevLink with proof.
// it errors for a badly-encoded proof.
func Verify(prevLink, proof []byte) (extLen uint64, newVal []byte, newLink []byte, err bool) {
	proofLen := uint64(len(proof))
	if proofLen%cryptoffi.HashLen != 0 {
		err = true
		return
	}
	extLen = proofLen / cryptoffi.HashLen

	newLink = prevLink
	for i := uint64(0); i < extLen; i++ {
		start := i * cryptoffi.HashLen
		end := (i + 1) * cryptoffi.HashLen
		newVal = proof[start:end]
		newLink = GetNextLink(newLink, newVal)
	}
	return
}

func New() *HashChain {
	return &HashChain{lastLink: GetEmptyLink()}
}

func GetEmptyLink() []byte {
	return cryptoutil.Hash(nil)
}

func GetNextLink(prevLink, nextVal []byte) []byte {
	hr := cryptoffi.NewHasher()
	hr.Write(prevLink)
	hr.Write(nextVal)
	return hr.Sum(nil)
}
