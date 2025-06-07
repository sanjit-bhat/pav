// Package hashchain commits to a list of values.
package hashchain

import (
	"github.com/goose-lang/std"
	"github.com/mit-pdos/pav/cryptoffi"
	"github.com/mit-pdos/pav/cryptoutil"
	"github.com/mit-pdos/pav/marshalutil"
)

type HashChain struct {
	lastLink []byte
	// vals is pre-flattened to quickly convert it to a proof.
	vals []byte
}

// Append adds a val and returns the new link.
// it errors if the val isn't constant len, which lets us encode smaller proofs.
func (c *HashChain) Append(val []byte) ([]byte, bool) {
	if uint64(len(val)) != cryptoffi.HashLen {
		return nil, true
	}
	c.lastLink = compNextLink(c.lastLink, val)
	c.vals = append(c.vals, val...)
	return c.lastLink, false
}

// Prove lets a client go from knowing a prevLen prefix to knowing
// the last val of the latest list.
// it returns a proof and the last val.
// it expects there to be vals and errors if
// prevLen >= the curr len.
func (c *HashChain) Prove(prevLen uint64) ([]byte, []byte, bool) {
	numVals := uint64(len(c.vals)) / cryptoffi.HashLen
	std.Assert(numVals != 0)
	if prevLen >= numVals {
		return nil, nil, true
	}

	proofLen := (numVals - 1 - prevLen) * cryptoffi.HashLen
	start := prevLen * cryptoffi.HashLen
	end := start + proofLen
	var proof = make([]byte, 0, 8+proofLen)
	proof = marshalutil.WriteSlice1D(proof, c.vals[start:end])
	lastVal := std.BytesClone(c.vals[end:])
	return proof, lastVal, false
}

// Verify checks that newVal is in the list, returning the new length and link.
// it errors if the proof is improperly encoded or the new length overflows.
func Verify(prevLen uint64, prevLink, proof, newVal []byte) (uint64, []byte, bool) {
	proof0, _, err := marshalutil.ReadSlice1D(proof)
	if err {
		return 0, nil, true
	}
	proofLen := uint64(len(proof0))
	if proofLen%cryptoffi.HashLen != 0 {
		return 0, nil, true
	}
	proofVals := proofLen / cryptoffi.HashLen
	if !std.SumNoOverflow(prevLen, proofVals+1) {
		return 0, nil, true
	}
	newLen := prevLen + proofVals + 1

	var newLink = prevLink
	for i := uint64(0); i < proofVals; i++ {
		start := i * cryptoffi.HashLen
		end := (i + 1) * cryptoffi.HashLen
		newLink = compNextLink(newLink, proof0[start:end])
	}
	newLink = compNextLink(newLink, newVal)
	return newLen, newLink, false
}

func New() *HashChain {
	return &HashChain{lastLink: cryptoutil.Hash(nil)}
}

func compNextLink(prevLink, nextVal []byte) []byte {
	hr := cryptoffi.NewHasher()
	hr.Write(prevLink)
	hr.Write(nextVal)
	return hr.Sum(nil)
}
