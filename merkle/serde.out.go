// Auto-generated from spec "github.com/mit-pdos/pav/merkle/serde.go"
// using compiler "github.com/mit-pdos/pav/serde".
package merkle

import (
	"github.com/mit-pdos/pav/marshalutil"
)

func MerkleProofDecode(b0 []byte) (*MerkleProof, []byte, bool) {
	a1, b1, err1 := marshalutil.ReadSlice1D(b0)
	if err1 {
		return nil, nil, true
	}
	a2, b2, err2 := marshalutil.ReadSlice1D(b1)
	if err2 {
		return nil, nil, true
	}
	a3, b3, err3 := marshalutil.ReadSlice1D(b2)
	if err3 {
		return nil, nil, true
	}
	return &MerkleProof{Siblings: a1, LeafLabel: a2, LeafVal: a3}, b3, false
}
