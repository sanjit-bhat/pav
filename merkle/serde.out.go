// Auto-generated from spec "github.com/sanjit-bhat/pav/merkle/serde.go"
// using compiler "github.com/sanjit-bhat/pav/serde".
package merkle

import (
	"github.com/sanjit-bhat/pav/safemarshal"
	"github.com/tchajed/marshal"
)

func MerkleProofEncode(b0 []byte, o *MerkleProof) []byte {
	var b = b0
	b = safemarshal.WriteSlice1D(b, o.Siblings)
	b = marshal.WriteBool(b, o.IsOtherLeaf)
	b = safemarshal.WriteSlice1D(b, o.LeafLabel)
	b = safemarshal.WriteSlice1D(b, o.LeafVal)
	return b
}
func MerkleProofDecode(b0 []byte) (*MerkleProof, []byte, bool) {
	a1, b1, err1 := safemarshal.ReadSlice1D(b0)
	if err1 {
		return nil, nil, true
	}
	a2, b2, err2 := safemarshal.ReadBool(b1)
	if err2 {
		return nil, nil, true
	}
	a3, b3, err3 := safemarshal.ReadSlice1D(b2)
	if err3 {
		return nil, nil, true
	}
	a4, b4, err4 := safemarshal.ReadSlice1D(b3)
	if err4 {
		return nil, nil, true
	}
	return &MerkleProof{Siblings: a1, IsOtherLeaf: a2, LeafLabel: a3, LeafVal: a4}, b4, false
}
