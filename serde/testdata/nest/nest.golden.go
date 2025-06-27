// Auto-generated from spec "github.com/sanjit-bhat/pav/serde/testdata/nest/nest.go"
// using compiler "github.com/sanjit-bhat/pav/serde".
package serde

import (
	"github.com/sanjit-bhat/pav/marshalutil"
	"github.com/tchajed/marshal"
)

func innerEncode(b0 []byte, o *inner) []byte {
	var b = b0
	b = marshal.WriteInt(b, o.a1)
	return b
}
func innerDecode(b0 []byte) (*inner, []byte, bool) {
	a1, b1, err1 := marshalutil.ReadInt(b0)
	if err1 {
		return nil, nil, true
	}
	return &inner{a1: a1}, b1, false
}
func outerEncode(b0 []byte, o *outer) []byte {
	var b = b0
	b = innerEncode(b, o.a1)
	b = innerSlice1DEncode(b, o.a2)
	b = Mapuint64innerEncode(b, o.a3)
	return b
}
func outerDecode(b0 []byte) (*outer, []byte, bool) {
	a1, b1, err1 := innerDecode(b0)
	if err1 {
		return nil, nil, true
	}
	a2, b2, err2 := innerSlice1DDecode(b1)
	if err2 {
		return nil, nil, true
	}
	a3, b3, err3 := Mapuint64innerDecode(b2)
	if err3 {
		return nil, nil, true
	}
	return &outer{a1: a1, a2: a2, a3: a3}, b3, false
}
