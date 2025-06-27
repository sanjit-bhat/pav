// Auto-generated from spec "github.com/sanjit-bhat/pav/serde/testdata/types/types.go"
// using compiler "github.com/sanjit-bhat/pav/serde".
package serde

import (
	"github.com/sanjit-bhat/pav/marshalutil"
	"github.com/tchajed/marshal"
)

func argsEncode(b0 []byte, o *args) []byte {
	var b = b0
	b = marshal.WriteBool(b, o.a1)
	b = marshalutil.WriteByte(b, o.a2)
	b = marshal.WriteInt(b, o.a3)
	b = marshalutil.WriteSlice1D(b, o.a4)
	b = marshalutil.WriteSlice2D(b, o.a5)
	b = marshalutil.WriteSlice3D(b, o.a6)
	return b
}
func argsDecode(b0 []byte) (*args, []byte, bool) {
	a1, b1, err1 := marshalutil.ReadBool(b0)
	if err1 {
		return nil, nil, true
	}
	a2, b2, err2 := marshalutil.ReadByte(b1)
	if err2 {
		return nil, nil, true
	}
	a3, b3, err3 := marshalutil.ReadInt(b2)
	if err3 {
		return nil, nil, true
	}
	a4, b4, err4 := marshalutil.ReadSlice1D(b3)
	if err4 {
		return nil, nil, true
	}
	a5, b5, err5 := marshalutil.ReadSlice2D(b4)
	if err5 {
		return nil, nil, true
	}
	a6, b6, err6 := marshalutil.ReadSlice3D(b5)
	if err6 {
		return nil, nil, true
	}
	return &args{a1: a1, a2: a2, a3: a3, a4: a4, a5: a5, a6: a6}, b6, false
}
