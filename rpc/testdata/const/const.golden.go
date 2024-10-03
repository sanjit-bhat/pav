// Auto-generated from spec "github.com/mit-pdos/pav/rpc/testdata/const/const.go"
// using compiler "github.com/mit-pdos/pav/rpc".
package rpc

import (
	"github.com/mit-pdos/pav/marshalutil"
	"github.com/tchajed/marshal"
)

func argsEncode(b0 []byte, o *args) []byte {
	var b = b0
	b = marshal.WriteBool(b, true)
	b = marshalutil.WriteByte(b, 3)
	b = marshal.WriteInt(b, 3)
	return b
}
func argsDecode(b0 []byte) (*args, []byte, bool) {
	a1, b1, err1 := marshalutil.ReadConstBool(b0, true)
	if err1 {
		return nil, nil, true
	}
	a2, b2, err2 := marshalutil.ReadConstByte(b1, 3)
	if err2 {
		return nil, nil, true
	}
	a3, b3, err3 := marshalutil.ReadConstInt(b2, 3)
	if err3 {
		return nil, nil, true
	}
	return &args{a1: a1, a2: a2, a3: a3}, b3, false
}
