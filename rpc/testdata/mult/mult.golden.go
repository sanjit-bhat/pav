// Auto-generated from spec "github.com/mit-pdos/pav/rpc/testdata/mult/mult.go"
// using compiler "github.com/mit-pdos/pav/rpc".
package rpc

import (
	"github.com/mit-pdos/pav/marshalutil"
	"github.com/tchajed/marshal"
)

func arg1Encode(b0 []byte, o *arg1) []byte {
	var b = b0
	b = marshal.WriteInt(b, o.x)
	return b
}
func arg1Decode(b0 []byte) (*arg1, []byte, bool) {
	a1, b1, err1 := marshalutil.ReadInt(b0)
	if err1 {
		return nil, true
	}
	return &arg1{x: a1}, b1, false
}
func arg2Encode(b0 []byte, o *arg2) []byte {
	var b = b0
	b = marshal.WriteInt(b, o.y)
	return b
}
func arg2Decode(b0 []byte) (*arg2, []byte, bool) {
	a1, b1, err1 := marshalutil.ReadInt(b0)
	if err1 {
		return nil, true
	}
	return &arg2{y: a1}, b1, false
}
