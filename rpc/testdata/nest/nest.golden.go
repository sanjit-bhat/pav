// Auto-generated from spec "github.com/mit-pdos/pav/rpc/testdata/nest/nest.go"
// using compiler "github.com/mit-pdos/pav/rpc".
package rpc

import (
	"github.com/mit-pdos/pav/marshalutil"
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
		return nil, true
	}
	return &inner{a1: a1}, b1, false
}
func outerEncode(b0 []byte, o *outer) []byte {
	var b = b0
	b = innerEncode(b, o.a1)
	return b
}
func outerDecode(b0 []byte) (*outer, []byte, bool) {
	a1, b1, err1 := innerDecode(b0)
	if err1 {
		return nil, true
	}
	return &outer{a1: a1}, b1, false
}
