// Auto-generated from spec "github.com/mit-pdos/pav/rpc/testdata/nest/nest.go"
// using compiler "github.com/mit-pdos/pav/rpc".
package rpc

import (
	"github.com/mit-pdos/pav/marshalutil"
	"github.com/tchajed/marshal"
)

func (o *inner) Encode() []byte {
	var b = make([]byte, 0)
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
func (o *outer) Encode() []byte {
	var b = make([]byte, 0)
	b = marshal.WriteBytes(b, o.a1.Encode())
	return b
}
func outerDecode(b0 []byte) (*outer, []byte, bool) {
	a1, b1, err1 := innerDecode(b0)
	if err1 {
		return nil, true
	}
	return &outer{a1: a1}, b1, false
}
