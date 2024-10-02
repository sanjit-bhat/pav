// Auto-generated from spec "github.com/mit-pdos/pav/rpc/testdata/mult/mult.go"
// using compiler "github.com/mit-pdos/pav/rpc".
package rpc

import (
	"github.com/mit-pdos/pav/marshalutil"
	"github.com/tchajed/marshal"
)

func (o *arg1) Encode() []byte {
	var b = make([]byte, 0)
	b = marshal.WriteInt(b, o.x)
	return b
}
func (o *arg1) Decode(b0 []byte) ([]byte, bool) {
	x, b1, err1 := marshalutil.ReadInt(b0)
	if err1 {
		return nil, true
	}
	o.x = x
	return b1, false
}
func (o *arg2) Encode() []byte {
	var b = make([]byte, 0)
	b = marshal.WriteInt(b, o.y)
	return b
}
func (o *arg2) Decode(b0 []byte) ([]byte, bool) {
	y, b1, err1 := marshalutil.ReadInt(b0)
	if err1 {
		return nil, true
	}
	o.y = y
	return b1, false
}
