// Auto-generated from spec "github.com/mit-pdos/pav/rpc/testdata/alias/alias.go"
// using compiler "github.com/mit-pdos/pav/rpc".
package rpc

import (
	"github.com/mit-pdos/pav/marshalutil"
	"github.com/tchajed/marshal"
)

func (o *arg) Encode() []byte {
	var b = make([]byte, 0)
	b = marshal.WriteInt(b, o.x)
	b = marshal.WriteInt(b, o.y)
	return b
}
func (o *arg) Decode(b0 []byte) ([]byte, bool) {
	x, b1, err1 := marshalutil.ReadInt(b0)
	if err1 {
		return nil, true
	}
	y, b2, err2 := marshalutil.ReadInt(b1)
	if err2 {
		return nil, true
	}
	o.x = x
	o.y = y
	return b2, false
}
