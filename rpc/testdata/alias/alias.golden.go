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
func argDecode(b0 []byte) (*arg, []byte, bool) {
	a1, b1, err1 := marshalutil.ReadInt(b0)
	if err1 {
		return nil, true
	}
	a2, b2, err2 := marshalutil.ReadInt(b1)
	if err2 {
		return nil, true
	}
	return &arg{x: a1, y: a2}, b2, false
}
