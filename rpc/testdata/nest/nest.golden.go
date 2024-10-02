// Auto-generated from spec "github.com/mit-pdos/pav/rpc/testdata/types/types.go"
// using compiler "github.com/mit-pdos/pav/rpc".
package rpc

import (
	"github.com/mit-pdos/pav/marshalutil"
	"github.com/tchajed/marshal"
)

func (o *inner) encode() []byte {
	var b = make([]byte, 0)
	b = marshal.WriteInt(b, o.a1)
	return b
}
func (o *inner) decode(b0 []byte) ([]byte, bool) {
	var b = b0
	a1, b, err := marshalutil.ReadInt(b)
	if err {
		return nil, true
	}
	o.a1 = a1
	return b, false
}
func (o *outer) encode() []byte {
	var b = make([]byte, 0)
	b = marshal.WriteBytes(b, o.a1.encode())
	return b
}
func (o *outer) decode(b0 []byte) ([]byte, bool) {
	var b = b0
	a1 := &inner{}
	b, err := a1.decode(b)
	if err {
		return nil, true
	}
	o.a1 = a1
	return b, false
}
