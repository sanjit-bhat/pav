// Auto-generated from spec "github.com/mit-pdos/pav/rpc/testdata/mult/mult.go"
// using compiler "github.com/mit-pdos/pav/rpc".
package rpc

import (
	"github.com/mit-pdos/pav/marshalutil"
	"github.com/tchajed/marshal"
)

func (o *arg1) encode() []byte {
	var b = make([]byte, 0)
	b = marshal.WriteInt(b, o.x)
	return b
}
func (o *arg1) decode(b0 []byte) ([]byte, errorTy) {
	var b = b0
	x, b, err := marshalutil.ReadInt(b)
	if err {
		return nil, err
	}
	o.x = x
	return b, errNone
}
func (o *arg2) encode() []byte {
	var b = make([]byte, 0)
	b = marshal.WriteInt(b, o.y)
	return b
}
func (o *arg2) decode(b0 []byte) ([]byte, errorTy) {
	var b = b0
	y, b, err := marshalutil.ReadInt(b)
	if err {
		return nil, err
	}
	o.y = y
	return b, errNone
}
