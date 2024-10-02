// Auto-generated from spec "github.com/mit-pdos/pav/rpc/testdata/const/const.go"
// using compiler "github.com/mit-pdos/pav/rpc".
package rpc

import (
	"github.com/mit-pdos/pav/marshalutil"
	"github.com/tchajed/marshal"
)

func (o *args) encode() []byte {
	var b = make([]byte, 0)
	b = marshal.WriteBool(b, true)
	b = marshalutil.WriteByte(b, 3)
	b = marshal.WriteInt(b, 3)
	return b
}
func (o *args) decode(b0 []byte) ([]byte, errorTy) {
	var b = b0
	a1, b, err := marshalutil.ReadConstBool(b, true)
	if err {
		return nil, err
	}
	a2, b, err := marshalutil.ReadConstByte(b, 3)
	if err {
		return nil, err
	}
	a3, b, err := marshalutil.ReadConstInt(b, 3)
	if err {
		return nil, err
	}
	o.a1 = a1
	o.a2 = a2
	o.a3 = a3
	return b, errNone
}
