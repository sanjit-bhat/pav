package rpc

import (
	"github.com/mit-pdos/pav/marshalutil"
	"github.com/tchajed/marshal"
)

type errorTy = bool

const (
	errNone errorTy = false
	errSome errorTy = true
)

func (o *arg) encode() []byte {
	var b = make([]byte, 0)
	b = marshal.WriteInt(b, o.x)
	b = marshal.WriteInt(b, o.y)
	return b
}

func (o *arg) decode(b0 []byte) ([]byte, errorTy) {
	var b = b0
	x, b, err := marshalutil.SafeReadInt(b)
	if err {
		return nil, err
	}
	y, b, err := marshalutil.SafeReadInt(b)
	if err {
		return nil, err
	}
	o.x = x
	o.y = y
	return b, errNone
}
