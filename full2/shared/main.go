package shared

import (
	"github.com/tchajed/marshal"
)

type ErrorT = uint64

const (
	ErrNone    ErrorT = 0
	ErrSome    ErrorT = 1
	RpcGet     uint64 = 1
	RpcPut     uint64 = 2
	AliceNum   uint64 = 0
	BobNum     uint64 = 1
	MaxSenders uint64 = 2
	AliceMsg   uint64 = 10
	BobMsg     uint64 = 11
	SigLen     uint64 = 69
)

// *MsgT

type MsgT struct {
	Body uint64
}

const MSGT_SIZE uint64 = 8

func (m *MsgT) Equals(o *MsgT) bool {
	return m.Body == o.Body
}

func IsMsgTPrefix(short, long []*MsgT) bool {
	if len(long) < len(short) {
		return false
	}
	var ret = true
	for i, m := range short {
		if !m.Equals(long[i]) {
			ret = false
		}
	}
	return ret
}

func NewMsgT(body uint64) *MsgT {
	return &MsgT{Body: body}
}

func EncodeMsgT(m *MsgT) []byte {
	var b = make([]byte, 0)
	b = marshal.WriteInt(b, m.Body)
	return b
}

func DecodeMsgT(b []byte) (*MsgT, []byte) {
	body, b2 := marshal.ReadInt(b)
	return NewMsgT(body), b2
}

// []*MsgT

func EncodeMsgTSlice(sl []*MsgT) []byte {
	var b = make([]byte, 0)
	b = marshal.WriteInt(b, uint64(len(sl)))
	for _, v := range sl {
		b = marshal.WriteBytes(b, EncodeMsgT(v))
	}
	return b
}

func DecodeMsgTSlice(b []byte) ([]*MsgT, []byte) {
	var b2 = b
	l, b2 := marshal.ReadInt(b2)
	sl := make([]*MsgT, l)
	for i := uint64(0); i < l; i++ {
		sl[i], b2 = DecodeMsgT(b2)
	}
	return sl, b2
}
