package full2

import (
	"github.com/tchajed/marshal"
)

type errorT = uint64

const (
	ErrNone    errorT = 0
	ErrSome    errorT = 1
	RpcGet     uint64 = 1
	RpcPut     uint64 = 2
	AliceNum   uint64 = 0
	BobNum     uint64 = 1
	MaxSenders uint64 = 2
	AliceMsg   uint64 = 10
	BobMsg     uint64 = 11
	SigLen     uint64 = 69
)

// *msgT

type msgT struct {
	body uint64
}

const MSGT_SIZE uint64 = 8

func (m *msgT) equals(o *msgT) bool {
    return m.body == o.body
}

func isMsgTPrefix(short, long []*msgT) bool {
	if len(long) < len(short) {
		return false
	}
	for i, m := range short {
		if !m.equals(long[i]) {
			return false
		}
	}
	return true
}

func newMsgT(body uint64) *msgT {
	return &msgT{body: body}
}

func encodeMsgT(m *msgT) []byte {
	var b = make([]byte, 0)
	b = marshal.WriteInt(b, m.body)
	return b
}

func decodeMsgT(b []byte) (*msgT, []byte) {
	body, b2 := marshal.ReadInt(b)
	return newMsgT(body), b2
}

// []*msgT

func encodeMsgTSlice(sl []*msgT) []byte {
	var b = make([]byte, 0)
	b = marshal.WriteInt(b, uint64(len(sl)))
	for _, v := range sl {
		b = marshal.WriteBytes(b, encodeMsgT(v))
	}
	return b
}

func decodeMsgTSlice(b []byte) ([]*msgT, []byte) {
	var b2 = b
	l, b2 := marshal.ReadInt(b2)
	sl := make([]*msgT, l)
	for i := uint64(0); i < l; i++ {
		sl[i], b2 = decodeMsgT(b2)
	}
	return sl, b2
}
