package full2

import (
	"github.com/tchajed/marshal"
)

type errorT = bool

const (
	errNone bool   = false
	errSome bool   = true
	rpcGet  uint64 = 1
	rpcPut  uint64 = 2
)

// *msgT

type msgT struct {
    body uint64
}

const MSGT_SIZE uint64 = 8

func newMsgT(body uint64) *msgT {
	return &msgT{body: body}
}

func encodeMsgT(m *msgT) []byte {
    var b []byte
	b = marshal.WriteInt(b, m.body)
	return b
}

func decodeMsgT(b []byte) (*msgT, []byte) {
	body, b := marshal.ReadInt(b)
	return newMsgT(body), b
}

// []*msgT

func encodeSliceMsgT(sl []*msgT) []byte {
    var b []byte
    b = marshal.WriteInt(b, uint64(len(sl)))
    for _, v := range sl {
        b = marshal.WriteBytes(b, encodeMsgT(v))
    }
    return b
}

func decodeSliceMsgT(b []byte) ([]*msgT, []byte) {
    l, b := marshal.ReadInt(b)
    sl := make([]*msgT, l)
    for i := 0; i < int(l); i++ {
        sl[i], b = decodeMsgT(b)
    }
    return sl, b
}
