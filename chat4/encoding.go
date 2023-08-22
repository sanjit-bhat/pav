package chat4

import (
	"github.com/tchajed/marshal"
)

type msgT struct {
	body uint64
	sn   uint64
	pin  uint64
}

func newMsgT(body, sn, pin uint64) msgT {
	return msgT{body: body, sn: sn, pin: pin}
}

func encodeMsgT(m msgT) []byte {
	b1 := make([]byte, 0)
	b2 := marshal.WriteInt(b1, m.body)
	b3 := marshal.WriteInt(b2, m.sn)
	b4 := marshal.WriteInt(b3, m.pin)
	return b4
}

func newMsgTSlice() []byte {
	return make([]byte, 24)
}

func decodeMsgT(b1 []byte) msgT {
	body, b2 := marshal.ReadInt(b1)
	sn, b3 := marshal.ReadInt(b2)
	pin, _ := marshal.ReadInt(b3)
	return newMsgT(body, sn, pin)
}
