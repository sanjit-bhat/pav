package chat4

import (
	"github.com/tchajed/marshal"
)

type msgT struct {
	tag uint64
	body uint64
	pin  uint64
}

const MSGT_SIZE uint64 = 8 + 8 + 8

func newMsgT(tag, body, pin uint64) *msgT {
	return &msgT{tag: tag, body: body, pin: pin}
}

func newMsgTSlice() []byte {
	return make([]byte, MSGT_SIZE)
}

func encodeMsgT(m *msgT) []byte {
	b1 := make([]byte, 0)
	b2 := marshal.WriteInt(b1, m.tag)
	b3 := marshal.WriteInt(b2, m.body)
	b4 := marshal.WriteInt(b3, m.pin)
	return b4
}

func decodeMsgT(b []byte) (*msgT, []byte) {
	tag, b2 := marshal.ReadInt(b)
	body, b3 := marshal.ReadInt(b2)
	pin, b4 := marshal.ReadInt(b3)
	return newMsgT(tag, body, pin), b4
}

type msgWrapT struct {
	msg *msgT
	// The sig is over only the msg field.
	// It is a slice for convenience, although we assume it has a fixed length of 64.
	sig []byte
	sn  uint64
}
const MSGWRAPT_ADD_SIZE uint64 = 64 + 8
const MSGWRAPT_SIZE uint64 = MSGT_SIZE + MSGWRAPT_ADD_SIZE

func newMsgWrapT(msg *msgT, sig []byte, sn uint64) *msgWrapT {
	return &msgWrapT{msg: msg, sig: sig, sn: sn}
}

func newMsgWrapTSlice() []byte {
	return make([]byte, MSGWRAPT_SIZE)
}

func encodeMsgWrapT(m *msgWrapT) []byte {
	b1 := encodeMsgT(m.msg)
	b2 := marshal.WriteBytes(b1, m.sig)
	b3 := marshal.WriteInt(b2, m.sn)
	return b3
}

func decodeMsgWrapT(b []byte) (*msgWrapT, []byte) {
	msg, b2 := decodeMsgT(b)
	sig, b3 := marshal.ReadBytesCopy(b2, 64)
	sn, b4 := marshal.ReadInt(b3)
	return newMsgWrapT(msg, sig, sn), b4
}
