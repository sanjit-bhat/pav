package shared

import (
	"github.com/tchajed/goose/machine"
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

func NewMsgT(body uint64) *MsgT {
	return &MsgT{Body: body}
}

func (m *MsgT) Equals(o *MsgT) bool {
	return m.Body == o.Body
}

func (m *MsgT) Copy() *MsgT {
	return &MsgT{Body: m.Body}
}

func (m *MsgT) Encode() []byte {
	var b = make([]byte, 0)
	b = marshal.WriteInt(b, m.Body)
	return b
}

func DecodeMsgT(b []byte) (*MsgT, []byte) {
	body, b2 := marshal.ReadInt(b)
	return NewMsgT(body), b2
}

// []*MsgT

func CopyMsgTSlice(sl []*MsgT) []*MsgT {
	var sl2 = make([]*MsgT, len(sl))
	for i, v := range sl {
		sl2[i] = v.Copy()
	}
	return sl2
}

func IsMsgTSlicePrefix(short, long []*MsgT) bool {
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

func EncodeMsgTSlice(sl []*MsgT) []byte {
	var b = make([]byte, 0)
	b = marshal.WriteInt(b, uint64(len(sl)))
	for _, v := range sl {
		b = marshal.WriteBytes(b, v.Encode())
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

// *PutArg

type PutArg struct {
	Sender uint64
	Sig    []byte
	LogB   []byte
}

func NewPutArg(sender uint64, sig, logB []byte) *PutArg {
	return &PutArg{Sender: sender, Sig: sig, LogB: logB}
}

func (pa *PutArg) Encode() []byte {
	// ECDSA_P256 gave diff len sigs, which complicates encoding.
	// ED25519 should have const len sigs.
	machine.Assume(uint64(len(pa.Sig)) == SigLen)
	var b = make([]byte, 0)
	b = marshal.WriteInt(b, pa.Sender)
	b = marshal.WriteBytes(b, pa.Sig)
	b = marshal.WriteBytes(b, pa.LogB)
	return b
}

// Input comes from adv RPC, so need to validate it.
func DecodePutArg(b []byte) (*PutArg, ErrorT) {
	if len(b) < 8 {
		return nil, ErrSome
	}
	sender, r2 := marshal.ReadInt(b)
	if !(0 <= sender && sender < MaxSenders) {
		return nil, ErrSome
	}
	if uint64(len(r2)) < SigLen {
		return nil, ErrSome
	}
	sig, logB := marshal.ReadBytes(r2, SigLen)
	return NewPutArg(sender, sig, logB), ErrNone
}
