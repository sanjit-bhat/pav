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

// MsgT

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

func (m *MsgT) Decode(b []byte) []byte {
	body, b2 := marshal.ReadInt(b)
	m = NewMsgT(body)
	return b2
}

// LogT

type LogT struct {
	Msgs []*MsgT
}

func NewLogT(msgs []*MsgT) *LogT {
	return &LogT{Msgs: msgs}
}

func (l *LogT) Copy() *LogT {
	msgsCopy := make([]*MsgT, len(l.Msgs))
	copy(msgsCopy, l.Msgs)
	return &LogT{Msgs: msgsCopy}
}

func (short *LogT) IsPrefix(long *LogT) bool {
	if len(long.Msgs) < len(short.Msgs) {
		return false
	}
	var ret = true
	for i, m := range short.Msgs {
		if !m.Equals(long.Msgs[i]) {
			ret = false
		}
	}
	return ret
}

func (l *LogT) Encode() []byte {
	var b = make([]byte, 0)
	b = marshal.WriteInt(b, uint64(len(l.Msgs)))
	for _, v := range l.Msgs {
		b = marshal.WriteBytes(b, v.Encode())
	}
	return b
}

func (l *LogT) Decode(b []byte) []byte {
	var b2 = b
	ln, b2 := marshal.ReadInt(b2)
	sl := make([]*MsgT, ln)
	for i := uint64(0); i < ln; i++ {
		b2 = sl[i].Decode(b2)
	}
	l = NewLogT(sl)
	return b2
}

// SigDataT

type SigDataT struct {
	Msg  *MsgT
	Hist *LogT
}

func NewSigDataT(msg *MsgT, hist *LogT) *SigDataT {
	return &SigDataT{Msg: msg, Hist: hist}
}

func (s *SigDataT) Encode() []byte {
	var b = make([]byte, 0)
	b = marshal.WriteBytes(b, s.Msg.Encode())
	b = marshal.WriteBytes(b, s.Hist.Encode())
	return b
}

func (s *SigDataT) Decode(b []byte) []byte {
	var b2 = b
	b2 = s.Msg.Decode(b2)
	b2 = s.Hist.Decode(b2)
	return b2
}

// PutArgT

// Keep SigData as bytes here because this will soon
// be run thru crypto verify to assume its structure,
// without us having to manually write structure checks.
type PutArgT struct {
	Sender  uint64
	Sig     []byte
	SigData []byte
}

func NewPutArgT(sender uint64, sig, sigData []byte) *PutArgT {
	return &PutArgT{Sender: sender, Sig: sig, SigData: sigData}
}

func (p *PutArgT) Encode() []byte {
	// ECDSA_P256 gave diff len sigs, which complicates encoding.
	// ED25519 should have const len sigs.
	machine.Assume(uint64(len(p.Sig)) == SigLen)
	var b = make([]byte, 0)
	b = marshal.WriteInt(b, p.Sender)
	b = marshal.WriteBytes(b, p.Sig)
	b = marshal.WriteInt(b, uint64(len(p.SigData)))
	b = marshal.WriteBytes(b, p.SigData)
	return b
}

// Input comes from adv RPC, so need to validate it.
func (p *PutArgT) Decode(b []byte) ([]byte, ErrorT) {
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
	sig, r3 := marshal.ReadBytes(r2, SigLen)
	if uint64(len(r3)) < 8 {
		return nil, ErrSome
	}
	ln, r4 := marshal.ReadInt(r3)
	if uint64(len(r4)) < ln {
		return nil, ErrSome
	}
	sigData := r4[:ln]
	r5 := r4[ln:]
	p = NewPutArgT(sender, sig, sigData)
	return r5, ErrNone
}

// GetArgT

type GetArgT struct {
	Args []*PutArgT
}

func NewGetArgT(args []*PutArgT) *GetArgT {
	return &GetArgT{Args: args}
}

func (l *GetArgT) Encode() []byte {
	var b = make([]byte, 0)
	b = marshal.WriteInt(b, uint64(len(l.Args)))
	for _, v := range l.Args {
		b = marshal.WriteBytes(b, v.Encode())
	}
	return b
}

func (l *GetArgT) Decode(b []byte) ([]byte, ErrorT) {
	if uint64(len(b)) < 8 {
		return nil, ErrSome
	}
	ln, b := marshal.ReadInt(b)
	sl := make([]*PutArgT, ln)
	for i := uint64(0); i < ln; i++ {
		_, err := sl[i].Decode(b)
		if err != ErrNone {
			return nil, ErrSome
		}
	}
	l = NewGetArgT(sl)
	return b, ErrNone
}
