package shared

import (
	"bytes"
	"github.com/tchajed/goose/machine"
	"github.com/tchajed/marshal"
)

type ErrorT = uint64

const (
	// Errors
	ErrNone ErrorT = 0
	ErrSome ErrorT = 1
	// RPCs
	RpcPrepare uint64 = 1
	RpcCommit  uint64 = 2
	// Ops
	OpGet uint64 = 1
	OpPut uint64 = 2
	// Users
	MaxUsers uint64 = 2
	// Sig
	SigLen uint64 = 69
)

// KeyValue

type KeyValue struct {
	K uint64
	V []byte
}

func (k *KeyValue) Equals(o *KeyValue) bool {
	return k.K == o.K && bytes.Equal(k.V, o.V)
}

func (k *KeyValue) Encode() []byte {
	var b = make([]byte, 0)
	b = marshal.WriteInt(b, k.K)
	b = marshal.WriteInt(b, uint64(len(k.V)))
	b = marshal.WriteBytes(b, k.V)
	return b
}

func (k *KeyValue) Decode(b []byte) []byte {
	key, b := marshal.ReadInt(b)
	l, b := marshal.ReadInt(b)
	value, b := marshal.ReadBytes(b, l)
	k.K = key
	k.V = value
	return b
}

// LogEntry

type LogEntry struct {
	Op   uint64
	Data []byte
}

func (e *LogEntry) Equals(o *LogEntry) bool {
	return e.Op == o.Op && bytes.Equal(e.Data, o.Data)
}

func (e *LogEntry) Encode() []byte {
	var b = make([]byte, 0)
	b = marshal.WriteInt(b, e.Op)
	b = marshal.WriteInt(b, uint64(len(e.Data)))
	b = marshal.WriteBytes(b, e.Data)
	return b
}

func (e *LogEntry) Decode(b []byte) []byte {
	op, b := marshal.ReadInt(b)
	length, b := marshal.ReadInt(b)
	data, b := marshal.ReadBytes(b, length)
	e.Op = op
	e.Data = data
	return b
}

// Log

type Log struct {
	Log []*LogEntry
}

func (short *Log) IsPrefix(long *Log) bool {
	if len(long.Log) < len(short.Log) {
		return false
	}
	var ret = true
	for i, e := range short.Log {
		if !e.Equals(long.Log[i]) {
			ret = false
		}
	}
	return ret
}

func (l *Log) GetData() [][]byte {
	log := make([][]byte, 0)
	for _, e := range l.Log {
		if e.Op == OpPut {
			log = append(log, e.Data)
		}
	}
	return log
}

func (l *Log) Encode() []byte {
	var b = make([]byte, 0)
	b = marshal.WriteInt(b, uint64(len(l.Log)))
	for _, e := range l.Log {
		b = marshal.WriteBytes(b, e.Encode())
	}
	return b
}

func (l *Log) Decode(b []byte) []byte {
	length, b := marshal.ReadInt(b)
	log := make([]*LogEntry, length)
	for i := uint64(0); i < length; i++ {
		log[i] = &LogEntry{}
		b = log[i].Decode(b)
	}
	l.Log = log
	return b
}

// SignedLog

type SignedLog struct {
	Sender uint64
	Sig    []byte
	Log    *Log
}

func (s *SignedLog) Encode() []byte {
	// ECDSA_P256 gave diff len sigs, which complicates encoding.
	// ED25519 should have const len sigs.
	machine.Assume(uint64(len(s.Sig)) == SigLen)
	var b = make([]byte, 0)
	b = marshal.WriteInt(b, s.Sender)
	b = marshal.WriteBytes(b, s.Sig)
	b = marshal.WriteBytes(b, s.Log.Encode())
	return b
}

// Input comes from adv RPC, so need to validate it.
func (s *SignedLog) Decode(b []byte) ErrorT {
	if len(b) < 8 {
		return ErrSome
	}
	sender, b := marshal.ReadInt(b)
	if !(0 <= sender && sender < MaxUsers) {
		return ErrSome
	}
	if uint64(len(b)) < SigLen {
		return ErrSome
	}
	sig, b := marshal.ReadBytes(b, SigLen)
	log := &Log{}
	log.Decode(b)
	s.Sender = sender
	s.Sig = sig
	s.Log = log
	return ErrNone
}
