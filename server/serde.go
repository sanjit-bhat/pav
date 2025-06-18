package server

import (
	"github.com/mit-pdos/pav/ktserde"
)

type StartCliReply struct {
	StartEpochLen uint64
	StartLink     []byte
	ChainProof    []byte
	LinkSig       []byte
}

type PutArg struct {
	Uid uint64
	Pk  []byte
	Ver uint64
}

type HistoryArg struct {
	Uid        uint64
	PrevEpoch  uint64
	PrevVerLen uint64
}

type HistoryReply struct {
	ChainProof []byte
	LinkSig    []byte
	Hist       []*ktserde.Memb
	Bound      *ktserde.NonMemb
	Err        bool
}

type AuditArg struct {
	Epoch uint64
}

type AuditReply struct {
	P   *ktserde.AuditProof
	Err bool
}
