package server

import (
	"github.com/mit-pdos/pav/ktcore"
)

type StartReply struct {
	StartEpochLen uint64
	StartLink     []byte
	ChainProof    []byte
	LinkSig       []byte
	VrfPk         []byte
	VrfSig        []byte
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
	Hist       []*ktcore.Memb
	Bound      *ktcore.NonMemb
	Err        ktcore.Blame
}

type AuditArg struct {
	PrevEpochLen uint64
}

type AuditReply struct {
	P   []*ktcore.AuditProof
	Err ktcore.Blame
}
