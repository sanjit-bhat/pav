package server

import (
	"github.com/sanjit-bhat/pav/ktcore"
)

type StartChain struct {
	// give [PrevLink] to prove that latest dig in hashchain.
	PrevEpochLen uint64
	PrevLink     []byte
	ChainProof   []byte
	LinkSig      []byte
}

type StartVrf struct {
	VrfPk  []byte
	VrfSig []byte
}

type StartReply struct {
	Chain *StartChain
	Vrf   *StartVrf
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
	Err        bool
}

type AuditArg struct {
	PrevEpoch uint64
}

type AuditReply struct {
	P   []*ktcore.AuditProof
	Err bool
}
