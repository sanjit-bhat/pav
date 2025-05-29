package server

import (
	"github.com/mit-pdos/pav/ktserde"
)

type ServerPutArg struct {
	Uid uint64
	Pk  []byte
	Ver uint64
}

type ServerHistoryArg struct {
	Uid       uint64
	PrefixLen uint64
}

type ServerHistoryReply struct {
	Dig   *ktserde.SigDig
	Hist  []*ktserde.Memb
	Bound *ktserde.NonMemb
	Err   bool
}

type ServerAuditArg struct {
	Epoch uint64
}

type ServerAuditReply struct {
	P   *ktserde.UpdateProof
	Err bool
}
