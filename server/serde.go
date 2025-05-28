package server

import (
	"github.com/mit-pdos/pav/ktserde"
)

type ServerPutArg struct {
	Uid uint64
	Pk  []byte
	Ver uint64
}

type ServerPutReply struct {
	Err bool
}

type ServerGetArg struct {
	Uid uint64
}

type ServerGetReply struct {
	Dig    *ktserde.SigDig
	Hist   []*ktserde.MembHide
	IsReg  bool
	Latest *ktserde.Memb
	Bound  *ktserde.NonMemb
}

type ServerSelfMonArg struct {
	Uid uint64
}

type ServerSelfMonReply struct {
	Dig   *ktserde.SigDig
	Bound *ktserde.NonMemb
}

type ServerAuditArg struct {
	Epoch uint64
}

type ServerAuditReply struct {
	P   *ktserde.UpdateProof
	Err bool
}
