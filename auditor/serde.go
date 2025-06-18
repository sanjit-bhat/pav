package auditor

import (
	"github.com/mit-pdos/pav/ktserde"
)

type UpdateArg struct {
	P *ktserde.AuditProof
}

type UpdateReply struct {
	Err bool
}

type GetArg struct {
	Epoch uint64
}

type GetReply struct {
	X   *EpochInfo
	Err bool
}

type EpochInfo struct {
	Link    []byte
	ServSig []byte
	AdtrSig []byte
}
