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
	Link        []byte
	ServLinkSig []byte
	AdtrLinkSig []byte
	VrfPk       []byte
	ServVrfSig  []byte
	AdtrVrfSig  []byte
	Err         bool
}
