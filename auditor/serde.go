package auditor

import (
	"github.com/mit-pdos/pav/ktcore"
)

type UpdateReply struct {
	Err ktcore.Blame
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
	Err         ktcore.Blame
}
