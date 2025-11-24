package auditor

import (
	"github.com/sanjit-bhat/pav/ktcore"
)

type UpdateReply struct {
	Err ktcore.Blame
}

type GetArg struct {
	Epoch uint64
}

type SignedLink struct {
	Link    []byte
	ServSig []byte
	AdtrSig []byte
}

type SignedVrfPk struct {
	VrfPk   []byte
	ServSig []byte
	AdtrSig []byte
}

type GetReply struct {
	Link *SignedLink
	Vrf  *SignedVrfPk
	Err  bool
}
