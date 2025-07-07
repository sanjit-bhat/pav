package client

import (
	"github.com/goose-lang/std"
	"github.com/sanjit-bhat/pav/cryptoffi"
	"github.com/sanjit-bhat/pav/ktcore"
)

// Evid is evidence that the server misbehaved.
type Evid struct {
	vrf  *evidVrf
	link *evidLink
}

type evidVrf struct {
	vrfPk0 []byte
	sig0   []byte
	vrfPk1 []byte
	sig1   []byte
}

type evidLink struct {
	epoch uint64
	link0 []byte
	sig0  []byte
	link1 []byte
	sig1  []byte
}

func (e *evidVrf) Check(pk cryptoffi.SigPublicKey) (err bool) {
	if ktcore.VerifyVrfSig(pk, e.vrfPk0, e.sig0) {
		return true
	}
	if ktcore.VerifyVrfSig(pk, e.vrfPk1, e.sig1) {
		return true
	}
	return std.BytesEqual(e.vrfPk0, e.vrfPk1)
}

func (e *evidLink) Check(pk cryptoffi.SigPublicKey) (err bool) {
	if ktcore.VerifyLinkSig(pk, e.epoch, e.link0, e.sig0) {
		return true
	}
	if ktcore.VerifyLinkSig(pk, e.epoch, e.link1, e.sig1) {
		return true
	}
	return std.BytesEqual(e.link0, e.link1)
}

// Check returns an error if the evidence does not check out.
// otherwise, it proves that the server was dishonest.
func (e *Evid) Check(pk cryptoffi.SigPublicKey) bool {
	if e.vrf != nil {
		return e.vrf.Check(pk)
	}
	if e.link != nil {
		return e.link.Check(pk)
	}
	return true
}
