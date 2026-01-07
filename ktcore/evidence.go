package ktcore

import (
	"bytes"

	"github.com/sanjit-bhat/pav/cryptoffi"
)

// Evid is irrefutable (i.e., cryptographic) evidence that
// a party signed contradicting statements.
// a user can whistleblow by providing this to other users.
type Evid struct {
	Vrf  *EvidVrf
	Link *EvidLink
}

// EvidVrf has sigs over different VRF pks.
type EvidVrf struct {
	VrfPk0 []byte
	Sig0   []byte
	VrfPk1 []byte
	Sig1   []byte
}

// EvidLink has sigs over different hashchain links, for the same epoch.
type EvidLink struct {
	Epoch uint64
	Link0 []byte
	Sig0  []byte
	Link1 []byte
	Sig1  []byte
}

// Check errors if the evidence does not check out.
// otherwise, it proves that the pk owner was misbehaving.
func (e *Evid) Check(pk cryptoffi.SigPublicKey) (err bool) {
	if e.Vrf != nil {
		if e.Link != nil {
			return true
		}
		return e.Vrf.check(pk)
	} else {
		if e.Link == nil {
			return true
		}
		return e.Link.check(pk)
	}
}

func (e *EvidVrf) check(pk cryptoffi.SigPublicKey) (err bool) {
	if VerifyVrfSig(pk, e.VrfPk0, e.Sig0) {
		return true
	}
	if VerifyVrfSig(pk, e.VrfPk1, e.Sig1) {
		return true
	}
	return bytes.Equal(e.VrfPk0, e.VrfPk1)
}

func (e *EvidLink) check(pk cryptoffi.SigPublicKey) (err bool) {
	if VerifyLinkSig(pk, e.Epoch, e.Link0, e.Sig0) {
		return true
	}
	if VerifyLinkSig(pk, e.Epoch, e.Link1, e.Sig1) {
		return true
	}
	return bytes.Equal(e.Link0, e.Link1)
}
