package ktserde

import (
	"github.com/mit-pdos/pav/cryptoffi"
	"github.com/mit-pdos/pav/cryptoutil"
)

func SignVrf(sk *cryptoffi.SigPrivateKey, vrfPk []byte) []byte {
	var b = make([]byte, 0, 1+8+cryptoffi.HashLen)
	b = VrfSigEncode(b, &VrfSig{SigTag: VrfSigTag, VrfPk: vrfPk})
	sig := sk.Sign(b)
	// benchmark: turn off sigs for akd compat.
	// var sig []byte
	return sig
}

func VerifyVrfSig(pk cryptoffi.SigPublicKey, vrfPk, sig []byte) bool {
	var b = make([]byte, 0, 1+8+cryptoffi.HashLen)
	b = VrfSigEncode(b, &VrfSig{SigTag: VrfSigTag, VrfPk: vrfPk})
	return pk.Verify(b, sig)
}

func SignLink(sk *cryptoffi.SigPrivateKey, epoch uint64, link []byte) []byte {
	var b = make([]byte, 0, 1+8+8+cryptoffi.HashLen)
	b = LinkSigEncode(b, &LinkSig{SigTag: LinkSigTag, Epoch: epoch, Link: link})
	sig := sk.Sign(b)
	// benchmark: turn off sigs for akd compat.
	// var sig []byte
	return sig
}

func VerifyLinkSig(pk cryptoffi.SigPublicKey, epoch uint64, link, sig []byte) bool {
	var b = make([]byte, 0, 1+8+8+cryptoffi.HashLen)
	b = LinkSigEncode(b, &LinkSig{SigTag: LinkSigTag, Epoch: epoch, Link: link})
	return pk.Verify(b, sig)
}

// ProveMapLabel rets the vrf output and proof for mapLabel (VRF(uid || ver)).
func ProveMapLabel(uid uint64, ver uint64, sk *cryptoffi.VrfPrivateKey) ([]byte, []byte) {
	var b = make([]byte, 0, 16)
	b = MapLabelEncode(b, &MapLabel{Uid: uid, Ver: ver})
	return sk.Prove(b)
}

// EvalMapLabel rets the vrf output for mapLabel (VRF(uid || ver)).
func EvalMapLabel(uid uint64, ver uint64, sk *cryptoffi.VrfPrivateKey) []byte {
	var b = make([]byte, 0, 16)
	b = MapLabelEncode(b, &MapLabel{Uid: uid, Ver: ver})
	return sk.Evaluate(b)
}

// CheckMapLabel checks the vrf proof, computes the label, and errors on fail.
func CheckMapLabel(pk *cryptoffi.VrfPublicKey, uid, ver uint64, proof []byte) ([]byte, bool) {
	var b = make([]byte, 0, 16)
	b = MapLabelEncode(b, &MapLabel{Uid: uid, Ver: ver})
	return pk.Verify(b, proof)
}

// GetMapVal rets mapVal (Hash(pk || rand)).
func GetMapVal(pkOpen *CommitOpen) []byte {
	var b = make([]byte, 0, 8+uint64(len(pkOpen.Val))+8+cryptoffi.HashLen)
	b = CommitOpenEncode(b, pkOpen)
	return cryptoutil.Hash(b)
}
