// Package ktcore defines the core KT protocol.
// the normal key directory maps from uid to a list (the versions) of pks.
// the hidden key directory computes the map label as VRF(uid || ver).
// the map value is a commitment, Hash(pk || rand).
package ktcore

import (
	"github.com/sanjit-bhat/pav/cryptoffi"
	"github.com/sanjit-bhat/pav/cryptoutil"
)

// Blame a specific party when a bad thing happens.
// if a party is good, we should not see its [Blame] code.
type Blame uint64

const BlameNone Blame = 0

const (
	// BlameServSig only faults a signing predicate, whereas
	// [BlameServFull] additionally faults the full server RPC spec.
	BlameServSig Blame = 1 << iota
	BlameServFull
	BlameAdtrSig
	BlameAdtrFull
	BlameClients
	// BlameUnknown should only be used sparingly.
	// it's the equivalent of throwing up your hands in despair.
	// in this system, only miscellaneous network errors are allowed
	// to be [BlameUnknown] at the client-correctness level.
	BlameUnknown
)

// CheckBlame prevents bad parties from giving bad [Blame] codes.
func CheckBlame(b Blame, allowed []Blame) (err bool) {
	var all Blame
	for _, x := range allowed {
		all |= x
	}
	return b & ^all != 0
}

func SignVrf(sk *cryptoffi.SigPrivateKey, vrfPk []byte) (sig []byte) {
	b := make([]byte, 0, 1+8+cryptoffi.HashLen)
	b = VrfSigEncode(b, &VrfSig{SigTag: VrfSigTag, VrfPk: vrfPk})
	// benchmark: turn off sigs for akd compat.
	sig = sk.Sign(b)
	return
}

func VerifyVrfSig(pk cryptoffi.SigPublicKey, vrfPk, sig []byte) (err bool) {
	b := make([]byte, 0, 1+8+cryptoffi.HashLen)
	b = VrfSigEncode(b, &VrfSig{SigTag: VrfSigTag, VrfPk: vrfPk})
	return pk.Verify(b, sig)
}

func SignLink(sk *cryptoffi.SigPrivateKey, epoch uint64, link []byte) (sig []byte) {
	b := make([]byte, 0, 1+8+8+cryptoffi.HashLen)
	b = LinkSigEncode(b, &LinkSig{SigTag: LinkSigTag, Epoch: epoch, Link: link})
	// benchmark: turn off sigs for akd compat.
	sig = sk.Sign(b)
	return
}

func VerifyLinkSig(pk cryptoffi.SigPublicKey, epoch uint64, link, sig []byte) (err bool) {
	b := make([]byte, 0, 1+8+8+cryptoffi.HashLen)
	b = LinkSigEncode(b, &LinkSig{SigTag: LinkSigTag, Epoch: epoch, Link: link})
	return pk.Verify(b, sig)
}

func ProveMapLabel(sk *cryptoffi.VrfPrivateKey, uid uint64, ver uint64) (label []byte, proof []byte) {
	b := make([]byte, 0, 16)
	b = MapLabelEncode(b, &MapLabel{Uid: uid, Ver: ver})
	return sk.Prove(b)
}

func EvalMapLabel(sk *cryptoffi.VrfPrivateKey, uid uint64, ver uint64) (label []byte) {
	b := make([]byte, 0, 16)
	b = MapLabelEncode(b, &MapLabel{Uid: uid, Ver: ver})
	return sk.Evaluate(b)
}

func CheckMapLabel(pk *cryptoffi.VrfPublicKey, uid, ver uint64, proof []byte) (label []byte, err bool) {
	b := make([]byte, 0, 16)
	b = MapLabelEncode(b, &MapLabel{Uid: uid, Ver: ver})
	return pk.Verify(b, proof)
}

func GetMapVal(pkOpen *CommitOpen) (val []byte) {
	b := CommitOpenEncode(nil, pkOpen)
	return cryptoutil.Hash(b)
}

// GetCommitRand computes the psuedo-random (wrt commitSecret) bits
// used in a mapVal commitment.
func GetCommitRand(commitSecret, label []byte) (rand []byte) {
	hr := cryptoffi.NewHasher()
	hr.Write(commitSecret)
	hr.Write(label)
	return hr.Sum(nil)
}
