// Package ktcore defines the core KT protocol.
// the normal key directory maps from uid to a list (the versions) of pks.
// the hidden key directory computes the map label as VRF(uid || ver).
// the map value is a commitment, Hash(pk || rand).
package ktcore

import (
	"github.com/sanjit-bhat/pav/cryptoffi"
	"github.com/sanjit-bhat/pav/cryptoutil"
)

func SignVrf(sk *cryptoffi.SigPrivateKey, vrfPk []byte) (sig []byte) {
	b := make([]byte, 0, 1+8+32)
	b = VrfSigEncode(b, &VrfSig{SigTag: VrfSigTag, VrfPk: vrfPk})
	// benchmark: turn off sigs for akd compat.
	sig = sk.Sign(b)
	return
}

func VerifyVrfSig(pk cryptoffi.SigPublicKey, vrfPk, sig []byte) (err bool) {
	b := make([]byte, 0, 1+8+32)
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

func GetMapVal(pk []byte, rand []byte) (val []byte) {
	b := make([]byte, 0, 8+32+8+cryptoffi.HashLen)
	b = CommitOpenEncode(b, &CommitOpen{Val: pk, Rand: rand})
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
