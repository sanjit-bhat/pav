package ktmerkle

import (
	"github.com/goose-lang/std"
	"github.com/mit-pdos/pav/cryptoffi"
	"github.com/mit-pdos/pav/merkle"
)

// evidServLink is evidence that the server signed two conflicting links,
// either zero or one epochs away.
type evidServLink struct {
	epoch0    epochTy
	prevLink0 linkTy
	dig0      merkle.Digest
	sig0      cryptoffi.Sig

	epoch1    epochTy
	prevLink1 linkTy
	dig1      merkle.Digest
	sig1      cryptoffi.Sig
}

// check returns an error if the evidence does not check out.
// otherwise, it proves that the server was dishonest.
func (e *evidServLink) check(servPk cryptoffi.PublicKey) errorTy {
	linkSep0 := (&chainSepSome{epoch: e.epoch0, prevLink: e.prevLink0, data: e.dig0}).encode()
	link0 := cryptoffi.Hash(linkSep0)
	enc0 := (&servSepLink{link: link0}).encode()
	ok0 := servPk.Verify(enc0, e.sig0)
	if !ok0 {
		return errSome
	}

	linkSep1 := (&chainSepSome{epoch: e.epoch1, prevLink: e.prevLink1, data: e.dig1}).encode()
	link1 := cryptoffi.Hash(linkSep1)
	enc1 := (&servSepLink{link: link1}).encode()
	ok1 := servPk.Verify(enc1, e.sig1)
	if !ok1 {
		return errSome
	}

	if e.epoch0 == e.epoch1 {
		return std.BytesEqual(link0, link1)
	}
	if e.epoch0 == e.epoch1-1 {
		return std.BytesEqual(link0, e.prevLink1)
	}
	return errSome
}

// evidServPut is evidence when a server promises to put a value at a certain
// epoch but actually there's a different value (as evidenced by a merkle proof).
type evidServPut struct {
	epoch epochTy
	// For signed link.
	prevLink linkTy
	dig      merkle.Digest
	linkSig  cryptoffi.Sig
	// For signed put.
	id     merkle.Id
	val0   merkle.Val
	putSig cryptoffi.Sig
	// For merkle inclusion.
	val1  merkle.Val
	proof merkle.Proof
}

func (e *evidServPut) check(servPk cryptoffi.PublicKey) errorTy {
	// Proof of signing the link.
	preLink := (&chainSepSome{epoch: e.epoch, prevLink: e.prevLink, data: e.dig}).encode()
	link := cryptoffi.Hash(preLink)
	preLinkSig := (&servSepLink{link: link}).encode()
	linkOk := servPk.Verify(preLinkSig, e.linkSig)
	if !linkOk {
		return errSome
	}

	// Proof of signing the put promise.
	prePut := (&servSepPut{epoch: e.epoch, id: e.id, val: e.val0}).encode()
	putOk := servPk.Verify(prePut, e.putSig)
	if !putOk {
		return errSome
	}

	// Proof of merkle inclusion of the other val.
	err0 := merkle.CheckProof(merkle.MembProofTy, e.proof, e.id, e.val1, e.dig)
	if err0 {
		return errSome
	}

	return std.BytesEqual(e.val0, e.val1)
}
