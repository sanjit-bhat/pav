package kt

import (
	"github.com/goose-lang/std"
	"github.com/mit-pdos/pav/cryptoffi"
	"github.com/mit-pdos/pav/merkle"
)

type signedLink struct {
	epoch    epochTy
	prevLink linkTy
	dig      merkle.Digest
	sig      cryptoffi.Sig
}

func (o *signedLink) check(pk cryptoffi.PublicKey) (linkTy, errorTy) {
	preLink := (&chainSepSome{epoch: o.epoch, prevLink: o.prevLink, data: o.dig}).encode()
	link := cryptoffi.Hash(preLink)
	sepLink := (&servSepLink{link: link}).encode()
	ok := pk.Verify(sepLink, o.sig)
	return link, !ok
}

type signedPut struct {
	epoch epochTy
	id    merkle.Id
	val   merkle.Val
	sig   cryptoffi.Sig
}

func (o *signedPut) check(pk cryptoffi.PublicKey) errorTy {
	sepPut := (&servSepPut{epoch: o.epoch, id: o.id, val: o.val}).encode()
	okPut := pk.Verify(sepPut, o.sig)
	return !okPut
}

// evidServLink is evidence that the server signed two conflicting links,
// either zero or one epochs away.
type evidServLink struct {
	sigLn0 *signedLink
	sigLn1 *signedLink
}

// check returns an error if the evidence does not check out.
// otherwise, it proves that the server was dishonest.
func (e *evidServLink) check(servPk cryptoffi.PublicKey) errorTy {
	link0, err0 := e.sigLn0.check(servPk)
	if err0 {
		return errSome
	}

	link1, err1 := e.sigLn1.check(servPk)
	if err1 {
		return errSome
	}

	if e.sigLn0.epoch == e.sigLn1.epoch {
		return std.BytesEqual(link0, link1)
	}
	if e.sigLn1.epoch > 0 && e.sigLn0.epoch == e.sigLn1.epoch-1 {
		return std.BytesEqual(link0, e.sigLn1.prevLink)
	}
	return errSome
}

// evidServPut is evidence when a server promises to put a value at a certain
// epoch but actually there's a different value (as evidenced by a merkle proof).
type evidServPut struct {
	sigLn  *signedLink
	sigPut *signedPut
	// merkle inclusion.
	val   merkle.Val
	proof merkle.Proof
}

func (e *evidServPut) check(servPk cryptoffi.PublicKey) errorTy {
	_, err0 := e.sigLn.check(servPk)
	if err0 {
		return errSome
	}

	err1 := e.sigPut.check(servPk)
	if err1 {
		return errSome
	}

	err2 := merkle.CheckProof(merkle.MembProofTy, e.proof, e.sigPut.id, e.val, e.sigLn.dig)
	if err2 {
		return errSome
	}

	if e.sigLn.epoch != e.sigPut.epoch {
		return errSome
	}
	return std.BytesEqual(e.sigPut.val, e.val)
}
